"""Jira as a notification channel: the destination, the issues it made, the
events posted on them, and the case owner's veto (notify F7,
2026-09-24).

## What this adds

- `notify.jira_destination`: the one operator-declared Jira (a partial
  unique index keeps one live). Its credential is envelope-sealed
  (security/sealed.py lists it, so the key-ring readiness row and
  scripts/rewrap_secrets.py cover it) and becomes zero bytes, with no key
  id, when the destination is retired. The ceiling is capped at AMBER by
  a CHECK: invariant 8 restated in the schema.
- `notify.jira_link`: one issue per work item. It snapshots the base URL
  and the project it was raised in, so moving the destination closes the
  old links ('destination moved') instead of commenting on an issue in a
  project the administrator just cut off.
  `case_id` exists so the issues raised about a purged case can be found;
  it is never shown without being asked for.
- `notify.jira_event`: what makes one event one post. Keyed (link, event),
  it records whether that event is already on the issue, so three
  recipients of one request make one post and two identical events make
  two.
- `notify.case_route_block`: a case owner's veto. Its history is in
  audit.event, so lifting it is a DELETE.
- `notify.delivery.jira_link_id`.

## The record of what reached Jira is kept

The retention mitigation rests on the link rows: the links list by case
and the purge warning are how an operator finds a case's copies in a
third-party system. So jira_link and jira_event refuse DELETE and TRUNCATE
by trigger and the runtime role loses DELETE on both (GUARDED_TABLES,
read by test_app_role_privileges_pg.py). A closed link stays closed; the
issue key may still be written onto it once, for a create that succeeded
while the destination was being retired. case_route_block keeps DELETE:
that is how a veto is lifted.

## Locking

One transaction, as every revision (env.py). The ALTER of notify.delivery
takes ACCESS EXCLUSIVE until commit and the delivery_link_is_jira CHECK
scans the table under it. Stop the api and the cron before migrating.

## Downgrade

Drops the column, the tables and the functions. Lossless on an empty
database; on a live one it discards the destination and its sealed
credential, the link records and the vetoes (the audit rows remain),
which is why the upgrade note says to take a backup first.
"""
from alembic import op

revision = "0097"
down_revision = "0096"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: Guarded against deletion without being append-only: the table and the
#: privileges the runtime role KEEPS on it.
GUARDED_TABLES = {
    "notify.jira_link": ("SELECT", "INSERT", "UPDATE"),
    "notify.jira_event": ("SELECT", "INSERT", "UPDATE"),
}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE TABLE notify.jira_destination (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  label text NOT NULL,
  base_url text NOT NULL,
  host text NOT NULL,
  port integer NOT NULL,
  flavour text NOT NULL DEFAULT 'AUTO',
  auth_kind text NOT NULL,
  auth_user text,
  credential_ciphertext bytea NOT NULL,
  credential_key_id text,
  credential_set_at timestamptz NOT NULL DEFAULT now(),
  credential_set_by uuid NOT NULL REFERENCES iam.app_user(id),
  project_key text NOT NULL,
  issue_type text NOT NULL DEFAULT 'Task',
  issue_type_id text,
  ceiling core.tlp NOT NULL DEFAULT 'GREEN',
  field_exposure text NOT NULL DEFAULT 'SUBJECT',
  kinds text[] NOT NULL
    DEFAULT '{APPROVAL_REQUESTED,APPROVAL_DECIDED,PROPOSAL_QUEUED,CASE_REVIEW_DUE}',
  state text NOT NULL DEFAULT 'DRAFT',
  health text NOT NULL DEFAULT 'UNTESTED',
  health_detail text,
  health_changed_at timestamptz,
  tested_at timestamptz,
  server_version text,
  deployment_type text,
  edit_caveat text,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid NOT NULL REFERENCES iam.app_user(id),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by uuid NOT NULL REFERENCES iam.app_user(id),
  activated_at timestamptz,
  retired_at timestamptz,
  CONSTRAINT jira_destination_label_present
    CHECK (length(btrim(label)) BETWEEN 1 AND 80),
  CONSTRAINT jira_destination_url_shape
    CHECK (base_url ~ '^https?://[^/?#@]+(/[^?#]*)?$' AND right(base_url, 1) <> '/'),
  CONSTRAINT jira_destination_host_shape
    CHECK (host = lower(host) AND host ~ '^[a-z0-9.:\\[\\]-]{1,253}$'),
  CONSTRAINT jira_destination_port_range CHECK (port BETWEEN 1 AND 65535),
  CONSTRAINT jira_destination_flavour_known
    CHECK (flavour IN ('AUTO', 'CLOUD', 'DATA_CENTER')),
  CONSTRAINT jira_destination_auth_known
    CHECK (auth_kind IN ('CLOUD_API_TOKEN', 'DC_PAT', 'DC_BASIC')),
  CONSTRAINT jira_destination_auth_matches
    CHECK ((flavour <> 'CLOUD' OR auth_kind = 'CLOUD_API_TOKEN')
           AND (flavour <> 'DATA_CENTER' OR auth_kind IN ('DC_PAT', 'DC_BASIC'))),
  CONSTRAINT jira_destination_auth_user
    CHECK ((auth_kind = 'DC_PAT') = (auth_user IS NULL)),
  CONSTRAINT jira_destination_project_key
    CHECK (project_key ~ '^[A-Z][A-Z0-9_]{1,19}$'),
  CONSTRAINT jira_destination_issue_type_id
    CHECK (issue_type_id IS NULL OR issue_type_id ~ '^[0-9]{1,18}$'),
  CONSTRAINT jira_destination_below_floor
    CHECK (ceiling IN ('CLEAR', 'GREEN', 'AMBER')),
  CONSTRAINT jira_destination_exposure_known
    CHECK (field_exposure IN ('STUB', 'SUBJECT', 'SUMMARY')),
  CONSTRAINT jira_destination_kinds_present
    CHECK (coalesce(array_length(kinds, 1), 0) >= 1),
  CONSTRAINT jira_destination_state_known
    CHECK (state IN ('DRAFT', 'ACTIVE', 'PAUSED', 'RETIRED')),
  CONSTRAINT jira_destination_health_known
    CHECK (health IN ('UNTESTED', 'OK', 'FAILING', 'BROKEN')),
  CONSTRAINT jira_destination_live_is_resolved
    CHECK (state NOT IN ('ACTIVE', 'PAUSED')
           OR (flavour <> 'AUTO' AND issue_type_id IS NOT NULL
               AND activated_at IS NOT NULL AND tested_at IS NOT NULL)),
  CONSTRAINT jira_destination_retired_is_shredded
    CHECK (state <> 'RETIRED'
           OR (octet_length(credential_ciphertext) = 0
               AND credential_key_id IS NULL AND retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX jira_destination_one_live
  ON notify.jira_destination ((1)) WHERE state <> 'RETIRED';

CREATE TABLE notify.jira_link (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  destination_id uuid NOT NULL REFERENCES notify.jira_destination(id),
  case_id uuid NOT NULL REFERENCES core."case"(id),
  work_key uuid NOT NULL,
  ref text NOT NULL UNIQUE CONSTRAINT jira_link_ref_shape CHECK (ref ~ '^[a-z2-7]{16}$'),
  base_url text NOT NULL,
  project_key text NOT NULL,
  state text NOT NULL DEFAULT 'CREATING',
  issue_key text,
  issue_id text,
  classification core.tlp NOT NULL,
  exposure text NOT NULL,
  create_attempted_at timestamptz,
  creator_event_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  linked_at timestamptz,
  last_synced_at timestamptz,
  closed_at timestamptz,
  closed_reason text,
  CONSTRAINT jira_link_create_recorded
    CHECK ((create_attempted_at IS NULL) = (creator_event_id IS NULL)),
  CONSTRAINT jira_link_linked_was_created
    CHECK (state <> 'LINKED' OR create_attempted_at IS NOT NULL),
  CONSTRAINT jira_link_state_known CHECK (state IN ('CREATING', 'LINKED', 'CLOSED')),
  CONSTRAINT jira_link_exposure_known CHECK (exposure IN ('STUB', 'SUBJECT', 'SUMMARY')),
  CONSTRAINT jira_link_key_shape
    CHECK (issue_key IS NULL OR issue_key ~ '^[A-Z][A-Z0-9_]{1,19}-[1-9][0-9]{0,9}$'),
  CONSTRAINT jira_link_id_shape CHECK (issue_id IS NULL OR issue_id ~ '^[0-9]{1,18}$'),
  CONSTRAINT jira_link_linked_has_key
    CHECK (state <> 'LINKED' OR (issue_key IS NOT NULL AND linked_at IS NOT NULL)),
  CONSTRAINT jira_link_closed_has_time CHECK ((state = 'CLOSED') = (closed_at IS NOT NULL)),
  CONSTRAINT jira_link_closed_reason_known
    CHECK (closed_reason IS NULL OR closed_reason IN
           ('done in Jira', 'deleted in Jira', 'destination retired',
            'destination moved', 'case kept out'))
);
CREATE UNIQUE INDEX jira_link_one_open
  ON notify.jira_link (destination_id, work_key) WHERE state <> 'CLOSED';
CREATE INDEX jira_link_case_idx ON notify.jira_link (case_id, created_at DESC);
CREATE INDEX jira_link_issue_idx
  ON notify.jira_link (destination_id, issue_key) WHERE issue_key IS NOT NULL;

CREATE TABLE notify.jira_event (
  link_id uuid NOT NULL REFERENCES notify.jira_link(id),
  event_id uuid NOT NULL,
  marker text NOT NULL,
  state text NOT NULL,
  classification core.tlp NOT NULL,
  attempted_at timestamptz NOT NULL,
  posted_at timestamptz,
  posted_as text,
  comment_id text,
  PRIMARY KEY (link_id, event_id),
  CONSTRAINT jira_event_marker_shape CHECK (marker ~ '^[0-9a-f]{12}$'),
  CONSTRAINT jira_event_state_known CHECK (state IN ('POSTING', 'POSTED')),
  CONSTRAINT jira_event_posted_as_known
    CHECK (posted_as IS NULL OR posted_as IN ('CREATE', 'COMMENT')),
  CONSTRAINT jira_event_posted_is_complete
    CHECK ((state = 'POSTED') = (posted_at IS NOT NULL AND posted_as IS NOT NULL)),
  CONSTRAINT jira_event_comment_shape
    CHECK (comment_id IS NULL
           OR (posted_as = 'COMMENT' AND comment_id ~ '^[0-9]{1,18}$'))
);

CREATE TABLE notify.case_route_block (
  case_id uuid NOT NULL REFERENCES core."case"(id),
  channel text NOT NULL,
  reason text NOT NULL,
  blocked_by uuid NOT NULL REFERENCES iam.app_user(id),
  blocked_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, channel),
  CONSTRAINT case_route_block_channel_known CHECK (channel = 'JIRA'),
  CONSTRAINT case_route_block_reason_present
    CHECK (length(btrim(reason)) BETWEEN 5 AND 500)
);

ALTER TABLE notify.delivery
  ADD COLUMN jira_link_id uuid REFERENCES notify.jira_link(id),
  ADD CONSTRAINT delivery_link_is_jira CHECK (jira_link_id IS NULL OR channel = 'JIRA');
CREATE INDEX delivery_jira_link_idx ON notify.delivery (jira_link_id)
  WHERE jira_link_id IS NOT NULL;

CREATE FUNCTION notify.guard_jira_link() RETURNS trigger AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a Jira link is the record that case material reached a third-party system: it is closed, never deleted';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.destination_id IS DISTINCT FROM OLD.destination_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.work_key IS DISTINCT FROM OLD.work_key
     OR NEW.ref IS DISTINCT FROM OLD.ref
     OR NEW.base_url IS DISTINCT FROM OLD.base_url
     OR NEW.project_key IS DISTINCT FROM OLD.project_key
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'a Jira link names one work item on one destination and cannot be rewritten';
  END IF;
  IF OLD.state = 'CLOSED' THEN
    IF NEW.state <> 'CLOSED'
       OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
       OR NEW.closed_reason IS DISTINCT FROM OLD.closed_reason
       OR (OLD.issue_key IS NOT NULL AND NEW.issue_key IS DISTINCT FROM OLD.issue_key)
       OR (OLD.issue_id IS NOT NULL AND NEW.issue_id IS DISTINCT FROM OLD.issue_id) THEN
      RAISE EXCEPTION 'a closed Jira link stays closed; only a missing issue key may still be recorded on it';
    END IF;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER jira_link_guarded
  BEFORE UPDATE OR DELETE ON notify.jira_link
  FOR EACH ROW EXECUTE FUNCTION notify.guard_jira_link();
CREATE TRIGGER jira_link_no_truncate
  BEFORE TRUNCATE ON notify.jira_link
  FOR EACH STATEMENT EXECUTE FUNCTION notify.guard_jira_link();

CREATE FUNCTION notify.guard_jira_event() RETURNS trigger AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a Jira event row is the record of what was posted to a third-party system: it is never deleted';
  END IF;
  IF NEW.link_id IS DISTINCT FROM OLD.link_id
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.marker IS DISTINCT FROM OLD.marker THEN
    RAISE EXCEPTION 'a Jira event row cannot be moved to another issue or event';
  END IF;
  IF OLD.state = 'POSTED' AND (NEW.state <> 'POSTED'
       OR NEW.posted_at IS DISTINCT FROM OLD.posted_at
       OR NEW.posted_as IS DISTINCT FROM OLD.posted_as
       OR NEW.comment_id IS DISTINCT FROM OLD.comment_id) THEN
    RAISE EXCEPTION 'a posted Jira event stays posted';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER jira_event_guarded
  BEFORE UPDATE OR DELETE ON notify.jira_event
  FOR EACH ROW EXECUTE FUNCTION notify.guard_jira_event();
CREATE TRIGGER jira_event_no_truncate
  BEFORE TRUNCATE ON notify.jira_event
  FOR EACH STATEMENT EXECUTE FUNCTION notify.guard_jira_event();

COMMENT ON TABLE notify.jira_destination IS
  'The one operator-declared Jira destination (F7). The credential is '
  'envelope-sealed and zero bytes after retire; reach is decided by the '
  'egress route "jira", never by this row.';
COMMENT ON TABLE notify.jira_link IS
  'One Jira issue per work item. case_id exists so the issues raised about '
  'a purged case can be found, and is never shown without being asked for. '
  'Closed, never deleted.';
COMMENT ON TABLE notify.jira_event IS
  'Whether one event is already on its issue: what makes one event one post.';
COMMENT ON TABLE notify.case_route_block IS
  'A case owner keeps this case out of Jira. The history is in audit.event '
  '(NOTIFY_CASE_ROUTING_CHANGED); lifting the veto deletes the row.';
""")
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON notify.jira_link, notify.jira_event FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    run("""
DROP INDEX IF EXISTS notify.delivery_jira_link_idx;
ALTER TABLE notify.delivery
  DROP CONSTRAINT IF EXISTS delivery_link_is_jira,
  DROP COLUMN IF EXISTS jira_link_id;
DROP TABLE IF EXISTS notify.case_route_block;
DROP TABLE IF EXISTS notify.jira_event;
DROP TABLE IF EXISTS notify.jira_link;
DROP TABLE IF EXISTS notify.jira_destination;
DROP FUNCTION IF EXISTS notify.guard_jira_event();
DROP FUNCTION IF EXISTS notify.guard_jira_link();
""")
