"""The record of Web Key Directory lookups, and the two permissions that
make one (F10c, comms, 2026-09-24).

## Why a lookup needs a record at all

A WKD request tells the directory's operator which address was looked up
(the hash in the URL is reversible by an operator who knows its own
users), when, and from which address. That is case material leaving the
deployment, so docs/00 decision 75 applies: one person asks, a DIFFERENT
eligible person approves in a separate action, the request lapses, and
the record of what will be sent is committed before the first packet.

## What this adds

1. `comms.pgp_key_lookup`: the request, its labels and the route it may
   take, the decision, the URLs planned BEFORE anything was sent (both
   candidates, so a process that dies during the fallback leaves the right
   destinations named) and what came back. The CHECKs make the rules
   structural: two people (decided_by <> requested_by on every row that
   left), a lapse of at most 72 hours, only CLEAR, GREEN or AMBER, labels
   within the ceiling, and planned URLs that can only be the two hash-only
   URLs for the row's own address (no `?l=`).
2. `comms.guard_pgp_key_lookup()`: a request is born REQUESTED in a case
   with no compartments, never below its case or what it cites; what was
   asked never changes; states move REQUESTED to DECLINED, EXPIRED or
   SENDING (only before the lapse, and only while the case still has no
   compartments and is not above the request), and SENDING to FOUND,
   NOT_FOUND or FAILED once; nothing is deleted.
3. The acquisition learns a third source, WKD, which carries its lookup
   (one acquisition per lookup, at the lookup's own labels, and only while
   the lookup is SENDING, so the key is filed before the lookup is marked
   FOUND). A WKD acquisition has no compartments by construction.
4. Two permissions, both step-up: `comms.key.lookup` (Lead investigator,
   Collector) and `comms.key.lookup.approve` (Lead investigator,
   Reviewer).
5. DELETE revoked from the runtime role on the lookups (`GUARDED_TABLES`).

## Downgrade

Refuses while any lookup row exists: it is the record of a request made
outside this deployment, or refused before one was. Otherwise restores
0088's acquisition constraints and guard, drops the table and its guard,
and deletes the grants and the permissions.
"""
from alembic import op

revision = "0090"
down_revision = "0089"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

GUARDED_TABLES = {
    "comms.pgp_key_lookup": ("SELECT", "INSERT", "UPDATE"),
}

PERMISSIONS = (
    ("comms.key.lookup",
     "Ask for a vendor key to be looked up in a Web Key Directory. Nothing "
     "is sent until a second person approves", True),
    ("comms.key.lookup.approve",
     "Approve and send a key lookup somebody else asked for, which sends a "
     "request outside this deployment", True),
)
GRANTS = (
    ("CASE_OWNER", "comms.key.lookup"),
    ("COLLECTOR", "comms.key.lookup"),
    ("CASE_OWNER", "comms.key.lookup.approve"),
    ("REVIEWER", "comms.key.lookup.approve"),
)

WKD_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


UPGRADE_SQL = f"""
CREATE TABLE comms.pgp_key_lookup (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id            uuid NOT NULL REFERENCES core."case"(id),
  address            text NOT NULL,
  local_part         text NOT NULL,
  domain             text NOT NULL,
  wkd_hash           text NOT NULL,
  reason             text NOT NULL,
  channel_binding_id uuid,
  contact_block_id   uuid,
  classification     core.tlp NOT NULL,
  ceiling            core.tlp NOT NULL,
  route_name         text NOT NULL,
  state              text NOT NULL DEFAULT 'REQUESTED',
  requested_by       uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at       timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  decided_by         uuid REFERENCES iam.app_user(id),
  decided_at         timestamptz,
  decision_note      text,
  planned_urls       text[],
  sent_at            timestamptz,
  method_used        text,
  url_used           text,
  http_status        integer,
  response_sha256    bytea,
  response_bytes     integer,
  detail             text NOT NULL DEFAULT '',
  finished_at        timestamptz,
  CONSTRAINT pgp_key_lookup_id_case_key UNIQUE (id, case_id),
  CONSTRAINT pgp_key_lookup_binding_same_case
    FOREIGN KEY (channel_binding_id, case_id)
    REFERENCES comms.channel_binding(id, case_id),
  CONSTRAINT pgp_key_lookup_block_same_case
    FOREIGN KEY (contact_block_id, case_id)
    REFERENCES comms.contact_block(id, case_id),
  CONSTRAINT pgp_key_lookup_state_known
    CHECK (state IN ('REQUESTED', 'DECLINED', 'EXPIRED', 'SENDING',
                     'FOUND', 'NOT_FOUND', 'FAILED')),
  -- Invariant 8 for this path, in the schema.
  CONSTRAINT pgp_key_lookup_leaves_at_most_amber
    CHECK (classification IN ('CLEAR', 'GREEN', 'AMBER')),
  CONSTRAINT pgp_key_lookup_ceiling_binds
    CHECK (ceiling IN ('CLEAR', 'GREEN', 'AMBER') AND classification <= ceiling),
  CONSTRAINT pgp_key_lookup_hash_shape
    CHECK (wkd_hash ~ '^[{WKD_ALPHABET}]{{32}}$'),
  CONSTRAINT pgp_key_lookup_domain_shape
    CHECK (length(domain) <= 253
       AND domain ~ '^([a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$'),
  CONSTRAINT pgp_key_lookup_address_is_its_parts
    CHECK (address = local_part || '@' || domain),
  CONSTRAINT pgp_key_lookup_reason_size
    CHECK (length(btrim(reason)) BETWEEN 10 AND 2000),
  CONSTRAINT pgp_key_lookup_route_name_shape
    CHECK (route_name ~ '^[a-z][a-z0-9-]{{1,39}}$'),
  CONSTRAINT pgp_key_lookup_lapses
    CHECK (expires_at > requested_at
       AND expires_at <= requested_at + interval '72 hours'),
  CONSTRAINT pgp_key_lookup_requested_is_undecided
    CHECK (state <> 'REQUESTED'
        OR (decided_by IS NULL AND decided_at IS NULL AND decision_note IS NULL
            AND planned_urls IS NULL AND sent_at IS NULL)),
  CONSTRAINT pgp_key_lookup_declined_says_why
    CHECK (state <> 'DECLINED'
        OR (decided_by IS NOT NULL AND decided_at IS NOT NULL
            AND length(btrim(coalesce(decision_note, ''))) >= 3
            AND planned_urls IS NULL AND sent_at IS NULL)),
  CONSTRAINT pgp_key_lookup_expired_is_dated
    CHECK (state <> 'EXPIRED'
        OR (decided_at IS NOT NULL AND planned_urls IS NULL AND sent_at IS NULL)),
  -- Two people is a property of the table (0063's granted_to <> granted_by).
  CONSTRAINT pgp_key_lookup_sent_by_a_second_person
    CHECK (state NOT IN ('SENDING', 'FOUND', 'NOT_FOUND', 'FAILED')
        OR (decided_by IS NOT NULL AND decided_by <> requested_by
            AND decided_at IS NOT NULL AND sent_at IS NOT NULL
            AND cardinality(planned_urls) BETWEEN 1 AND 2)),
  CONSTRAINT pgp_key_lookup_hash_only_urls
    CHECK (planned_urls IS NULL
        OR planned_urls <@ ARRAY[
             'https://openpgpkey.' || domain || '/.well-known/openpgpkey/'
               || domain || '/hu/' || wkd_hash,
             'https://' || domain || '/.well-known/openpgpkey/hu/' || wkd_hash]),
  CONSTRAINT pgp_key_lookup_used_was_planned
    CHECK (url_used IS NULL OR url_used = ANY(planned_urls)),
  CONSTRAINT pgp_key_lookup_finished_is_dated
    CHECK ((state IN ('FOUND', 'NOT_FOUND', 'FAILED')) = (finished_at IS NOT NULL)),
  CONSTRAINT pgp_key_lookup_method_known
    CHECK (method_used IS NULL OR method_used IN ('ADVANCED', 'DIRECT')),
  CONSTRAINT pgp_key_lookup_found_is_whole
    CHECK (state <> 'FOUND'
        OR (http_status = 200 AND url_used IS NOT NULL AND method_used IS NOT NULL
            AND octet_length(response_sha256) = 32)),
  CONSTRAINT pgp_key_lookup_not_found_is_404
    CHECK (state <> 'NOT_FOUND' OR (http_status = 404 AND url_used IS NOT NULL)),
  CONSTRAINT pgp_key_lookup_digest_is_sha256
    CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
  CONSTRAINT pgp_key_lookup_detail_size CHECK (length(detail) <= 2000)
);
CREATE INDEX pgp_key_lookup_case_idx
  ON comms.pgp_key_lookup (case_id, requested_at DESC);
CREATE INDEX pgp_key_lookup_waiting_idx
  ON comms.pgp_key_lookup (case_id) WHERE state = 'REQUESTED';

COMMENT ON TABLE comms.pgp_key_lookup IS
  'Every Web Key Directory lookup asked for in a case: who asked, who '
  'approved it (always somebody else), what was planned and sent before '
  'the first packet, and what came back. Never deleted (F10c, docs/00 decision 75).';

CREATE FUNCTION comms.guard_pgp_key_lookup() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  case_cls core.tlp;
  case_comp text[];
  cited_cls core.tlp;
  cited_comp text[];
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a key lookup is the record of a request made outside this deployment, or of one refused before it was; it is never deleted';
  END IF;
  SELECT classification, compartments INTO case_cls, case_comp
    FROM core."case" WHERE id = NEW.case_id;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'REQUESTED' THEN
      RAISE EXCEPTION 'a key lookup is born REQUESTED';
    END IF;
    IF cardinality(case_comp) > 0 THEN
      RAISE EXCEPTION 'a compartmented case''s addresses are never looked up outside this deployment';
    END IF;
    IF NEW.classification < case_cls THEN
      RAISE EXCEPTION 'a key lookup is never filed below its case';
    END IF;
    IF NEW.channel_binding_id IS NOT NULL THEN
      SELECT classification, compartments INTO cited_cls, cited_comp
        FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
      IF cardinality(cited_comp) > 0 OR NEW.classification < cited_cls THEN
        RAISE EXCEPTION 'a key lookup is never filed below, or beside a compartment of, the binding it cites';
      END IF;
    END IF;
    IF NEW.contact_block_id IS NOT NULL THEN
      SELECT classification, compartments INTO cited_cls, cited_comp
        FROM comms.contact_block WHERE id = NEW.contact_block_id;
      IF cardinality(cited_comp) > 0 OR NEW.classification < cited_cls THEN
        RAISE EXCEPTION 'a key lookup is never filed below, or beside a compartment of, the contact block it cites';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  -- UPDATE: what was asked never changes.
  IF (NEW.id, NEW.case_id, NEW.address, NEW.local_part, NEW.domain,
      NEW.wkd_hash, NEW.reason, NEW.channel_binding_id, NEW.contact_block_id,
      NEW.classification, NEW.ceiling, NEW.route_name, NEW.requested_by,
      NEW.requested_at, NEW.expires_at)
     IS DISTINCT FROM
     (OLD.id, OLD.case_id, OLD.address, OLD.local_part, OLD.domain,
      OLD.wkd_hash, OLD.reason, OLD.channel_binding_id, OLD.contact_block_id,
      OLD.classification, OLD.ceiling, OLD.route_name, OLD.requested_by,
      OLD.requested_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'what a key lookup asked for is fixed when it is asked';
  END IF;
  IF OLD.state = 'REQUESTED' THEN
    IF NEW.state NOT IN ('DECLINED', 'EXPIRED', 'SENDING') THEN
      RAISE EXCEPTION 'a waiting key lookup is declined, lapses, or is approved and sent';
    END IF;
    IF NEW.state = 'SENDING' THEN
      IF now() >= NEW.expires_at THEN
        RAISE EXCEPTION 'the key lookup lapsed before it was approved';
      END IF;
      IF cardinality(case_comp) > 0 OR case_cls > NEW.classification THEN
        RAISE EXCEPTION 'the case''s labels changed since the key lookup was asked for, so it is not sent';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.state = 'SENDING' THEN
    IF NEW.state NOT IN ('FOUND', 'NOT_FOUND', 'FAILED') THEN
      RAISE EXCEPTION 'a key lookup that was sent ends FOUND, NOT_FOUND or FAILED';
    END IF;
    IF (NEW.decided_by, NEW.decided_at, NEW.decision_note, NEW.planned_urls,
        NEW.sent_at)
       IS DISTINCT FROM
       (OLD.decided_by, OLD.decided_at, OLD.decision_note, OLD.planned_urls,
        OLD.sent_at) THEN
      RAISE EXCEPTION 'the decision and the planned URLs of a sent key lookup are fixed';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'a key lookup that has finished is not changed';
END $$;

CREATE TRIGGER pgp_key_lookup_guarded
  BEFORE INSERT OR UPDATE OR DELETE ON comms.pgp_key_lookup
  FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_key_lookup();
CREATE TRIGGER pgp_key_lookup_no_truncate
  BEFORE TRUNCATE ON comms.pgp_key_lookup
  FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_key_lookup();

-- The acquisition learns its third source.
ALTER TABLE comms.pgp_key_acquisition
  DROP CONSTRAINT pgp_key_acquisition_source_known;
ALTER TABLE comms.pgp_key_acquisition
  ADD CONSTRAINT pgp_key_acquisition_source_known
    CHECK (source IN ('PASTE', 'FILE', 'WKD')),
  ADD COLUMN lookup_id uuid,
  ADD CONSTRAINT pgp_key_acquisition_lookup_same_case
    FOREIGN KEY (lookup_id, case_id) REFERENCES comms.pgp_key_lookup(id, case_id),
  ADD CONSTRAINT pgp_key_acquisition_wkd_has_its_lookup
    CHECK ((source = 'WKD') = (lookup_id IS NOT NULL)),
  ADD CONSTRAINT pgp_key_acquisition_wkd_uncompartmented
    CHECK (source <> 'WKD' OR cardinality(compartments) = 0);
CREATE UNIQUE INDEX pgp_key_acquisition_one_per_lookup
  ON comms.pgp_key_acquisition (lookup_id) WHERE lookup_id IS NOT NULL;

CREATE OR REPLACE FUNCTION comms.guard_pgp_key_acquisition() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  cited_cls core.tlp;
  cited_comp text[];
  cited_case uuid;
  lookup_state text;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a key acquisition is the record of what was obtained and from where; it is never deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.case_id, NEW.source, NEW.raw_bytes, NEW.raw_sha256,
        NEW.filename, NEW.source_ref, NEW.channel_binding_id,
        NEW.contact_block_id, NEW.evidence_id, NEW.classification,
        NEW.requested_by, NEW.requested_at, NEW.lookup_id)
       IS DISTINCT FROM
       (OLD.id, OLD.case_id, OLD.source, OLD.raw_bytes, OLD.raw_sha256,
        OLD.filename, OLD.source_ref, OLD.channel_binding_id,
        OLD.contact_block_id, OLD.evidence_id, OLD.classification,
        OLD.requested_by, OLD.requested_at, OLD.lookup_id)
       OR cardinality(NEW.compartments) <> cardinality(OLD.compartments) THEN
      RAISE EXCEPTION 'an acquisition''s record and labels are fixed; only a compartment rename may touch them';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT (NEW.compartments @> (SELECT compartments FROM core."case"
                                WHERE id = NEW.case_id)) THEN
    RAISE EXCEPTION 'an acquisition carries at least its case''s compartments';
  END IF;
  IF NEW.source = 'WKD' THEN
    SELECT state, classification INTO lookup_state, cited_cls
      FROM comms.pgp_key_lookup WHERE id = NEW.lookup_id;
    IF lookup_state IS DISTINCT FROM 'SENDING' THEN
      RAISE EXCEPTION 'a key found by a lookup is filed while its lookup is being answered';
    END IF;
    IF NEW.classification <> cited_cls THEN
      RAISE EXCEPTION 'a key found by a lookup is filed at the lookup''s own labels';
    END IF;
  END IF;
  IF NEW.evidence_id IS NOT NULL THEN
    SELECT case_id, classification, compartments
      INTO cited_case, cited_cls, cited_comp
      FROM core.evidence WHERE id = NEW.evidence_id;
    IF cited_case IS DISTINCT FROM NEW.case_id THEN
      RAISE EXCEPTION 'the exhibit belongs to another case';
    END IF;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the exhibit it cites';
    END IF;
  END IF;
  IF NEW.channel_binding_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the channel binding it cites';
    END IF;
  END IF;
  IF NEW.contact_block_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.contact_block WHERE id = NEW.contact_block_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the contact block it cites';
    END IF;
  END IF;
  RETURN NEW;
END $$;
"""

#: 0088's guard body, restored by the downgrade (migrations do not import
#: each other, so it is repeated here).
GUARD_0088 = """
CREATE OR REPLACE FUNCTION comms.guard_pgp_key_acquisition() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  cited_cls core.tlp;
  cited_comp text[];
  cited_case uuid;
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a key acquisition is the record of what was obtained and from where; it is never deleted';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.case_id, NEW.source, NEW.raw_bytes, NEW.raw_sha256,
        NEW.filename, NEW.source_ref, NEW.channel_binding_id,
        NEW.contact_block_id, NEW.evidence_id, NEW.classification,
        NEW.requested_by, NEW.requested_at)
       IS DISTINCT FROM
       (OLD.id, OLD.case_id, OLD.source, OLD.raw_bytes, OLD.raw_sha256,
        OLD.filename, OLD.source_ref, OLD.channel_binding_id,
        OLD.contact_block_id, OLD.evidence_id, OLD.classification,
        OLD.requested_by, OLD.requested_at)
       OR cardinality(NEW.compartments) <> cardinality(OLD.compartments) THEN
      RAISE EXCEPTION 'an acquisition''s record and labels are fixed; only a compartment rename may touch them';
    END IF;
    RETURN NEW;
  END IF;
  IF NOT (NEW.compartments @> (SELECT compartments FROM core."case"
                                WHERE id = NEW.case_id)) THEN
    RAISE EXCEPTION 'an acquisition carries at least its case''s compartments';
  END IF;
  IF NEW.evidence_id IS NOT NULL THEN
    SELECT case_id, classification, compartments
      INTO cited_case, cited_cls, cited_comp
      FROM core.evidence WHERE id = NEW.evidence_id;
    IF cited_case IS DISTINCT FROM NEW.case_id THEN
      RAISE EXCEPTION 'the exhibit belongs to another case';
    END IF;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the exhibit it cites';
    END IF;
  END IF;
  IF NEW.channel_binding_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the channel binding it cites';
    END IF;
  END IF;
  IF NEW.contact_block_id IS NOT NULL THEN
    SELECT classification, compartments INTO cited_cls, cited_comp
      FROM comms.contact_block WHERE id = NEW.contact_block_id;
    IF NEW.classification < cited_cls OR NOT (NEW.compartments @> cited_comp) THEN
      RAISE EXCEPTION 'an acquisition is never filed below the contact block it cites';
    END IF;
  END IF;
  RETURN NEW;
END $$;
"""


def _permission_sql() -> str:
    perms = ",\n  ".join(f"({_lit(k)}, {_lit(d)}, {'true' if s else 'false'})"
                         for k, d, s in PERMISSIONS)
    grants = ",\n  ".join(f"({_lit(r)}, {_lit(p)})" for r, p in GRANTS)
    return f"""
INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  {perms}
ON CONFLICT (key) DO NOTHING;
INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  {grants}
ON CONFLICT (role_key, permission_key) DO NOTHING;
"""


REVOKE_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON comms.pgp_key_lookup FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
"""

DOWNGRADE_SQL = """
DO $$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM comms.pgp_key_lookup;
  IF n > 0 THEN
    RAISE EXCEPTION 'refusing to downgrade 0090: % key lookups are recorded: they are the record of requests made outside this deployment, or refused before one was. Stay at this revision.', n;
  END IF;
END $$;

DROP INDEX comms.pgp_key_acquisition_one_per_lookup;
ALTER TABLE comms.pgp_key_acquisition
  DROP CONSTRAINT pgp_key_acquisition_wkd_uncompartmented,
  DROP CONSTRAINT pgp_key_acquisition_wkd_has_its_lookup,
  DROP CONSTRAINT pgp_key_acquisition_lookup_same_case,
  DROP COLUMN lookup_id;
ALTER TABLE comms.pgp_key_acquisition
  DROP CONSTRAINT pgp_key_acquisition_source_known;
ALTER TABLE comms.pgp_key_acquisition
  ADD CONSTRAINT pgp_key_acquisition_source_known
    CHECK (source IN ('PASTE', 'FILE'));

DROP TABLE comms.pgp_key_lookup;
DROP FUNCTION comms.guard_pgp_key_lookup();

DELETE FROM iam.role_permission WHERE permission_key IN
  ('comms.key.lookup', 'comms.key.lookup.approve');
DELETE FROM iam.permission WHERE key IN
  ('comms.key.lookup', 'comms.key.lookup.approve');
"""


def upgrade() -> None:
    run(UPGRADE_SQL)
    run(_permission_sql())
    run(REVOKE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL + GUARD_0088)
