"""Planned lookup batches (F15.4, 2026-09-24).

## What this adds

`ingest.lookup_batch`: an analyst's committed plan to look many selectors
up on one provider, paced by the provider's windows and sent by the
unattended drain (scripts/lookup_drain.py). `ingest.lookup.batch_id` ties
each queued row to it; 0099's guard makes the column immutable without
being redefined (it compares every column it does not name).

## NONE only

Every lookup that sends case material to somebody else's system waits
for a named second person's sign-off (docs/00 decision 75), and a batch
has no second person, so a batch is NONE only, held by a CHECK. The drain
sends NONE rows only, as a second guard.

## Totals are never served

`planned` and `cached` count every subject the plan resolved under the
requester's labels, and a reader with a lower clearance must not learn
from them how many hidden selectors the case holds. They are kept for the
record and never serialised: the batches list derives its progress from
the rows the reader can read.

## Downgrade

Refuses when any batch belongs to a case under legal hold. Otherwise
cancels the still-QUEUED rows of a batch (a transition 0099's guard
allows), then drops the column and the table. Sent rows lose only their
batch link; LOOKUP_BATCH_QUEUED stays in audit.event.
"""
from alembic import op

revision = "0101"
down_revision = "0100"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

GUARDED_TABLES = {
    "ingest.lookup_batch": ("SELECT", "INSERT", "UPDATE"),
}


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE TABLE ingest.lookup_batch (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id uuid NOT NULL REFERENCES core."case"(id),
  provider_id uuid NOT NULL REFERENCES ingest.provider(id),
  operation text NOT NULL,
  exposure_level text NOT NULL CONSTRAINT lookup_batch_is_none CHECK (exposure_level = 'NONE'),
  requested_by uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at timestamptz NOT NULL DEFAULT now(),
  note text NOT NULL,
  plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
  planned integer NOT NULL CHECK (planned BETWEEN 0 AND 500),
  cached integer NOT NULL DEFAULT 0 CHECK (cached >= 0),
  cancelled_at timestamptz,
  cancelled_by uuid REFERENCES iam.app_user(id),
  cancel_reason text,
  purged_at timestamptz,
  CONSTRAINT lookup_batch_justified CHECK (purged_at IS NOT NULL OR length(btrim(note)) > 10),
  CONSTRAINT lookup_batch_cancel_complete CHECK (
    (cancelled_at IS NULL) = (cancelled_by IS NULL)
    AND (cancelled_at IS NULL) = (cancel_reason IS NULL)),
  CONSTRAINT lookup_batch_purge_empties CHECK (
    purged_at IS NULL OR (note = '' AND coalesce(cancel_reason, '') = ''))
);
CREATE INDEX lookup_batch_case_idx ON ingest.lookup_batch (case_id, requested_at DESC);

ALTER TABLE ingest.lookup ADD COLUMN batch_id uuid REFERENCES ingest.lookup_batch(id);
CREATE INDEX lookup_batch_idx ON ingest.lookup (batch_id) WHERE batch_id IS NOT NULL;

CREATE FUNCTION ingest.guard_lookup_batch() RETURNS trigger AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a lookup batch is the record of an analyst''s plan: retention empties it, nothing deletes it';
  END IF;
  IF (to_jsonb(NEW) - ARRAY['cancelled_at', 'cancelled_by', 'cancel_reason', 'note', 'purged_at'])
     IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['cancelled_at', 'cancelled_by', 'cancel_reason', 'note', 'purged_at']) THEN
    RAISE EXCEPTION 'a lookup batch''s plan is fixed';
  END IF;
  IF OLD.cancelled_at IS NOT NULL AND (NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at
       OR NEW.cancelled_by IS DISTINCT FROM OLD.cancelled_by) THEN
    RAISE EXCEPTION 'a lookup batch is cancelled once';
  END IF;
  IF (NEW.note IS DISTINCT FROM OLD.note
      OR (OLD.cancel_reason IS NOT NULL AND NEW.cancel_reason IS DISTINCT FROM OLD.cancel_reason))
     AND NOT (OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL) THEN
    RAISE EXCEPTION 'a lookup batch''s notes change only when retention empties them';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER lookup_batch_guarded
  BEFORE UPDATE OR DELETE ON ingest.lookup_batch
  FOR EACH ROW EXECUTE FUNCTION ingest.guard_lookup_batch();
CREATE TRIGGER lookup_batch_no_truncate
  BEFORE TRUNCATE ON ingest.lookup_batch
  FOR EACH STATEMENT EXECUTE FUNCTION ingest.guard_lookup_batch();

COMMENT ON TABLE ingest.lookup_batch IS
  'A committed plan of NONE lookups, paced by the provider''s windows. Its '
  'totals are never served: progress is derived from the rows a reader can read.';
""")
    run(f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON ingest.lookup_batch FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE n bigint;
BEGIN
  IF to_regclass('ingest.lookup_batch') IS NOT NULL THEN
    SELECT count(*) INTO n FROM ingest.lookup_batch b
      JOIN core."case" c ON c.id = b.case_id WHERE c.legal_hold;
    IF n > 0 THEN
      RAISE EXCEPTION 'refusing to downgrade 0101: lookup batches belong to a case under legal hold, and legal hold overrides deletion';
    END IF;
    UPDATE ingest.lookup SET state = 'CANCELLED', refusal = 'batch support removed by downgrade'
     WHERE state = 'QUEUED' AND batch_id IS NOT NULL;
  END IF;
END
$pre$;
DROP INDEX IF EXISTS ingest.lookup_batch_idx;
ALTER TABLE IF EXISTS ingest.lookup DROP COLUMN IF EXISTS batch_id;
DROP TABLE IF EXISTS ingest.lookup_batch;
DROP FUNCTION IF EXISTS ingest.guard_lookup_batch();
""")
