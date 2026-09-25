"""What a poll records about itself, and a source's collection settings
(collection foundation, docs/00 decision 69, 2026-09-24).

## Why

The first collection adapters walk a site page by page (the forum
adapters) or speak a platform's own protocol (Telegram). Everything
they share lives once, in `CollectionService.run_once` and the adapter
contract, and it needs a few facts the schema did not keep:

- `collect.source.parser_config`: per-parser settings an adapter validates
  (a board's time zone, a page budget). A JSON object of at most 16 KiB.
- `collect.source.blocked_reason` / `blocked_at`: why the last poll could
  not run at all (no authority, no egress, a suspended persona). Cleared by
  the next good poll. A BLOCKED run is configuration, not parser health, so
  it never counts toward DEGRADED.
- `collect.source.cursor_reset_at`: runs started before it are not a resume
  point (a rebinding whose message ids restart).
- `collect.collection_run.requests`: the custody log of what a poll asked
  for, at most 100 entries, written ONCE when the run leaves RUNNING and
  never rewritten (trigger `collection_run_requests_once`).
- `collect.collection_run.requested_by`: who pressed Poll now; NULL is the
  system (the cron). A plain uuid, as `audit.event.actor_id` is: the run
  ledger records who asked, and it must never refuse to record a poll over
  the identity column (2026-09-24).
- `collect.collection_run.notes`: what a run wants known that is not a
  fault (a walk that stopped at its budget, a document with no clock).
- `collect.collection_run.items_deleted`: posts the site no longer shows.
- The cursor gains a size cap (16 KiB), validated in this transaction: every
  existing cursor is the default `{}`.

Two indexes serve the run listings: the unfiltered Recent runs, newest
first, and the per-source resume point (the latest finished run).

## What it does not add

The per-item lookups of the collector (the latest version of an external
id) are served by the existing unique index
`document_source_id_external_id_version_key` on (source_id, external_id,
version), which a backward scan reads newest first. A second index with
the version descending would duplicate that one, so it is not built.

## Downgrade

Refuses while any run carries a non-empty request log: the custody record
of what a poll asked for is not dropped by a schema rollback. Otherwise it
drops the trigger, the indexes, the constraints and the columns.
"""
from alembic import op

revision = "0081"
down_revision = "0080"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE collect.source
  ADD COLUMN parser_config jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN blocked_reason text,
  ADD COLUMN blocked_at timestamptz,
  ADD COLUMN cursor_reset_at timestamptz,
  ADD CONSTRAINT source_parser_config_is_object
    CHECK (jsonb_typeof(parser_config) = 'object'
           AND octet_length(parser_config::text) <= 16384),
  ADD CONSTRAINT source_blocked_complete
    CHECK ((blocked_reason IS NULL) = (blocked_at IS NULL));

COMMENT ON COLUMN collect.source.parser_config IS
  'Per-parser settings an adapter validates (a board''s time zone, a page budget). A JSON object of at most 16 KiB.';
COMMENT ON COLUMN collect.source.blocked_reason IS
  'Why the last poll could not run at all: no authority, no egress, a suspended persona. Cleared by the next good poll. Configuration, never parser health.';
COMMENT ON COLUMN collect.source.cursor_reset_at IS
  'Runs started before this are not a resume point: the next poll starts its reading position afresh.';

ALTER TABLE collect.collection_run
  ADD COLUMN requests jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN requested_by uuid,
  ADD COLUMN notes text[] NOT NULL DEFAULT '{}',
  ADD COLUMN items_deleted integer NOT NULL DEFAULT 0,
  ADD CONSTRAINT collection_run_requests_capped
    CHECK (jsonb_typeof(requests) = 'array'
           AND jsonb_array_length(requests) <= 100),
  ADD CONSTRAINT collection_run_notes_capped CHECK (cardinality(notes) <= 20),
  ADD CONSTRAINT collection_run_items_deleted_non_negative
    CHECK (items_deleted >= 0),
  ADD CONSTRAINT collection_run_cursor_capped
    CHECK (jsonb_typeof(cursor) = 'object'
           AND octet_length(cursor::text) <= 16384) NOT VALID;
ALTER TABLE collect.collection_run
  VALIDATE CONSTRAINT collection_run_cursor_capped;

COMMENT ON COLUMN collect.collection_run.requests IS
  'The custody log of what a poll asked for: at most 100 entries of time, path, query, status, bytes and digest. Written once as the run leaves RUNNING and never rewritten. Read under the source''s label.';
COMMENT ON COLUMN collect.collection_run.requested_by IS
  'Who pressed Poll now. NULL is the system (the cron). A plain uuid, as audit.event.actor_id is.';
COMMENT ON COLUMN collect.collection_run.notes IS
  'What a run wants known that is not a fault: a walk that stopped at its budget, documents with no retention clock, times with no zone.';
COMMENT ON COLUMN collect.collection_run.items_deleted IS
  'Items the site no longer shows, flagged on their latest version. The bodies are kept: deletions are intelligence.';

CREATE INDEX collection_run_started_idx
  ON collect.collection_run (started_at DESC NULLS LAST, id DESC);
CREATE INDEX collection_run_resume_idx
  ON collect.collection_run (source_id, started_at DESC NULLS LAST, id DESC)
  WHERE status <> 'RUNNING';

CREATE FUNCTION collect.guard_run_requests() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF OLD.requests = '[]'::jsonb AND OLD.status = 'RUNNING'
     AND NEW.status <> 'RUNNING' THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION USING MESSAGE =
    'a poll''s request log is written once, when the run finishes, and never '
    || 'rewritten: it is custody';
END
$f$;

CREATE TRIGGER collection_run_requests_once
  BEFORE UPDATE OF requests ON collect.collection_run
  FOR EACH ROW EXECUTE FUNCTION collect.guard_run_requests();
""")


def downgrade() -> None:
    run("""
DO $pre$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM collect.collection_run
   WHERE requests <> '[]'::jsonb;
  IF n > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0081: ' || n
      || CASE WHEN n = 1 THEN ' run carries' ELSE ' runs carry' END
      || ' a request log, the custody record of what a poll asked for, and '
      || 'a schema rollback does not drop it';
  END IF;
END
$pre$;

DROP TRIGGER IF EXISTS collection_run_requests_once ON collect.collection_run;
DROP FUNCTION IF EXISTS collect.guard_run_requests();
DROP INDEX IF EXISTS collect.collection_run_resume_idx;
DROP INDEX IF EXISTS collect.collection_run_started_idx;

ALTER TABLE collect.collection_run
  DROP CONSTRAINT IF EXISTS collection_run_cursor_capped,
  DROP CONSTRAINT IF EXISTS collection_run_items_deleted_non_negative,
  DROP CONSTRAINT IF EXISTS collection_run_notes_capped,
  DROP CONSTRAINT IF EXISTS collection_run_requests_capped,
  DROP COLUMN IF EXISTS items_deleted,
  DROP COLUMN IF EXISTS notes,
  DROP COLUMN IF EXISTS requested_by,
  DROP COLUMN IF EXISTS requests;

ALTER TABLE collect.source
  DROP CONSTRAINT IF EXISTS source_blocked_complete,
  DROP CONSTRAINT IF EXISTS source_parser_config_is_object,
  DROP COLUMN IF EXISTS cursor_reset_at,
  DROP COLUMN IF EXISTS blocked_at,
  DROP COLUMN IF EXISTS blocked_reason,
  DROP COLUMN IF EXISTS parser_config;
""")
