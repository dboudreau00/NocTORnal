"""An index on `ingest.record(duplicate_of)` for the queue's copies pass
and a record's own copies (L4, 2026-09-24).

## What was wrong

The ingest queue counts each page's folded copies in one pass
(`routers/ingest.py` `_queue_sql`, the `dup` CTE, `WHERE d.duplicate_of
IN (SELECT id FROM page)`), and the record detail lists a record's copies
(`_COPIES_SQL`, `WHERE d.duplicate_of = %s`). `ingest.record` had no index
on the column, only the foreign key, so both scanned the table. The
Alpha 6 made the queue choose its page before counting (a read
of a 50,000-record case had not answered after 212 seconds; it now takes
tens of milliseconds) and noted that an index would make the pass a
lookup, which needed a migration while the chain was closed.

## The index

Partial, `WHERE duplicate_of IS NOT NULL`: primaries are never looked up
by this column, and `duplicate_of = $1` and `duplicate_of IN (...)` are
strict, so they imply the predicate. The foreign key's own lookup when a
primary is deleted is served too.

Built inside the migration's transaction, not CONCURRENTLY: the upgrade
procedure stops the API first (release notes, step 1). An operator with a
very large table who cannot stop ingest may build it CONCURRENTLY
beforehand under the same name. A concurrent build that fails leaves an
INVALID index of that name, which `IF NOT EXISTS` would accept silently
and the planner would never use; the upgrade drops such an index and
builds it again. A VALID index of that name with another definition is
somebody else's, and the upgrade refuses rather than guessing.

## Downgrade

Drops the index. No data changes either way.
"""
from __future__ import annotations

from alembic import op

revision = "0072"
down_revision = "0071"
branch_labels = None
depends_on = None

INDEX = "record_duplicate_of_idx"

#: `pg_get_indexdef` of the index this migration builds, exactly.
EXPECTED_DEF = ("CREATE INDEX record_duplicate_of_idx ON ingest.record "
                "USING btree (duplicate_of) WHERE (duplicate_of IS NOT NULL)")

UPGRADE_SQL = f"""
DO $$
DECLARE
  idx regclass := to_regclass('ingest.{INDEX}');
  def text;
BEGIN
  IF idx IS NOT NULL THEN
    IF NOT (SELECT indisvalid FROM pg_index WHERE indexrelid = idx) THEN
      -- A failed CONCURRENTLY build: never used by the planner, and
      -- IF NOT EXISTS below would accept it. Built again instead.
      EXECUTE 'DROP INDEX ingest.{INDEX}';
    ELSE
      def := pg_get_indexdef(idx);
      IF def <> '{EXPECTED_DEF}' THEN
        RAISE EXCEPTION USING MESSAGE =
          'ingest.{INDEX} exists with a different definition (' || def
          || '); drop it or rename it, then run the upgrade again.';
      END IF;
    END IF;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS {INDEX} ON ingest.record
  USING btree (duplicate_of) WHERE duplicate_of IS NOT NULL;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(f"DROP INDEX IF EXISTS ingest.{INDEX};")
