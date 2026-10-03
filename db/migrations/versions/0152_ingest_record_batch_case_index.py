"""An index on `ingest.record (batch_id, case_id)` for the cases a batch fed
(F51, 2026-10-02).

## Why

A dead letter carries no case: a batch is parsed INTO a case and the case
lands on `ingest.record`, so a dead letter's cases are the cases its
batch's records went to (`routers/ingest.dead_letters`). 0154 puts
`ingest.dead_letter` under row-level security through one definer
predicate that asks exactly that, once per dead letter, and the listing
and the replay ask it through 0153's facts function. Each asks it as a
loose index scan: the first case of the batch, then the next case above
it, one probe per distinct case, never one row per record. A stealer-log
batch holds thousands of records and feeds one case, so the walk is two
probes where `record_batch_idx (batch_id)` alone reads every record of the
batch.

`record_batch_idx` stays: nothing here needs it gone, and dropping an
index others plan around is a change of its own.

A plain build, not CONCURRENTLY, for 0072's reason: the upgrade procedure
stops the API first, and a failed concurrent build leaves an INVALID index
that IF NOT EXISTS would accept silently. The upgrade drops such a leftover
and builds again, and refuses a VALID index of this name with another
definition rather than guessing whose it is.

## Downgrade

Drops the index. No data changes either way.
"""
from alembic import op

revision = "0152"
down_revision = "0151"
branch_labels = None
depends_on = None

INDEX = "record_batch_case_idx"

#: `pg_get_indexdef` of the index this migration builds, exactly.
EXPECTED_DEF = ("CREATE INDEX record_batch_case_idx ON ingest.record "
                "USING btree (batch_id, case_id)")

UPGRADE_SQL = f"""
DO $$
DECLARE
  idx regclass := to_regclass('ingest.{INDEX}');
  def text;
BEGIN
  IF idx IS NOT NULL THEN
    IF NOT (SELECT indisvalid FROM pg_index WHERE indexrelid = idx) THEN
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
  USING btree (batch_id, case_id);
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(f"DROP INDEX IF EXISTS ingest.{INDEX};")
