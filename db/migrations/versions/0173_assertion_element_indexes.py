"""Indexes that find every claim about an element or an exhibit, live or not
(G62 load gate, 2026-10-07).

## What was wrong

`core.assertion` is the largest table in a working deployment: every
entity and every tie carries at least one claim, and a year of a busy case
reaches a million rows. Its only indexes on `node_id` and `edge_id` are
PARTIAL, live claims only (`WHERE retracted_at IS NULL AND superseded_at
IS NULL`), `evidence_id` has none, and neither has
`core.evidence_link.evidence_id`. A lookup that does not repeat the
live predicate cannot use a partial index, so these scanned the whole
table, every case's claims, on every call:

- the deferred invariant-1 triggers, `core.require_node_assertion` and
  `core.require_edge_assertion`, which ask `EXISTS (... WHERE node_id =
  NEW.id)` once per entity and per tie at COMMIT. Every create, through
  the console or an accepted proposal, paid a full scan per element it
  wrote;
- the graph view's `has_evidence` mark on every entity and tie it draws
  (`projections.evidenced_sql`), which asks for unretracted claims citing
  an exhibit and says nothing of supersession, so the live index cannot
  answer it: one full scan per drawn entity, and the same in the report,
  the metrics and every other reader of the projection;
- an element's claim history (`GET .../nodes/{id}/assertions?
  include_retracted=true`, and the same for a tie), and the value a
  retraction restores (`GraphWriteService._supported_value`);
- the evidence register's "backs" counts (`routers/evidence.py`
  `_attached`), two claim scans and a link scan per exhibit, for EVERY
  exhibit of the case (the "backs nothing" total), on every page.

Measured on a 1,254,000-claim database (one case of 101,000 entities,
300,000 ties and 1,000,000 claims, 59 smaller ones), as the request role:
the trigger's lookup was a parallel sequential scan of 29,000 buffers, 188
ms per element, so creating one entity took 154 ms and one tie 143 ms
(9.0 ms and 9.7 ms after); a 2,000-entity graph view did not answer in two
minutes (1.0 s after); one exhibit's backs took 183 ms, so the register of
a 15,000-exhibit case never answered (3.6 s after).

## The indexes

Four. The three on `core.assertion` are partial on `IS NOT NULL` only, so
each holds just the rows that name the column (an entity's claims are not
in the tie index, and only a tenth of claims cite an exhibit); the link's
column is NOT NULL, so its index is plain. `node_id = $1`, `= ANY ($1)` and the
correlated `= x.id` are strict, so each implies its index's predicate and
the planner may use it. The live partial indexes stay: they are the
narrower answer for the projection's live checks.

## Lock and build

Built inside the migration's transaction, not CONCURRENTLY, for 0072's and
0115's reason: the upgrade procedure stops the API first, and a failed
concurrent build leaves an INVALID index that `IF NOT EXISTS` would accept
silently. A plain build takes a SHARE lock on `core.assertion`, which lets
reads through and holds writes until it ends: 2.1 s for all four on the
table measured (8 MB, 16 MB, 1.5 MB and 0.4 MB). An operator who cannot stop writes
for that long may build them CONCURRENTLY beforehand under these names; the
upgrade drops an INVALID leftover and builds it again, and refuses a VALID
index of one of these names with another definition rather than guessing
whose it is.

## Downgrade

Drops the four indexes. No data changes either way.
"""
from alembic import op

revision = "0173"
down_revision = "0172"
branch_labels = None
depends_on = None

#: index -> (its table in core, its column). The claim columns are
#: nullable and indexed where set; `evidence_link.evidence_id` never is.
INDEXES = {
    "assertion_node_any_idx": ("assertion", "node_id"),
    "assertion_edge_any_idx": ("assertion", "edge_id"),
    "assertion_evidence_idx": ("assertion", "evidence_id"),
    "evidence_link_evidence_idx": ("evidence_link", "evidence_id"),
}


def _where(table: str, column: str) -> str:
    return f" WHERE {column} IS NOT NULL" if table == "assertion" else ""


def expected_def(index: str, table: str, column: str) -> str:
    """`pg_get_indexdef` of the index this migration builds, exactly."""
    where = f" WHERE ({column} IS NOT NULL)" if table == "assertion" else ""
    return (f"CREATE INDEX {index} ON core.{table} USING btree ({column})"
            f"{where}")


def _one(index: str, table: str, column: str) -> str:
    return f"""
DO $$
DECLARE
  idx regclass := to_regclass('core.{index}');
  def text;
BEGIN
  IF idx IS NOT NULL THEN
    IF NOT (SELECT indisvalid FROM pg_index WHERE indexrelid = idx) THEN
      EXECUTE 'DROP INDEX core.{index}';
    ELSE
      def := pg_get_indexdef(idx);
      IF def <> '{expected_def(index, table, column)}' THEN
        RAISE EXCEPTION USING MESSAGE =
          'core.{index} exists with a different definition (' || def
          || '); drop it or rename it, then run the upgrade again.';
      END IF;
    END IF;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS {index} ON core.{table}
  USING btree ({column}){_where(table, column)};
"""


UPGRADE_SQL = "".join(_one(index, table, column)
                      for index, (table, column) in INDEXES.items())


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    for index in INDEXES:
        run(f"DROP INDEX IF EXISTS core.{index};")
