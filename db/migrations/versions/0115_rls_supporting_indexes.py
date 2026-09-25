"""Indexes for the policied tables whose case_id had none (S1).

0114's `core.assertion` policy and 0116's `core.hypothesis` and
`core.node_set` policies start `case_id = ANY (<the user's readable
cases>)`. Every other policied table already has an index leading on
case_id (node, edge, evidence, assumption, node_merge) or is reached
through its parent's primary key (links, custody, members, stances);
these three had none, so a case-wide read under the runtime role would
scan the table and filter.

A plain build, not CONCURRENTLY, for 0072's reason: these tables are
hundreds of thousands of rows at the largest deployment measured, the
build takes seconds, and a failed concurrent build leaves an INVALID
index that IF NOT EXISTS would then accept silently. The upgrade drops
such a leftover and builds again, and refuses a VALID index of this name
with another definition rather than guessing whose it is.

Downgrade drops them.
"""
from alembic import op

revision = "0115"
down_revision = "0114"
branch_labels = None
depends_on = None

#: index -> table, each on (case_id).
INDEXES = {
    "assertion_case_idx": "assertion",
    "hypothesis_case_idx": "hypothesis",
    "node_set_case_idx": "node_set",
}


def _one(index: str, table: str) -> str:
    expected = f"CREATE INDEX {index} ON core.{table} USING btree (case_id)"
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
      IF def <> '{expected}' THEN
        RAISE EXCEPTION USING MESSAGE =
          'core.{index} exists with a different definition (' || def
          || '); drop it or rename it, then run the upgrade again.';
      END IF;
    END IF;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS {index} ON core.{table} USING btree (case_id);
"""


UPGRADE_SQL = "".join(_one(index, table) for index, table in INDEXES.items())


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    for index in INDEXES:
        run(f"DROP INDEX IF EXISTS core.{index};")
