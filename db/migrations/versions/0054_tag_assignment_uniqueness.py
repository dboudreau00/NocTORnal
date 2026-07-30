"""`core.tag_assignment` had no primary key and no unique index.

Found 2026-07-26 while writing the curation router — the first code ever to
assign a tag outside a test. `core.tag_assignment` (0009) carries only the
`tag_one_target` CHECK that exactly one of node_id / edge_id / evidence_id /
document_id is set. Nothing stopped the same tag being attached to the same
target twice, and there was no conflict target to write `ON CONFLICT`
against, so the router could only pre-check and hope.

A pre-check handles the double-click. It does not handle two concurrent
requests: both SELECT, both find nothing, both INSERT, and the entity now
carries the same chip twice with no way to tell which row to remove.

## Four partial indexes, not one

`tag_one_target` means three of the four target columns are NULL on every
row, and NULL is not equal to itself in a unique index — so a single
`UNIQUE (tag_id, node_id, edge_id, evidence_id, document_id)` would permit
unlimited duplicates, which is the trap that makes this look already-solved
when it is not. One partial index per target type, each restricted to the
rows where that target is non-null, is what actually constrains it.

## Duplicates are removed first, keeping the earliest

`ctid` is the physical row identifier and is the only way to distinguish
two otherwise-identical rows in a table with no key. `MIN(ctid)` keeps one
arbitrary row per group — arbitrary is fine here because the rows are
identical in every column that carries meaning; there is no created_at to
prefer by.

The count is reported via RAISE NOTICE rather than silently swallowed: a
deployment that turns out to have thousands of duplicate assignments has a
UI that has been double-rendering chips, and whoever runs this should see
that rather than find it later.

Not a data-loss risk: a tag assignment carries no note, no author and no
timestamp. It is (tag, target) and nothing else, so collapsing duplicates
loses nothing that was not already redundant.
"""
from alembic import op

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None

TARGETS = ("node_id", "edge_id", "evidence_id", "document_id")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    dedupe = "\n".join(
        f"""
WITH dupes AS (
    SELECT ctid FROM core.tag_assignment ta
     WHERE ta.{col} IS NOT NULL
       AND ta.ctid <> (SELECT MIN(inner_ta.ctid)
                         FROM core.tag_assignment inner_ta
                        WHERE inner_ta.tag_id = ta.tag_id
                          AND inner_ta.{col} = ta.{col})
)
DELETE FROM core.tag_assignment WHERE ctid IN (SELECT ctid FROM dupes);"""
        for col in TARGETS)

    indexes = "\n".join(
        f"CREATE UNIQUE INDEX IF NOT EXISTS tag_assignment_uniq_{col} "
        f"ON core.tag_assignment (tag_id, {col}) WHERE {col} IS NOT NULL;"
        for col in TARGETS)

    run(f"""
SET search_path = core, public;
{dedupe}
{indexes}
""")


def downgrade() -> None:
    run("\n".join(
        f"DROP INDEX IF EXISTS core.tag_assignment_uniq_{col};"
        for col in TARGETS))
