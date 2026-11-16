"""The `deleted_by_merge` comment names both reasons a merge retires a tie
(docs/17, merge set-aside comment; decision 176).

## Why

0055 added `core.node_merge_edge.deleted_by_merge` for one case: a tie that
ran between the two entities merged, which repointing would turn into a
self-loop that `core.edge` forbids. Since decision 176 (2026-10-07) the flag
also marks a duplicate the merge set aside: a tie whose twin the surviving
entity already holds, and which the person merging could not read, is retired
instead of the merge being refused, because the refusal told the person merging that
two ties they could not read exist. The ledger keeps one flag for both, and
the column comment still named only the first.

## What changes

The comment, and nothing else: no data, no grant, no behaviour. It names
both reasons and where they are told apart: the `NODE_MERGED` audit detail
(`edges_self_loop_deleted`, `edges_duplicate_folded`) and the case owner's
notification. `MergeRecord.edges_self_loop_deleted` counts both, by design
(merges.py).

A later revision that rewords the comment restates it whole.

## Downgrade

Restores the 0055 text byte for byte, its double hyphen included: it is the
released text.
"""
from alembic import op

revision = "0185"
down_revision = "0184"
branch_labels = None
depends_on = None

#: What 0055 wrote.
PRIOR_COMMENT_0055 = (
    "True when THIS merge soft-deleted the edge because repointing it would "
    "have produced a self-loop. Only these may have deleted_at cleared on "
    "reversal -- an edge retired later, for its own reasons, must stay "
    "retired.")

#: Frozen text.
COMMENT = (
    "True when THIS merge soft-deleted the edge, for one of two reasons. "
    "Between: the tie ran between the two entities merged, so repointing it "
    "would have produced a self-loop, which core.edge forbids. "
    "Set aside: the tie duplicated a live tie the surviving entity already "
    "holds, of the same type, other end, start of validity and labels, and the "
    "person merging could not read it, so it was retired instead of refusing the merge "
    "(decision 176). While the merge is live a set-aside tie counts toward "
    "nothing and the tie the surviving entity holds stands alone. "
    "This one flag covers both; the NODE_MERGED audit detail tells them apart "
    "(edges_self_loop_deleted counts the ties between the two, "
    "edges_duplicate_folded the ones set aside). "
    "Only an edge with this flag has deleted_at cleared on reversal, which "
    "restores it whole; an edge retired later, for its own reasons, must stay "
    "retired.")


def _comment_sql(text: str) -> str:
    return ("COMMENT ON COLUMN core.node_merge_edge.deleted_by_merge IS\n  '"
            + text.replace("'", "''") + "';\n")


UPGRADE_SQL = _comment_sql(COMMENT)
DOWNGRADE_SQL = _comment_sql(PRIOR_COMMENT_0055)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
