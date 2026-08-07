"""`unmerge` resurrected edges that were retired for unrelated reasons.

Found 2026-08-07 by an adversarial pass, confirmed by reading the two
statements against each other.

`merge()` selects the edges to repoint with `WHERE deleted_at IS NULL`, so
every row it records in `core.node_merge_edge` was LIVE at merge time. It
then soft-deletes exactly one KIND of them: a tie that ran BETWEEN the two
nodes being merged, which would otherwise collapse into a self-loop that
`core.edge` forbids and that means nothing anyway.

`unmerge()` restored the endpoints and cleared `deleted_at` on **every**
recorded edge, unconditionally, with a comment saying it was undoing the
self-loop deletion. For the self-loops that is right. For the rest it
overwrites a retirement that had nothing to do with the merge:

    Monday    merge A into B. Twelve edges repointed, one self-loop
              soft-deleted.
    Tuesday   an analyst retires edge #4 -- wrong source, a mis-keyed
              import, a correction after the fact.
    Wednesday somebody reverses Monday's merge.
              Edge #4 is back in the graph.

Nothing records that it came back. `deleted_by` still names the analyst who
retired it, so the row now reads as "retired by Jane" while being live. It
violates invariant 5 (history is superseded, never overwritten) and puts an
edge into a graph where nothing is a fact without an assertion behind it.

This was pre-existing and became REACHABLE when node/edge retirement got a
caller (0053 and the `graph.soft_delete_edge` work on 2026-07-30). Before
that, nothing but a merge could set `deleted_at` on an edge, so clearing it
unconditionally was accidentally correct.

## Recording the fact rather than inferring it

The reversal needs to know which edges IT deleted. That is known exactly at
merge time and was simply not written down, so this adds the column and
sets it there. Inferring it later from timestamps -- "was `deleted_at`
close to `merged_at`" -- would be a guess, and the docstring on `unmerge`
is explicit that reversal is a restore and not a re-derivation, because
guesswork is what made the merge wrong in the first place.

## The backfill is exact, not a default

`DEFAULT false` alone would silently change the behaviour of every merge
already in the table: reversing one would leave its self-loop deleted, which
is the opposite defect. The merge-time decision is fully reconstructible --
substitute the merge's source for its target in the recorded original
endpoints and ask whether the two ends coincide -- so the backfill computes
precisely what `merge()` computed, for every historical row.

That reconstruction is sound because `original_src_node_id` and
`original_dst_node_id` are both recorded (0027 stores both deliberately,
"so the reversal is a straight restore with no reasoning required"), and
because a merge whose source or target no longer exists cannot occur:
both are `REFERENCES node(id)` with no cascade.
"""
from alembic import op

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE core.node_merge_edge
    ADD COLUMN deleted_by_merge boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.node_merge_edge.deleted_by_merge IS
  'True when THIS merge soft-deleted the edge because repointing it would '
  'have produced a self-loop. Only these may have deleted_at cleared on '
  'reversal -- an edge retired later, for its own reasons, must stay '
  'retired.';

-- Reconstruct the merge-time decision for every existing row. This is the
-- same expression merge() evaluates: repoint, then ask whether the two
-- ends coincide.
UPDATE core.node_merge_edge nme
   SET deleted_by_merge = true
  FROM core.node_merge nm
 WHERE nm.id = nme.merge_id
   AND (CASE WHEN nme.original_src_node_id = nm.source_node_id
             THEN nm.target_node_id ELSE nme.original_src_node_id END)
     = (CASE WHEN nme.original_dst_node_id = nm.source_node_id
             THEN nm.target_node_id ELSE nme.original_dst_node_id END);
""")


def downgrade() -> None:
    run("ALTER TABLE core.node_merge_edge DROP COLUMN deleted_by_merge;")
