"""Reversible entity merge (docs/01 "Entity resolution", Phase 6).

`core.node.merged_into_id / merged_at / merged_by` have existed since 0005
and nothing has ever written them, because a merge is not one column:

    Every merge is reversible: the losing node sets `merged_into_id`
    rather than being deleted, and its edges are re-pointed with a record
    of the original endpoints.

That record is what these tables are. Re-pointing an edge is destructive
to the original fact -- after the update, nothing in `core.edge` remembers
that the tie was observed against the losing node -- so the memory has to
live somewhere, or "reversible" is aspirational.

docs/01 opens the section with "merging is the operation most likely to
quietly corrupt a case", which is the whole reason this is a ledger rather
than a flag: an unreversible merge silently rewrites who did what, and the
analyst who made the call is usually not the one who discovers it was
wrong.

`node_merge` is one row per merge event, carrying its own reversal. It is
NOT append-only in the audit sense -- reversal stamps the same row -- but a
reversed merge keeps its history rather than disappearing, so the sequence
"merged, then unmerged, then merged again" is legible.
"""
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE node_merge (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  -- The LOSING node: it keeps its row and its history, and gains a
  -- merged_into_id pointing at the winner.
  source_node_id  uuid NOT NULL REFERENCES node(id),
  target_node_id  uuid NOT NULL REFERENCES node(id),
  reason          text NOT NULL,
  -- docs/01: auto-merge is permitted ONLY on a single is_strong selector
  -- match. Recording which selector justified it is what makes that rule
  -- auditable rather than a convention.
  basis_selector_id uuid REFERENCES selector(id),
  merged_at       timestamptz NOT NULL DEFAULT now(),
  merged_by       uuid NOT NULL,
  reversed_at     timestamptz,
  reversed_by     uuid,
  reversal_reason text,
  CONSTRAINT node_merge_not_self CHECK (source_node_id <> target_node_id),
  -- A reversal explains itself or it did not happen.
  CONSTRAINT node_merge_reversal_complete
    CHECK ((reversed_at IS NULL) = (reversed_by IS NULL)
       AND (reversed_at IS NULL) = (reversal_reason IS NULL))
);

-- One node can only be merged away ONCE while the merge stands. Without
-- this, two concurrent merges of the same node into different targets both
-- "succeed" and the second silently overwrites the first's redirect,
-- stranding the first merge's edge records.
CREATE UNIQUE INDEX node_merge_one_live_per_source
    ON node_merge (source_node_id) WHERE reversed_at IS NULL;
CREATE INDEX node_merge_case_idx ON node_merge (case_id, merged_at DESC);
CREATE INDEX node_merge_target_idx ON node_merge (target_node_id)
    WHERE reversed_at IS NULL;

-- The original endpoints, so re-pointing can be undone exactly. Both are
-- recorded even though only one changes per edge: which one moved is
-- derivable, but storing both makes the reversal a straight restore with
-- no reasoning required at the point where being wrong is expensive.
CREATE TABLE node_merge_edge (
  merge_id      uuid NOT NULL REFERENCES node_merge(id) ON DELETE CASCADE,
  edge_id       uuid NOT NULL REFERENCES edge(id),
  original_src_node_id uuid NOT NULL REFERENCES node(id),
  original_dst_node_id uuid NOT NULL REFERENCES node(id),
  PRIMARY KEY (merge_id, edge_id)
);
""")


def downgrade() -> None:
    run("""
DROP TABLE core.node_merge_edge;
DROP TABLE core.node_merge;
""")
