"""Selector index rows owned by a retired entity belong to nobody
(graph-selector-index-drift, verify round 2026-10-03).

## Why

An entity retired as a mistake "should never have been in the case file", so
the selector index must not keep naming it. Since the first fix round of
this review, retiring an entity lets go of its rows in the same transaction
(`SelectorStore.release_node`), and a live entity recording the same value
takes a row over from a retired owner (`SelectorStore.record`). Rows that
were already owned by a retired entity before that are only taken over
lazily, and until then `GET /selectors` and the entity's own selector list
still answer with the retired entity's id.

## What this does

Sets `core.selector.node_id` to NULL where the owner is retired
(`core.node.deleted_at IS NOT NULL`). Nothing else changes: no value, count
or date of any row, and no entity.

## What it leaves

A live duplicate of such a value is not handed the row here (the canonical
form of a label is the normaliser's, and a migration does not import
application code). It takes the row the first time it records the value, as
before, and `release_node` hands one over at once for every retirement from
now on.

## Downgrade

Nothing. The old owner of a released row is kept nowhere to put back, and a
row pointing at a retired entity is the defect this revision removes.
"""
from alembic import op

revision = "0138"
down_revision = "0137"
branch_labels = None
depends_on = None

#: Frozen text.
UPGRADE_SQL = """
UPDATE core.selector s
   SET node_id = NULL
  FROM core.node n
 WHERE n.id = s.node_id AND n.deleted_at IS NOT NULL
"""


def upgrade() -> None:
    op.get_bind().connection.driver_connection.execute(UPGRADE_SQL)


def downgrade() -> None:
    # Deliberately a no-op, see the docstring.
    pass
