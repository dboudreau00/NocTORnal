"""One live tie of a type per pair, per labels (beta review, 2026-10-03:
rls-3).

## Why

`edge_uniq_active` (0006) keyed a live tie on its two endpoints, its type
and its start of validity, and on nothing about who may see it. Row
security hides a RED tie from an AMBER analyst; a unique index does not.
So an AMBER analyst who created an AMBER tie between two entities they
could see met the hidden RED tie's key, and was told 400 "that record
already exists" where a pair with no hidden tie answered 201: one bit per
probe, across the label boundary, about the most sensitive fact in the
model (is there an attribution between these two).

## What changes

The key gains the tie's own classification and compartments, as
`pgp_key_acquisition_once` and `yara_ruleset_key_per_labels` already
carry theirs. A lower-labelled observation of a tie is then its own
element, visible at its own label, and creating it succeeds whatever is
held above it; a duplicate at the SAME labels is still refused, and is
one the creator can read. The merge's collision refusal and the reversal's
(`merges.py`) are about the same index and still apply, at equal labels.

The name is kept, so every comment and refusal that names it stays true.

## Downgrade

Restores the 0006 key. On a database that holds two live ties of a type
between one pair at different labels, the downgrade fails on the unique
build, which is the honest answer (reversible on an empty database is
the contract, CONVENTIONS.md).
"""
from alembic import op

revision = "0133"
down_revision = "0132"
branch_labels = None
depends_on = None

#: Frozen text.
UPGRADE_SQL = """
DROP INDEX core.edge_uniq_active;
CREATE UNIQUE INDEX edge_uniq_active ON core.edge
    (src_node_id, dst_node_id, edge_type,
     coalesce(valid_from, '-infinity'::timestamptz),
     classification, compartments)
 WHERE deleted_at IS NULL;
"""

DOWNGRADE_SQL = """
DROP INDEX core.edge_uniq_active;
CREATE UNIQUE INDEX edge_uniq_active ON core.edge
    (src_node_id, dst_node_id, edge_type,
     coalesce(valid_from, '-infinity'::timestamptz))
 WHERE deleted_at IS NULL;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
