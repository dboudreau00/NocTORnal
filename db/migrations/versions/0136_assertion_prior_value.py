"""A correction records the value it replaced, so retracting it can put the
supported value back (graph-retracted-correction-stays-in-force, review
2026-10-03).

## Why

`PATCH /graph/nodes/{id}` and `PATCH /graph/edges/{id}` write the new label,
attributes or weight onto the element and record a claim carrying the new
value. Every reader (the projection, the lists, the metrics) reads the
element's columns. Retracting the correction withdrew the claim and left
the value, which then rested on no live claim: a withdrawn "kingpin"
attribute or a withdrawn weight of 9000 kept driving the canvas and the
centrality figures. The old value survived only in the audit row's detail,
which no API returns.

## What this adds

`core.assertion.prior_value`, a JSON object set once, at insert, on a
correction: for each field the correction changes, the value the element
held just before it. `GraphWriteService.retract_assertion` uses it in the
retraction's own transaction: a field reverts to the value of the newest
live correction of that field, or, when none remains, to the value the
element held before its first correction of that field, which is that
correction's `prior_value`. Nothing else writes it. 0135 left the runtime
roles no UPDATE on any column but the marked row's, so this one is
write-once for them as every other claim column is.

## Corrections made before this revision

Each carries no prior value of its own, but its audit row does: the update
endpoints write `NODE_UPDATED` / `EDGE_UPDATED` in the same transaction as
the claim, with the overwritten values under `detail.previous`, and a
transaction has one `now()`, so the claim's `recorded_at` equals the audit
row's `occurred_at` for that element. The upgrade fills `prior_value` from
that row for every correction it can match exactly (element, and time), and
only for the fields the retraction restores: label, attributes and weight.
A correction with no matching audit row (made by a script, not the
endpoints) stays NULL. When such a claim is the oldest correction of a
field and no live correction of the field remains, the original value is
not known to the database and the field is left as it is; the retraction
still succeeds and its audit row names the field under `not_restored`.

## Downgrade

Drops the column. On an empty database nothing is lost; on a live one the
recorded prior values go (the audit rows they were copied from stay), and a
later retraction of those corrections leaves the value in place, as before
this revision.
"""
from alembic import op

revision = "0136"
down_revision = "0135"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: Frozen text: a later revision that changes it restates it.
UPGRADE_SQL = """
ALTER TABLE core.assertion
  ADD COLUMN prior_value jsonb,
  ADD CONSTRAINT assertion_prior_value_object
    CHECK (prior_value IS NULL OR jsonb_typeof(prior_value) = 'object');

COMMENT ON COLUMN core.assertion.prior_value IS
  'On a correction: for each field it changes, the value the element held '
  'just before it, set once at insert (review 2026-10-03). Retracting the '
  'correction restores the value the remaining live claims support.';

-- Corrections already recorded: the overwritten values are in the audit row
-- the same transaction wrote (same now(), same element).
UPDATE core.assertion a
   SET prior_value = m.prior
  FROM (
    SELECT c.id,
           jsonb_object_agg(k.key, e.detail -> 'previous' -> k.key) AS prior
      FROM core.assertion c
      JOIN audit.event e
        ON e.object_id = coalesce(c.node_id, c.edge_id)
       AND e.action IN ('NODE_UPDATED', 'EDGE_UPDATED')
       AND e.occurred_at = c.recorded_at
     CROSS JOIN LATERAL jsonb_object_keys(c.claim_value) AS k(key)
     WHERE jsonb_typeof(c.claim_value) = 'object'
       AND (c.claim_path IS NULL
            OR c.claim_path IN ('label', 'attrs', 'weight', 'valid_to'))
       AND k.key IN ('label', 'attrs', 'weight')
       AND jsonb_typeof(e.detail -> 'previous') = 'object'
       AND (e.detail -> 'previous') ? k.key
       AND NOT EXISTS (
             SELECT 1 FROM jsonb_object_keys(c.claim_value) x(key)
              WHERE x.key NOT IN ('label', 'attrs', 'weight', 'confidence',
                                  'valid_to'))
     GROUP BY c.id) m
 WHERE a.id = m.id AND a.prior_value IS NULL;
"""

DOWNGRADE_SQL = """
ALTER TABLE core.assertion
  DROP CONSTRAINT IF EXISTS assertion_prior_value_object,
  DROP COLUMN IF EXISTS prior_value;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
