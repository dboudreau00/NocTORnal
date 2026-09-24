"""Ties entered before Alpha 6 get the review state they would be born in.

## What was wrong

Until Alpha 6 nothing set `core.edge.review`, so every tie ever entered
reads PROPOSED: an analyst's own direct observation and a Triage
suggestion a reviewer had already accepted alike. Every node then carries
the unreviewed-proposal ring, and the inspector's "Unreviewed proposals"
equals "Ties in projection" (492 ties in one demo case), work no reviewer
can clear one click at a time (ux05-inspector
review-state-never-leaves-proposed, 2026-09-23). Alpha 6 gives a tie a
person asserts ACCEPTED, and a tie founded on a machine's claim PROPOSED
(`GraphWriteService.create_edge`).

## The rule, applied to the ties already there

- set ACCEPTED: a PROPOSED live tie whose founding claim (its earliest)
  is a person's, meaning any basis but AUTOMATED_INFERENCE, or which a
  reviewer accepted from a Triage proposal;
- left alone: a tie founded on a machine's claim that nobody accepted (it
  is still waiting for a person), any tie someone has reviewed (an
  EDGE_REVIEWED row exists, so a person who reopened a tie meant it), a
  retired tie, and a tie in any other state.

Every tie it moves gets an EDGE_REVIEWED audit row (actor SYSTEM, the
state it left, the reason, `by` "the Alpha 6 upgrade"), the row the tie
inspector's Review history reads, so the change is on the record rather
than silent. It covers every case, CLOSED and ARCHIVED included: it
decides nothing a person has not already decided, it records the state
those ties should have been given. On a new database it finds nothing.

`BORN_STATE_SQL` is one statement, so it commits whole; run again it
changes nothing. test_tie_review_pg.py holds it to the rule create_edge
applies. It was first written as a file for operators to run by hand
after upgrading; an upgrade that forgot it would ring every node, so it
runs here instead.

## Downgrade

Nothing. The review states stay what this set them to, and so do the
audit rows (`audit.event` is append-only). Alpha 5.2's code never reads
the column.
"""
from __future__ import annotations

from alembic import op

revision = "0067"
down_revision = "0066"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


BORN_STATE_SQL = """
WITH reviewed AS (
  SELECT DISTINCT ev.object_id AS edge_id
    FROM audit.event ev
   WHERE ev.action = 'EDGE_REVIEWED' AND ev.object_type = 'edge'
     AND ev.object_id IS NOT NULL),
triaged AS (
  SELECT DISTINCT p.applied_edge_id AS edge_id
    FROM collect.proposal p
   WHERE p.state = 'ACCEPTED' AND p.applied_edge_id IS NOT NULL),
founding AS (
  SELECT DISTINCT ON (a.edge_id) a.edge_id, a.basis
    FROM core.assertion a
   WHERE a.edge_id IS NOT NULL
   ORDER BY a.edge_id, a.recorded_at, a.id),
due AS (
  SELECT f.edge_id, t.edge_id IS NOT NULL AS from_triage
    FROM founding f
    LEFT JOIN triaged t ON t.edge_id = f.edge_id
   WHERE f.basis <> 'AUTOMATED_INFERENCE' OR t.edge_id IS NOT NULL),
born AS (
  UPDATE core.edge e
     SET review = 'ACCEPTED'
    FROM due d
   WHERE d.edge_id = e.id
     AND e.review = 'PROPOSED'
     AND e.deleted_at IS NULL
     AND NOT EXISTS (SELECT 1 FROM reviewed r WHERE r.edge_id = e.id)
  RETURNING e.id, e.case_id, d.from_triage),
logged AS (
  INSERT INTO audit.event
         (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
  SELECT NULL, 'SYSTEM', 'EDGE_REVIEWED', 'edge', b.id, b.case_id,
         jsonb_build_object(
           'review', 'ACCEPTED',
           'previous', 'PROPOSED',
           'by', 'the Alpha 6 upgrade',
           'note', CASE WHEN b.from_triage
             THEN 'a reviewer accepted this tie from a Triage proposal before '
                  'the acceptance was recorded on the tie itself'
             ELSE 'a person entered this tie as their own claim, which is not '
                  'a proposal, before such ties were entered as ACCEPTED' END)
    FROM born b
  RETURNING object_id, case_id, detail ->> 'note' AS reason)
SELECT c.code AS case_code, l.object_id AS edge_id, l.reason
  FROM logged l
  JOIN core."case" c ON c.id = l.case_id
 ORDER BY c.code, l.object_id;
"""


def upgrade() -> None:
    run(BORN_STATE_SQL)


def downgrade() -> None:
    pass
