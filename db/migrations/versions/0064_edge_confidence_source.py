"""A tie's confidence has one source: the live assertions behind it.

## What was wrong

Found 2026-09-22 by the usability review (ux05 two-disagreeing-confidences,
ux06 edge-confidence-not-stored) and confirmed by reading the write path.

`core.edge.confidence` is the value the analysis acts on: canvas opacity,
the Min confidence filter, the node panel's "Tie confidence (best)" and
every projection run with a confidence floor. It was written once, at
creation, from a parameter nothing supplied. `POST /edges` never passed
one, so `GraphWriteService.create_edge` took its default of LOW, and a tie
graded HIGH in the Add relationship form was stored, drawn and filtered as
LOW. The grade the analyst chose reached only the assertion. The inspector
then printed both values, one above the other, with nothing saying which
was which. The seed scripts widened the gap by passing an edge confidence
of their own beside an assertion graded something else: in the demo estate
259 of 637 edges disagreed with every assertion behind them.

## The rule

A tie's confidence is the HIGHEST confidence among its live assertions
(not retracted, not superseded) that are claims about THE TIE, and LOW,
the ungraded value, when none of them is (see "A tie no live claim
grades" below). Two kinds count:

- a claim that the tie exists: no `claim_path` and no `claim_value`. The
  founding assertion `POST /edges` writes, and every corroborating one
  `POST /edges/{id}/assertions` adds, are of this kind. It counts at its
  own grade.
- a correction that states the tie's confidence (`PATCH /graph/edges`
  with `confidence`, alone or beside other fields). It carries the value in
  `claim_value.confidence` and counts at the value it states. Since this
  revision the service also grades such a correction at the value it
  states, so for new corrections the two agree; reading `claim_value` is
  what honours corrections recorded before it (see the backfill).

A correction to some OTHER field of the tie (its weight, its attributes)
does not count. Its grade is the analyst's confidence in the new weight or
the new attributes, not in the tie: counting it let a weight fix graded
HIGH raise a LOW tie to HIGH, and then refuse the analyst's attempt to put
it back (found by the fix-round verifier, 2026-09-22).

The rule is written in one place, as two functions. `core.tie_grade(a)`
says what ONE assertion says about its tie: the grade it counts at, or
NULL when it is not a claim about the tie. `core.tie_confidence(edge_id)`
takes the highest `tie_grade` among the edge's live assertions, or LOW
when there is none. The
triggers, the backfill and the service's correction check all call them,
and the service also uses `tie_grade` to name the claims that stop a
correction (see `GraphWriteService.update_edge`), so the message cannot
count claims the rule does not.

Why the highest and not the latest. Corroboration must never weaken a tie.
A second, weaker source for a tie already graded HIGH is still a second
source; under "latest wins", recording it would drop the tie to LOW and
hide it from a HIGH filter, which punishes the analyst for recording more.
Lowering a tie is done by withdrawing the claim that graded it high, with
a reason, which is what retraction is for and which leaves the withdrawn
grade on the record where a reviewer can see it. It is also the reading
the node panel already offers as "Tie confidence (best)".

## Why triggers and not the service

The service is not the only thing that writes assertions or changes their
state: retraction, the seed scripts and every test that inserts rows by
hand all do. Two triggers make the column a function of the assertions
whoever writes:

- `assertion_derives_tie_confidence`, AFTER INSERT, DELETE, or UPDATE OF
  the columns the rule reads, on `core.assertion`. It re-derives the edge
  (both edges, in the never-used case of an assertion moved between two).
- `edge_confidence_is_derived`, BEFORE UPDATE OF confidence, on
  `core.edge`. It REFUSES a value the rule disagrees with, so a direct
  UPDATE cannot reopen the gap. It refuses rather than quietly substituting
  the derived value, because an UPDATE that reports success and stores
  something other than what it was given is the silent kind of failure
  invariant 12 forbids.

## Concurrency: lock the edge, then derive

Found by the re-verifier, 2026-09-23, with two connections. The first
version derived and wrote in one statement, so each writer derived from
the snapshot its statement began with. A retraction and a new claim on the
same tie, committed together, then left the column wrong: the retraction
derived LOW (the new claim not yet committed), the new claim derived HIGH
(the retraction not yet committed), saw the column already HIGH, wrote
nothing and took no lock, and the retraction's LOW landed last. The tie
was drawn and filtered LOW while a live claim said HIGH, which is the
defect this revision exists to remove, and nothing repaired it until the
next write on that tie. The other shape failed closed but refused a good
claim: two corroborations at once, the second writer's UPDATE waiting on
the first and then tripping the edge guard with a message that blamed a
direct write.

`core.sync_tie_confidence` therefore locks the edge row FIRST, in a
statement of its own, and derives in a LATER statement. Under READ
COMMITTED (the application's isolation, psycopg's default) every
statement of a volatile function takes a fresh snapshot, so the
derivation runs after the lock is held and sees every writer that
committed before it. Each writer holds the lock from its derivation to
its commit, so the last writer to commit always derives last, from
everything. `FOR NO KEY UPDATE` and not `FOR UPDATE`: inserting an
assertion takes `FOR KEY SHARE` on its edge through the foreign key,
which `FOR UPDATE` conflicts with, so two writers that had each inserted
a claim would deadlock waiting for each other's key-share lock. `FOR NO
KEY UPDATE` is the lock an UPDATE of `confidence` takes anyway, conflicts
with itself (which serialises the writers) and not with a key share.
Under REPEATABLE READ or SERIALIZABLE the lock raises a serialisation
failure instead of waiting on a changed row, which fails closed.

## A tie no live claim grades

It takes LOW, the ungraded value (final review U11, 2026-09-23). The
first version of this revision kept the value the tie last had, on the
reasoning that inventing a grade would be worse. The value it kept was
not neutral, though: it was the grade of a claim that had just been
withdrawn. Retract a tie's founding HIGH claim while a correction to its
weight still stands, and the projection keeps the tie (any live assertion
is live support, decision 24), so it went on being drawn, filtered,
counted under a HIGH floor and reported at HIGH, and the inspector called
HIGH its strongest live claim when no live claim graded it at all. LOW is
not an invented grade: it is what the service records for anything nobody
graded (F, 6, LOW), so a tie nobody grades now reads as one. A tie with
no live assertion at all has left the live graph, so the LOW it takes
there is read by nothing that draws or counts it.

"Live" here is not retracted AND not superseded, and since the same
review the projection's live-support leg means the same thing
(`projections.py`). Until then it tested `retracted_at` alone, which no
reader noticed while nothing wrote `superseded_at`; the demo seed's
`--regrade` does, and a tie whose replacement claim was then retracted
stayed drawn on a superseded claim that no card offers to retract.

## The backfill

Every edge whose column disagrees with the rule is set to what the rule
says. The values replaced were not analysts' grades: they were the LOW
default nobody chose, or a seed script's number beside an assertion graded
differently. The one place a column value WAS a considered choice is a
correction made through PATCH, and those are honoured, because the
correction's `claim_value` still states the value and the rule counts it.

A correction that LOWERED a tie beneath a claim that is still live cannot
be honoured under this rule and is not. Nothing about it is lost: the
correction assertion, its `claim_value`, and the EDGE_UPDATED audit row
recording the value it replaced all survive. The analyst's remedy is the
one the service now offers at the moment of correction: add a claim at
the lower grade, with its own grading and exhibit, then retract the claim
that grades the tie higher. The console's tie inspector has the control
for the first step since the final review (C14, 2026-09-23); before it,
the only route there was to retract first and correct afterwards, which
left the tie resting on an ungraded correction.

The demo estate is the one place the backfill costs something visible.
`scripts/seed_showcase.py` passed each tie a confidence of its own beside
a claim graded MODERATE, so the backfill turns every seeded NIGHTJAR and
CORVID tie MODERATE, and the demo loses the variety its confidence
encoding (opacity) exists to show. That is the rule reading the claims
correctly. The seed now grades the claims instead, and
`seed_showcase.py --owner-email ... --regrade` brings an estate seeded
before this revision back to the seed's grades by superseding its claims,
without dropping it. Run it after upgrading a development database.

## Downgrade

Drops the triggers and the functions. It does not put the replaced values
back: they are the defect this revision fixes, and restoring them would
turn every analyst-graded tie back into LOW. The derived values are
ordinary values of the column, and the code below this revision reads
them as such.
"""
from __future__ import annotations

from alembic import op

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: The rule, in two halves. `->>` on a jsonb that is not an object yields
#: NULL rather than an error, and the IN list keeps a malformed claim_value
#: from making the cast (and with it every assertion write on that edge)
#: fail. A JSON `null` in claim_value is read as no claim_value at all, the
#: same as SQL NULL, so the two spellings of "nothing" cannot disagree.
#: `tie_grade` does not look at liveness; `tie_confidence` does, once, and
#: is never NULL: a tie no live claim grades is LOW (final review U11).
RULE_SQL = """
CREATE OR REPLACE FUNCTION core.tie_grade(a core.assertion)
RETURNS core.analytic_confidence
LANGUAGE sql STABLE
SET search_path = core, public
AS $f$
  SELECT CASE
           WHEN a.claim_value ->> 'confidence' IN ('LOW', 'MODERATE', 'HIGH')
           THEN (a.claim_value ->> 'confidence')::core.analytic_confidence
           WHEN a.claim_path IS NULL
                AND coalesce(jsonb_typeof(a.claim_value), 'null') = 'null'
           THEN a.confidence
         END
$f$;

COMMENT ON FUNCTION core.tie_grade(core.assertion) IS
  'What one assertion says about its tie''s confidence: its own grade for a '
  'claim about the tie itself (no claim_path and no claim_value), the value '
  'a correction states in claim_value.confidence, and NULL for a correction '
  'to another field (weight, attrs), which does not grade the tie. Liveness '
  'is core.tie_confidence''s business, not this function''s. Migration 0064.';

CREATE OR REPLACE FUNCTION core.tie_confidence(p_edge uuid)
RETURNS core.analytic_confidence
LANGUAGE sql STABLE
SET search_path = core, public
AS $f$
  SELECT coalesce(max(core.tie_grade(a)), 'LOW')
    FROM core.assertion a
   WHERE a.edge_id = p_edge
     AND a.retracted_at IS NULL
     AND a.superseded_at IS NULL
$f$;

COMMENT ON FUNCTION core.tie_confidence(uuid) IS
  'A tie''s confidence: the highest core.tie_grade among its live '
  'assertions (not retracted, not superseded), and LOW, the ungraded value, '
  'when no live assertion is a claim about the tie. Never NULL. Migration 0064.';
"""

#: `sync_tie_confidence` is plpgsql, VOLATILE, and three statements on
#: purpose: lock, derive, write. See "Concurrency" in the docstring; folding
#: the lock and the derivation back into one statement reopens the race.
TRIGGERS_SQL = """
CREATE OR REPLACE FUNCTION core.sync_tie_confidence(p_edge uuid)
RETURNS void AS $$
DECLARE
  derived core.analytic_confidence;
BEGIN
  -- 1. Lock the edge. Waits here for any other writer still deriving
  --    this tie, until it commits.
  PERFORM 1 FROM core.edge WHERE id = p_edge FOR NO KEY UPDATE;
  -- 2. Derive, in a statement that starts after the lock is held, so its
  --    snapshot includes whatever that writer committed.
  SELECT core.tie_confidence(p_edge) INTO derived;
  -- 3. Write only a change, so an unchanged tie is not rewritten. Never
  --    skipped for want of a grade: the rule answers LOW for a tie no live
  --    claim grades, where it used to answer NULL and leave a withdrawn
  --    claim's grade standing (final review U11, 2026-09-23).
  UPDATE core.edge
     SET confidence = derived
   WHERE id = p_edge
     AND confidence IS DISTINCT FROM derived;
END $$ LANGUAGE plpgsql VOLATILE SET search_path = core, public;

-- Nested by operation rather than one boolean, so no branch ever reads
-- NEW on a DELETE or OLD on an INSERT.
CREATE OR REPLACE FUNCTION core.assertion_derives_tie_confidence()
RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.edge_id IS NOT NULL THEN
      PERFORM core.sync_tie_confidence(NEW.edge_id);
    END IF;
    RETURN NULL;
  END IF;
  IF OLD.edge_id IS NOT NULL THEN
    PERFORM core.sync_tie_confidence(OLD.edge_id);
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.edge_id IS NOT NULL AND NEW.edge_id IS DISTINCT FROM OLD.edge_id THEN
      PERFORM core.sync_tie_confidence(NEW.edge_id);
    END IF;
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE TRIGGER assertion_derives_tie_confidence
  AFTER INSERT OR DELETE
     OR UPDATE OF edge_id, confidence, claim_path, claim_value, retracted_at,
                  superseded_at
  ON core.assertion
  FOR EACH ROW EXECUTE FUNCTION core.assertion_derives_tie_confidence();

CREATE OR REPLACE FUNCTION core.edge_confidence_is_derived()
RETURNS trigger AS $$
DECLARE
  derived core.analytic_confidence := core.tie_confidence(NEW.id);
BEGIN
  IF NEW.confidence IS DISTINCT FROM derived THEN
    RAISE EXCEPTION
      'edge %: confidence is derived from its live assertions (%), not written directly. Record or retract an assertion instead.',
      NEW.id, derived
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE TRIGGER edge_confidence_is_derived
  BEFORE UPDATE OF confidence ON core.edge
  FOR EACH ROW EXECUTE FUNCTION core.edge_confidence_is_derived();
"""

#: Computed once per edge through the rule itself, so the backfill cannot
#: disagree with the triggers about what "right" means.
BACKFILL_SQL = """
UPDATE core.edge e
   SET confidence = d.conf
  FROM (SELECT id, core.tie_confidence(id) AS conf FROM core.edge) d
 WHERE d.id = e.id
   AND e.confidence IS DISTINCT FROM d.conf;
"""

DOWNGRADE_SQL = """
DROP TRIGGER IF EXISTS edge_confidence_is_derived ON core.edge;
DROP FUNCTION IF EXISTS core.edge_confidence_is_derived();
DROP TRIGGER IF EXISTS assertion_derives_tie_confidence ON core.assertion;
DROP FUNCTION IF EXISTS core.assertion_derives_tie_confidence();
DROP FUNCTION IF EXISTS core.sync_tie_confidence(uuid);
DROP FUNCTION IF EXISTS core.tie_confidence(uuid);
DROP FUNCTION IF EXISTS core.tie_grade(core.assertion);
"""


def upgrade() -> None:
    run(RULE_SQL)
    run(TRIGGERS_SQL)
    run(BACKFILL_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
