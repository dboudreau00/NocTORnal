"""A claim that replaces another names it (Triage claims with no observation
date, docs/00 open question 11, settled 2026-10-02).

## Why

Claims accepted from Triage before Alpha 6 carry no `observed_at`, and
writing a date onto a recorded claim rewrites it, which invariant 5 forbids.
The owner's decision (2026-10-02) is that invariant 5 is NOT amended: an
undated claim stays undated, and the way to give it a date is the
supersession the model already has. The old claim is superseded, never
overwritten, by a new claim that carries the date and the analyst's
rationale.

The model had half of that. `superseded_at` and `superseded_by` (0007) stamp
the OLD row once, and every reader honours them, but nothing in the product
wrote them and nothing on the NEW row said what it replaced. A reader of the
new claim could not tell it was a restatement without searching every other
row for a pointer at it.

## What this adds

- `core.assertion.supersedes_id`, set once at INSERT: the claim this one
  replaces. The request role holds UPDATE on the whole table, not on named
  columns, so a trigger (`assertion_supersedes_fixed`) refuses any change
  to it afterwards, whoever makes it; an operator who must correct one
  disables the trigger by name, as the table comments say of the other
  guards.
- A claim is replaced at most once: a unique index over the column. Two
  analysts dating the same claim at the same moment cannot both win; the
  second insert is refused, and so is the second stamp (the service's
  `WHERE superseded_at IS NULL`).
- `core.assertion_supersedes_guard()`, BEFORE INSERT when the column is set:
  the replaced claim exists, is in the same case, is about the same entity
  or tie, and is still live (not retracted, not superseded). Structural only:
  what a replacement may change is the service's rule, and it changes the
  observation date and the rationale and nothing else. SECURITY DEFINER with
  a pinned search path, as every invariant trigger that reads a policied
  table is (0113): an invisible row must not read as "not there".

Nothing is backfilled. No existing row changes, and the only writes that set
the column are `GraphWriteService.supersede_assertion` and the demo seed's
regrade, which does not set it.

## Downgrade

Drops the two triggers, their functions, the index, the check and the column. It
loses nothing the record needs: the replaced row keeps `superseded_by`,
which names the new claim, so the pair is still reconstructible from the old
side. Upgrading again leaves the column NULL on every row that had one, and
the new side of each pair stops naming what it replaced.
"""
from alembic import op

revision = "0131"
down_revision = "0130"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: Frozen text: a later revision that changes it restates it.
UPGRADE_SQL = """
ALTER TABLE core.assertion
  ADD COLUMN supersedes_id uuid REFERENCES core.assertion(id),
  ADD CONSTRAINT assertion_not_self_superseding
    CHECK (supersedes_id IS NULL OR supersedes_id <> id);

CREATE UNIQUE INDEX assertion_replaced_once
  ON core.assertion (supersedes_id) WHERE supersedes_id IS NOT NULL;

COMMENT ON COLUMN core.assertion.supersedes_id IS
  'The claim this one replaces, set once at insert (migration '
  'assertion_supersedes, 2026-10-02). The replaced row carries superseded_at '
  'and superseded_by, stamped once from NULL; its own columns are never '
  'written again.';

CREATE FUNCTION core.assertion_supersedes_guard() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
  prior core.assertion%ROWTYPE;
BEGIN
  SELECT * INTO prior FROM core.assertion WHERE id = NEW.supersedes_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'a claim that replaces another must name a claim that exists';
  END IF;
  IF prior.case_id IS DISTINCT FROM NEW.case_id THEN
    RAISE EXCEPTION 'a claim replaces only a claim in its own case';
  END IF;
  IF prior.node_id IS DISTINCT FROM NEW.node_id
     OR prior.edge_id IS DISTINCT FROM NEW.edge_id THEN
    RAISE EXCEPTION 'a claim replaces only a claim about the same entity or tie';
  END IF;
  IF prior.retracted_at IS NOT NULL OR prior.superseded_at IS NOT NULL THEN
    RAISE EXCEPTION 'a retracted or superseded claim is history and is not replaced again';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER assertion_supersedes_guarded
  BEFORE INSERT ON core.assertion
  FOR EACH ROW WHEN (NEW.supersedes_id IS NOT NULL)
  EXECUTE FUNCTION core.assertion_supersedes_guard();

-- Written once, at insert. The body reads no table, so it needs no definer.
CREATE FUNCTION core.assertion_supersedes_fixed() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
  RAISE EXCEPTION 'the claim a claim replaces is recorded once, when it is written';
END
$f$;

CREATE TRIGGER assertion_supersedes_unchanged
  BEFORE UPDATE OF supersedes_id ON core.assertion
  FOR EACH ROW WHEN (OLD.supersedes_id IS DISTINCT FROM NEW.supersedes_id)
  EXECUTE FUNCTION core.assertion_supersedes_fixed();
"""

DOWNGRADE_SQL = """
DROP TRIGGER IF EXISTS assertion_supersedes_unchanged ON core.assertion;
DROP FUNCTION IF EXISTS core.assertion_supersedes_fixed();
DROP TRIGGER IF EXISTS assertion_supersedes_guarded ON core.assertion;
DROP FUNCTION IF EXISTS core.assertion_supersedes_guard();
DROP INDEX IF EXISTS core.assertion_replaced_once;
ALTER TABLE core.assertion
  DROP CONSTRAINT IF EXISTS assertion_not_self_superseding,
  DROP COLUMN IF EXISTS supersedes_id;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
