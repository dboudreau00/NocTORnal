"""Turning a case's merge requirement off takes a second signature, bound to
the switch as it stands (F9b, 2026-09-24).

## What was wrong

`core.case.dual_control_merge` (0028) was set by `PUT /cases/{id}/policy`
with one signature in both directions. The route's own docstring named the
threat: turning a control OFF is exactly what a borrowed session wants.
It still let one person do it.

## What this adds

- `dual_control_merge_epoch`, a counter that moves by one every time the
  switch changes, in either direction, and at no other time. A relax
  approval names the epoch it was raised against, so an approval granted
  for one "on" cannot be banked across an off and on again and spent on
  the next one (the A-B-A case).
- `core.guard_case_merge_switch()`, BEFORE UPDATE on `core."case"`, fired
  only when the switch or its epoch changes. Turning the switch from true
  to false is refused unless a `case.policy.relax` approval for THIS case
  and THIS epoch was consumed in the same transaction (`consumed_at =
  now()`, which the approval guard of this cluster pins at consumption).
  Turning it on is never refused: a tightening that needs a second
  signature is one nobody makes.

Creation, deletion and every other case update are untouched (the WHEN
clause), so test teardowns that delete a case with the switch on still
work, and so does every write that does not touch the switch.

## Downgrade

Drops the trigger, its function and the epoch. It restores the previous
release's one-signature behaviour together with that release's code, which
is what a rollback is for, so it does not refuse.
"""
from alembic import op

revision = "0076"
down_revision = "0075"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE core."case"
  ADD COLUMN dual_control_merge_epoch bigint NOT NULL DEFAULT 0;

CREATE FUNCTION core.guard_case_merge_switch() RETURNS trigger
LANGUAGE plpgsql AS $f$
BEGIN
  IF OLD.dual_control_merge IS NOT DISTINCT FROM NEW.dual_control_merge THEN
    IF NEW.dual_control_merge_epoch IS DISTINCT FROM OLD.dual_control_merge_epoch THEN
      RAISE EXCEPTION 'dual_control_merge_epoch moves only with the merge switch';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.dual_control_merge AND NOT NEW.dual_control_merge
     AND NOT EXISTS (
       SELECT 1 FROM core.approval_request r
        WHERE r.operation = 'case.policy.relax'
          AND r.case_id = NEW.id
          AND r.state = 'CONSUMED'
          AND r.consumed_at = now()
          AND r.payload->>'setting' = 'dual_control_merge'
          AND r.payload->>'to' = 'false'
          AND r.payload->>'epoch' = OLD.dual_control_merge_epoch::text) THEN
    RAISE EXCEPTION '%', 'case ' || NEW.code || ' requires a second signature'
      || ' on merges, and turning that off takes a case.policy.relax approval'
      || ' for the switch as it stands, consumed in the same transaction';
  END IF;
  NEW.dual_control_merge_epoch := OLD.dual_control_merge_epoch + 1;
  RETURN NEW;
END
$f$;

CREATE TRIGGER case_merge_switch_guarded
  BEFORE UPDATE ON core."case"
  FOR EACH ROW
  WHEN (OLD.dual_control_merge IS DISTINCT FROM NEW.dual_control_merge
        OR OLD.dual_control_merge_epoch IS DISTINCT FROM NEW.dual_control_merge_epoch)
  EXECUTE FUNCTION core.guard_case_merge_switch();

COMMENT ON COLUMN core."case".dual_control_merge_epoch IS
  'Moves by one with every change of dual_control_merge. A case.policy.relax '
  'approval names the epoch it was raised against (migration '
  'case_merge_relax_two_people, F9b 2026-09-24).';
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS case_merge_switch_guarded ON core."case";
DROP FUNCTION IF EXISTS core.guard_case_merge_switch();
ALTER TABLE core."case" DROP COLUMN IF EXISTS dual_control_merge_epoch;
""")
