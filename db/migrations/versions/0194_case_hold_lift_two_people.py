"""Lifting a case's legal hold takes a second person, bound to the hold as it
stands (decision 229, 2026-11-15).

## What was wrong

`core."case".legal_hold` went from true to false on one person's word:
`RetentionService.set_case_legal_hold` wrote it once the lifter's ceiling
covered everything the case holds, and nothing in the database asked who
else had agreed. A case's hold governs every exhibit, record, sample, lookup
and cited document of the case, and lifting it makes all of them destroyable
at once.

## What this adds

The same shape as an exhibit's (migration exhibit_hold_lift_two_people):

- `legal_hold_epoch` on `core."case"`, which moves by one every time the
  case's hold goes on, comes off or is placed again for another reason, and
  at no other time. A `legal_hold.lift_case` approval names the epoch it was
  raised against, so it cannot be kept across a lift and a new hold.
- `core.guard_case_hold_lift()`, BEFORE UPDATE on `core."case"`, fired only
  when the hold, its reason or its epoch changes. Taking the hold from true
  to false is refused unless a `legal_hold.lift_case` approval for THIS case
  and THIS epoch was consumed in the same transaction (`consumed_at =
  now()`). Placing a hold is never refused here.

The guard binds every caller, the schema owner and the system role included,
and is a SECURITY DEFINER with a pinned search path, as the exhibit's is.
Every other case update is untouched (the WHEN clause), so the merge switch's
own guard (0076) and the ten columns the request role writes (0178) behave as
before.

## Grants

None. The column rides the table-level SELECT both runtime roles hold, and
only the trigger writes it: the request role's column grants on the case do
not name it (0178). `scripts/runtime_roles.py` is unchanged.

## Downgrade

Drops the trigger, its function and the epoch. It restores the previous
release's one-person lift together with that release's code, so it does not
refuse. Existing holds start at epoch 0; nothing is backfilled.
"""
from alembic import op

revision = "0194"
down_revision = "0193"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE core."case"
  ADD COLUMN legal_hold_epoch bigint NOT NULL DEFAULT 0;

CREATE FUNCTION core.guard_case_hold_lift() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
  IF (OLD.legal_hold, OLD.legal_hold_reason)
     IS NOT DISTINCT FROM (NEW.legal_hold, NEW.legal_hold_reason) THEN
    IF NEW.legal_hold_epoch IS DISTINCT FROM OLD.legal_hold_epoch THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
        'legal_hold_epoch moves only with the legal hold';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.legal_hold AND NOT NEW.legal_hold AND NOT EXISTS (
       SELECT 1 FROM core.approval_request r
        WHERE r.operation = 'legal_hold.lift_case'
          AND r.case_id = NEW.id
          AND r.state = 'CONSUMED'
          AND r.consumed_at = now()
          AND r.payload->>'epoch' = OLD.legal_hold_epoch::text) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'case ' || NEW.code || ' is under a legal hold, and lifting it takes a'
      || ' legal_hold.lift_case approval for the hold as it stands, consumed'
      || ' in the same transaction';
  END IF;
  NEW.legal_hold_epoch := OLD.legal_hold_epoch + 1;
  RETURN NEW;
END
$f$;

CREATE TRIGGER case_hold_lift_guarded
  BEFORE UPDATE ON core."case"
  FOR EACH ROW
  WHEN (OLD.legal_hold IS DISTINCT FROM NEW.legal_hold
        OR OLD.legal_hold_reason IS DISTINCT FROM NEW.legal_hold_reason
        OR OLD.legal_hold_epoch IS DISTINCT FROM NEW.legal_hold_epoch)
  EXECUTE FUNCTION core.guard_case_hold_lift();

COMMENT ON COLUMN core."case".legal_hold_epoch IS
  'Moves by one each time the case''s legal hold goes on, comes off or is placed '
  'again for another reason. A legal_hold.lift_case approval names the epoch it '
  'was raised against (migration case_hold_lift_two_people, decision 229).';

COMMENT ON FUNCTION core.guard_case_hold_lift() IS
  'A case''s legal hold comes off only in a transaction that consumed a '
  'legal_hold.lift_case approval for that case and that epoch, whoever writes it '
  '(migration case_hold_lift_two_people, decision 229).';
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS case_hold_lift_guarded ON core."case";
DROP FUNCTION IF EXISTS core.guard_case_hold_lift();
ALTER TABLE core."case" DROP COLUMN IF EXISTS legal_hold_epoch;
""")
