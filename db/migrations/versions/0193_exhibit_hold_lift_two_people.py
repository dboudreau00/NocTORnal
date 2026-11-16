"""Lifting an exhibit's legal hold takes a second person, bound to the hold
as it stands (decision 229, 2026-11-15).

## What was wrong

`core.evidence.legal_hold` went from true to false on one person's word:
`RetentionService.set_legal_hold` wrote it after the route's gate, and
nothing in the database asked who else had agreed. Lifting a hold is what
makes a later destruction lawful, and a hold placed on a court order should
not be undone by one person (the owner, 2026-11-14, reversing decision 193).

## What this adds

- `legal_hold_epoch`, a counter that moves by one every time the hold goes
  on, comes off or is placed again for another reason, and at no other
  time. A `legal_hold.lift_exhibit` approval names the epoch it was raised
  against, so an approval granted for one hold cannot be kept across a
  lift and a new hold and spent on the next one (0076's A-B-A reasoning).
- `core.guard_exhibit_hold_lift()`, BEFORE UPDATE on `core.evidence`, fired
  only when the hold, its reason or its epoch changes. Taking the hold from
  true to false is refused unless a `legal_hold.lift_exhibit` approval for
  THIS exhibit, in its own case, and THIS epoch was consumed in the same
  transaction (`consumed_at = now()`, which 0074 pins at consumption).
  Placing a hold is never refused here: preservation never waits.

The guard binds every caller, the schema owner and the system role
included: the system role is the one that lifts, so exempting it would
exempt the lift. A SECURITY DEFINER with a pinned search path, so it reads
the approval whatever the caller's row security, and its one-line RAISE is
what `safe_detail` forwards. The trigger fires after `evidence_anchors_fixed`
and before `evidence_hold_purge_exclusive`, which it does not touch.

## Grants

None. The column rides the table-level SELECT both runtime roles already
hold, and only the trigger writes it: the request role holds UPDATE on
`storage_version_id` alone (0178), and the system role's table UPDATE meets
the guard like any other writer. `scripts/runtime_roles.py` is unchanged.

## Downgrade

Drops the trigger, its function and the epoch. It restores the previous
release's one-person lift together with that release's code, which is what
a rollback is for, so it does not refuse (0076 takes the same stance).
Existing holds start at epoch 0; nothing is backfilled.
"""
from alembic import op

revision = "0193"
down_revision = "0192"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE core.evidence
  ADD COLUMN legal_hold_epoch bigint NOT NULL DEFAULT 0;

CREATE FUNCTION core.guard_exhibit_hold_lift() RETURNS trigger
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
        WHERE r.operation = 'legal_hold.lift_exhibit'
          AND r.case_id = NEW.case_id
          AND r.state = 'CONSUMED'
          AND r.consumed_at = now()
          AND r.payload->>'evidence_id' = NEW.id::text
          AND r.payload->>'epoch' = OLD.legal_hold_epoch::text) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'exhibit ' || NEW.id || ' is under a legal hold, and lifting it takes a'
      || ' legal_hold.lift_exhibit approval for the hold as it stands, consumed'
      || ' in the same transaction';
  END IF;
  NEW.legal_hold_epoch := OLD.legal_hold_epoch + 1;
  RETURN NEW;
END
$f$;

CREATE TRIGGER evidence_hold_lift_guarded
  BEFORE UPDATE ON core.evidence
  FOR EACH ROW
  WHEN (OLD.legal_hold IS DISTINCT FROM NEW.legal_hold
        OR OLD.legal_hold_reason IS DISTINCT FROM NEW.legal_hold_reason
        OR OLD.legal_hold_epoch IS DISTINCT FROM NEW.legal_hold_epoch)
  EXECUTE FUNCTION core.guard_exhibit_hold_lift();

COMMENT ON COLUMN core.evidence.legal_hold_epoch IS
  'Moves by one each time the legal hold goes on, comes off or is placed again '
  'for another reason. A legal_hold.lift_exhibit approval names the epoch it '
  'was raised against (migration exhibit_hold_lift_two_people, decision 229).';

COMMENT ON FUNCTION core.guard_exhibit_hold_lift() IS
  'An exhibit''s legal hold comes off only in a transaction that consumed a '
  'legal_hold.lift_exhibit approval for that exhibit and that epoch, whoever '
  'writes it (migration exhibit_hold_lift_two_people, decision 229).';
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS evidence_hold_lift_guarded ON core.evidence;
DROP FUNCTION IF EXISTS core.guard_exhibit_hold_lift();
ALTER TABLE core.evidence DROP COLUMN IF EXISTS legal_hold_epoch;
""")
