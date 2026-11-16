"""Lifting a collected document's legal hold takes a second person, bound to
every version held as it stands (decision 229, 2026-11-15).

## What was wrong

A hold on a collected document covers it and every earlier version
(decision 74), and `RetentionService.set_document_legal_hold` took it off
every version on one person's word. A document belongs to no case, so a
document-level hold is often all that keeps a post a court named from the
deployment-wide sweep. The request role holds table UPDATE on
`collect.document`, so one statement injected into a request could also
take the hold off a document within its own labels.

## What this adds

- `legal_hold_epoch` on `collect.document`, which moves by one every time
  that version's hold goes on, comes off or is placed again for another
  reason, and at no other time.
- `collect.guard_document_hold_lift()`, BEFORE UPDATE on `collect.document`,
  fired only when the hold, its reason or its epoch changes. Taking a
  version's hold from true to false is refused unless a
  `legal_hold.lift_document` approval naming THAT version at THAT epoch was
  consumed in the same transaction (`consumed_at = now()`). The approval
  names every version it releases with its epoch (`versions` in its
  payload), so it cannot be kept across a version held, lifted or held again
  afterwards. Placing a hold is never refused here.

A document's lift has no case, so its approval is deployment-wide
(`case_id IS NULL`). The guard binds every caller, the schema owner and the
system role included, and is a SECURITY DEFINER with a pinned search path,
as the exhibit's and the case's are (migrations exhibit_hold_lift_two_people
and case_hold_lift_two_people).

## Grants

None. The column rides the table-level grants the runtime roles already
hold on the table, and the guard refuses a change to it that does not come
with the hold, whoever writes it, so only the trigger moves it.
`scripts/runtime_roles.py` is unchanged.

## Downgrade

Drops the trigger, its function and the epoch. It restores the previous
release's one-person lift together with that release's code, so it does not
refuse. Existing holds start at epoch 0; nothing is backfilled.
"""
from alembic import op

revision = "0195"
down_revision = "0194"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE collect.document
  ADD COLUMN legal_hold_epoch bigint NOT NULL DEFAULT 0;

CREATE FUNCTION collect.guard_document_hold_lift() RETURNS trigger
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
        WHERE r.operation = 'legal_hold.lift_document'
          AND r.case_id IS NULL
          AND r.state = 'CONSUMED'
          AND r.consumed_at = now()
          AND r.payload->'versions'->>(NEW.id::text) = OLD.legal_hold_epoch::text) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'collected document ' || NEW.id || ' is under a legal hold, and lifting it'
      || ' takes a legal_hold.lift_document approval for the hold as it stands,'
      || ' consumed in the same transaction';
  END IF;
  NEW.legal_hold_epoch := OLD.legal_hold_epoch + 1;
  RETURN NEW;
END
$f$;

CREATE TRIGGER document_hold_lift_guarded
  BEFORE UPDATE ON collect.document
  FOR EACH ROW
  WHEN (OLD.legal_hold IS DISTINCT FROM NEW.legal_hold
        OR OLD.legal_hold_reason IS DISTINCT FROM NEW.legal_hold_reason
        OR OLD.legal_hold_epoch IS DISTINCT FROM NEW.legal_hold_epoch)
  EXECUTE FUNCTION collect.guard_document_hold_lift();

COMMENT ON COLUMN collect.document.legal_hold_epoch IS
  'Moves by one each time this version''s legal hold goes on, comes off or is '
  'placed again for another reason. A legal_hold.lift_document approval names '
  'every version it releases at its epoch (migration '
  'document_hold_lift_two_people, decision 229).';

COMMENT ON FUNCTION collect.guard_document_hold_lift() IS
  'A collected document''s legal hold comes off a version only in a transaction '
  'that consumed a legal_hold.lift_document approval naming that version at that '
  'epoch, whoever writes it (migration document_hold_lift_two_people, decision 229).';
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS document_hold_lift_guarded ON collect.document;
DROP FUNCTION IF EXISTS collect.guard_document_hold_lift();
ALTER TABLE collect.document DROP COLUMN IF EXISTS legal_hold_epoch;
""")
