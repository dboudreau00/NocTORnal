"""A held exhibit is never marked destroyed, and a destroyed one is never
held (review finding evidence-purge-hold-race, 2026-10-03).

## Why

The scheduled and the out-of-schedule purge read the legal holds once, before
the object store deletes, and then marked the rows purged without reading
them again. A hold placed in between was acknowledged to the officer (200,
LEGAL_HOLD_APPLIED) and the exhibit was destroyed and its tombstone said
DELETED. The purge now locks the rows and their cases and rereads the holds
under those locks (retention.py, same date). Nothing in the database said the
two states could not meet.

## What this adds

`core.guard_evidence_hold_purge()`, BEFORE UPDATE on `core.evidence` when
`purged_at` or `legal_hold` changes:

- marking an exhibit purged (`purged_at` from NULL) is refused while the
  exhibit or its case is under legal hold;
- placing a hold on an exhibit already purged is refused, so a hold can never
  be reported on content that no longer exists.

SECURITY DEFINER with a pinned search path: it reads the case's hold, and row
security must not make a held case read as unheld (0113's rule for invariant
triggers that read a policied table).

## Downgrade

Drops the trigger and its function. The purge's own locks still keep the two
apart.
"""
from alembic import op

revision = "0142"
down_revision = "0141"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: Frozen text: a later revision that changes it restates it.
UPGRADE_SQL = """
CREATE FUNCTION core.guard_evidence_hold_purge() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
  case_held boolean;
BEGIN
  IF OLD.purged_at IS NULL AND NEW.purged_at IS NOT NULL THEN
    SELECT c.legal_hold INTO case_held FROM core."case" c WHERE c.id = NEW.case_id;
    IF NEW.legal_hold OR coalesce(case_held, false) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
        'an exhibit under legal hold is not destroyed: a hold overrides all deletion';
    END IF;
  END IF;
  IF OLD.purged_at IS NOT NULL AND NEW.legal_hold AND NOT OLD.legal_hold THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'a destroyed exhibit cannot be placed under legal hold';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER evidence_hold_purge_exclusive
  BEFORE UPDATE OF purged_at, legal_hold ON core.evidence
  FOR EACH ROW
  WHEN ((OLD.purged_at IS DISTINCT FROM NEW.purged_at)
        OR (OLD.legal_hold IS DISTINCT FROM NEW.legal_hold))
  EXECUTE FUNCTION core.guard_evidence_hold_purge();

COMMENT ON FUNCTION core.guard_evidence_hold_purge() IS
  'A held exhibit is never marked purged and a purged one is never held '
  '(evidence-purge-hold-race, 2026-10-03).';
"""

DOWNGRADE_SQL = """
DROP TRIGGER evidence_hold_purge_exclusive ON core.evidence;
DROP FUNCTION core.guard_evidence_hold_purge();
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
