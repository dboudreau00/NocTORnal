"""An exhibit's identity is fixed when it is lodged (review finding
evidence-integrity-anchors-mutable, 2026-10-03).

## Why

Integrity verification compares the stored bytes with `core.evidence.sha256`
and `blake3`, and every read re-checks against the same row. The request role
holds UPDATE on the whole table (0060), and nothing guarded those columns, so
a connection bound to a case member could rewrite the hashes to match a
substituted object: verify, view and export then all passed on forged bytes
(measured on 2026-10-03: "rows changed: 1", then verify True and the forged
bytes served).

## What this adds

`core.guard_evidence_anchors()`, BEFORE UPDATE on `core.evidence`: refuses any
change to `sha256`, `blake3`, `byte_size`, `storage_key`, `storage_bucket` and
`case_id`, and to `storage_version_id` once it is set (it goes from NULL to
the version the store returned exactly once, in the ingest's own
transaction). Whoever makes the change: the owner included, who must disable
the trigger by name to correct a row, as for the other guards. Retention,
legal hold, purge, labels, title and description stay writable.

The body reads no table, so it needs no definer.

## Downgrade

Drops the trigger and its function. The anchors become writable again.
"""
from alembic import op

revision = "0140"
down_revision = "0139"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: Frozen text: a later revision that changes it restates it.
UPGRADE_SQL = """
CREATE FUNCTION core.guard_evidence_anchors() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
  IF NEW.sha256 IS DISTINCT FROM OLD.sha256
     OR NEW.blake3 IS DISTINCT FROM OLD.blake3
     OR NEW.byte_size IS DISTINCT FROM OLD.byte_size
     OR NEW.storage_key IS DISTINCT FROM OLD.storage_key
     OR NEW.storage_bucket IS DISTINCT FROM OLD.storage_bucket
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR (OLD.storage_version_id IS NOT NULL
         AND NEW.storage_version_id IS DISTINCT FROM OLD.storage_version_id)
  THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'an exhibit''s hashes, size, case and stored object are fixed when it is lodged';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER evidence_anchors_fixed
  BEFORE UPDATE ON core.evidence
  FOR EACH ROW EXECUTE FUNCTION core.guard_evidence_anchors();

COMMENT ON FUNCTION core.guard_evidence_anchors() IS
  'Refuses a change to an exhibit''s hashes, size, case or stored object '
  '(evidence-integrity-anchors-mutable, 2026-10-03). An operator who must '
  'correct one disables evidence_anchors_fixed by name.';
"""

DOWNGRADE_SQL = """
DROP TRIGGER evidence_anchors_fixed ON core.evidence;
DROP FUNCTION core.guard_evidence_anchors();
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
