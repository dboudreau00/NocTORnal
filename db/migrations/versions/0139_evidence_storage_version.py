"""An exhibit names the stored version of its object (review finding
evidence-integrity-anchors-mutable, 2026-10-03).

## Why

The evidence bucket is versioned (forced by `--with-lock`), and a locked key
still accepts a NEW version: measured on 2026-10-03, a second put on a
COMPLIANCE-locked key is accepted, a plain get then returns the replaced
bytes, and a keyless delete leaves a marker that makes a plain get raise
NoSuchKey. Every read of an exhibit asked for the LATEST version of its key,
so what the system served was whatever was written there last, not what was
lodged.

## What this adds

`core.evidence.storage_version_id`: the version id the object store returned
when the exhibit's bytes were put. Reads ask for that version, so a later
version on the key is never served and a delete marker does not hide the
exhibit. NULL on every existing row and on a store that does not version (the
test doubles); those rows keep reading the latest version, and a missing
object is now an integrity alarm rather than a 500 (the service, same date).

Set once: the ingest writes the row first and the version after the put, in
the same transaction, and `evidence_anchors_fixed` (the next revision) refuses
any later change.

## Downgrade

Drops the column. Exhibits then read the latest version of their key again.
"""
from alembic import op

revision = "0139"
down_revision = "0138"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


#: Frozen text: a later revision that changes it restates it.
UPGRADE_SQL = """
ALTER TABLE core.evidence ADD COLUMN storage_version_id text;

COMMENT ON COLUMN core.evidence.storage_version_id IS
  'The object store version the exhibit was lodged as, set once after the put '
  '(evidence-integrity-anchors-mutable, 2026-10-03). Reads ask for this '
  'version; NULL reads the latest version of storage_key.';
"""

DOWNGRADE_SQL = """
ALTER TABLE core.evidence DROP COLUMN storage_version_id;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
