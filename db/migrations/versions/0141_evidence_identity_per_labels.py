"""Identical bytes are one exhibit per labels while it is live, and every
exhibit has an object of its own (review findings rls-4,
evidence-ingest-dedup-oracle and evidence-reingest-after-purge-dropped,
2026-10-03).

## Why

`UNIQUE (case_id, sha256)` spanned labels and outlived destruction.

- An AMBER analyst uploading the bytes of a RED exhibit in the same case could
  not see the RED row, so the deduplication missed it, the bytes were put as a
  new locked version under the RED exhibit's own key, and the INSERT then hit
  the constraint: a 500 against a 201 for novel bytes, a one-bit oracle for
  the content of an exhibit above the uploader, and an undeletable version on
  the hidden object per probe.
- A purged exhibit kept its (case_id, sha256), so re-lodging the same bytes
  answered "deduplicated" with the destroyed exhibit's id and stored nothing.

## What this changes

- `evidence_case_id_sha256_key` goes.
- `evidence_live_bytes_per_labels`: unique over (case_id, sha256,
  classification, compartments) for rows not purged. An upload whose labels
  are within the uploader's ceiling can never collide with a row above it,
  because their labels differ, so bytes the uploader may not see become their
  own exhibit at the uploader's labels, exactly as a novel upload does. The
  same bytes at the same labels stay one exhibit, and a destroyed exhibit no
  longer stops its bytes being lodged again.
- `evidence_one_object_per_exhibit`: unique over (case_id, sha256,
  storage_key), for every row. Two exhibits of the same bytes never share an
  object, so no upload can add a version to another exhibit's object; the
  service gives a second exhibit of the same bytes a key of its own.

The service sorts compartments before it writes, so one set has one spelling.

## Downgrade

Drops both indexes and restores `UNIQUE (case_id, sha256)`. On a database
that holds two exhibits of the same bytes in one case (the point of this
revision) the constraint cannot be restored, and the downgrade refuses first,
naming how many sets of bytes collide and printing none of them: Postgres's
own refusal, a unique violation, prints the case and the SHA-256. That is the
designed refusal: merging or deleting exhibits to make a rollback succeed
would destroy evidence.
"""
from alembic import op

revision = "0141"
down_revision = "0140"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


#: Frozen text: a later revision that changes it restates it.
UPGRADE_SQL = """
ALTER TABLE core.evidence DROP CONSTRAINT evidence_case_id_sha256_key;

CREATE UNIQUE INDEX evidence_live_bytes_per_labels
  ON core.evidence (case_id, sha256, classification, compartments)
  WHERE purged_at IS NULL;

CREATE UNIQUE INDEX evidence_one_object_per_exhibit
  ON core.evidence (case_id, sha256, storage_key);

COMMENT ON INDEX core.evidence_live_bytes_per_labels IS
  'Identical bytes are one live exhibit per labels (rls-4, '
  'evidence-reingest-after-purge-dropped, 2026-10-03).';
COMMENT ON INDEX core.evidence_one_object_per_exhibit IS
  'Two exhibits of the same bytes never share an object '
  '(evidence-ingest-dedup-oracle, 2026-10-03).';
"""

DOWNGRADE_SQL = """
DROP INDEX core.evidence_one_object_per_exhibit;
DROP INDEX core.evidence_live_bytes_per_labels;
ALTER TABLE core.evidence
  ADD CONSTRAINT evidence_case_id_sha256_key UNIQUE (case_id, sha256);
"""


#: The keys the 0008 constraint would refuse. It spans every row, purged ones
#: included, so the count does too.
COUNT_SQL = """
SELECT count(*) FROM (
  SELECT 1 FROM core.evidence
   GROUP BY case_id, sha256
  HAVING count(*) > 1) AS held_as_more_than_one_exhibit
"""


def downgrade_refusal(n: int) -> str:
    held = "set of identical bytes is" if n == 1 else "sets of identical bytes are"
    return (f"refusing to downgrade 0141: {n} {held} held as more than one exhibit "
            "in one case, and the 0008 key allows one. This revision's downgrade "
            "changed nothing, so the database is now at 0141 and the revisions "
            "above it are already undone. Run alembic upgrade head to return, or "
            "restore a backup taken before 0141 was applied. An exhibit is never "
            "merged or deleted to make a downgrade pass.")


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run(DOWNGRADE_SQL)
