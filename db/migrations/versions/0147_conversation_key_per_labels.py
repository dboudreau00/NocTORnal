"""A conversation's external key is unique per labels (rls-5, 2026-10-03).

## Why

`conversation_external_idx` made (case, platform, external_ref) unique
across labels, and `CommsService.open_conversation` upserts on it. When
a RED or compartmented capture of a room already existed, an AMBER
caller's ON CONFLICT DO UPDATE met a row the UPDATE policy hides: the
request role got Postgres's row-security refusal (a 403 and an
RLS_REFUSED row, where a fresh reference answers 201), so a caller with
comms.bind could confirm whether the case holds a hidden capture of a
room by its external id. On a connection row security does not filter
(development, the suite) the same call retitled the hidden row and
handed back its id.

## What

The key gains the labels, as `comms.pgp_key_acquisition_once` and
`lab.yara_ruleset_key_per_labels` already carry them: a capture of the
same room at different labels is its own record, visible at its own
labels, which is the honest model of two captures. A caller can only
create at labels within its own ceiling (`deps.check_writable_labels`),
so the row its upsert can now meet is always one it may read, and a
hidden capture answers exactly as no capture does. The upsert names the
same columns (`comms.py`).

## Downgrade

Restores the narrower index. On a database that by then holds two
captures of one room at different labels the index cannot be rebuilt, and
the downgrade refuses first, naming how many references collide and
printing none of them: Postgres's own refusal, a unique violation, prints
the duplicated key, the room's external id with it. That is the designed
refusal (CONVENTIONS.md: reversible on an empty database); a capture is
never merged or deleted to make it pass.
"""
from alembic import op

revision = "0147"
down_revision = "0146"
branch_labels = None
depends_on = None

UPGRADE_SQL = """
DROP INDEX comms.conversation_external_idx;
CREATE UNIQUE INDEX conversation_external_idx
  ON comms.conversation (case_id, platform_key, external_ref, classification, compartments)
  WHERE external_ref IS NOT NULL;
"""

DOWNGRADE_SQL = """
DROP INDEX comms.conversation_external_idx;
CREATE UNIQUE INDEX conversation_external_idx
  ON comms.conversation (case_id, platform_key, external_ref)
  WHERE external_ref IS NOT NULL;
"""


#: The keys the 0034 index would refuse, over its own columns and predicate,
#: so the count is the index build's verdict.
COUNT_SQL = """
SELECT count(*) FROM (
  SELECT 1 FROM comms.conversation
   WHERE external_ref IS NOT NULL
   GROUP BY case_id, platform_key, external_ref
  HAVING count(*) > 1) AS held_at_different_labels
"""


def downgrade_refusal(n: int) -> str:
    held = "reference is" if n == 1 else "references are"
    return (f"refusing to downgrade 0147: {n} conversation {held} held at different "
            "labels, and the 0034 index allows one capture per case, platform and "
            "external reference. This revision's downgrade changed nothing, so the "
            "database is now at 0147 and the revisions above it are already undone. "
            "Run alembic upgrade head to return, or restore a backup taken before "
            "0147 was applied.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run(DOWNGRADE_SQL)
