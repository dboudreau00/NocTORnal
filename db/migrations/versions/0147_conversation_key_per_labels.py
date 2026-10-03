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
captures of one room at different labels the downgrade stops on the
duplicate, which is the designed refusal (CONVENTIONS.md: reversible on
an empty database).
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


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
