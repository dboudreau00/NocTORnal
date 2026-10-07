"""A persona's forum session, sealed beside its credential (the
authenticated forum path, 2026-10-02).

## What this adds

`collect.collection_account` gains `session_ciphertext`, `session_key_id`
and `session_sealed_at`: the cookies a forum handed the persona when it
signed in, sealed under the same envelope as the credential, so the next
poll can read as the member without signing in again. A session cookie
obtained with a persona's credentials IS a credential: it is sealed here,
opened only inside the member adapter's run, never logged, never returned
by a route, and cleared (the three columns NULL) when the persona signs
out or stops. The three columns are set together or not at all
(`collection_account_session_complete`).

The egress proxy's role reads this table by a column list
(egress_ledger.EGRESS_GRANTS) and is given none of these: a session is no
business of the proxy's.

## Downgrade

Drops the three columns. A session is re-established by signing in again,
so nothing is lost but a cookie.
"""
from __future__ import annotations

from alembic import op

revision = "0161"
down_revision = "0160"
branch_labels = None
depends_on = None

UPGRADE_SQL = """
ALTER TABLE collect.collection_account
  ADD COLUMN session_ciphertext bytea,
  ADD COLUMN session_key_id text,
  ADD COLUMN session_sealed_at timestamptz,
  ADD CONSTRAINT collection_account_session_complete
    CHECK ((session_ciphertext IS NULL) = (session_key_id IS NULL)
           AND (session_ciphertext IS NULL) = (session_sealed_at IS NULL));

COMMENT ON COLUMN collect.collection_account.session_ciphertext IS
  'The persona''s forum session cookies, sealed as its credential is '
  '(2026-10-02). Opened only inside a member read; NULL once signed out.';
"""

DOWNGRADE_SQL = """
ALTER TABLE collect.collection_account
  DROP CONSTRAINT collection_account_session_complete,
  DROP COLUMN session_sealed_at,
  DROP COLUMN session_key_id,
  DROP COLUMN session_ciphertext;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
