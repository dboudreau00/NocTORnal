"""An administrator-issued password must be replaced at the next sign-in.

## The gap (owner decision, 2026-09-23)

There was no password reset anywhere: not in the console, not in the API,
not in `scripts/bootstrap.py`. An administrator could re-enrol a lost
authenticator or clear a lockout, and a forgotten password had no way
back but a new account. The owner decided the reset is ADMINISTRATOR
ISSUED: an administrator (or `bootstrap.py reset-password`, for the last
one) sets a generated one-time password, shows it once, and the person
must choose their own at their next sign-in. There is no email path.

## Why a column and not a session marker

The one-time password is known to whoever issued it, so it must stop
being the account's password before anything else happens under it.
`POST /auth/login` refuses to mint a session for an account carrying this
flag unless the same request also carries the new password, and it clears
the flag in the transaction that stores the new hash. No session exists
while the flag is set (the reset revokes every live one), so nothing else
in the API has to check it: the rule lives in one place, at the door.

`password_changed_at` already exists (0001) and was never written; it is
now stamped by every path that sets a password, which is what lets the
admin pane say when a password was last changed.

The default is false, so every existing account keeps signing in exactly
as before. Table-level grants (0060) cover a new column.
"""
from __future__ import annotations

from alembic import op

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE iam.app_user
    ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN iam.app_user.must_change_password IS
    'Set when an administrator issues a one-time password; sign-in refuses to '
    'mint a session until the account chooses its own (0066).';
""")


def downgrade() -> None:
    run("""
ALTER TABLE iam.app_user DROP COLUMN IF EXISTS must_change_password;
""")
