"""TOTP replay protection: iam.app_user.totp_last_counter.

Stores the last accepted TOTP time-step counter per user (docs/05). A
code is rejected unless its step counter is strictly greater, so a code
cannot be replayed within its validity window. NULL = no TOTP code has
been accepted yet.
"""
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
ALTER TABLE iam.app_user ADD COLUMN totp_last_counter bigint;
COMMENT ON COLUMN iam.app_user.totp_last_counter IS
  'Last accepted RFC 6238 TOTP step counter; a code with counter <= this is a replay.';
""")


def downgrade() -> None:
    run("ALTER TABLE iam.app_user DROP COLUMN totp_last_counter;")
