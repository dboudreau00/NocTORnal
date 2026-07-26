"""${message}"""
from alembic import op

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def run(sql: str) -> None:
    # Raw psycopg connection: no bind-parameter or %-placeholder parsing
    # (RAISE format strings contain both), multi-statement blocks allowed.
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
