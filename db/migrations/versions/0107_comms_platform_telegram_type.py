"""The Telegram platform names the ontology's durable selector type (roadmap
F5.4 (b), 2026-09-24).

0034 seeded `comms.platform.durable_selector_type` for TELEGRAM as
'TELEGRAM_UID', which is not an ontology selector type: the ontology's is
TELEGRAM_ID, and `comms.PLATFORM_SELECTOR_TYPE` already normalises
Telegram values under it. Only the catalogue row the Comms pane shows was
wrong. The eight other unknown types in that seed go to docs/17 as one
flagged item; this migration corrects the one the Telegram work stands on.

Downgrade restores 'TELEGRAM_UID' only where the value is 'TELEGRAM_ID',
so a later deliberate change is never undone.
"""
from alembic import op

revision = "0107"
down_revision = "0106"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
UPDATE comms.platform SET durable_selector_type = 'TELEGRAM_ID'
 WHERE key = 'TELEGRAM' AND durable_selector_type = 'TELEGRAM_UID';
""")


def downgrade() -> None:
    run("""
UPDATE comms.platform SET durable_selector_type = 'TELEGRAM_UID'
 WHERE key = 'TELEGRAM' AND durable_selector_type = 'TELEGRAM_ID';
""")
