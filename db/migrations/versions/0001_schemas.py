"""Schemas: core, collect, iam, audit, analytics.

Extensions are deliberately NOT here — CREATE EXTENSION needs superuser
and lives in db/init/00-extensions.sql, run once by the Postgres image.
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS collect;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS analytics;
""")


def downgrade() -> None:
    # No CASCADE: a non-empty schema at this point means revisions above
    # were not fully reverted, and that must fail loudly.
    run("""
DROP SCHEMA analytics;
DROP SCHEMA audit;
DROP SCHEMA iam;
DROP SCHEMA collect;
DROP SCHEMA core;
""")
