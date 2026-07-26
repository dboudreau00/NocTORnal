"""Alembic environment for NocTORnal.

Pure-SQL migrations: there is no SQLAlchemy metadata and no autogenerate.
The schema of record is the ordered set of revisions in versions/;
db/schema.sql is a human-readable reference that must be kept in sync.
"""
import os

from alembic import context
from sqlalchemy import create_engine, pool


def get_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set — migrations refuse to guess a target. "
            "Dev stack example: "
            "postgresql+psycopg://noctornal:<password>@localhost:5432/noctornal"
        )
    return url


def run_migrations_offline() -> None:
    context.configure(url=get_url(), literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(get_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
