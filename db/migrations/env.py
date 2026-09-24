"""Alembic environment for NocTORnal.

Pure-SQL migrations: there is no SQLAlchemy metadata and no autogenerate.
The schema of record is the ordered set of revisions in versions/;
db/schema.sql is GENERATED from a migrated database by scripts/dump_schema.py
and gated in CI; regenerate it after every revision rather than editing it.
"""
import os

from alembic import context
from sqlalchemy import create_engine, pool


def get_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        # SystemExit, not RuntimeError: `alembic current` in a second
        # terminal is the ordinary way to meet this, and a RuntimeError
        # ended it in a Python traceback that read as a broken install
        # (Alpha 6 pre-release check, 2026-09-23). The file is NOT loaded
        # here, deliberately: migrations refuse to guess a target, and a
        # stray .env.local on a host whose operator forgot to export the
        # real DSN is exactly the guess that must not be made. The message
        # names the file instead, so the fix is one line away.
        raise SystemExit(
            "alembic: DATABASE_URL is not set or is empty, and migrations refuse to "
            "guess a target. The installers write it to .env.local; load "
            "that into this shell first (set -a; . ./.env.local; set +a) "
            "or export DATABASE_URL yourself."
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
