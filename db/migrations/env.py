"""Alembic environment for NocTORnal.

Pure-SQL migrations: there is no SQLAlchemy metadata and no autogenerate.
The schema of record is the ordered set of revisions in versions/;
db/schema.sql is GENERATED from a migrated database by scripts/dump_schema.py
and gated in CI; regenerate it after every revision rather than editing it.
"""
import os
import sys

from alembic import context
from sqlalchemy import create_engine, pool


def refuse_unsafe_environment_in_production() -> None:
    """The migration job is a job like the cron ones: under
    NOCTORNAL_ENV=production it refuses to run on a credential this
    repository publishes, as the API does at boot (infra-12, 2026-10-03).
    The migrate service starts before the API and does not wait for it, so
    with the template's placeholders the owner role ran DDL on a password
    anyone can read while the API it precedes refused to start.

    It is the helper every job makes (`config.refuse_unsafe_job_environment`)
    with the owner half switched off: Alembic is the process that connects as
    the schema owner, so the owner's credential in its environment is its
    ordinary state, and a published value anywhere in it is not.

    The package is imported only in production, so a bare `alembic` on a
    machine without it behaves as it always did; a production image always
    carries it."""
    if os.environ.get("NOCTORNAL_ENV", "").strip().lower() != "production":
        return
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment

    refusals = refuse_unsafe_job_environment("alembic", holds_owner_credential=True)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        raise SystemExit(JOB_REFUSAL_EXIT)


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
            "that into this shell first, as data and not as a script "
            "(eval \"$(python scripts/_env.py export)\") "
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


refuse_unsafe_environment_in_production()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
