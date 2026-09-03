"""Database connection helper.

Reads DATABASE_URL (the same variable Alembic uses) and normalises the
SQLAlchemy-style scheme to plain psycopg. Secrets come from the
environment, never a default in code (repo convention).
"""
from __future__ import annotations

import os

import psycopg


def dsn() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        # SET-BUT-EMPTY is a different problem from ABSENT, and reporting
        # "is not set" for it sends people to look in the wrong place --
        # typically at .env.local, where the value is sitting perfectly
        # correctly the whole time.
        #
        # The variable ends up defined-and-empty more easily than it looks:
        # `docker run -e DATABASE_URL` with no `=value` forwards it as
        # empty when the host has no such variable, a CI matrix can supply
        # a blank default, and PowerShell's
        # `[Environment]::SetEnvironmentVariable(name, $null, 'Process')`
        # leaves the name defined with an empty value rather than removing
        # it. In every one of those cases scripts/_env.py deliberately
        # declines to override an already-defined variable, so the file
        # value never arrives.
        if "DATABASE_URL" in os.environ:
            raise RuntimeError(
                "DATABASE_URL is set but empty. An empty value still counts "
                "as set, so it overrides the one in .env.local. Unset the "
                "variable entirely, or give it a value.")
        raise RuntimeError("DATABASE_URL is not set")
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def connect() -> psycopg.Connection:
    # autocommit=True: the stores are single-statement and atomic (the TOTP
    # counter advance and the lockout increment are compare-and-set UPDATEs),
    # so no multi-statement transaction is needed and read paths never leave
    # a connection "idle in transaction" pinning the vacuum horizon.
    #
    # connect_timeout: libpq's default is effectively "wait for ever" on a
    # host that does not answer. A database that is down therefore did not
    # FAIL -- every request, every test and every script sat in TCP connect
    # until something external killed it (a 300s CI timeout, a person).
    # Found 2026-09-01 when the dev stack was down and a read-only audit
    # hung for five minutes with no message. A connect that cannot complete
    # in ten seconds is not going to; say so.
    return psycopg.connect(dsn(), autocommit=True,
                           connect_timeout=connect_timeout_seconds())


def connect_timeout_seconds() -> int:
    """Seconds to wait for the TCP/handshake phase before giving up.

    Overridable for tests and for genuinely slow links; never unbounded.
    A value of 0 would mean "no limit" to libpq, so it is clamped to 1.
    """
    raw = os.environ.get("NOCTORNAL_DB_CONNECT_TIMEOUT", "10").strip()
    try:
        return max(1, int(raw))
    except ValueError:
        return 10
