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
        raise RuntimeError("DATABASE_URL is not set")
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def connect() -> psycopg.Connection:
    # autocommit=True: the stores are single-statement and atomic (the TOTP
    # counter advance and the lockout increment are compare-and-set UPDATEs),
    # so no multi-statement transaction is needed and read paths never leave
    # a connection "idle in transaction" pinning the vacuum horizon.
    return psycopg.connect(dsn(), autocommit=True)
