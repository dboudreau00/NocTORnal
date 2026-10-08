"""A connection whose whole test runs in ONE transaction that is rolled back
(docs/17, test isolation, Beta 1.1). Not a test module: the suites import it.

Why. A suite that commits its rows has to delete them again, and some rows
cannot be deleted (Telegram chats and messages, the append-only ledgers), so
they stay and the next suite that counts rows meets them. A readiness row
that says "no list is loaded" or "no Telegram source is active" is a count
over the whole database, and a test of it skipped whenever another suite had
left a row, which CI's no-skip gate turns into a failure. In a transaction that
is rolled back nothing was ever committed, and the test can switch off what
others left for the length of its own transaction and only that.

The connection is the autocommit one the application uses (`db.connect`),
with an explicit BEGIN: the code under test opens `conn.transaction()` blocks
as savepoints inside it, exactly as it does inside any caller's transaction.
Code that COMMITs would commit the lot, so the end of the test checks the
transaction is still open and says so if it is not.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager

import psycopg
from psycopg.pq import TransactionStatus


@contextmanager
def rolled_back(connect: Callable[[], psycopg.Connection] | None = None
                ) -> Iterator[psycopg.Connection]:
    if connect is None:
        from noctornal_api.db import connect as app_connect
        connect = app_connect
    conn = connect()
    conn.execute("BEGIN")
    try:
        yield conn
        committed = conn.info.transaction_status == TransactionStatus.IDLE
    finally:
        try:
            if conn.info.transaction_status != TransactionStatus.IDLE:
                conn.execute("ROLLBACK")
        finally:
            conn.close()
    assert not committed, \
        "the test committed its transaction, so its rows are in the database"


def empty_ledgers(conn: psycopg.Connection) -> None:
    """Inside the caller's transaction, remove every row of the audit log and
    the custody ledger, so a chain walk meets only what the test writes next.

    A verification walks the whole of both chains, and a database that
    another suite (or a real estate) left a break in no longer verifies
    clean, so a test that tampers and expects the tamper to be the ONLY break
    skipped (`_starts_clean`) or failed. The append-only guards are off for
    the two statements and on again, and the transaction's end restores
    every row."""
    for table in ("audit.event", "core.evidence_custody"):
        conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
        conn.execute(f"DELETE FROM {table}")
        conn.execute(f"ALTER TABLE {table} ENABLE TRIGGER USER")


def seed_ledgers(conn: psycopg.Connection, *, audit: int = 6, custody: int = 4) -> None:
    """After `empty_ledgers`: a few rows in each chain for a test to anchor,
    tamper with and walk (a user, a case and an exhibit for the custody rows
    to belong to), in the caller's transaction."""
    import os
    from uuid import uuid4

    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'Ledger', 'x', 'RED') RETURNING id""",
        (f"g49n-{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
    for i in range(audit):
        conn.execute(
            "INSERT INTO audit.event (actor_kind, action, outcome, detail) "
            "VALUES ('USER', %s, 'SUCCESS', '{}'::jsonb)", (f"G49_SEED_{i}",))
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Ledger IT', 'AMBER', %s, 'dev', '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-G49-{uuid4().hex[:6]}", uid))
    exhibit = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification, acquisition_method,
                acquired_at, acquired_by)
           VALUES (%s, 'ledger', 'image/png', 1, %s, %s, %s, 'b', 'AMBER',
                   'SCREENSHOT', now(), %s) RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"g49/{uuid4().hex}", uid)
    ).fetchone()[0]
    for _ in range(custody):
        conn.execute(
            "INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
            "VALUES (%s, 'VIEWED', %s)", (exhibit, uid))
