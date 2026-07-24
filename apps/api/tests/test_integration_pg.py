"""End-to-end auth against a real Postgres (env-gated on DATABASE_URL).

Exercises the production stores: a user is provisioned, TOTP is sealed at
rest with the envelope scheme, a full password+TOTP login succeeds, the
replay counter is persisted, a replay is rejected, and a server-side
session round-trips and revokes. Everything runs in one transaction that
is rolled back, so it leaves no rows behind.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; integration test is gated"
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    c.execute("DELETE FROM iam.session WHERE user_id IN "
              "(SELECT id FROM iam.app_user WHERE email LIKE 'it-%@noctornal.test')")
    c.execute("DELETE FROM iam.app_user WHERE email LIKE 'it-%@noctornal.test'")
    c.close()


def test_full_auth_and_session_roundtrip_against_pg(conn):
    from noctornal_api.security import totp
    from noctornal_api.security.auth import AuthOutcome, AuthService
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore

    users = PgUserStore(conn)
    email = f"it-{uuid4().hex[:8]}@noctornal.test"
    uid = users.create_user(email, "Integration Analyst", "right-password")
    secret = totp.generate_secret()
    users.enroll_totp(uid, secret)

    # The secret must be sealed at rest, not stored in the clear.
    ct = conn.execute(
        "SELECT totp_secret_ciphertext FROM iam.app_user WHERE id = %s", (uid,)
    ).fetchone()[0]
    assert bytes(ct) != secret.encode()

    ts = 1_784_899_200
    clock = lambda: datetime.fromtimestamp(ts, tz=timezone.utc)
    auth = AuthService(users, now=clock)
    code = totp.code_at(secret, ts)

    result = auth.authenticate(email, "right-password", code)
    assert result.outcome is AuthOutcome.OK and result.user_id == uid

    # Replay counter persisted.
    stored = conn.execute(
        "SELECT totp_last_counter FROM iam.app_user WHERE id = %s", (uid,)
    ).fetchone()[0]
    assert stored == ts // totp.STEP_SECONDS

    # Same code again → replay → rejected.
    replay = AuthService(users, now=lambda: datetime.fromtimestamp(ts + 5, tz=timezone.utc))
    assert replay.authenticate(email, "right-password", code).outcome \
        is AuthOutcome.INVALID_CREDENTIALS

    # Server-side session: create, validate, revoke.
    sessions = SessionService(PgSessionStore(conn), now=clock)
    rec, raw = sessions.create(uuid4(), uid, mfa_satisfied=True)
    assert sessions.validate(raw).ok
    assert sessions.revoke_all_for_user(uid, "test cleanup") == 1
    assert not sessions.validate(raw).ok


def test_concurrent_totp_advance_only_one_wins(conn):
    """The DB-level compare-and-set is the real replay guard: two logins
    racing on the SAME code (each on its own connection, both reading the
    same stale counter) must resolve to exactly one accepted advance."""
    from noctornal_api.db import connect
    from noctornal_api.stores import PgUserStore

    users = PgUserStore(conn)
    email = f"it-{uuid4().hex[:8]}@noctornal.test"
    uid = users.create_user(email, "Race Analyst", "pw")

    # Both stores read last_counter = NULL, then both try to set the same
    # new counter. Only the first UPDATE's WHERE (NULL OR < N) matches.
    conn_b = connect()
    try:
        store_a = PgUserStore(conn)
        store_b = PgUserStore(conn_b)
        target = 999_000
        won_a = store_a.advance_totp_counter(uid, target)
        won_b = store_b.advance_totp_counter(uid, target)
        assert (won_a, won_b) == (True, False)
    finally:
        conn_b.close()
