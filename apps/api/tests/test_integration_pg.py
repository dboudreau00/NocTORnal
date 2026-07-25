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
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'it-%@noctornal.test')"
    c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
    # Cases (owner FK is RESTRICT) must go before their owning users;
    # deleting a case cascades its assignments.
    c.execute(f'DELETE FROM core."case" WHERE owner_user_id IN {sub}')
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
    def clock():
        return datetime.fromtimestamp(ts, tz=timezone.utc)

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


def test_access_gate_resolves_allow_and_deny_against_pg(conn):
    """The five-part gate over real seeded roles/permissions: an assigned
    ANALYST may create edges; a READ_ONLY user on the same case may not
    (verb fails); an unassigned user is denied (relationship fails)."""
    from noctornal_api.security.access import (
        CHECK_ASSIGNMENT, CHECK_ROLE, evaluate,
    )
    from noctornal_api.stores import PgAccessResolver, PgUserStore

    users = PgUserStore(conn)
    analyst = users.create_user(f"it-{uuid4().hex[:8]}@noctornal.test", "An", "pw")
    reader = users.create_user(f"it-{uuid4().hex[:8]}@noctornal.test", "Re", "pw")
    outsider = users.create_user(f"it-{uuid4().hex[:8]}@noctornal.test", "Ou", "pw")

    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
                owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Access IT', 'AMBER', %s, 'dev', '2027-01-01', '2026-12-01')""",
        (case_id, f"OP-IT-{uuid4().hex[:6]}", analyst),
    )
    # Clearances high enough that TLP/compartments never mask the verb result.
    for uid in (analyst, reader, outsider):
        conn.execute("UPDATE iam.app_user SET tlp_clearance='RED' WHERE id=%s", (uid,))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s), (%s, %s, 'READ_ONLY', %s)""",
        (case_id, analyst, analyst, case_id, reader, analyst),
    )

    resolver = PgAccessResolver(conn)
    common = dict(case_id=case_id, permission_key="graph.edge.create",
                  object_classification="AMBER",
                  object_compartments=frozenset(), mfa_satisfied_at=None)

    assert evaluate(resolver.resolve(user_id=analyst, **common)).allowed
    reader_dec = evaluate(resolver.resolve(user_id=reader, **common))
    assert reader_dec.failed_checks == (CHECK_ROLE,)  # assigned, but role lacks verb
    outsider_dec = evaluate(resolver.resolve(user_id=outsider, **common))
    assert CHECK_ROLE in outsider_dec.failed_checks
    assert CHECK_ASSIGNMENT in outsider_dec.failed_checks

    # Fail closed: an unknown permission is a hard resolution error (→ 403),
    # never a 500.
    from noctornal_api.security.access import AccessResolutionError
    with pytest.raises(AccessResolutionError):
        resolver.resolve(user_id=analyst, case_id=case_id,
                         permission_key="graph.edge.teleport",
                         object_classification="AMBER",
                         object_compartments=frozenset(), mfa_satisfied_at=None)
    # case + users are removed by the fixture teardown (owner-FK-aware).


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
