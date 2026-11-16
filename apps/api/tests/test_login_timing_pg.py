"""A recovery-shaped second factor costs the same work on every route that checks a credential.

`test_login_timing.py` pins the service: one password verify and `recovery.CODE_COUNT` recovery verifies on every
path, whatever the account holds. This pins the two routes that reach it, with the real hasher counted and not
replaced: `POST /auth/login`, where an unauthenticated caller can try a password, and `POST /auth/password`, where
a stolen session can try the account's own (`authenticate` is called there with the account's own email). Before,
a correct password with a recovery-shaped code on an account holding ten codes cost eleven verifies and a wrong
password one, and the wait said which was right.

Email prefix `lt-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the route-level timing count is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"
WRONG_CODE = "zzzzz-zzzzz-zzzzz"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'lt-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'lt-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


@pytest.fixture
def counted(monkeypatch):
    """The real hashers, wrapped to count: (password verifies, recovery verifies) since the last `take`."""
    from noctornal_api.security import passwords
    real_password, real_recovery = passwords.verify_password, passwords.verify_recovery_code
    seen = {"password": 0, "recovery": 0}

    def password(stored_hash, submitted):
        seen["password"] += 1
        return real_password(stored_hash, submitted)

    def recovery(stored_hash, submitted):
        seen["recovery"] += 1
        return real_recovery(stored_hash, submitted)

    monkeypatch.setattr(passwords, "verify_password", password)
    monkeypatch.setattr(passwords, "verify_recovery_code", recovery)

    def take() -> tuple[int, int]:
        out = (seen["password"], seen["recovery"])
        seen["password"] = seen["recovery"] = 0
        return out

    return take


def _account(conn):
    """An enrolled account holding a full set of recovery codes: (id, email, totp secret, codes)."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"lt-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Lt", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    return uid, email, secret, store.issue_recovery_codes(uid)


def _session(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def test_a_recovery_shaped_code_costs_the_same_on_login_and_on_the_account_password_route(
        conn, client, counted):
    from noctornal_api.security import recovery, totp
    uid, email, secret, codes = _account(conn)
    headers = _session(conn, uid)
    counted()  # the account's own set-up is not the sign-in's work
    full = (1, recovery.CODE_COUNT)

    def login(**body):
        return client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD, **body})

    def own_password(current: str, code: str):
        return client.post("/api/v1/auth/password", headers=headers, json={
            "current_password": current, "totp_code": code, "new_password": "another long passphrase"})

    # An account that does not exist, a wrong password, a right password and a wrong code, a right one.
    assert client.post("/api/v1/auth/login", json={
        "email": f"lt-nobody-{uuid4().hex[:6]}@noctornal.test", "password": PASSWORD,
        "totp_code": codes[0]}).status_code == 401
    assert counted() == full, "an unknown account is not the work a real one is"
    assert login(password="not the password", totp_code=codes[0]).status_code == 401
    assert counted() == full, "a wrong password is not the work a right one is"
    assert login(totp_code=WRONG_CODE).status_code == 401
    assert counted() == full, "a right password with a wrong code is not the work a wrong password is"
    assert login(totp_code=codes[0]).status_code == 204
    assert counted() == full, "a right password with a right code is not the work a wrong one is"

    # The same on the route a stolen session can reach.
    assert own_password("not the password", codes[1]).status_code == 403
    assert counted() == full
    assert own_password(PASSWORD, WRONG_CODE).status_code == 403
    assert counted() == full
    assert own_password(PASSWORD, codes[1]).status_code == 200
    assert counted() == full

    # An authenticator code stays one verify, whoever the caller.
    assert login(totp_code="000000").status_code == 401
    assert counted() == (1, 0)
    conn.execute("UPDATE iam.app_user SET totp_last_counter = NULL WHERE id = %s", (uid,))
    assert client.post("/api/v1/auth/login", json={
        "email": email, "password": "another long passphrase",
        "totp_code": totp.code_at(secret, int(time.time()))}).status_code == 204
    assert counted() == (1, 0)
