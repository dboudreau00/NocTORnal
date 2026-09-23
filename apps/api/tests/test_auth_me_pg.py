"""`GET /auth/me` carries who you are, not just which row you are.

Until 2026-09-02 the response held `user_id` and `recovery_codes_remaining`
and nothing else, and the analyst UI put `me.user_id` straight into the app
bar -- so every signed-in analyst was greeted by their own UUID. The
display name and email have been on `iam.app_user` since 0001; nothing
read them back to the person they belong to.

The existing fields are kept exactly: the UI and the recovery-code flow
read `recovery_codes_remaining`, and a response that renamed it would
break a client that was correct yesterday.

Email prefix `me-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; /auth/me e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"
DISPLAY_NAME = "Mia Exemplar"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'me-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'me-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"me-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, DISPLAY_NAME, PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    return uid, email, secret


def _session(conn, email) -> str:
    """A signed-in caller, minted the way `scripts/bootstrap.py session`
    mints one: the account looked up by email, then `SessionService`
    against the same store the API validates against. Unbound -- no
    address, no User-Agent, because nothing here has one to give -- which
    0058 records and only `NOCTORNAL_SESSION_STRICT_BINDING` refuses; it
    is off in these tests.

    Not `POST /auth/login`, which since 2026-09-10 answers 204 and leaves
    the token only in `__Host-session`. Nothing in this file is about the
    sign-in path, so this takes the short honest route to a session
    rather than driving a login and unpicking a Set-Cookie header for a
    value it would hand straight back as a Bearer. It also drops the
    constraint the login helper carried: TOTP codes are single-use, so
    two sign-ins for one account inside one 30-second step failed on the
    code, not on the thing under test.
    """
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    # mfa_satisfied=True, as both real mint sites pass: a session that
    # never satisfied MFA is refused by every step-up gated route, which
    # would make this helper quietly narrower than the login it replaces.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_me_carries_display_name_and_email(conn, client):
    uid, email, secret = _make_user(conn)
    r = client.get("/api/v1/auth/me", headers=_auth(_session(conn, email)))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user_id"] == str(uid)
    assert body["display_name"] == DISPLAY_NAME
    assert body["email"] == email


def test_me_keeps_every_field_it_already_had(conn, client):
    """`recovery_codes_remaining` is what the UI and the recovery-code flow
    read; adding a name must not cost it."""
    _, email, secret = _make_user(conn)
    body = client.get("/api/v1/auth/me",
                      headers=_auth(_session(conn, email))).json()
    assert body["recovery_codes_remaining"] == 0
    assert {"user_id", "recovery_codes_remaining", "display_name", "email"} <= set(body)


def test_the_response_model_and_the_wire_agree(conn, client):
    """Reads both halves: the pydantic model the router declares and the
    JSON it actually serves. A field added to one and not the other is
    exactly the kind of drift `response_model` is supposed to prevent,
    and this makes sure it does."""
    from noctornal_api.http.routers.auth import Me
    _, email, secret = _make_user(conn)
    body = client.get("/api/v1/auth/me",
                      headers=_auth(_session(conn, email))).json()
    assert set(body) == set(Me.model_fields)
    assert {"display_name", "email"} <= set(Me.model_fields)


def test_me_reflects_a_renamed_account(conn, client):
    """Read live from the row, not from anything cached in the session, so
    an administrator's correction shows up on the analyst's next load."""
    uid, email, secret = _make_user(conn)
    token = _session(conn, email)
    conn.execute("UPDATE iam.app_user SET display_name = 'Mia Corrected' WHERE id = %s",
                 (uid,))
    body = client.get("/api/v1/auth/me", headers=_auth(token)).json()
    assert body["display_name"] == "Mia Corrected"


def test_me_states_the_two_limits_the_session_runs_under(conn, client):
    """expiry-drops-context (2026-09-22): the console warns five minutes
    before either limit, so it has to know them. The idle timeout is the
    server's own constant, and the absolute limit is a DISTANCE the
    browser can count down without trusting its clock to agree with this
    one. A session minted a moment ago has close to its full 12 hours."""
    from noctornal_api.security.sessions import ABSOLUTE_LIFETIME, IDLE_TIMEOUT
    _, email, _secret = _make_user(conn)
    body = client.get("/api/v1/auth/me",
                      headers=_auth(_session(conn, email))).json()
    assert body["idle_timeout_seconds"] == int(IDLE_TIMEOUT.total_seconds())
    full = int(ABSOLUTE_LIFETIME.total_seconds())
    assert full - 120 <= body["session_expires_in_seconds"] <= full


def test_me_counts_down_the_session_it_was_asked_on(conn, client):
    """The distance belongs to the presenting session, not to the account's
    newest one: two sessions minted hours apart report different limits."""
    _, email, _secret = _make_user(conn)
    old = _session(conn, email)
    conn.execute(
        "UPDATE iam.session SET expires_at = now() + interval '1 hour' "
        "WHERE user_id = (SELECT id FROM iam.app_user WHERE email = %s)",
        (email,))
    fresh = _session(conn, email)
    near = client.get("/api/v1/auth/me", headers=_auth(old)).json()
    far = client.get("/api/v1/auth/me", headers=_auth(fresh)).json()
    assert 3400 <= near["session_expires_in_seconds"] <= 3600
    assert far["session_expires_in_seconds"] > 11 * 3600


def test_me_says_how_long_the_step_up_gate_stays_open(conn, client):
    """Fix round, 2026-09-22: the console asks for a fresh sign-in BEFORE a
    step-up gated request once this reaches zero, because every refused
    POST /auth/recovery-codes spends a token of its rate limit. The gate
    it describes is the route's own: open (and issuing) while this is
    above zero, shut (403) once it is zero."""
    from noctornal_api.security.sessions import STEP_UP_FRESHNESS
    _, email, _secret = _make_user(conn)
    token = _session(conn, email)
    full = int(STEP_UP_FRESHNESS.total_seconds())
    body = client.get("/api/v1/auth/me", headers=_auth(token)).json()
    assert full - 120 <= body["step_up_fresh_seconds"] <= full
    ok = client.post("/api/v1/auth/recovery-codes", headers=_auth(token))
    assert ok.status_code == 200, ok.text

    conn.execute(
        "UPDATE iam.session SET mfa_satisfied_at = now() - interval '20 minutes' "
        "WHERE user_id = (SELECT id FROM iam.app_user WHERE email = %s)", (email,))
    stale = client.get("/api/v1/auth/me", headers=_auth(token)).json()
    assert stale["step_up_fresh_seconds"] == 0
    refused = client.post("/api/v1/auth/recovery-codes", headers=_auth(token))
    assert refused.status_code == 403, refused.text

    conn.execute(
        "UPDATE iam.session SET mfa_satisfied_at = NULL "
        "WHERE user_id = (SELECT id FROM iam.app_user WHERE email = %s)", (email,))
    never = client.get("/api/v1/auth/me", headers=_auth(token)).json()
    assert never["step_up_fresh_seconds"] == 0
