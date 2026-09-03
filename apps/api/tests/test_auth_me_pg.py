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
import time
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


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_me_carries_display_name_and_email(conn, client):
    uid, email, secret = _make_user(conn)
    r = client.get("/api/v1/auth/me", headers=_auth(_login(client, email, secret)))
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
                      headers=_auth(_login(client, email, secret))).json()
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
                      headers=_auth(_login(client, email, secret))).json()
    assert set(body) == set(Me.model_fields)
    assert {"display_name", "email"} <= set(Me.model_fields)


def test_me_reflects_a_renamed_account(conn, client):
    """Read live from the row, not from anything cached in the session, so
    an administrator's correction shows up on the analyst's next load."""
    uid, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    conn.execute("UPDATE iam.app_user SET display_name = 'Mia Corrected' WHERE id = %s",
                 (uid,))
    body = client.get("/api/v1/auth/me", headers=_auth(token)).json()
    assert body["display_name"] == "Mia Corrected"
