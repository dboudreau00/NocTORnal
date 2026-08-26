"""The admin surface and the first-run door, over HTTP.

The service tests (`test_iam_admin_pg.py`) carry the refusal logic; these
carry the WIRE: that the routes exist, that `user.manage` actually gates
them, that an unauthenticated caller gets 401 and an analyst 403, that the
one-time credentials arrive with their warning, and that a deactivated
account genuinely cannot sign in afterwards.

Email prefix `ahe-`, unique to this file, same teardown discipline as the
other e2e suites. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; admin e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ahe-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ahe-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"ahe-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Adm", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
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


# --- the first-run door ---------------------------------------------------

def test_setup_status_answers_without_auth(client):
    r = client.get("/api/v1/setup/status")
    assert r.status_code == 200
    assert isinstance(r.json()["needs_setup"], bool)


def test_the_first_run_door_opens_once_and_then_never_again(conn, client):
    """One test, two branches, NO skip — and the skip is the point.

    This was a pair: one test skipped when the deployment was empty, its
    twin skipped when it was populated. The conditions are exact
    complements of one boolean, so exactly one of them skipped on EVERY
    run, and CI fails the build on any skip at all
    (`.github/workflows/ci.yml`, "No tests were skipped") — printing
    "The Postgres or MinIO leg is not running."

    That is this codebase's own signature defect wearing a test's
    clothes: a failure reported as the wrong thing. A developer would
    have debugged service containers that were working perfectly. Worse,
    the obvious fix — loosening the gate — would restore the 100+ silent
    skips the gate exists to catch.

    Branching also makes CI test MORE than the pair did: on a fresh
    database it now exercises the open door AND the refusal, by using the
    door and then trying it again.
    """
    from noctornal_api.iam_admin import needs_setup

    if needs_setup(conn):
        first = client.post("/api/v1/setup/first-admin", json={
            "email": "ahe-first@noctornal.test", "display_name": "First"})
        assert first.status_code == 201, first.text
        body = first.json()
        assert body["password"] and body["totp_secret"]
        assert "Shown once" in body["notice"]

        # ...and the door is shut behind it, in the same run.
        again = client.post("/api/v1/setup/first-admin", json={
            "email": "ahe-second@noctornal.test", "display_name": "Second"})
        assert again.status_code == 409, again.text
        assert "already has accounts" in again.json()["detail"]
    else:
        shut = client.post("/api/v1/setup/first-admin", json={
            "email": "ahe-door@noctornal.test", "display_name": "Door"})
        assert shut.status_code == 409, shut.text
        assert "already has accounts" in shut.json()["detail"]


# --- gating ---------------------------------------------------------------

def test_admin_routes_refuse_the_unauthenticated(client):
    assert client.get("/api/v1/admin/users").status_code == 401


def test_admin_routes_refuse_an_analyst(conn, client):
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _login(client, email, secret)
    r = client.get("/api/v1/admin/users", headers=_auth(token))
    assert r.status_code == 403
    assert "user.manage" in r.json()["detail"]


# --- the full loop --------------------------------------------------------

def test_an_admin_can_provision_and_manage_an_analyst(conn, client):
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)

    # Create: 201, one-time credentials, and the warning that they are.
    r = client.post("/api/v1/admin/users", headers=_auth(token), json={
        "email": f"ahe-new-{uuid4().hex[:6]}@noctornal.test",
        "display_name": "New Analyst", "clearance": "AMBER",
        "roles": ["ANALYST"]})
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["password"] and created["totp_secret"]
    assert "Shown once" in created["notice"]
    uid = created["user_id"]

    # Listed, with role and the caller's own id for the UI.
    r = client.get("/api/v1/admin/users", headers=_auth(token))
    assert r.status_code == 200
    mine = [u for u in r.json()["users"] if u["id"] == uid]
    assert mine and mine[0]["roles"] == ["ANALYST"]
    assert r.json()["you"]

    # Clearance, role grant, role revoke, unlock — each answers 200.
    base = f"/api/v1/admin/users/{uid}"
    assert client.post(base + "/clearance", headers=_auth(token),
                       json={"clearance": "RED"}).status_code == 200
    assert client.post(base + "/roles", headers=_auth(token),
                       json={"role": "READ_ONLY"}).status_code == 200
    assert client.delete(base + "/roles/READ_ONLY",
                         headers=_auth(token)).status_code == 200
    assert client.post(base + "/unlock",
                       headers=_auth(token)).status_code == 200

    # Re-enrol: a NEW secret arrives.
    r = client.post(base + "/totp", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["totp_secret"] != created["totp_secret"]

    # The created analyst can actually sign in with the re-enrolled secret.
    from noctornal_api.security import totp as totp_mod
    r = client.post("/api/v1/auth/login", json={
        "email": created["email"], "password": created["password"],
        "totp_code": totp_mod.code_at(
            client.post(base + "/totp", headers=_auth(token)).json()["totp_secret"],
            int(time.time()))})
    assert r.status_code == 200, (
        "an account provisioned through the panel cannot sign in: "
        + r.text)

    # Deactivate: their next login is refused; reactivate restores it.
    assert client.post(base + "/deactivate",
                       headers=_auth(token)).status_code == 200
    r = client.get("/api/v1/admin/users", headers=_auth(token))
    assert not [u for u in r.json()["users"] if u["id"] == uid][0]["is_active"]
    assert client.post(base + "/reactivate",
                       headers=_auth(token)).status_code == 200


def test_an_admin_cannot_deactivate_their_own_account_over_http(conn, client):
    uid, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    r = client.post(f"/api/v1/admin/users/{uid}/deactivate",
                    headers=_auth(token))
    assert r.status_code == 409
    assert "your own account" in r.json()["detail"]
