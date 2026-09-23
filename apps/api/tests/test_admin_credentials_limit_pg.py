"""A fresh install's operator can add their team, over HTTP.

Final review U18 (2026-09-23). Account creation and TOTP re-enrolment
shared the administrator's own `auth.recovery_codes` meter: three at
once, then one every twelve minutes. First run spends one of the three
issuing the operator's recovery codes, so the operator could add two
colleagues and the third was a 429. A refused request spends from a meter
too (the limit runs before the gate's step-up check), so every click from
a session whose step-up had lapsed also used up a chance to reissue their
own codes.

Both tests fail on 1667cc1. Email prefix `acl-`, unique to this file.
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; admin limit e2e is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "acl-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM notify.preference WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    """A fresh in-process meter per test, so the numbers below are the
    catalogue's and nothing another test spent."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _admin(conn):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    store = PgUserStore(conn)
    uid = store.create_user(f"{PREFIX}{uuid4().hex[:8]}@noctornal.test",
                            "ACL Operator", "correct-horse-battery-staple-9")
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'SYS_ADMIN')", (uid,))
    return uid


def _auth(conn, uid, *, fresh=True) -> dict:
    """`fresh=False` is a session whose step-up has lapsed: every
    `user.manage` route refuses it with a 403."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=fresh)
    return {"Authorization": f"Bearer {token}"}


def _create(client, auth):
    return client.post("/api/v1/admin/users", headers=auth, json={
        "email": f"{PREFIX}{uuid4().hex[:8]}@noctornal.test",
        "display_name": "ACL Colleague", "clearance": "AMBER",
        "roles": ["ANALYST"]})


def test_after_first_run_the_operator_can_add_a_team_and_still_reissue_codes(
        conn, client):
    """The finding's sequence: first-run codes, then colleagues. Six is
    double what the shared bucket allowed after first run."""
    auth = _auth(conn, _admin(conn))
    first_run = client.post("/api/v1/auth/recovery-codes", headers=auth)
    assert first_run.status_code == 200, first_run.text
    for n in range(6):
        r = _create(client, auth)
        assert r.status_code == 201, f"colleague {n + 1}: {r.status_code} {r.text}"
    again = client.post("/api/v1/auth/recovery-codes", headers=auth)
    assert again.status_code == 200, (
        "provisioning colleagues used up the operator's own recovery-code "
        "meter: " + again.text)


def test_stale_step_up_clicks_do_not_spend_the_operators_recovery_codes(
        conn, client):
    """Refused 403s still spend from the meter the route names. On the
    shared bucket three of them locked the operator out of reissuing their
    own codes; now they spend only from the admin meter."""
    uid = _admin(conn)
    stale = _auth(conn, uid, fresh=False)
    for _ in range(3):
        r = _create(client, stale)
        assert r.status_code == 403, r.text
    r = client.post("/api/v1/auth/recovery-codes", headers=_auth(conn, uid))
    assert r.status_code == 200, r.text
