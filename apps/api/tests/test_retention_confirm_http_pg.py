"""Confirming a retention rule, over HTTP, with and without step-up.

`RetentionService.confirm_rule` and `POST /retention/rules/{category}` have
existed since Phase 6, and the service had a test; the endpoint had none.
That left the step-up requirement -- `retention.manage` is flagged
`requires_step_up` in the seed and `require_global` is what honours the
flag -- as a claim made by two files that had never been run against each
other. A permission marked step-up in the database and a gate that forgot
to read the column would each look right on their own, which is this
codebase's "two internally consistent halves that are wrong together".

So this file confirms a rule through the router with a freshly
re-authenticated session and reads `confirmed_by`/`confirmed_at` back off
the row; then ages the session's second factor past `STEP_UP_FRESHNESS`
and proves the same request is refused and the row untouched.

Categories are `TEST_HTTP_*` and rules are global, so teardown removes
them; the governance suites already delete `TEST%` for the same reason.
Email prefix `rc-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; retention-confirm e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"
RATIONALE = "counsel determination 2026-09, HTTP test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'rc-%@noctornal.test')"
    with c.transaction():
        # A confirmed rule names the human who confirmed it; the reference
        # has to go before the human can.
        c.execute(f"UPDATE core.retention_rule SET confirmed_by = NULL, "
                  f"confirmed_at = NULL WHERE confirmed_by IN {sub}")
        c.execute("DELETE FROM core.retention_rule WHERE category LIKE 'TEST_HTTP_%'")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'rc-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, global_roles=("SYS_ADMIN",)):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"rc-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Retention", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
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


def _rule_row(conn, category: str):
    return conn.execute(
        """SELECT retain_days, rationale, confirmed_by, confirmed_at
             FROM core.retention_rule WHERE category = %s""",
        (category,)).fetchone()


def _age_second_factor(conn, uid) -> None:
    """Push the session's MFA timestamp past STEP_UP_FRESHNESS without
    touching the session's validity: the token still works for everything
    that is not step-up gated."""
    from noctornal_api.security.sessions import STEP_UP_FRESHNESS
    conn.execute(
        """UPDATE iam.session
              SET mfa_satisfied_at = now() - %s - interval '1 minute'
            WHERE user_id = %s""",
        (STEP_UP_FRESHNESS, uid))


def test_a_fresh_step_up_session_confirms_a_rule_and_the_row_says_who(conn, client):
    uid, email, secret = _make_user(conn)
    token = _login(client, email, secret)   # login satisfies MFA: fresh
    category = f"TEST_HTTP_{uuid4().hex[:6].upper()}"

    r = client.post(f"/api/v1/retention/rules/{category}", headers=_auth(token),
                    json={"retain_days": 45, "rationale": RATIONALE})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["category"] == category
    assert body["retain_days"] == 45
    assert body["confirmed_by"] == str(uid)
    assert body["is_placeholder"] is False

    retain_days, rationale, confirmed_by, confirmed_at = _rule_row(conn, category)
    assert (retain_days, rationale) == (45, RATIONALE)
    assert confirmed_by == uid
    assert confirmed_at is not None

    # The audit trail carries the same fact.
    audited = conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'RETENTION_RULE_CONFIRMED' AND actor_id = %s
              AND detail->>'category' = %s""",
        (uid, category)).fetchone()[0]
    assert audited == 1


def test_a_session_whose_second_factor_has_aged_is_refused(conn, client):
    """`retention.manage` is a step-up permission in the seed -- read from
    the database here, not assumed -- and `require_global` is the code
    that honours the flag. Both halves, one test."""
    (requires_step_up,) = conn.execute(
        "SELECT requires_step_up FROM iam.permission WHERE key = 'retention.manage'"
    ).fetchone()
    assert requires_step_up is True

    uid, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    _age_second_factor(conn, uid)
    category = f"TEST_HTTP_{uuid4().hex[:6].upper()}"

    r = client.post(f"/api/v1/retention/rules/{category}", headers=_auth(token),
                    json={"retain_days": 45, "rationale": RATIONALE})
    assert r.status_code == 403, r.text
    assert "re-authentication" in r.json()["detail"]
    assert _rule_row(conn, category) is None, "a refused confirmation wrote a row"

    # The session itself is still alive -- only the step-up gate closed.
    assert client.get("/api/v1/auth/me", headers=_auth(token)).status_code == 200


def test_the_permission_gates_the_route_not_just_the_step_up(conn, client):
    """An analyst with a fresh second factor and no `retention.manage`
    is refused for the permission, so the refusal names the right
    thing."""
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/retention/rules/TEST_HTTP_ANALYST", headers=_auth(token),
                    json={"retain_days": 45, "rationale": RATIONALE})
    assert r.status_code == 403
    assert "retention.manage" in r.json()["detail"]
    assert _rule_row(conn, "TEST_HTTP_ANALYST") is None


def test_a_non_positive_period_is_a_400_not_a_write(conn, client):
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    r = client.post("/api/v1/retention/rules/TEST_HTTP_ZERO", headers=_auth(token),
                    json={"retain_days": 0, "rationale": RATIONALE})
    assert r.status_code in (400, 422), r.text
    assert _rule_row(conn, "TEST_HTTP_ZERO") is None
