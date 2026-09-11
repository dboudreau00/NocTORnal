"""The two policy routes state the cap the routers enforce (2026-09-11).

Env-gated on DATABASE_URL. **The email prefix is `szp-` and must stay
unique.**
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; size policy e2e is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
EMAIL_LIKE = "szp-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _owner(conn) -> str:
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"szp-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Size", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    # Cases default to AMBER and a new account to GREEN; the owner has to
    # be able to see their own case.
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, 'CASE_OWNER')",
                 (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid, mfa_satisfied=True)
    return token


def _case(client, token) -> str:
    r = client.post("/api/v1/cases", headers={"Authorization": f"Bearer {token}"}, json={
        "code": f"OP-SZP-{uuid4().hex[:6]}", "title": "Operation Size",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_the_policy_routes_state_the_cap_the_routers_enforce(conn, client):
    from noctornal_api import samples
    from noctornal_api.config import EVIDENCE_CAP_ENV, SAMPLE_CAP_ENV, cap_is_declared
    from noctornal_api.http.routers import evidence as evidence_router
    token = _owner(conn)
    case_id = _case(client, token)
    auth = {"Authorization": f"Bearer {token}"}

    r = client.get(f"/api/v1/cases/{case_id}/evidence/policy", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["max_bytes"] == evidence_router.MAX_EVIDENCE_BYTES
    assert r.json()["declared"] is cap_is_declared(EVIDENCE_CAP_ENV)
    assert "split" in r.json()["notice"]

    r = client.get("/api/v1/samples/policy", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["max_sample_bytes"] == samples.MAX_SAMPLE_BYTES
    assert r.json()["max_sample_bytes_declared"] is cap_is_declared(SAMPLE_CAP_ENV)

    # A session, not a permission: the cap is the deployment's. No session
    # is still no answer.
    assert client.get(f"/api/v1/cases/{case_id}/evidence/policy").status_code == 401
