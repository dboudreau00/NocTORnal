"""The selector store refuses an empty canonical form (2026-09-11).

`SelectorStore.record` stored whatever the normaliser returned, and for
input the normaliser could not reduce that was '' -- a value to `UNIQUE
(case_id, selector_type, norm_value)`, so every unreducible observation
of one type in a case collapsed onto ONE row. On a strong type that row is
a merge lead between strangers. The bare positive Telegram id, refused
by the normaliser since the same day, is the case that made it explicit.

Env-gated on DATABASE_URL. **The email prefix is `slr-` and must stay
unique.**
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; selector refusal e2e is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
EMAIL_LIKE = "slr-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
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


def _case(conn, client) -> str:
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"slr-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Refusal", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    # Cases default to AMBER and a new account to GREEN; the owner has to
    # be able to see their own case.
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, 'CASE_OWNER')",
                 (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid, mfa_satisfied=True)
    r = client.post("/api/v1/cases", headers={"Authorization": f"Bearer {token}"}, json={
        "code": f"OP-SLR-{uuid4().hex[:6]}", "title": "Operation Refusal",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_a_bare_positive_telegram_id_is_refused_and_nothing_is_stored(conn, client):
    from noctornal_api.selectors import SelectorError, SelectorStore
    case_id = _case(conn, client)
    store = SelectorStore(conn)
    with pytest.raises(SelectorError) as caught:
        store.record(case_id=case_id, selector_type="TELEGRAM_ID", raw_value="1234567890")
    assert "u:<id>" in str(caught.value) and "c:<id>" in str(caught.value)
    assert conn.execute(
        "SELECT count(*) FROM core.selector WHERE case_id = %s", (case_id,)
    ).fetchone()[0] == 0

    # Typed, it records, in its own namespace.
    user = store.record(case_id=case_id, selector_type="TELEGRAM_ID", raw_value="u:1234567890")
    channel = store.record(case_id=case_id, selector_type="TELEGRAM_ID", raw_value="c:1234567890")
    assert user.norm_value == "u:1234567890" and channel.norm_value == "c:1234567890"
    assert user.id != channel.id
    # The Bot-API form of the channel lands on the channel's row.
    bot_api = store.record(case_id=case_id, selector_type="TELEGRAM_ID",
                           raw_value="-1001234567890")
    assert bot_api.id == channel.id and bot_api.observation_cnt == 2


def test_nothing_unreducible_is_stored_as_the_empty_string(conn, client):
    """Two junk observations of one strong type used to become ONE row."""
    from noctornal_api.selectors import SelectorError, SelectorStore
    case_id = _case(conn, client)
    store = SelectorStore(conn)
    for junk in ("not a number", "???"):
        with pytest.raises(SelectorError) as caught:
            store.record(case_id=case_id, selector_type="TELEGRAM_ID", raw_value=junk)
        assert "canonical TELEGRAM_ID" in str(caught.value)
    with pytest.raises(SelectorError):
        store.find(case_id=case_id, selector_type="TELEGRAM_ID", raw_value="???")
    assert conn.execute(
        "SELECT count(*) FROM core.selector WHERE case_id = %s AND norm_value = ''",
        (case_id,)).fetchone()[0] == 0
