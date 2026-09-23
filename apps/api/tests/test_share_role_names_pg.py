"""The Share roster names roles the way the owner decided, over HTTP.

Final review U21, 2026-09-23. Migration 0062 made CASE_OWNER read as
"Lead investigator", but the name reached only the admin pane, through
`/admin/roles`, which needs user.manage. The Share panel is opened by every
case worker and printed the raw key in each roster chip, in the outcome of
a regrade and in the removal message, because nothing it could read
carried the name. The roster, the grant and the revoke now return the name
beside the key; `test_ui_purge_binding_and_role_names.py` holds the
console to reading it.

**The email prefix is `srn-` and must stay unique**: the fixture cleans up
by deleting on it. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; share role names are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'srn-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"    OR case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'srn-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, name, roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"srn-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, name, "correct-horse-battery-staple")
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                 (uid,))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid, email


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _names(conn) -> dict[str, str]:
    return dict(conn.execute(
        "SELECT key, display_name FROM iam.role").fetchall())


def test_the_roster_grant_and_revoke_carry_the_role_name(conn, client):
    names = _names(conn)
    # The owner's decision is the reason for this test; if the seed ever
    # stops saying it, this should say so first.
    assert names["CASE_OWNER"] == "Lead investigator"

    owner, _ = _user(conn, "Srn Owner", roles=("CASE_OWNER",))
    auth = _auth(conn, owner)
    r = client.post("/api/v1/cases", headers=auth, json={
        "code": f"OP-SRN-{uuid4().hex[:6].upper()}", "title": "Operation SRN",
        "legal_basis": "production order 2026-0923",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)), "classification": "AMBER"})
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    colleague, email = _user(conn, "Srn Colleague")

    # Added as a co-lead, then regraded: the answer names both grades.
    first = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                        json={"email": email, "role_key": "CASE_OWNER"})
    assert first.status_code == 200, first.text
    assert first.json()["role_name"] == "Lead investigator"
    assert first.json()["replaced_role_name"] is None
    second = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                         json={"email": email, "role_key": "REVIEWER"})
    assert second.status_code == 200, second.text
    assert second.json()["replaced_role"] == "CASE_OWNER"
    assert second.json()["replaced_role_name"] == "Lead investigator"
    assert second.json()["role_name"] == names["REVIEWER"]

    # The roster, which a LIAISON or READ_ONLY reader opens too.
    roster = client.get(f"/api/v1/cases/{case_id}/users", headers=auth)
    assert roster.status_code == 200, roster.text
    rows = {u["user_id"]: u for u in roster.json()["users"]}
    assert rows[str(owner)]["role_key"] == "CASE_OWNER"
    assert rows[str(owner)]["role_name"] == "Lead investigator"
    assert rows[str(colleague)]["role_name"] == names["REVIEWER"]

    gone = client.delete(f"/api/v1/cases/{case_id}/users/{colleague}",
                         headers=auth)
    assert gone.status_code == 200, gone.text
    assert gone.json()["revoked_role"] == "REVIEWER"
    assert gone.json()["revoked_role_name"] == names["REVIEWER"]
