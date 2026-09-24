"""The case record and the caller's standing on it, over HTTP (2026-09-23).

The console's Case record, Status dialog, case list and app bar read these
fields; each was missing, so the console could not show them:

- ux02-cases:case-record-invisible-and-uneditable: `summary` and
  `authority_ref` were never returned, so the record written at creation
  could not be shown again;
- ux02-cases:status-prompt-free-text-one-way-transitions: nothing said
  which moves are legal from here, so the prompt listed all six;
- ux02-cases:case-list-lacks-triage-fields and
  ux02-cases:header-says-analyst-no-permission-cues: nothing said what
  the CALLER is on the case, or what their clearance is, so every account
  was "analyst" and every action was offered to everyone.

The role fields are hints for the console and never a gate; the routes
that act still run the five-part check, which test_case_lifecycle_api_pg
holds.

**The email prefix is `crec-` and must stay unique**: every fixture here
tears down by deleting on it.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the case record API is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'crec-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'crec-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, name="Case Record", clearance="AMBER", global_roles=()):
    from noctornal_api.stores import PgUserStore
    email = f"crec-{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(conn).create_user(email, name, "correct-horse-battery-staple")
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid, email


def _session(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid,
                                                           mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(client, auth, **extra) -> str:
    body = {"code": f"OP-CREC-{uuid4().hex[:6]}", "title": "Operation Record",
            "legal_basis": "production order 2026-0101",
            "retention_until": str(date(2028, 1, 1)),
            "review_due": str(date(2027, 1, 1)),
            "summary": "What the case is about",
            "authority_ref": "warrant 2026-0101"}
    body.update(extra)
    r = client.post("/api/v1/cases", headers=auth, json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _role_name(conn, key: str) -> str:
    return conn.execute("SELECT display_name FROM iam.role WHERE key = %s",
                        (key,)).fetchone()[0]


def test_the_record_carries_what_was_written_at_creation(conn, client):
    owner, _ = _user(conn, name="Rhea Owner", global_roles=("CASE_OWNER",))
    auth = _session(conn, owner)
    case_id = _case(client, auth)
    got = client.get(f"/api/v1/cases/{case_id}", headers=auth).json()
    assert got["summary"] == "What the case is about"
    assert got["authority_ref"] == "warrant 2026-0101"
    assert got["legal_basis"] == "production order 2026-0101"
    assert got["owner_name"] == "Rhea Owner"


def test_the_record_names_the_legal_moves_and_they_follow_the_status(conn, client):
    """DRAFT offers ACTIVE and ARCHIVED; after the move, ACTIVE offers
    DORMANT and CLOSED. The table is the service's own."""
    from noctornal_api.cases import _TRANSITIONS
    owner, _ = _user(conn, global_roles=("CASE_OWNER",))
    auth = _session(conn, owner)
    case_id = _case(client, auth)
    got = client.get(f"/api/v1/cases/{case_id}", headers=auth).json()
    assert got["status"] == "DRAFT"
    assert set(got["allowed_transitions"]) == _TRANSITIONS["DRAFT"]
    moved = client.post(f"/api/v1/cases/{case_id}/status", headers=auth,
                        json={"status": "ACTIVE"})
    assert moved.status_code == 200, moved.text
    assert moved.json()["allowed_transitions"] == ["DORMANT", "CLOSED"]
    listed = next(c for c in client.get("/api/v1/cases", headers=auth).json()
                  if c["id"] == case_id)
    assert listed["allowed_transitions"] == ["DORMANT", "CLOSED"]


def test_the_caller_is_told_their_own_role_and_what_it_carries(conn, client):
    """The owner reads Lead investigator (the role's display name, from
    iam.role, not the console) and case.close; an analyst on the same case
    reads their own role and no case.close; the list says the same."""
    owner, _ = _user(conn, global_roles=("CASE_OWNER",))
    owner_auth = _session(conn, owner)
    case_id = _case(client, owner_auth)
    analyst, _ = _user(conn)
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by) "
        "VALUES (%s, %s, 'ANALYST', %s)", (case_id, analyst, owner))
    analyst_auth = _session(conn, analyst)

    mine = client.get(f"/api/v1/cases/{case_id}", headers=owner_auth).json()
    assert mine["my_role"] == "CASE_OWNER"
    assert mine["my_role_name"] == _role_name(conn, "CASE_OWNER")
    assert "case.close" in mine["my_permissions"]
    assert "case.update" in mine["my_permissions"]

    theirs = client.get(f"/api/v1/cases/{case_id}", headers=analyst_auth).json()
    assert theirs["my_role"] == "ANALYST"
    assert theirs["my_role_name"] == _role_name(conn, "ANALYST")
    assert "case.close" not in theirs["my_permissions"]
    assert "case.read" in theirs["my_permissions"]
    # The same case, the same owner, read by either of them.
    assert theirs["owner_name"] == mine["owner_name"]

    listed = next(c for c in client.get("/api/v1/cases", headers=analyst_auth).json()
                  if c["id"] == case_id)
    assert listed["my_role"] == "ANALYST"


def test_an_expired_assignment_is_not_reported_as_a_role(conn, client):
    """The role reported is the one the gate would read: unexpired."""
    from noctornal_api.cases import CaseService
    from noctornal_api.http.routers.cases import _with_caller
    owner, _ = _user(conn, global_roles=("CASE_OWNER",))
    case_id = _case(client, _session(conn, owner))
    other, _ = _user(conn)
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by, "
        "expires_at) VALUES (%s, %s, 'ANALYST', %s, now() - interval '1 hour')",
        (case_id, other, owner))
    row = _with_caller(conn, [CaseService(conn).get(case_id)], other)[0]
    assert row.my_role is None and row.my_permissions == []


def test_a_correction_answers_with_the_record_and_the_callers_standing(conn, client):
    owner, _ = _user(conn, global_roles=("CASE_OWNER",))
    auth = _session(conn, owner)
    case_id = _case(client, auth)
    r = client.patch(f"/api/v1/cases/{case_id}", headers=auth,
                     json={"authority_ref": "warrant 2026-0202",
                           "retention_until": str(date(2029, 1, 1))})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["authority_ref"] == "warrant 2026-0202"
    assert body["retention_until"] == "2029-01-01"
    assert body["my_role"] == "CASE_OWNER" and body["access_lost"] == []


def test_the_signed_in_account_is_told_its_own_clearance(conn, client):
    uid, _ = _user(conn, clearance="GREEN")
    me = client.get("/api/v1/auth/me", headers=_session(conn, uid)).json()
    assert me["tlp_clearance"] == "GREEN"
