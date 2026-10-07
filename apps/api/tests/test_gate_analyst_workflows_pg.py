"""Defects found driving the analyst workflows end to end (Beta 1 release
gate 61, 2026-10-07), each pinned where it was found.

- An exhibit above the caller's labels answered its routes with the gate's
  403 "missing permission evidence.read on this case", to an analyst who
  holds that permission, while an unknown id answered 404: a hidden exhibit
  was told from a missing one. The entity and tie routes made that one
  answer on 2026-10-03 (http_ui-016); the exhibit routes had not.
- Opening a conversation on a platform key the registry does not hold was
  the foreign key's violation and a 500.
- Flagging a handle as incidental answered 200 and the flag when no
  participant of the conversation had that handle, and changed nothing.

**The email prefix is `g61w-` and must stay unique**: the fixture cleans
up by deleting on it.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; gate 61 tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
_SUB = "(SELECT id FROM iam.app_user WHERE email LIKE 'g61w-%@noctornal.test')"
_CSUB = f'(SELECT id FROM core."case" WHERE owner_user_id IN {_SUB})'


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    with c.transaction():
        c.execute(f"DELETE FROM comms.participant WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {_CSUB})")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {_CSUB}")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {_CSUB}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {_CSUB}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {_SUB}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {_CSUB}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {_SUB}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {_SUB}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'g61w-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, clearance, roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"g61w-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Gate Sixty-One", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(conn, client, owner) -> str:
    r = client.post("/api/v1/cases", headers=_auth(conn, owner), json={
        "code": f"OP-G61W-{uuid4().hex[:6].upper()}", "title": "Gate 61",
        "legal_basis": "gate 61 regression", "classification": "AMBER",
        "retention_until": str(date(2030, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, uid, owner, role):
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, %s, %s)", (case_id, uid, role, owner))


def _exhibit(conn, case_id, owner, level):
    """Inserted directly, with no custody rows, so the fixture may delete
    it. Only its labels matter: every route refuses before a byte is read."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'note.txt', 'text/plain', 64, %s, %s, %s,
                   'test-bucket', %s, 'MANUAL_UPLOAD', now(), %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}",
         level, owner)).fetchone()[0]


def test_an_exhibit_above_the_caller_answers_as_a_missing_one(conn, client):
    owner = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    case_id = _case(conn, client, owner)
    red = _exhibit(conn, case_id, owner, "RED")
    # An AMBER analyst (evidence.read, evidence.upload) and an AMBER Lead
    # investigator (evidence.export) on the AMBER case.
    analyst = _user(conn, clearance="AMBER")
    lead = _user(conn, clearance="AMBER")
    _assign(conn, case_id, analyst, owner, "ANALYST")
    _assign(conn, case_id, lead, owner, "CASE_OWNER")
    base = f"/api/v1/cases/{case_id}/evidence"
    routes = [
        (analyst, "GET", "custody", None),
        (analyst, "GET", "content", None),
        (analyst, "GET", "backs", None),
        (analyst, "POST", "verify", None),
        (analyst, "POST", "links", {"node_id": str(uuid4())}),
        (lead, "POST", "export", None),
        (lead, "POST", "production-ticket", None),
    ]
    for who, method, tail, body in routes:
        auth = _auth(conn, who)
        hidden = client.request(method, f"{base}/{red}/{tail}", headers=auth,
                                json=body)
        missing = client.request(method, f"{base}/{uuid4()}/{tail}",
                                 headers=auth, json=body)
        assert (hidden.status_code, hidden.json()["detail"]) == \
            (missing.status_code, missing.json()["detail"]) == \
            (404, "evidence does not exist in this case"), (tail, hidden.text)
    # The refusal is still recorded as the denial it is.
    denied = conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'AUTHZ_DENIED' AND actor_id = %s
              AND detail->'failed_checks' ? 'tlp_clearance_dominates'""",
        (analyst,)).fetchone()[0]
    assert denied >= 5


def test_an_exhibit_within_the_caller_still_opens(conn, client):
    """The other side: the change turns only a label refusal, so an exhibit
    the analyst may read is still past the gate (its bytes are not in the
    store, which is the 4xx/5xx the content read gives, not a 404)."""
    owner = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    case_id = _case(conn, client, owner)
    amber = _exhibit(conn, case_id, owner, "AMBER")
    analyst = _user(conn, clearance="AMBER")
    _assign(conn, case_id, analyst, owner, "ANALYST")
    r = client.get(f"/api/v1/cases/{case_id}/evidence/{amber}/custody",
                   headers=_auth(conn, analyst))
    assert r.status_code == 200, r.text
    # A liaison holds no evidence.upload: the verb is still the gate's 403.
    liaison = _user(conn, clearance="AMBER")
    _assign(conn, case_id, liaison, owner, "LIAISON")
    r = client.post(f"/api/v1/cases/{case_id}/evidence/{amber}/links",
                    headers=_auth(conn, liaison), json={"node_id": str(uuid4())})
    assert r.status_code == 403


def test_a_conversation_on_an_unknown_platform_is_a_400_not_a_500(conn, client):
    owner = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    case_id = _case(conn, client, owner)
    r = client.post(f"/api/v1/cases/{case_id}/comms/conversations",
                    headers=_auth(conn, owner),
                    json={"platform_key": "telegram",
                          "provenance_class": "OPEN_GROUP"})
    assert r.status_code == 400, r.text
    assert "unknown platform" in r.json()["detail"]


def test_flagging_a_handle_nobody_in_the_conversation_has_is_refused(conn, client):
    owner = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    case_id = _case(conn, client, owner)
    auth = _auth(conn, owner)
    conv = client.post(f"/api/v1/cases/{case_id}/comms/conversations",
                       headers=auth, json={"platform_key": "MATRIX",
                                           "provenance_class": "OPEN_GROUP"})
    assert conv.status_code == 201, conv.text
    conv_id = conv.json()["id"]
    conn.execute(
        """INSERT INTO comms.participant
               (conversation_id, observed_handle, message_count)
           VALUES (%s, '@bystander:example.test', 1)""", (conv_id,))
    path = f"/api/v1/cases/{case_id}/comms/conversations/{conv_id}/incidental"
    r = client.post(path, headers=auth, json={"handle": "@bystandr:example.test"})
    assert r.status_code == 404, r.text
    r = client.post(path, headers=auth, json={"handle": "@bystander:example.test"})
    assert r.status_code == 200 and r.json()["is_incidental"] is True
    assert conn.execute(
        "SELECT is_incidental FROM comms.participant WHERE conversation_id = %s",
        (conv_id,)).fetchone()[0] is True
