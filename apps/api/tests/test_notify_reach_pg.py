"""N1 (2026-09-02): a four-eyes request that reached nobody must say so,
and a notify failure after the primary write must not turn a completed
action into a 500.

Two defects of the same family -- a failure reported as the wrong thing:

1. `notify_events.approval_requested` counted how many approvers it
   reached and returned it; `ApprovalService.request` called it as a bare
   statement and threw the count away, and `ApprovalOut` had no field for
   it. A request nobody was told about was a 201 like any other, and dual
   control was "just a merge button that does not work" -- the exact
   failure the notification exists to prevent.
2. `request()`, `decide()` and `BreakGlassService._alert` are notify
   writes on an autocommit connection AFTER the primary row committed. A
   failure there surfaced as a 500, which reads as "the request was not
   made" when it was -- so the analyst raises it again (409: identical
   request pending), or the break-glass analyst believes they were refused
   access they in fact hold.

**The email prefix is `nreach-` and must stay unique** -- every fixture in
this suite cleans up on an email pattern.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from datetime import date
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; notify-reach tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
EMAIL_LIKE = "nreach-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}")
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
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


def _make_user(conn, *, clearance="AMBER", global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"nreach-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Reach", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
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


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-NREACH-{uuid4().hex[:6]}", "title": "Reach",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, user_id, role, granted_by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user_id, role, granted_by))


def _payload() -> dict:
    return {"source_node_id": str(uuid4()), "target_node_id": str(uuid4()),
            "reason": "same PGP fingerprint", "basis_selector_id": None}


def _request(client, token, case_id):
    return client.post(f"/api/v1/cases/{case_id}/approvals", headers=_auth(token),
                       json={"operation": "node.merge", "payload": _payload(),
                             "justification": "two handles, one fingerprint"})


# ---------------------------------------------------------------------------
# request(): reach is reported, and a notify failure is not a 500
# ---------------------------------------------------------------------------

def test_a_request_that_reached_nobody_is_201_with_zero_reach_and_a_warning(conn, client):
    """The only other assignee holds graph.merge but is cleared BELOW the
    case, so suppression 2 drops the notification at write time. Before
    N1 that was a 201 indistinguishable from one that reached three
    approvers."""
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    below, _, _ = _make_user(conn, clearance="GREEN")
    _assign(conn, case_id, below, "ANALYST", owner)

    r = _request(client, token, case_id)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["approvers_notified"] == 0
    assert any("no approver was notified" in w for w in body["warnings"]), body
    assert conn.execute(
        "SELECT count(*) FROM notify.notification WHERE kind = 'APPROVAL_REQUESTED' "
        "AND case_id = %s", (UUID(case_id),)).fetchone()[0] == 0


def test_a_request_that_reached_an_approver_reports_the_count_and_no_warning(conn, client):
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    approver, _, _ = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, approver, "ANALYST", owner)

    r = _request(client, token, case_id)
    assert r.status_code == 201, r.text
    assert r.json()["approvers_notified"] == 1
    assert r.json()["warnings"] == []


def test_a_failed_request_notification_is_201_not_500(conn, client, monkeypatch):
    """The approval row committed before the notify write ran. A 500 here
    tells the analyst the request was not made; it was, and their retry is
    a 409 for an identical pending request."""
    from noctornal_api import notify_events

    def boom(*a, **kw):
        raise RuntimeError("notify.notification is unreachable")
    monkeypatch.setattr(notify_events, "approval_requested", boom)

    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    approver, _, _ = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, approver, "ANALYST", owner)

    r = _request(client, token, case_id)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["approvers_notified"] is None
    assert any("notification failed" in w for w in body["warnings"]), body
    row = conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                       (UUID(body["id"]),)).fetchone()
    assert row is not None and row[0] == "PENDING", "the request itself stands"


# ---------------------------------------------------------------------------
# decide(): same shape
# ---------------------------------------------------------------------------

def _raise_and_get_decider(conn, client):
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    approver, a_email, a_secret = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, approver, "ANALYST", owner)
    r = _request(client, token, case_id)
    assert r.status_code == 201, r.text
    return case_id, r.json()["id"], _login(client, a_email, a_secret)


def test_deciding_reports_whether_the_requester_was_told(conn, client):
    case_id, request_id, a_token = _raise_and_get_decider(conn, client)
    r = client.post(f"/api/v1/cases/{case_id}/approvals/{request_id}/decide",
                    headers=_auth(a_token), json={"approve": True, "note": "checked"})
    assert r.status_code == 200, r.text
    assert r.json()["requester_notified"] is True
    assert r.json()["warnings"] == []


def test_a_failed_decision_notification_is_200_not_500(conn, client, monkeypatch):
    from noctornal_api import notify_events

    def boom(*a, **kw):
        raise RuntimeError("notify.notification is unreachable")
    monkeypatch.setattr(notify_events, "approval_decided", boom)

    case_id, request_id, a_token = _raise_and_get_decider(conn, client)
    r = client.post(f"/api/v1/cases/{case_id}/approvals/{request_id}/decide",
                    headers=_auth(a_token), json={"approve": True, "note": "checked"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "APPROVED"
    assert body["requester_notified"] is None
    assert any("notification failed" in w for w in body["warnings"]), body
    assert conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                        (UUID(request_id),)).fetchone()[0] == "APPROVED"


# ---------------------------------------------------------------------------
# break-glass: the grant stands even if the alert could not be written
# ---------------------------------------------------------------------------

def test_a_failed_break_glass_alert_does_not_unmake_the_grant(conn, monkeypatch):
    """Since 2026-09-01 a live grant RAISES the caller's effective
    clearance. A 500 after the grant row committed tells the analyst they
    were refused access they now hold -- at 3am, in the incident the
    control exists for. The grant is still in the unreviewed queue, which
    is the durable half of the control; the alert is the loud half, and a
    failure to be loud is logged, not converted into a lie."""
    from noctornal_api.break_glass import BreakGlassService

    officer, _, _ = _make_user(conn, global_roles=("SECURITY_OFFICER",))
    analyst, _, _ = _make_user(conn)

    def boom(self, grant, officers):
        raise RuntimeError("notify.notification is unreachable")
    monkeypatch.setattr(BreakGlassService, "_alert", boom)

    grant = BreakGlassService(conn).invoke(
        user_id=analyst, case_id=None,
        justification="live incident, the case owner is unreachable")
    assert conn.execute("SELECT count(*) FROM iam.break_glass WHERE id = %s",
                        (grant.id,)).fetchone()[0] == 1


# ---------------------------------------------------------------------------
# the contract crosses three files: service record -> router model -> client
# ---------------------------------------------------------------------------

def test_the_reach_fields_exist_on_both_sides_of_the_http_boundary():
    """`ApprovalRequest` carries the reach; `ApprovalOut` must declare it
    or pydantic drops it without a sound -- the same silent loss that hid
    the drain's `revoked` counter."""
    from dataclasses import fields

    from noctornal_api.approvals import ApprovalRequest
    from noctornal_api.http.routers.approvals import ApprovalOut

    record = {f.name for f in fields(ApprovalRequest)}
    out = set(ApprovalOut.model_fields)
    for name in ("approvers_notified", "requester_notified"):
        assert name in record, f"ApprovalRequest lacks {name}"
        assert name in out, f"ApprovalOut lacks {name}"
    assert "warnings" in out
