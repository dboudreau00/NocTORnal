"""The two-person policy over HTTP (F9, 2026-09-24): the global
approvals routes (`/approvals`) and Administration, Two-person controls
(`/admin/dual-control`).

What the database file (`test_dual_control_policy_pg.py`) cannot show is
the wiring: who each route lets in, the step-up words the console
recognises, a countersigner told who took over their account and when, and
a change that commits through the API's own connections and is restored
the same way.

## Isolation

Rule (c) of the policy file: a change the API commits is visible to every
connection, so each test that makes one takes it back through the same
two-person flow in a `finally`, and if that fails the owner-level helper
resets node.merge and the test fails loudly. Accounts are written directly
(no USER_CREATED or ROLE_GRANTED audit row), so the seven-day rule does not
apply to them unless a test produces the event on purpose. Teardown is the
policy file's rule (d) for the prefix `dcq-`; no PENDING deployment-wide
request survives a test.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import re
from datetime import date
from uuid import uuid4

import pytest

from test_dual_control_policy_pg import (
    force_mode,
    merge_mode,
    teardown,
    throwaway_pair,
)
from test_dual_control_policy_pg import user as _user

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the HTTP routes are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "dcq-"  # dch- is test_deception_hosts_pg's
API = "/api/v1"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    # A limiter this file alone owns (test_http_e2e.py says why).
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def user(conn, *roles, **kw):
    return _user(conn, *roles, prefix=PREFIX, **kw)


def session(conn, uid, *, fresh: bool = True) -> dict:
    """A signed-in caller, minted as `bootstrap.py session` mints one.
    `fresh` False back-dates the second factor past the step-up window."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    if not fresh:
        conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() - "
                     "interval '2 hours' WHERE id = %s", (record.id,))
    return {"Authorization": f"Bearer {token}"}


def _propose(client, who, change, justification="standing orders"):
    return client.post(f"{API}/admin/dual-control/changes", headers=who,
                       json=dict(change, justification=justification))


def _decide(client, who, request_id, approve=True, note=None):
    return client.post(f"{API}/approvals/{request_id}/decide", headers=who,
                       json={"approve": approve, "note": note})


def _apply(client, who, request_id):
    return client.post(f"{API}/admin/dual-control/changes/{request_id}/apply",
                       headers=who)


def _two_person(client, admin, officer, change):
    """Propose, countersign and apply one change; each step must succeed."""
    r = _propose(client, admin, change)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    d = _decide(client, officer, rid)
    assert d.status_code == 200, d.text
    a = _apply(client, admin, rid)
    assert a.status_code == 200, a.text
    return r.json(), a.json()


def _restore_per_case(conn, client, admin, officer) -> None:
    """Rule (c): back to PER_CASE through the flow, else by the owner-level
    helper, and then fail loudly."""
    if merge_mode(conn) == "PER_CASE":
        return
    try:
        _two_person(client, admin, officer,
                    {"change": "OPERATION_MODE", "operation": "node.merge",
                     "to": "PER_CASE"})
    finally:
        if merge_mode(conn) != "PER_CASE":
            force_mode(conn, "PER_CASE")
            raise AssertionError("node.merge could not be restored through "
                                 "the flow; reset by the owner-level helper")


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-DCH-{uuid4().hex[:6]}", title="Two-person routes",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


# ---------------------------------------------------------------------------
# The flow
# ---------------------------------------------------------------------------

def test_the_two_person_flow_over_http(conn, client):
    admin_id = user(conn, "SYS_ADMIN", name="Dch Admin")
    officer_id = user(conn, "SECURITY_OFFICER", name="Dch Officer")
    admin, officer = session(conn, admin_id), session(conn, officer_id)
    try:
        r = _propose(client, admin, {"change": "OPERATION_MODE",
                                     "operation": "node.merge", "to": "ALWAYS"},
                     justification="QUOTE-ME-NOT standing orders")
        assert r.status_code == 201, r.text
        body = r.json()
        rid = body["id"]
        assert body["state"] == "PENDING" and body["case_id"] is None
        assert body["payload"]["from"] == "PER_CASE"
        assert body["approvers_notified"] >= 1 and body["warnings"] == []
        assert body["preview"]["effect"].startswith(
            "Every merge on this deployment will need a second signature.")
        told = conn.execute(
            """SELECT classification, case_id, subject || summary || body
                 FROM notify.notification
                WHERE recipient_id = %s AND object_id = %s""",
            (officer_id, rid)).fetchone()
        assert told is not None, "the officer was not told"
        assert told[0] == "GREEN" and told[1] is None
        assert "QUOTE-ME-NOT" not in told[2]

        listed = client.get(f"{API}/approvals",
                            params={"operation": "dual_control.policy",
                                    "state": "OPEN"}, headers=officer)
        assert listed.status_code == 200, listed.text
        row = next(a for a in listed.json()["approvals"] if a["id"] == rid)
        assert row["countersign"]["allowed"] is True
        assert row["requested_by_name"] == "Dch Admin"
        assert row["stale"] is False

        d = _decide(client, officer, rid, note="NOTE-NOT-QUOTED")
        assert d.status_code == 200, d.text
        assert d.json()["state"] == "APPROVED"
        assert d.json()["requester_notified"] is True
        told = conn.execute(
            """SELECT classification, case_id, kind, subject || summary || body
                 FROM notify.notification
                WHERE recipient_id = %s AND object_id = %s
                  AND kind = 'APPROVAL_DECIDED'""", (admin_id, rid)).fetchone()
        assert told is not None, "the proposer was not told"
        assert told[0] == "GREEN" and told[1] is None
        assert "NOTE-NOT-QUOTED" not in told[3]
        assert "Administration, Two-person controls" in told[3]
        a = _apply(client, admin, rid)
        assert a.status_code == 200, a.text
        first_change = a.json()["change"]["id"]
        assert a.json()["approval"]["state"] == "CONSUMED"
        over = client.get(f"{API}/admin/dual-control", headers=admin).json()
        merge = next(o for o in over["operations"] if o["key"] == "node.merge")
        assert merge["mode"] == "ALWAYS" and merge["change_id"] == first_change

        # And back, the same way; the second change names the first.
        back, _ = _two_person(client, admin, officer,
                              {"change": "OPERATION_MODE",
                               "operation": "node.merge", "to": "PER_CASE"})
        assert back["payload"]["based_on"] == first_change
        assert merge_mode(conn) == "PER_CASE"
        history = client.get(f"{API}/admin/dual-control/history",
                             headers=officer).json()["changes"]
        mine = [h for h in history if h["proposer_name"] == "Dch Admin"]
        assert [h["to"] for h in mine[:2]] == ["PER_CASE", "ALWAYS"]
        assert all("Dch Officer" == h["countersigner_name"] for h in mine[:2])
    finally:
        _restore_per_case(conn, client, admin, officer)


def test_pairs_are_added_and_removed_through_the_flow(conn, client):
    admin_id = user(conn, "SYS_ADMIN")
    officer_id = user(conn, "SECURITY_OFFICER")
    admin, officer = session(conn, admin_id), session(conn, officer_id)
    a, b = throwaway_pair(conn, PREFIX)
    before = conn.execute("SELECT count(*) FROM iam.separated_duty").fetchone()[0]
    added, _ = _two_person(client, admin, officer, {
        "change": "SEPARATED_DUTY_ADD", "permission_a": b, "permission_b": a,
        "why": "held apart for this route test"})
    assert (added["payload"]["permission_a"],
            added["payload"]["permission_b"]) == (a, b), "not stored sorted"
    pairs = client.get(f"{API}/admin/dual-control", headers=admin
                       ).json()["separated_duties"]
    pair = next(p for p in pairs if p["permission_a"] == a)
    assert pair["origin"] == "policy" and pair["countersigner_name"]
    _two_person(client, admin, officer, {
        "change": "SEPARATED_DUTY_REMOVE", "permission_a": a,
        "permission_b": b})
    assert conn.execute("SELECT count(*) FROM iam.separated_duty"
                        ).fetchone()[0] == before


def test_a_stale_apply_is_refused_audited_and_keeps_its_signature(conn, client):
    admin_id = user(conn, "SYS_ADMIN")
    officer_id = user(conn, "SECURITY_OFFICER")
    admin, officer = session(conn, admin_id), session(conn, officer_id)
    a, b = throwaway_pair(conn, PREFIX)
    change = {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
              "permission_b": b, "why": "held apart for this route test"}
    twins = []
    for _ in range(2):
        r = _propose(client, admin, change)
        assert r.status_code == 201, r.text
        assert _decide(client, officer, r.json()["id"]).status_code == 200
        twins.append(r.json()["id"])
    try:
        assert _apply(client, admin, twins[0]).status_code == 200
        stale = _apply(client, admin, twins[1])
        assert stale.status_code == 409, stale.text
        assert "changed after this was countersigned" in stale.json()["detail"]
        listed = client.get(f"{API}/approvals", params={"state": "APPROVED"},
                            headers=admin).json()["approvals"]
        row = next(x for x in listed if x["id"] == twins[1])
        assert row["stale"] is True, "the card would still offer Apply"
        assert conn.execute("SELECT state FROM core.approval_request "
                            "WHERE id = %s", (twins[1],)).fetchone()[0] == "APPROVED"
        refused = conn.execute(
            """SELECT outcome FROM audit.event
                WHERE action = 'DUAL_CONTROL_APPLY_REFUSED'
                  AND object_id = %s""", (twins[1],)).fetchone()
        assert refused is not None and refused[0] == "DENIED"
    finally:
        _two_person(client, admin, officer, {
            "change": "SEPARATED_DUTY_REMOVE", "permission_a": a,
            "permission_b": b})


# ---------------------------------------------------------------------------
# Who each route lets in
# ---------------------------------------------------------------------------

def test_a_stale_sign_in_is_told_to_re_authenticate(conn, client):
    """The console's withStepUp recognises the global gate's words, so a
    stale countersigner is asked to sign in rather than told nothing."""
    admin_id = user(conn, "SYS_ADMIN")
    officer_id = user(conn, "SECURITY_OFFICER")
    r = _propose(client, session(conn, admin_id),
                 {"change": "OPERATION_MODE", "operation": "node.merge",
                  "to": "ALWAYS"})
    assert r.status_code == 201, r.text
    stale = session(conn, officer_id, fresh=False)
    for answer in (
            _decide(client, stale, r.json()["id"]),
            client.get(f"{API}/admin/dual-control", headers=stale),
            client.get(f"{API}/approvals", headers=stale)):
        assert answer.status_code == 403, answer.text
        assert re.search("re-authenticat", answer.json()["detail"])
    withdrawn = client.post(f"{API}/approvals/{r.json()['id']}/withdraw",
                            headers=session(conn, admin_id))
    assert withdrawn.status_code == 200, withdrawn.text


def test_an_officer_cannot_propose_or_apply(conn, client):
    officer = session(conn, user(conn, "SECURITY_OFFICER"))
    r = _propose(client, officer, {"change": "OPERATION_MODE",
                                   "operation": "node.merge", "to": "ALWAYS"})
    assert r.status_code == 403
    assert r.json()["detail"] == "missing global permission dual_control.manage"
    r = _apply(client, officer, uuid4())
    assert r.status_code == 403
    assert r.json()["detail"] == "missing global permission dual_control.manage"


def test_an_administrator_cannot_countersign(conn, client):
    admin_id = user(conn, "SYS_ADMIN")
    other = session(conn, user(conn, "SYS_ADMIN"))
    user(conn, "SECURITY_OFFICER")
    both_id = user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
    r = _propose(client, session(conn, admin_id),
                 {"change": "OPERATION_MODE", "operation": "node.merge",
                  "to": "ALWAYS"})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    try:
        d = _decide(client, other, rid)
        assert d.status_code == 403
        assert d.json()["detail"] == ("missing global permission "
                                      "dual_control.countersign")
        # One account holding both roles is one person.
        both = session(conn, both_id)
        d = _decide(client, both, rid)
        assert d.status_code == 409 and "same person twice" in d.json()["detail"]
        own = _propose(client, both, {"change": "OPERATION_MODE",
                                      "operation": "node.merge",
                                      "to": "ALWAYS"}, justification="mine")
        # The identical pending request refuses the second copy; a pending
        # request of its own is what the both-roles account would sign.
        assert own.status_code == 409
        view = client.get(f"{API}/admin/dual-control", headers=both).json()
        assert view["you"]["may_propose"] is True
        assert view["you"]["may_countersign"] is False
    finally:
        client.post(f"{API}/approvals/{rid}/withdraw",
                    headers=session(conn, admin_id))


def test_an_account_holding_both_roles_cannot_countersign_its_own_request(
        conn, client):
    both_id = user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
    user(conn, "SECURITY_OFFICER")
    both = session(conn, both_id)
    r = _propose(client, both, {"change": "OPERATION_MODE",
                                "operation": "node.merge", "to": "ALWAYS"})
    assert r.status_code == 201, r.text
    d = _decide(client, both, r.json()["id"])
    assert d.status_code == 409, d.text
    assert "two distinct humans" in d.json()["detail"]
    assert client.post(f"{API}/approvals/{r.json()['id']}/withdraw",
                       headers=both).status_code == 200


def test_an_analyst_is_refused_everywhere_and_sees_no_global_request(conn, client):
    admin_id = user(conn, "SYS_ADMIN")
    user(conn, "SECURITY_OFFICER")
    analyst = session(conn, user(conn, "ANALYST"))
    r = _propose(client, session(conn, admin_id),
                 {"change": "OPERATION_MODE", "operation": "node.merge",
                  "to": "ALWAYS"})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    try:
        for answer in (
                client.get(f"{API}/approvals", headers=analyst),
                client.get(f"{API}/admin/dual-control", headers=analyst),
                client.get(f"{API}/admin/dual-control/history", headers=analyst),
                _decide(client, analyst, rid),
                _decide(client, analyst, uuid4()),
                client.post(f"{API}/approvals/{rid}/withdraw", headers=analyst),
                _propose(client, analyst, {"change": "OPERATION_MODE",
                                           "operation": "node.merge",
                                           "to": "ALWAYS"})):
            assert answer.status_code == 403, answer.text
            assert "missing global permission" in answer.json()["detail"]
        access = client.get(f"{API}/admin/access", headers=analyst).json()
        assert access["dual_control_awaiting"] == 0
    finally:
        client.post(f"{API}/approvals/{rid}/withdraw",
                    headers=session(conn, admin_id))


def test_a_case_request_cannot_be_decided_or_withdrawn_through_the_global_routes(
        conn, client):
    lead_id = user(conn, "CASE_OWNER")
    officer = session(conn, user(conn, "SECURITY_OFFICER"))
    admin = session(conn, user(conn, "SYS_ADMIN"))
    case_id = _case(conn, lead_id)
    from noctornal_api.approvals import ApprovalService
    req = ApprovalService(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(uuid4()), "target_node_id": str(uuid4())},
        justification="case scoped", requested_by=lead_id)
    assert _decide(client, officer, req.id).status_code == 404
    assert client.post(f"{API}/approvals/{req.id}/withdraw",
                       headers=admin).status_code == 404
    assert client.post(f"{API}/approvals/{req.id}/withdraw",
                       headers=session(conn, lead_id)).status_code == 403
    assert ApprovalService(conn).get(req.id).state == "PENDING"


def test_a_case_withdraw_is_bound_to_its_path_case(conn, client):
    """case.read on case A no longer withdraws a request raised in case B
    (2026-09-24)."""
    lead_id = user(conn, "CASE_OWNER", "ANALYST")
    lead = session(conn, lead_id)
    case_a, case_b = _case(conn, lead_id), _case(conn, lead_id)
    from noctornal_api.approvals import ApprovalService
    req = ApprovalService(conn).request(
        operation="node.merge", case_id=case_b,
        payload={"source_node_id": str(uuid4()), "target_node_id": str(uuid4())},
        justification="raised in b", requested_by=lead_id)
    through_a = client.post(f"{API}/cases/{case_a}/approvals/{req.id}/withdraw",
                            headers=lead)
    assert through_a.status_code == 404, through_a.text
    assert ApprovalService(conn).get(req.id).state == "PENDING"
    through_b = client.post(f"{API}/cases/{case_b}/approvals/{req.id}/withdraw",
                            headers=lead)
    assert through_b.status_code == 200, through_b.text


def test_a_global_operation_cannot_be_raised_in_a_case(conn, client):
    lead_id = user(conn, "CASE_OWNER", "SYS_ADMIN")
    lead = session(conn, lead_id)
    case_id = _case(conn, lead_id)
    for op in ("dual_control.policy", "role.manage", "collection_account.reveal"):
        r = client.post(f"{API}/cases/{case_id}/approvals", headers=lead,
                        json={"operation": op, "payload": {},
                              "justification": "wrong place"})
        assert r.status_code == 400, r.text
        assert "deployment-wide" in r.json()["detail"]
    listed = client.get(f"{API}/cases/{case_id}/approvals", headers=lead).json()
    from noctornal_api.approvals import OPERATIONS
    assert set(listed["operations"]) == {
        k for k, v in OPERATIONS.items() if v.scope == "case"}
    assert "dual_control.policy" not in listed["operations"]


# ---------------------------------------------------------------------------
# The seven-day rule, over the routes
# ---------------------------------------------------------------------------

def test_a_countersignature_after_a_password_reset_is_refused_and_audited(
        conn, client):
    admin_id = user(conn, "SYS_ADMIN")
    resetter_id = user(conn, "SYS_ADMIN", name="Dch Resetter")
    officer_id = user(conn, "SECURITY_OFFICER")
    user(conn, "SECURITY_OFFICER")
    reset = client.post(f"{API}/admin/users/{officer_id}/password",
                        headers=session(conn, resetter_id))
    assert reset.status_code == 200, reset.text
    # The reset signed the officer out everywhere: a new session.
    officer = session(conn, officer_id)
    r = _propose(client, session(conn, admin_id),
                 {"change": "OPERATION_MODE", "operation": "node.merge",
                  "to": "ALWAYS"})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    try:
        d = _decide(client, officer, rid)
        assert d.status_code == 409, d.text
        said = d.json()["detail"]
        assert said.startswith("You may countersign this from ")
        assert "Dch Resetter reset your password on " in said
        assert said.count(" UTC") == 2, said
        refused = conn.execute(
            """SELECT outcome, detail->>'event_action' FROM audit.event
                WHERE action = 'DUAL_CONTROL_COUNTERSIGN_REFUSED'
                  AND object_id = %s AND actor_id = %s""",
            (rid, officer_id)).fetchone()
        assert refused == ("DENIED", "PASSWORD_RESET")
        listed = client.get(f"{API}/approvals",
                            params={"operation": "dual_control.policy"},
                            headers=officer).json()["approvals"]
        row = next(a for a in listed if a["id"] == rid)
        assert row["countersign"]["allowed"] is False
        assert row["countersign"]["may_refuse"] is True
        assert "Dch Resetter reset your password" in row["countersign"]["reason"]
        # Refusing is never blocked.
        no = _decide(client, officer, rid, approve=False)
        assert no.status_code == 200 and no.json()["state"] == "REJECTED"
    finally:
        client.post(f"{API}/approvals/{rid}/withdraw",
                    headers=session(conn, admin_id))


# ---------------------------------------------------------------------------
# The way in
# ---------------------------------------------------------------------------

def test_admin_access_carries_the_two_person_fields(conn, client):
    admin_id = user(conn, "SYS_ADMIN")
    officer_id = user(conn, "SECURITY_OFFICER")
    admin, officer = session(conn, admin_id), session(conn, officer_id)
    got = client.get(f"{API}/admin/access", headers=admin).json()
    assert (got["dual_control_manage"], got["dual_control_countersign"],
            got["dual_control_awaiting"]) == (True, False, 0)
    before = client.get(f"{API}/admin/access", headers=officer
                        ).json()["dual_control_awaiting"]
    r = _propose(client, admin, {"change": "OPERATION_MODE",
                                 "operation": "node.merge", "to": "ALWAYS"})
    assert r.status_code == 201, r.text
    try:
        got = client.get(f"{API}/admin/access", headers=officer).json()
        assert got["dual_control_countersign"] is True
        assert got["dual_control_manage"] is False
        assert got["dual_control_awaiting"] == before + 1
        assert client.get(f"{API}/admin/access", headers=admin
                          ).json()["dual_control_awaiting"] == 0
    finally:
        client.post(f"{API}/approvals/{r.json()['id']}/withdraw", headers=admin)
    assert client.get(f"{API}/admin/access", headers=officer
                      ).json()["dual_control_awaiting"] == before
