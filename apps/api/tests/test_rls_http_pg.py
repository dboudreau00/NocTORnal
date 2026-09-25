"""Routes that row-level security must not break, in production's shape
(S1, 2026-09-25).

NOCTORNAL_TEST_ASSUME_ROLE makes every request connection SET ROLE to the
request role (bound by the session) and every system connection SET ROLE
to the system role, while the fixtures seed as the owner. Each test is one
such case, answered through the real route:

- case-scoped break-glass: an AMBER analyst assigned to a RED case invokes
  a RED grant on it and is told the case's code (the invoke's assignment
  check can no longer read core."case" for a case above the caller);
- node retirement over a tie above the caller is refused, not half-done;
- a legal hold on an exhibit above the officer is placed;
- a session with no row-security binding is refused and audited.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import rls_support as s

pytestmark = s.GATED

WHY = "A row security emergency long enough to be a justification."


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    s.cleanup(c)
    c.close()


@pytest.fixture
def client():
    from noctornal_api.http.app import app
    return TestClient(app)


def _auth(conn, uid) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}


def test_an_amber_analyst_invokes_a_case_scoped_red_grant_on_their_red_case(owner, client):
    boss = s.user(owner, "RED")
    analyst = s.user(owner, "AMBER")
    s.grant_global(owner, analyst, "CASE_OWNER")
    # Break-glass refuses while no active Security Officer could review it.
    officer = s.user(owner, "RED")
    s.grant_global(owner, officer, "SECURITY_OFFICER")
    red_case = s.case(owner, boss, "RED")
    s.assign(owner, red_case, analyst)
    code = owner.execute('SELECT code FROM core."case" WHERE id = %s',
                         (red_case,)).fetchone()[0]
    r = client.post("/api/v1/break-glass", headers=_auth(owner, analyst),
                    json={"justification": WHY, "duration_hours": 1,
                          "case_id": str(red_case), "classification": "RED"})
    assert r.status_code == 201, r.text
    assert r.json()["case_code"] == code
    owner.execute("UPDATE iam.break_glass SET revoked_at = now() WHERE user_id = %s",
                  (analyst,))


def test_retiring_a_node_with_a_tie_above_the_caller_is_refused(owner, client):
    boss = s.user(owner, "RED")
    analyst = s.user(owner, "AMBER")
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst, "CASE_OWNER")
    hub = s.node(owner, case_id, boss, "hub")
    secret = s.node(owner, case_id, boss, "secret", "RED")
    s.edge(owner, case_id, boss, hub, secret, "RED")
    r = client.request("DELETE", f"/api/v1/cases/{case_id}/graph/nodes/{hub}",
                       headers=_auth(owner, analyst), json={"reason": "retire"})
    assert r.status_code in (400, 409), r.text
    assert "above your clearance" in r.text
    assert owner.execute("SELECT deleted_at IS NULL FROM core.node WHERE id = %s",
                         (hub,)).fetchone()[0]


def test_a_legal_hold_reaches_an_exhibit_above_the_officer(owner, client):
    boss = s.user(owner, "RED")
    officer = s.user(owner, "AMBER")
    s.grant_global(owner, officer, "CASE_OWNER")
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, officer, "CASE_OWNER")
    exhibit = s.exhibit(owner, case_id, boss, "RED")
    held = False
    try:
        r = client.post("/api/v1/retention/legal-hold", headers=_auth(owner, officer),
                        json={"evidence_id": str(exhibit), "on": True,
                              "reason": "preservation order 12"})
        if r.status_code == 403 and "missing" in r.text:
            pytest.fail(f"the fixture's officer lacks retention.manage: {r.text}")
        assert r.status_code == 200, r.text
        held = owner.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                             (exhibit,)).fetchone()[0]
        assert held is True
    finally:
        if held:
            owner.execute("UPDATE core.evidence SET legal_hold = false, "
                          "legal_hold_reason = NULL WHERE id = %s", (exhibit,))


def test_a_session_that_cannot_be_bound_is_refused_and_audited(owner, client):
    uid = s.user(owner, "AMBER")
    sid, raw = s.session(owner, uid)
    owner.execute("UPDATE iam.session SET rls_binding_hash = NULL WHERE id = %s", (sid,))
    r = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 401
    row = owner.execute(
        """SELECT detail->>'reason' FROM audit.event
            WHERE action = 'RLS_BINDING_FAILED' AND detail->>'session_id' = %s""",
        (str(sid),)).fetchone()
    assert row == ("unbound",)


def test_a_bound_session_lists_its_cases_as_the_request_role(owner, client):
    boss = s.user(owner, "RED")
    analyst = s.user(owner, "AMBER")
    mine = s.case(owner, boss)
    s.case(owner, boss)
    s.assign(owner, mine, analyst)
    r = client.get("/api/v1/cases", headers=_auth(owner, analyst))
    assert r.status_code == 200, r.text
    assert [c["id"] for c in r.json()] == [str(mine)]
