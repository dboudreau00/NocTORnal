"""A refusal is stored as one (docs/17, "refusals are recorded as SUCCESS").

`deps.audit_auth_event` wrote AUTHZ_DENIED, AUTH_SESSION_REJECTED,
RLS_BINDING_FAILED, SESSION_BINDING_REFUSED and CASE_SHARE_REFUSED with the
column's default outcome, SUCCESS, while the sign-in, rate-limit and
row-security refusals were stored DENIED. A reader that filtered the log on
outcome found some of the refusals and missed these. They are DENIED now,
whichever gate refused, and the two readers of the column keep working: the
officer's listing returns the stored value and the chain verifier recomputes
each row from it.

Rows written before then keep SUCCESS (the log is append-only), so an
officer looks for those by action.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

CLAIM = g.CLAIM

#: Every action `audit_auth_event` writes.
AUTH_EVENT_ACTIONS = ("AUTHZ_DENIED", "AUTH_SESSION_REJECTED", "RLS_BINDING_FAILED",
                      "SESSION_BINDING_REFUSED", "CASE_SHARE_REFUSED")


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _rows(owner, actor, action="AUTHZ_DENIED"):
    """(seq, outcome, scope, failed_checks) of the actor's rows, oldest first."""
    return owner.execute(
        """SELECT seq, outcome, detail->>'scope', detail->'failed_checks'
             FROM audit.event WHERE actor_id = %s AND action = %s ORDER BY seq""",
        (actor, action)).fetchall()


def test_a_refusal_at_the_case_gate_is_stored_denied(owner, client):
    w = g.World(owner)
    r = client.post(w.url("/nodes"), headers=w.headers(w.reader), json={
        "node_type": "IDENTITY", "label": "g78 nope", "assertion": CLAIM})
    assert r.status_code == 403, r.text
    [(_, outcome, scope, failed)] = _rows(owner, w.reader)
    assert outcome == "DENIED"
    assert scope is None and "case_assignment_unexpired" not in (failed or [])


def test_a_refusal_at_the_global_gate_is_stored_denied(owner, client):
    w = g.World(owner)
    r = client.get("/api/v1/audit/events", headers=w.headers(w.analyst))
    assert r.status_code == 403, r.text
    [(_, outcome, scope, _)] = _rows(owner, w.analyst)
    assert (outcome, scope) == ("DENIED", "global")


def test_a_stale_sign_in_refused_by_the_gate_is_stored_denied(owner, client):
    """The case gate's step-up leg, and a route's own."""
    w = g.World(owner)
    _, raw = s.session(owner, w.boss, mfa=False)
    stale = {"Authorization": f"Bearer {raw}"}
    r = client.post(w.url("/users"), headers=stale,
                    json={"user_id": str(w.reader), "role_key": "READ_ONLY"})
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    [(_, outcome, _, failed)] = _rows(owner, w.boss)
    assert outcome == "DENIED" and "step_up_freshness" in failed


def test_a_caller_with_no_assignment_is_refused_and_stored_denied(owner, client):
    """The 404 that hides the case still leaves its row, and the row is a
    refusal."""
    w = g.World(owner)
    outsider = s.user(owner, "AMBER", prefix=g.PREFIX)
    _, raw = s.session(owner, outsider)
    r = client.get(w.url("/graph/nodes/count"),
                   headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 404, r.text
    [(_, outcome, _, failed)] = _rows(owner, outsider)
    assert outcome == "DENIED" and "case_assignment_unexpired" in failed


def test_every_row_audit_auth_event_writes_is_stored_denied(owner):
    from noctornal_api.http.deps import audit_auth_event
    w = g.World(owner)
    for action in AUTH_EVENT_ACTIONS:
        audit_auth_event(owner, action, w.analyst, w.case_id, {"probe": action})
    stored = dict(owner.execute(
        """SELECT action, outcome FROM audit.event
            WHERE actor_id = %s AND case_id = %s AND detail ? 'probe'""",
        (w.analyst, w.case_id)).fetchall())
    assert stored == {action: "DENIED" for action in AUTH_EVENT_ACTIONS}


def test_the_sign_in_routers_refusals_are_stored_denied(owner, client):
    """RECOVERY_CODES_DENIED sat beside AUTH_FAILED, which was already DENIED."""
    w = g.World(owner)
    _, raw = s.session(owner, w.analyst, mfa=False)
    r = client.post("/api/v1/auth/recovery-codes",
                    headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 403, r.text
    assert [row[1] for row in _rows(owner, w.analyst, "RECOVERY_CODES_DENIED")] == [
        "DENIED"]


def test_the_officers_listing_returns_the_stored_outcome(owner, client):
    w = g.World(owner)
    officer = s.user(owner, "AMBER", prefix=g.PREFIX)
    s.grant_global(owner, officer, "SECURITY_OFFICER")
    for _ in range(2):
        assert client.post(w.url("/nodes"), headers=w.headers(w.reader), json={
            "node_type": "IDENTITY", "label": "g78 nope",
            "assertion": CLAIM}).status_code == 403

    r = client.get("/api/v1/audit/events", headers=w.headers(officer),
                   params={"action": "AUTHZ_DENIED", "actor_id": str(w.reader)})
    assert r.status_code == 200, r.text
    events = r.json()["events"]
    assert len(events) == 2
    assert {e["outcome"] for e in events} == {"DENIED"}
    assert {e["action"] for e in events} == {"AUTHZ_DENIED"}


def test_the_chain_still_verifies_the_rows_it_now_stores_denied(owner, client):
    from noctornal_api.audit_verify import verify_chain
    w = g.World(owner)
    assert client.post(w.url("/nodes"), headers=w.headers(w.reader), json={
        "node_type": "IDENTITY", "label": "g78 nope",
        "assertion": CLAIM}).status_code == 403
    mine = {row[0] for row in _rows(owner, w.reader)}
    assert len(mine) == 1
    report = verify_chain(owner, limit=200)
    assert report.checked >= 1
    assert not [b for b in report.breaks if b.seq in mine], report.breaks


def test_a_refused_share_by_address_is_stored_denied(owner, client):
    """CASE_SHARE_REFUSED goes through the same writer: an address that names
    no active account is refused, recorded, and the record is a refusal."""
    w = g.World(owner)
    ghost = f"nobody-{uuid4().hex[:8]}@example.org"
    r = client.post(w.url("/users"), headers=w.headers(w.boss),
                    json={"email": ghost, "role_key": "READ_ONLY"})
    assert r.status_code == 404, r.text
    [(_, outcome, _, _)] = _rows(owner, w.boss, "CASE_SHARE_REFUSED")
    assert outcome == "DENIED"
