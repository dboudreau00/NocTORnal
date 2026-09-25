"""Turning a case's merge requirement off takes a second Lead investigator,
bound to the switch as it stands (F9b, 2026-09-24; migration
case_merge_relax_two_people).

The switch (`core.case.dual_control_merge`, 0028) was one signature in both
directions. Now the database refuses true to false unless a
`case.policy.relax` approval for this case and this epoch of the switch was
consumed in the same transaction, and the epoch moves by one with every
change of the switch, so an approval cannot be banked across an off and on
again. Turning it on stays one signature.

Database tests run on the autocommit fixture, inside rolled-back
transactions where a change succeeds, and with two real transactions where
the point is "consumed EARLIER". HTTP tests drive `PUT /cases/{id}/policy`
and the case approvals routes. The one test that needs node.merge ALWAYS
sets it with the owner-level helper of the policy file and restores it in
a `finally`. Email prefix `cmr-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from test_dual_control_policy_pg import force_mode, merge_mode, teardown
from test_dual_control_policy_pg import user as _user

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the switch is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
PREFIX = "cmr-"
API = "/api/v1"
RELAX = "case.policy.relax"


class _RollBack(Exception):
    pass


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
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def user(conn, *roles, **kw):
    return _user(conn, *roles, prefix=PREFIX, **kw)


def session(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(conn, lead, deputy=None):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-CMR-{uuid4().hex[:6]}", title="Merge switch",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=lead, created_by=lead,
        deputy_user_id=deputy)


def _switch(conn, case_id) -> tuple[bool, int]:
    row = conn.execute('SELECT dual_control_merge, dual_control_merge_epoch '
                       'FROM core."case" WHERE id = %s', (case_id,)).fetchone()
    return bool(row[0]), int(row[1])


def _on(conn, case_id) -> None:
    conn.execute('UPDATE core."case" SET dual_control_merge = true '
                 'WHERE id = %s', (case_id,))


def _approved_relax(conn, case_id, lead, deputy):
    from noctornal_api.approvals import ApprovalService, relax_payload
    svc = ApprovalService(conn)
    req = svc.request(operation=RELAX, case_id=case_id,
                      payload=relax_payload(_switch(conn, case_id)[1]),
                      justification="no longer contested", requested_by=lead)
    return svc.decide(req.id, decided_by=deputy, approve=True)


def _relax(conn, req, case_id, lead) -> None:
    """Consume and switch off in one transaction, as set_policy does."""
    from noctornal_api.approvals import ApprovalService
    with conn.transaction():
        ApprovalService(conn).consume(req.id, actor_id=lead, operation=RELAX,
                                      case_id=case_id, payload=req.payload)
        conn.execute('UPDATE core."case" SET dual_control_merge = false '
                     'WHERE id = %s', (case_id,))


# ---------------------------------------------------------------------------
# The database
# ---------------------------------------------------------------------------

def test_a_direct_update_to_false_is_refused_by_the_database(conn):
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    _on(conn, case_id)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="requires a second signature on merges"):
        conn.execute('UPDATE core."case" SET dual_control_merge = false '
                     'WHERE id = %s', (case_id,))
    assert _switch(conn, case_id)[0] is True


def test_turning_on_is_never_refused_and_moves_the_epoch(conn):
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    assert _switch(conn, case_id) == (False, 0)
    _on(conn, case_id)
    assert _switch(conn, case_id) == (True, 1)
    # A no-op write of the same value is not a change and moves nothing.
    _on(conn, case_id)
    assert _switch(conn, case_id) == (True, 1)


def test_the_epoch_moves_only_with_the_switch(conn):
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    for epoch in (0, 7):
        with pytest.raises(psycopg.errors.RaiseException,
                           match="moves only with the merge switch"):
            conn.execute('UPDATE core."case" SET dual_control_merge_epoch = %s + 1 '
                         'WHERE id = %s', (epoch, case_id))
    # Every other update of the case is untouched by the guard.
    conn.execute('UPDATE core."case" SET title = %s WHERE id = %s',
                 ("Merge switch renamed", case_id))
    assert _switch(conn, case_id) == (False, 0)


def test_a_relax_approval_consumed_in_the_same_transaction_turns_it_off(conn):
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    _on(conn, case_id)
    with pytest.raises(_RollBack), conn.transaction():
        req = _approved_relax(conn, case_id, lead, deputy)
        _relax(conn, req, case_id, lead)
        assert _switch(conn, case_id) == (False, 2)
        raise _RollBack


def test_an_approval_consumed_in_an_earlier_transaction_does_not_relax(conn):
    """Two real transactions on the autocommit connection: the consume
    commits, and the UPDATE in the next one is refused."""
    from noctornal_api.approvals import ApprovalService
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    _on(conn, case_id)
    req = _approved_relax(conn, case_id, lead, deputy)
    ApprovalService(conn).consume(req.id, actor_id=lead, operation=RELAX,
                                  case_id=case_id, payload=req.payload)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="consumed in the same transaction"):
        with conn.transaction():
            conn.execute('UPDATE core."case" SET dual_control_merge = false '
                         'WHERE id = %s', (case_id,))
    assert _switch(conn, case_id) == (True, 1)


def test_a_relax_approval_banked_across_an_off_on_cycle_is_refused(conn):
    """An A-B-A for the switch: R1 approved and kept, its
    twin R2 applied, the switch turned on again, and R1 spent last. The
    epoch refuses it: it was raised for a state of the switch that is gone."""
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    _on(conn, case_id)
    with pytest.raises(_RollBack), conn.transaction():
        banked = _approved_relax(conn, case_id, lead, deputy)
        twin = _approved_relax(conn, case_id, lead, deputy)
        assert banked.payload == twin.payload
        _relax(conn, twin, case_id, lead)
        _on(conn, case_id)
        assert _switch(conn, case_id) == (True, 3)
        with pytest.raises(psycopg.errors.RaiseException,
                           match="for the switch as it stands"):
            _relax(conn, banked, case_id, lead)
        assert _switch(conn, case_id) == (True, 3)
        raise _RollBack


def test_a_relax_approval_from_another_case_does_not_relax(conn):
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_a, case_b = _case(conn, lead, deputy), _case(conn, lead, deputy)
    _on(conn, case_a)
    _on(conn, case_b)
    from noctornal_api.approvals import ApprovalService
    with pytest.raises(_RollBack), conn.transaction():
        req = _approved_relax(conn, case_a, lead, deputy)
        with pytest.raises(psycopg.errors.RaiseException,
                           match="requires a second signature"), \
                conn.transaction():
            ApprovalService(conn).consume(req.id, actor_id=lead, operation=RELAX,
                                          case_id=case_a, payload=req.payload)
            conn.execute('UPDATE core."case" SET dual_control_merge = false '
                         'WHERE id = %s', (case_b,))
        raise _RollBack


def _migration():
    path = next(VERSIONS.glob("*_case_merge_relax_two_people.py"))
    spec = importlib.util.spec_from_file_location("m_cmr", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_migration_round_trips(conn):
    m = _migration()
    m.run = lambda sql: conn.execute(sql)
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    _on(conn, case_id)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        assert conn.execute(
            "SELECT count(*) FROM information_schema.columns WHERE table_schema "
            "= 'core' AND table_name = 'case' AND column_name = "
            "'dual_control_merge_epoch'").fetchone()[0] == 0
        # The previous release's one signature, with its code.
        conn.execute('UPDATE core."case" SET dual_control_merge = false '
                     'WHERE id = %s', (case_id,))
        conn.execute('UPDATE core."case" SET dual_control_merge = true '
                     'WHERE id = %s', (case_id,))
        m.upgrade()
        with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
            conn.execute('UPDATE core."case" SET dual_control_merge = false '
                         'WHERE id = %s', (case_id,))
        raise _RollBack


# ---------------------------------------------------------------------------
# Over HTTP
# ---------------------------------------------------------------------------

def _raise_relax(client, who, case_id, epoch, justification="no longer contested"):
    return client.post(f"{API}/cases/{case_id}/approvals", headers=who, json={
        "operation": RELAX,
        "payload": {"setting": "dual_control_merge", "from": True, "to": False,
                    "epoch": epoch},
        "justification": justification})


def _put(client, who, case_id, **body):
    return client.put(f"{API}/cases/{case_id}/policy", headers=who, json=body)


def test_turning_merge_control_off_takes_a_second_lead(conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead, deputy = session(conn, lead_id), session(conn, deputy_id)
    assert _put(client, lead, case_id, dual_control_merge=True).status_code == 200
    epoch = client.get(f"{API}/cases/{case_id}/policy", headers=lead
                       ).json()["dual_control_merge_epoch"]
    raised = _raise_relax(client, lead, case_id, epoch)
    assert raised.status_code == 201, raised.text
    assert raised.json()["approvers_notified"] == 1
    rid = raised.json()["id"]
    decided = client.post(f"{API}/cases/{case_id}/approvals/{rid}/decide",
                          headers=deputy, json={"approve": True})
    assert decided.status_code == 200, decided.text
    off = _put(client, lead, case_id, dual_control_merge=False,
               approval_request_id=rid)
    assert off.status_code == 200, off.text
    assert off.json()["dual_control_merge"] is False
    assert off.json()["dual_control_merge_epoch"] == epoch + 1
    detail = conn.execute(
        """SELECT detail FROM audit.event WHERE case_id = %s
              AND action = 'CASE_POLICY_CHANGED' ORDER BY seq DESC LIMIT 1""",
        (case_id,)).fetchone()[0]
    assert detail == {"setting": "dual_control_merge", "from": True, "to": False,
                      "epoch": epoch, "approval_request_id": rid,
                      "approved_by": str(deputy_id)}
    row = conn.execute("SELECT state, result_ref FROM core.approval_request "
                       "WHERE id = %s", (rid,)).fetchone()
    assert row == ("CONSUMED", case_id)
    # Spent: the same approval does not turn it off a second time.
    assert _put(client, lead, case_id, dual_control_merge=True).status_code == 200
    again = _put(client, lead, case_id, dual_control_merge=False,
                 approval_request_id=rid)
    assert again.status_code == 409, again.text


def test_turning_it_off_without_an_approval_is_refused(conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead = session(conn, lead_id)
    assert _put(client, lead, case_id, dual_control_merge=True).status_code == 200
    r = _put(client, lead, case_id, dual_control_merge=False)
    assert r.status_code == 409, r.text
    assert r.json()["title"] == "Approval required"
    assert "second Lead investigator" in r.json()["detail"]
    assert _switch(conn, case_id)[0] is True


def test_the_requester_cannot_approve_their_own_relax(conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead = session(conn, lead_id)
    _on(conn, case_id)
    raised = _raise_relax(client, lead, case_id, _switch(conn, case_id)[1])
    assert raised.status_code == 201, raised.text
    own = client.post(
        f"{API}/cases/{case_id}/approvals/{raised.json()['id']}/decide",
        headers=lead, json={"approve": True})
    assert own.status_code == 409 and "two distinct humans" in own.json()["detail"]


def test_a_relax_request_carries_exactly_the_switch_as_it_stands(conn, client):
    """Hostile payloads: anything but the one shape is a 400 before a
    request exists; a switch that is off, or an epoch that moved, is a 409."""
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead = session(conn, lead_id)
    off = _raise_relax(client, lead, case_id, 0)
    assert off.status_code == 409
    assert off.json()["detail"] == "Merges in this case take one signature already."
    _on(conn, case_id)
    for payload in (
            {}, {"setting": "dual_control_merge"},
            {"setting": "dual_control_merge", "from": True, "to": False,
             "epoch": True},
            {"setting": "dual_control_merge", "from": True, "to": False,
             "epoch": "1"},
            {"setting": "dual_control_merge", "from": True, "to": False,
             "epoch": 1.0},
            {"setting": "withheld_disclosure", "from": True, "to": False,
             "epoch": 1},
            {"setting": "dual_control_merge", "from": 1, "to": 0, "epoch": 1},
            {"setting": "dual_control_merge", "from": True, "to": False,
             "epoch": 1, "extra": "<script>"},
            ["dual_control_merge"]):
        r = client.post(f"{API}/cases/{case_id}/approvals", headers=lead,
                        json={"operation": RELAX, "payload": payload,
                              "justification": "hostile"})
        assert r.status_code in (400, 422), (payload, r.text)
    moved = _raise_relax(client, lead, case_id, 0)
    assert moved.status_code == 409
    assert "changed after this was prepared" in moved.json()["detail"]
    assert conn.execute("SELECT count(*) FROM core.approval_request WHERE "
                        "case_id = %s", (case_id,)).fetchone()[0] == 0


def test_a_case_cannot_turn_off_what_the_deployment_requires(conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead = session(conn, lead_id)
    _on(conn, case_id)
    epoch = _switch(conn, case_id)[1]
    force_mode(conn, "ALWAYS")
    try:
        raised = _raise_relax(client, lead, case_id, epoch)
        assert raised.status_code == 409
        assert "Every merge on this deployment" in raised.json()["detail"]
        put = _put(client, lead, case_id, dual_control_merge=False,
                   approval_request_id=str(uuid4()))
        assert put.status_code == 409
        assert "Every merge on this deployment" in put.json()["detail"]
        read = client.get(f"{API}/cases/{case_id}/policy", headers=lead).json()
        assert read["dual_control_merge_mode"] == "ALWAYS"
        assert read["dual_control_merge_effective"] is True
        # Under ALWAYS a case may still switch itself on: stored, for the
        # day the deployment goes back to PER_CASE.
        other = _case(conn, lead_id)
        on = _put(client, lead, other, dual_control_merge=True)
        assert on.status_code == 200 and on.json()["dual_control_merge"] is True
    finally:
        force_mode(conn, "PER_CASE")
    assert merge_mode(conn) == "PER_CASE"


def test_the_merge_refusal_names_the_deployment_rule_under_always(conn, client):
    lead_id = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead_id)
    lead = session(conn, lead_id)
    per_case = client.post(f"{API}/cases/{case_id}/merges", headers=lead, json={})
    assert per_case.status_code != 409 or "deployment" not in per_case.text
    force_mode(conn, "ALWAYS")
    try:
        r = client.post(f"{API}/cases/{case_id}/merges", headers=lead, json={})
        assert r.status_code == 409, r.text
        assert r.json()["detail"].startswith(
            "this deployment requires a second signature on every merge")
    finally:
        force_mode(conn, "PER_CASE")
    _on(conn, case_id)
    r = client.post(f"{API}/cases/{case_id}/merges", headers=lead, json={})
    assert r.status_code == 409
    assert r.json()["detail"].startswith("this case requires dual control on merges")


def test_turning_it_on_is_still_one_signature(conn, client):
    lead_id = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead_id)
    r = _put(client, session(conn, lead_id), case_id, dual_control_merge=True)
    assert r.status_code == 200, r.text
    assert r.json()["dual_control_merge"] is True
    assert r.json()["dual_control_merge_epoch"] == 1


def test_a_relax_approval_does_not_consume_in_another_case(conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_a = _case(conn, lead_id, deputy_id)
    case_b = _case(conn, lead_id, deputy_id)
    lead, deputy = session(conn, lead_id), session(conn, deputy_id)
    for case_id in (case_a, case_b):
        _on(conn, case_id)
    raised = _raise_relax(client, lead, case_a, _switch(conn, case_a)[1])
    rid = raised.json()["id"]
    assert client.post(f"{API}/cases/{case_a}/approvals/{rid}/decide",
                       headers=deputy, json={"approve": True}).status_code == 200
    r = _put(client, lead, case_b, dual_control_merge=False,
             approval_request_id=rid)
    assert r.status_code == 404, r.text
    assert _switch(conn, case_b)[0] is True
    assert conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                        (rid,)).fetchone()[0] == "APPROVED"


def test_the_policy_read_says_the_mode_and_who_could_approve(conn, client):
    """relax_signers counts other people on the case holding case.update
    whose labels dominate it: a deputy yes, an analyst no, the caller no,
    and a Lead investigator whose clearance sits below the case no."""
    lead_id = user(conn, "CASE_OWNER", clearance="RED")
    deputy_id = user(conn, clearance="RED")
    low_id = user(conn, clearance="AMBER")
    analyst_id = user(conn, clearance="RED")
    from noctornal_api.cases import CaseService
    case_id = CaseService(conn).create(
        code=f"OP-CMR-{uuid4().hex[:6]}", title="Merge switch",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=lead_id, created_by=lead_id,
        classification="RED", deputy_user_id=deputy_id)
    conn.execute("""INSERT INTO iam.case_assignment
                        (case_id, user_id, role_key, granted_by)
                    VALUES (%s, %s, 'CASE_OWNER', %s), (%s, %s, 'ANALYST', %s)""",
                 (case_id, low_id, lead_id, case_id, analyst_id, lead_id))
    got = client.get(f"{API}/cases/{case_id}/policy",
                     headers=session(conn, lead_id)).json()
    assert got["dual_control_merge_mode"] == "PER_CASE"
    assert got["dual_control_merge_effective"] is False
    assert got["dual_control_merge_epoch"] == 0
    assert got["relax_signers"] == 1
