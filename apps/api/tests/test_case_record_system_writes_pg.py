"""A case's record is written on a system connection after the route's gate (SystemPurpose.CASE_RECORD),
and the request role updates no column of a case (0186).

The governance record (`PATCH /cases/{id}`), the lifecycle (`POST /cases/{id}/status`) and the
policy switches (`PUT /cases/{id}/policy`, with a relax approval's spend) are written as the system
role once every refusal the route makes has run on the request's own connection: a system
connection sees the case whatever the caller's labels, so nothing may reach it before the gate has.
The audit row still names the caller. The same columns forged as the request role, bound by a real
session, are refused by the privilege check itself. Run as that role and over HTTP in production's
shape (NOCTORNAL_TEST_ASSUME_ROLE). Account prefix `rlscr-`.
"""
from __future__ import annotations

import importlib.util
from datetime import date
from pathlib import Path

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

P = "rlscr-"
API = "/api/v1"


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, P)
    c.close()


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def purposes(monkeypatch):
    """Every system purpose a request opened a connection for, in order."""
    from noctornal_api import db
    opened: list = []
    real = db.connect_system

    def recording(purpose):
        opened.append(purpose)
        return real(purpose)

    monkeypatch.setattr(db, "connect_system", recording)
    return opened


def _lead_case(owner):
    lead = s.user(owner, prefix=P)
    case_id = s.case(owner, lead)
    _sid, raw = s.session(owner, lead)
    return lead, case_id, {"Authorization": f"Bearer {raw}"}


def _rows(owner, case_id, action):
    return owner.execute(
        "SELECT actor_id, outcome, detail FROM audit.event "
        "WHERE case_id = %s AND action = %s ORDER BY seq", (case_id, action)).fetchall()


def test_a_case_edit_writes_as_the_system_role_and_audits_the_caller(owner, client, purposes):
    from noctornal_api.db import SystemPurpose
    lead, case_id, headers = _lead_case(owner)
    r = client.patch(f"{API}/cases/{case_id}", headers=headers,
                     json={"title": "Edited by its lead", "retention_until": "2031-01-01"})
    assert r.status_code == 200, r.text
    assert r.json()["title"] == "Edited by its lead"
    assert SystemPurpose.CASE_RECORD in purposes
    assert owner.execute('SELECT title, retention_until FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone() == ("Edited by its lead", date(2031, 1, 1))
    (actor, outcome, detail), = _rows(owner, case_id, "CASE_UPDATED")
    assert (actor, outcome) == (lead, "SUCCESS")
    assert detail["changed"]["title"] == "Edited by its lead"
    assert "unverified_actor_id" not in detail


def test_a_status_move_writes_as_the_system_role_and_audits_the_caller(owner, client, purposes):
    from noctornal_api.db import SystemPurpose
    lead, case_id, headers = _lead_case(owner)
    for status in ("ACTIVE", "CLOSED"):
        r = client.post(f"{API}/cases/{case_id}/status", headers=headers, json={"status": status})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == status
    assert purposes.count(SystemPurpose.CASE_RECORD) == 2
    status, closed = owner.execute('SELECT status, closed_at FROM core."case" WHERE id = %s',
                                   (case_id,)).fetchone()
    assert status == "CLOSED" and closed is not None
    moves = _rows(owner, case_id, "CASE_STATUS_CHANGED")
    assert [(m[0], m[1], m[2]["to"]) for m in moves] == [
        (lead, "SUCCESS", "ACTIVE"), (lead, "SUCCESS", "CLOSED")]
    # An illegal move is the service's refusal, on the system connection: nothing is written.
    r = client.post(f"{API}/cases/{case_id}/status", headers=headers, json={"status": "DRAFT"})
    assert r.status_code == 400, r.text
    assert len(_rows(owner, case_id, "CASE_STATUS_CHANGED")) == 2
    # The gate's refusal opens no system connection.
    reader = s.user(owner, prefix=P)
    s.assign(owner, case_id, reader, "READ_ONLY")
    _sid, raw = s.session(owner, reader)
    purposes.clear()
    r = client.post(f"{API}/cases/{case_id}/status",
                    headers={"Authorization": f"Bearer {raw}"}, json={"status": "ARCHIVED"})
    assert r.status_code == 403, r.text
    assert SystemPurpose.CASE_RECORD not in purposes
    assert owner.execute('SELECT status FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone()[0] == "CLOSED"


def _lead_and_deputy(owner):
    from uuid import uuid4

    from noctornal_api.cases import CaseService
    lead, deputy = s.user(owner, prefix=P), s.user(owner, prefix=P)
    case_id = CaseService(owner).create(
        code=f"OP-RLSCR-{uuid4().hex[:8].upper()}", title="Merge switch",
        legal_basis="test authority", retention_until=date(2030, 1, 1),
        review_due=date(2029, 1, 1), owner_user_id=lead, created_by=lead,
        deputy_user_id=deputy)
    # The second person had held case.update on the case for the seasoning window.
    owner.execute("UPDATE iam.case_assignment SET granted_at = now() - interval '8 days' "
                  "WHERE case_id = %s AND user_id = %s", (case_id, deputy))
    _sid, raw = s.session(owner, lead)
    return lead, deputy, case_id, {"Authorization": f"Bearer {raw}"}


def _approved_relax(owner, case_id, lead, deputy, epoch):
    from noctornal_api.approvals import ApprovalService, relax_payload
    svc = ApprovalService(owner)
    req = svc.request(operation="case.policy.relax", case_id=case_id,
                      payload=relax_payload(epoch), justification="no longer contested",
                      requested_by=lead)
    return svc.decide(req.id, decided_by=deputy, approve=True)


def _switch(owner, case_id):
    return owner.execute('SELECT dual_control_merge, dual_control_merge_epoch, '
                         'withheld_disclosure FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone()


def test_a_policy_change_writes_as_the_system_role_and_audits_the_caller(owner, client, purposes):
    from noctornal_api.db import SystemPurpose
    lead, case_id, headers = _lead_case(owner)
    r = client.put(f"{API}/cases/{case_id}/policy", headers=headers,
                   json={"dual_control_merge": True, "withheld_disclosure": "COUNT"})
    assert r.status_code == 200, r.text
    assert r.json()["dual_control_merge"] is True
    assert SystemPurpose.CASE_RECORD in purposes
    switch, epoch, disclosure = _switch(owner, case_id)
    assert (switch, disclosure) == (True, "COUNT") and epoch == 1
    changed = _rows(owner, case_id, "CASE_POLICY_CHANGED")
    assert sorted((c[0], c[1], c[2]["setting"]) for c in changed) == [
        (lead, "SUCCESS", "dual_control_merge"), (lead, "SUCCESS", "withheld_disclosure")]


def test_relaxing_a_cases_merge_switch_spends_its_approval_in_the_writing_transaction(
        owner, client, purposes):
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.db import SystemPurpose
    lead, deputy, case_id, headers = _lead_and_deputy(owner)
    policy = f"{API}/cases/{case_id}/policy"
    assert client.put(policy, headers=headers, json={"dual_control_merge": True}).status_code == 200
    # Raised against the switch as it stood, then banked across an off and on: the database's
    # guard refuses it, and the consume that ran beside the refused UPDATE is rolled back with it.
    stale = _approved_relax(owner, case_id, lead, deputy, epoch=1)
    fresh = _approved_relax(owner, case_id, lead, deputy, epoch=1)
    r = client.put(policy, headers=headers,
                   json={"dual_control_merge": False, "approval_request_id": str(fresh.id)})
    assert r.status_code == 200, r.text
    assert ApprovalService(owner).get(fresh.id).state == "CONSUMED"
    assert _switch(owner, case_id)[:2] == (False, 2)
    assert client.put(policy, headers=headers, json={"dual_control_merge": True}).status_code == 200
    assert _switch(owner, case_id)[:2] == (True, 3)
    purposes.clear()
    r = client.put(policy, headers=headers,
                   json={"dual_control_merge": False, "approval_request_id": str(stale.id)})
    assert r.status_code == 409, r.text
    assert "requires a second signature" in r.json()["detail"]
    assert SystemPurpose.CASE_RECORD in purposes
    assert ApprovalService(owner).get(stale.id).state == "APPROVED"
    assert _switch(owner, case_id)[:2] == (True, 3)
    relaxed = [c for c in _rows(owner, case_id, "CASE_POLICY_CHANGED")
               if c[2]["setting"] == "dual_control_merge" and c[2]["to"] is False]
    assert [(c[0], c[2]["approval_request_id"]) for c in relaxed] == [(lead, str(fresh.id))]
    consumed = owner.execute(
        "SELECT actor_id FROM audit.event WHERE action = 'APPROVAL_CONSUMED' AND object_id = %s",
        (fresh.id,)).fetchall()
    assert consumed == [(lead,)]


def test_a_failed_case_edit_writes_no_audit_row_and_a_refused_one_writes_its_denied_row_on_the_request_connection(
        owner, client, purposes):
    from noctornal_api.db import SystemPurpose
    lead, case_id, headers = _lead_case(owner)
    # The route's own refusals, on the request connection: no system connection is opened.
    for body in ({"classification": "GREEN"}, {"retention_until": "2029-06-01"},
                 {"classification": "RED"}, {"summary": None}):
        r = client.patch(f"{API}/cases/{case_id}", headers=headers, json=body)
        assert r.status_code in (400, 403), (body, r.text)
    assert SystemPurpose.CASE_RECORD not in purposes
    # The service's own refusal, on the system connection: nothing is written.
    r = client.patch(f"{API}/cases/{case_id}", headers=headers,
                     json={"review_due": "2030-06-01"})
    assert r.status_code == 400, r.text
    assert _rows(owner, case_id, "CASE_UPDATED") == []
    assert owner.execute('SELECT title, classification, retention_until, review_due '
                         'FROM core."case" WHERE id = %s', (case_id,)).fetchone() == (
        "Row security", "AMBER", date(2030, 1, 1), date(2029, 1, 1))
    # The gate's refusal: its AUTHZ_DENIED row names the caller it was bound to.
    reader = s.user(owner, prefix=P)
    s.assign(owner, case_id, reader, "READ_ONLY")
    _sid, raw = s.session(owner, reader)
    purposes.clear()
    r = client.patch(f"{API}/cases/{case_id}", headers={"Authorization": f"Bearer {raw}"},
                     json={"title": "Not theirs to edit"})
    assert r.status_code == 403, r.text
    assert SystemPurpose.CASE_RECORD not in purposes
    denied = owner.execute(
        "SELECT actor_id, outcome FROM audit.event WHERE action = 'AUTHZ_DENIED' "
        "AND actor_id = %s", (reader,)).fetchall()
    assert denied == [(reader, "DENIED")]
    assert _rows(owner, case_id, "CASE_UPDATED") == []


ROOT = Path(__file__).resolve().parents[3]

#: Each column 0178 left the request role, forged as that role.
RECORD_FORGERIES = {
    "title": "UPDATE core.\"case\" SET title = 'forged' WHERE id = %s",
    "summary": "UPDATE core.\"case\" SET summary = 'forged' WHERE id = %s",
    "authority_ref": "UPDATE core.\"case\" SET authority_ref = 'forged' WHERE id = %s",
    "review_due": "UPDATE core.\"case\" SET review_due = '2000-01-01' WHERE id = %s",
    "retention_until": "UPDATE core.\"case\" SET retention_until = '2000-01-01' WHERE id = %s",
    "classification": "UPDATE core.\"case\" SET classification = 'GREEN' WHERE id = %s",
    "status": "UPDATE core.\"case\" SET status = 'CLOSED' WHERE id = %s",
    "closed_at": "UPDATE core.\"case\" SET closed_at = now() WHERE id = %s",
    "dual_control_merge": "UPDATE core.\"case\" SET dual_control_merge = true WHERE id = %s",
    "withheld_disclosure": "UPDATE core.\"case\" SET withheld_disclosure = 'COUNT' WHERE id = %s",
}

_RECORD = ('SELECT title, summary, authority_ref, review_due, retention_until, classification, '
           'status, closed_at, dual_control_merge, withheld_disclosure FROM core."case" WHERE id = %s')


def _migration():
    path = next((ROOT / "db" / "migrations" / "versions").glob("*_case_record_system_writes.py"))
    spec = importlib.util.spec_from_file_location("m_case_record", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("column", sorted(RECORD_FORGERIES))
def test_a_cases_record_is_not_the_request_roles(owner, column):
    _lead, case_id, headers = _lead_case(owner)
    raw = headers["Authorization"].split(" ", 1)[1]
    before = owner.execute(_RECORD, (case_id,)).fetchone()
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege,
                           match="permission denied for table case"):
            app.execute(RECORD_FORGERIES[column], (case_id,))
        # The case is still the request role's to read.
        assert app.execute('SELECT title FROM core."case" WHERE id = %s',
                           (case_id,)).fetchone() is not None
    finally:
        app.close()
    assert owner.execute(_RECORD, (case_id,)).fetchone() == before


def test_the_request_role_holds_no_column_of_a_case_and_the_system_role_keeps_the_table(owner):
    assert set(RECORD_FORGERIES) == set(_migration().CASE_COLUMNS)
    held = [r[0] for r in owner.execute(
        """SELECT attname FROM pg_attribute
            WHERE attrelid = 'core."case"'::regclass AND attnum > 0 AND NOT attisdropped
              AND has_column_privilege(%s, attrelid, attnum, 'UPDATE')""",
        (s.APP_ROLE,)).fetchall()]
    assert held == []
    assert owner.execute("SELECT has_table_privilege(%s, 'core.\"case\"', 'UPDATE')",
                         (s.WORKER_ROLE,)).fetchone()[0] is True


@pytest.mark.parametrize("lock", ["FOR UPDATE", "FOR SHARE"])
def test_the_request_role_takes_no_row_lock_on_a_case(owner, lock):
    """A row lock needs UPDATE on a column, and the request role holds none: the hold, the purge and
    a sample's rejection lock the case row on a system connection."""
    _lead, case_id, headers = _lead_case(owner)
    app = s.app_conn(headers["Authorization"].split(" ", 1)[1])
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(f'SELECT id FROM core."case" WHERE id = %s {lock}', (case_id,))
    finally:
        app.close()


def test_the_case_record_revoke_replays_after_the_grants_that_hand_it_back(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's blanket grant and 0178's column grants,
    which hand the ten columns back, and then 0186's revoke. In a transaction that is rolled
    back, on this test database only."""
    spec = importlib.util.spec_from_file_location(
        "runtime_roles_case_record", ROOT / "scripts" / "runtime_roles.py")
    roles = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(roles)
    held = None
    try:
        with owner.transaction():
            roles.grant(owner)
            held = [c for c in _migration().CASE_COLUMNS if owner.execute(
                "SELECT has_column_privilege(%s, 'core.\"case\"', %s, 'UPDATE')",
                (s.APP_ROLE, c)).fetchone()[0]]
            raise psycopg.Rollback()
    except psycopg.Rollback:
        pass
    assert held == []
