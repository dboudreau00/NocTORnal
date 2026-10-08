"""A request appends a state-bearing audit row only where it may act (0176).

0168's INSERT policy admitted any row, so a bound user not on a case could
append a triage verdict, a category correction, an ACH history line or a
hypothesis note naming it, and the readers that take those rows as state
read it. For `STATE_BEARING` actions the request role's append must now
name a case it may read, or be a case-less `ingest` row from an
`ingest.manage` holder; every other append, a refusal above all, is
admitted as before. Run as the request role bound by a real session's
proof, seeded as the owner. Account prefix `rlsapp-`.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Json

import rls_support as s

pytestmark = s.GATED

P = "rlsapp-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration():
    path = next(VERSIONS.glob("0176_*.py"))
    spec = importlib.util.spec_from_file_location("m0176", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, P)
    c.close()


def _append(conn, *, action: str, object_type: str, case_id=None,
            object_id=None, actor_id=None) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
         object_id or uuid4(), case_id, Json({"state": "DISCARDED", "reason": "planted"})))


def _refused(conn, **kw) -> None:
    conn.execute("SAVEPOINT plant")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _append(conn, **kw)
    conn.execute("ROLLBACK TO SAVEPOINT plant")


def _team(owner):
    """A case, a member of it and an outsider, both bound."""
    lead = s.user(owner, prefix=P)
    case_id = s.case(owner, lead)
    member = s.user(owner, prefix=P)
    s.assign(owner, case_id, member)
    outsider = s.user(owner, prefix=P)
    return case_id, member, outsider


CASE_STATE = [("HYPOTHESIS_STATUS", "hypothesis"), ("HYPOTHESIS_STANCE", "hypothesis"),
              ("HYPOTHESIS_STANCE_CLEARED", "hypothesis"), ("EDGE_REVIEWED", "edge"),
              ("INGEST_RECORD_TRIAGED", "ingest"), ("INGEST_CATEGORY_CORRECTED", "ingest"),
              ("INGEST_RECORD_ATTACHED", "ingest")]


@pytest.mark.parametrize("action,object_type", CASE_STATE,
                         ids=[a for a, _t in CASE_STATE])
def test_state_naming_a_case_the_writer_is_not_on_is_refused(owner, action, object_type):
    case_id, member, outsider = _team(owner)
    _sid, raw = s.session(owner, outsider)
    app = s.app_conn(raw)
    try:
        with app.transaction():
            _refused(app, action=action, object_type=object_type, case_id=case_id,
                     actor_id=outsider)
    finally:
        app.close()
    # The case's own team still appends it.
    _sid, raw = s.session(owner, member)
    app = s.app_conn(raw)
    try:
        _append(app, action=action, object_type=object_type, case_id=case_id,
                actor_id=member)
    finally:
        app.close()


def test_a_refusal_still_names_a_case_its_writer_cannot_read(owner):
    case_id, _member, outsider = _team(owner)
    marker = uuid4()
    _sid, raw = s.session(owner, outsider)
    app = s.app_conn(raw)
    try:
        _append(app, action="AUTHZ_DENIED", object_type="auth", case_id=case_id,
                object_id=marker, actor_id=outsider)
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        _append(unbound, action="AUTHZ_DENIED", object_type="auth", case_id=case_id,
                object_id=marker)
    finally:
        unbound.close()
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s",
                   (marker,)) == 2


def test_a_quarantine_row_needs_the_operator_verb(owner):
    plain = s.user(owner, prefix=P)
    operator = s.user(owner, prefix=P)
    s.grant_global(owner, operator, "SYS_ADMIN")
    assert owner.execute(
        "SELECT EXISTS (SELECT 1 FROM iam.role_permission WHERE role_key = 'SYS_ADMIN' "
        "AND permission_key = 'ingest.manage')").fetchone()[0]
    _sid, raw = s.session(owner, plain)
    app = s.app_conn(raw)
    try:
        with app.transaction():
            _refused(app, action="INGEST_RECORD_TRIAGED", object_type="ingest",
                     actor_id=plain)
    finally:
        app.close()
    _sid, raw = s.session(owner, operator)
    app = s.app_conn(raw)
    try:
        _append(app, action="INGEST_RECORD_TRIAGED", object_type="ingest",
                actor_id=operator)
        # The operator verb answers case-less INGEST rows only.
        with app.transaction():
            _refused(app, action="HYPOTHESIS_STATUS", object_type="hypothesis",
                     actor_id=operator)
    finally:
        app.close()


@pytest.mark.parametrize("action", ["PASSWORD_RESET", "TOTP_REENROLLED", "USER_REACTIVATED",
                                    "USER_UNLOCKED", "ROLE_GRANTED", "USER_CREATED",
                                    "SCREENING_RESCAN", "BREAK_GLASS_INVOKED"])
def test_what_only_a_system_connection_writes_is_refused_to_a_request(owner, action):
    victim = s.user(owner, prefix=P)
    planter = s.user(owner, prefix=P)
    s.grant_global(owner, planter, "SYS_ADMIN")
    _sid, raw = s.session(owner, planter)
    app = s.app_conn(raw)
    try:
        with app.transaction():
            _refused(app, action=action, object_type="app_user", object_id=victim,
                     actor_id=planter)
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        with unbound.transaction():
            _refused(unbound, action=action, object_type="app_user", object_id=victim)
    finally:
        unbound.close()


def test_the_system_role_still_appends_every_state_bearing_row(owner):
    from noctornal_api.db import connect
    worker = connect()
    try:
        worker.execute(f"SET ROLE {s.WORKER_ROLE}")
        with worker.transaction(force_rollback=True):
            for action in _migration().STATE_BEARING:
                _append(worker, action=action, object_type="test")
    finally:
        worker.close()


def test_every_action_a_state_reader_names_is_held():
    """The readers that take rows as state (test_rls_audit_paths, CASE and
    INGEST) name their actions in SQL; each must be in the policy's list."""
    import test_rls_audit_paths as paths
    held = set(_migration().STATE_BEARING)
    named: set[str] = set()
    readers = paths._readers()
    for (rel, scope), treatment in paths._READERS.items():
        if treatment not in ("CASE", "INGEST"):
            continue
        for text in readers[(rel, scope)]:
            for one, many in re.findall(r"action\s*(?:=\s*'([A-Z_]+)'|IN\s*\(([^)]*)\))", text):
                named.update([one] if one else re.findall(r"'([A-Z_]+)'", many))
    assert named, "the scan found no action at all: the pattern is stale"
    assert named <= held, sorted(named - held)


def test_the_database_readers_actions_are_held(owner):
    """The countersigning rule and the screening fact name theirs in SQL."""
    held = set(_migration().STATE_BEARING)
    for function in ("iam.countersign_blocked_by(uuid, text, timestamptz, uuid, text, interval)",
                     "audit.last_screening_pass(interval)"):
        src = owner.execute("SELECT prosrc FROM pg_proc WHERE oid = %s::regprocedure",
                            (function,)).fetchone()[0]
        names: set[str] = set()
        for clause in re.findall(r"action\s*(?:=\s*'[A-Z_]+'|IN\s*\([^)]*\))", src):
            names.update(re.findall(r"'([A-Z_]+)'", clause))
        assert names and names <= held, (function, sorted(names - held))


def test_the_policy_reads_its_terms_once_per_statement(owner):
    check = owner.execute(
        "SELECT with_check FROM pg_policies WHERE schemaname = 'audit' "
        "AND tablename = 'event' AND cmd = 'INSERT'").fetchone()[0]
    assert "rls_cases()" in check and "rls_holds_global('ingest.manage'" in check
    assert check.count("SELECT iam.") == 2, check
    for action in _migration().STATE_BEARING:
        assert f"'{action}'" in check, action


def test_a_case_member_still_records_a_hypothesis_status_over_http(owner, monkeypatch):
    """The route in production's shape: the request role, bound."""
    from fastapi.testclient import TestClient

    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    lead = s.user(owner, prefix=P)
    case_id = s.case(owner, lead)
    _sid, raw = s.session(owner, lead)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Authorization": f"Bearer {raw}"}
    r = client.post(f"/api/v1/cases/{case_id}/ach/hypotheses", headers=headers,
                    json={"statement": "Ransomware affiliate", "confidence": "LOW"})
    assert r.status_code == 201, r.text
    hypothesis = r.json()["id"]
    r = client.post(f"/api/v1/cases/{case_id}/ach/hypotheses/{hypothesis}/status",
                    headers=headers, json={"status": "REJECTED", "note": "ruled out by logs"})
    assert r.status_code == 200, r.text
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                          "AND action = 'HYPOTHESIS_STATUS' AND case_id = %s",
                   (hypothesis, case_id)) == 1
