"""A request raises only the notices the product writes, in its own words (0181).

0145 bound `notify.enqueue` to a live session and an honest delivery plan;
it did not limit what a bound account could say. A request-role caller now
raises only the kinds a request raises, at their own priority, as itself,
with a subject and a summary in one of the kind's templates. Every
request-role producer in `notify_events.py` is run here on a bound
request-role connection and must still be written; anything else is
refused. The owner and the system role keep the function they had. Account
prefix `rlsntf-`.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import rls_support as s
from lab_static_fixtures import MemoryStore
from screening_fixtures import assert_scrubbed, declare, payload, scrub

pytestmark = s.GATED

P = "rlsntf-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"

ENQUEUE = ("SELECT outcome FROM notify.enqueue("
           "%s::uuid, %s::uuid, %s, %s::smallint, %s, %s, 'body text', 'GREEN'::core.tlp, "
           "'{}'::text[], NULL, NULL, %s::uuid, NULL, %s::jsonb, NULL)")
PLAN = json.dumps([{"channel": "IN_APP", "state": "SENT"},
                   {"channel": "SMTP", "state": "PENDING"}])


def _migration():
    path = next(VERSIONS.glob("0181_*.py"))
    spec = importlib.util.spec_from_file_location("m0181", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner(monkeypatch):
    declare(monkeypatch)
    c = s.owner_conn()
    yield c
    s.cleanup(c, P)
    scrub(c, P)
    assert_scrubbed(c, P)
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


def _bound(owner, uid):
    _sid, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _enqueue(conn, recipient, *, kind, priority, subject, summary, actor, case_id=None):
    with conn.transaction(force_rollback=True):
        return conn.execute(ENQUEUE, (recipient, case_id, kind, priority, subject, summary,
                                      actor, PLAN)).fetchone()[0]


GLOBAL_DECIDED = ("APPROVAL_DECIDED", 2, "Your request was countersigned: Change a role definition",
                  "Your deployment-wide request was countersigned.")


def test_a_kind_the_product_writes_in_its_own_words_is_written(owner):
    me = s.user(owner, "AMBER", prefix=P)
    them = s.user(owner, "AMBER", prefix=P)
    app = _bound(owner, me)
    try:
        kind, priority, subject, summary = GLOBAL_DECIDED
        assert _enqueue(app, them, kind=kind, priority=priority, subject=subject,
                        summary=summary, actor=me) == "WRITTEN"
    finally:
        app.close()


@pytest.mark.parametrize("change", [
    {"kind": "MERGE_PERFORMED"},
    {"kind": "BREAK_GLASS_INVOKED", "priority": 1},
    {"subject": "Your account is locked: sign in at https://evil.example"},
    {"summary": "Reply with your password to keep your account."},
    {"subject": "Your request was countersigned: Change a role definition. Call 555 0100"},
    {"priority": 1},
    {"actor": None},
], ids=["kind_merge", "kind_break_glass", "subject_free", "summary_free", "subject_suffix",
        "priority_raised", "no_actor"])
def test_anything_else_from_a_bound_request_is_refused(owner, change):
    me = s.user(owner, "AMBER", prefix=P)
    them = s.user(owner, "AMBER", prefix=P)
    kind, priority, subject, summary = GLOBAL_DECIDED
    args = {"kind": kind, "priority": priority, "subject": subject, "summary": summary,
            "actor": me, **change}
    app = _bound(owner, me)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _enqueue(app, them, **args)
    finally:
        app.close()


def test_a_case_code_is_the_named_cases_own(owner):
    lead = s.user(owner, "AMBER", prefix=P)
    case_id = s.case(owner, lead)
    code = owner.execute('SELECT code FROM core."case" WHERE id = %s', (case_id,)).fetchone()[0]
    analyst = s.user(owner, "AMBER", prefix=P)
    s.assign(owner, case_id, analyst)
    alarm = ("EVIDENCE_INTEGRITY_ALARM", 1)
    summary = (f"An exhibit on {code} no longer matches the hash recorded when it was "
               f"acquired. Treat the case's evidence as suspect until this is explained.")
    app = _bound(owner, analyst)
    try:
        assert _enqueue(app, lead, kind=alarm[0], priority=alarm[1], case_id=case_id,
                        subject=f"{code}: an exhibit failed its integrity check",
                        summary=summary, actor=analyst) == "WRITTEN"
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _enqueue(app, lead, kind=alarm[0], priority=alarm[1], case_id=case_id,
                     subject="OP-ELSEWHERE: an exhibit failed its integrity check",
                     summary=summary.replace(code, "OP-ELSEWHERE"), actor=analyst)
    finally:
        app.close()


def test_a_case_notice_comes_only_from_someone_who_acts_on_the_case(owner):
    """The words are right and the caller is bound, but the case is not
    theirs: no priority-1 alarm about somebody else's case."""
    lead = s.user(owner, "AMBER", prefix=P)
    case_id = s.case(owner, lead)
    code = owner.execute('SELECT code FROM core."case" WHERE id = %s', (case_id,)).fetchone()[0]
    outsider = s.user(owner, "AMBER", prefix=P)
    app = _bound(owner, outsider)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="case it may act on"):
            _enqueue(app, lead, kind="EVIDENCE_INTEGRITY_ALARM", priority=1, case_id=case_id,
                     subject=f"{code}: an exhibit failed its integrity check",
                     summary=(f"An exhibit on {code} no longer matches the hash recorded "
                              f"when it was acquired. Treat the case's evidence as suspect "
                              f"until this is explained."), actor=outsider)
    finally:
        app.close()


def test_the_owner_and_the_system_role_keep_the_function_they_had(owner):
    """Any kind, any words, no actor: an exempt caller's plan is taken as
    given (its in-app copy carries its own sent time)."""
    victim = s.user(owner, "AMBER", prefix=P)
    plan = json.dumps([{"channel": "IN_APP", "state": "SENT",
                        "sent_at": "2026-10-08T00:00:00+00:00"},
                       {"channel": "SMTP", "state": "PENDING"}])
    worker = s.owner_conn()
    worker.execute(f"SET ROLE {s.WORKER_ROLE}")
    try:
        for conn in (owner, worker):
            with conn.transaction(force_rollback=True):
                assert conn.execute(ENQUEUE, (victim, None, "MERGE_PERFORMED", 2,
                                              "any subject", "any summary", None,
                                              plan)).fetchone()[0] == "WRITTEN"
    finally:
        worker.close()


def test_every_request_role_producer_is_still_written(owner, store):
    """Each producer a request runs, in production's shape: a bound
    request-role connection, rolled back after."""
    from noctornal_api import notify_events as ev
    from noctornal_api.samples import SampleService

    lead = s.user(owner, "AMBER", prefix=P)
    me = s.user(owner, "AMBER", prefix=P)
    officer = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, officer, "SECURITY_OFFICER")
    s.grant_global(owner, me, "MALWARE_ANALYST")
    s.grant_global(owner, lead, "MALWARE_ANALYST")
    case_id = s.case(owner, lead)
    s.assign(owner, case_id, me)
    exhibit = s.exhibit(owner, case_id, lead)
    caseless = SampleService(owner, store).submit(payload("ntf-free"), submitted_by=me)
    in_case = SampleService(owner, store).submit(payload("ntf-case"), submitted_by=me,
                                                 case_id=case_id)
    calls = {
        "approval_requested": lambda c: ev.approval_requested(
            c, case_id=case_id, request_id=uuid4(), operation="node.merge",
            permission="graph.merge", justification="two handles, one person",
            actor_id=me) == 1,
        "approval_decided": lambda c: ev.approval_decided(
            c, case_id=case_id, request_id=uuid4(), operation="node.merge",
            requested_by=lead, approved=False, note="not yet", actor_id=me) is not None,
        "global_approval_requested": lambda c: ev.global_approval_requested(
            c, request_id=uuid4(), operation="dual_control.policy",
            description="Change which operations need two people",
            permission="dual_control.countersign", requester_permission="dual_control.manage",
            actor_id=me) >= 1,
        "global_approval_decided": lambda c: ev.global_approval_decided(
            c, request_id=uuid4(), description="Change a role definition",
            requested_by=lead, approved=True, actor_id=me) is not None,
        "proposals_queued": lambda c: ev.proposals_queued(
            c, case_id=case_id, count=3, actor_id=me) is True,
        "proposals_queued_one": lambda c: ev.proposals_queued(
            c, case_id=case_id, count=1, actor_id=me) is True,
        "evidence_integrity_alarm": lambda c: ev.evidence_integrity_alarm(
            c, case_id=case_id, evidence_id=exhibit, actor_id=me, on_read=True) is not None,
        "detonation_signoff_requested_case": lambda c: ev.detonation_signoff_requested(
            c, detonation_id=uuid4(), sample_id=in_case.id, authoriser_id=lead,
            requester_id=me, target="the lab sandbox") is not None,
        "detonation_signoff_requested_free": lambda c: ev.detonation_signoff_requested(
            c, detonation_id=uuid4(), sample_id=caseless.id, authoriser_id=lead,
            requester_id=me, target="the lab sandbox") is not None,
        "detonation_signoff_decided": lambda c: ev.detonation_signoff_decided(
            c, detonation_id=uuid4(), sample_id=in_case.id, requester_id=lead,
            approved=True, actor_id=me) is not None,
        "detonation_named": lambda c: ev.detonation_named(
            c, detonation_id=uuid4(), sample_id=in_case.id, named_id=lead,
            requester_id=me, target="a vendor sandbox", exposure_level="VENDOR") is not None,
    }
    app = _bound(owner, me)
    written = {}
    try:
        for name, call in calls.items():
            with app.transaction(force_rollback=True):
                written[name] = call(app)
    finally:
        app.close()
    assert all(written.values()), written


def test_the_templates_follow_the_catalogues():
    from noctornal_api.approvals import OPERATIONS
    from noctornal_api.notifications import KINDS
    m = _migration()
    for kind, priority in m.REQUEST_KINDS.items():
        assert KINDS[kind].default_priority == priority, kind
    globals_ = {op.description for op in OPERATIONS.values() if op.scope == "global"}
    assert globals_ == set(m.GLOBAL_DESCRIPTIONS), globals_ ^ set(m.GLOBAL_DESCRIPTIONS)
    assert {kind for kind, _s, _m in m.TEMPLATES} == set(m.REQUEST_KINDS)
