"""The second person on a case's merge switch must have held `case.update`
on the case for the seasoning window (F9b, docs/17 F39 and docs/00 open
question 12, settled by the owner 2026-10-02).

The hole: turning a case's merge requirement off takes a second holder of
`case.update` on the case, so an account holding SYS_ADMIN and CASE_OWNER
could create a second Lead investigator, assign it to the case and approve
its own relax within the minute. The rule, modelled on the deployment-wide
policy's seven-day countersigner rule: the second person has held the
permission on that case for at least `NOCTORNAL_RELAX_SEASONING_DAYS` days
(default 7, 0 off), read from the assignment's `granted_at` by the database
clock, and the refusal names the rule and the date they become eligible.

The existing relax tests (test_case_merge_relax_pg.py and the audit test in
test_http_e2e.py) relied on a deputy assigned a moment ago deciding at once,
which is exactly what the rule now refuses; each of them ages the deputy
first (`season`), and this file holds the rule itself. Every test that
states the rule fails on 718f92d, where a deputy assigned a moment ago
approved; the two that state what the rule leaves alone (rejecting, and a
merge's second person) pass there too and hold it so.

Database tests run on the autocommit fixture, so the refusals the service
writes out of band survive and can be read back. Email prefix `rsn-`.
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from test_case_merge_relax_pg import _on, _put, _raise_relax, _switch, season
from test_case_merge_relax_pg import session as _session
from test_dual_control_policy_pg import teardown
from test_dual_control_policy_pg import user as _user

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the rule is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "rsn-"
API = "/api/v1"
RELAX = "case.policy.relax"
ENV = "NOCTORNAL_RELAX_SEASONING_DAYS"


@pytest.fixture(autouse=True)
def _no_declared_window(monkeypatch):
    """Every test starts from the documented default unless it declares one."""
    monkeypatch.delenv(ENV, raising=False)


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
    return _session(conn, uid)


def _case(conn, lead, deputy=None):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-RSN-{uuid4().hex[:6]}", title="Seasoning",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=lead, created_by=lead,
        deputy_user_id=deputy)


def _ask(conn, case_id, lead):
    """The switch on, and a relax request raised against it."""
    from noctornal_api.approvals import ApprovalService, relax_payload
    _on(conn, case_id)
    return ApprovalService(conn).request(
        operation=RELAX, case_id=case_id,
        payload=relax_payload(_switch(conn, case_id)[1]),
        justification="no longer contested", requested_by=lead)


def _decide(conn, request_id, who, approve=True):
    from noctornal_api.approvals import ApprovalService
    return ApprovalService(conn).decide(request_id, decided_by=who,
                                        approve=approve)


def _age(conn, case_id, uid, interval: str) -> None:
    """Set an assignment's grant time `interval` back, by hand."""
    conn.execute(
        "UPDATE iam.case_assignment SET granted_at = now() - %s::interval "
        "WHERE case_id = %s AND user_id = %s", (interval, case_id, uid))


def _granted_at(conn, case_id, uid) -> datetime:
    return conn.execute(
        "SELECT granted_at FROM iam.case_assignment WHERE case_id = %s "
        "AND user_id = %s", (case_id, uid)).fetchone()[0]


def _utc(moment: datetime) -> str:
    from noctornal_api.approvals import utc_text
    return utc_text(moment)


def _refusals(conn, request_id, action="DUAL_CONTROL_COUNTERSIGN_REFUSED"):
    return conn.execute(
        """SELECT outcome, case_id, actor_id, detail FROM audit.event
            WHERE action = %s AND object_id = %s ORDER BY seq""",
        (action, request_id)).fetchall()


# ---------------------------------------------------------------------------
# The hole, closed
# ---------------------------------------------------------------------------

def test_an_account_cannot_create_its_own_second_person_and_approve_at_once(
        conn, client):
    """The finding as a story, over the routes. One account holding
    SYS_ADMIN and CASE_OWNER makes a new account, gives it the Lead
    investigator role on its case through the sharing route, raises a relax
    and has the new account approve it. The sharing body even offers a
    `granted_at` from long ago, which the route ignores: the request never
    supplies the time that counts."""
    from noctornal_api.approvals import ApprovalService
    boss_id = user(conn, "CASE_OWNER", "SYS_ADMIN")
    sock_id = user(conn)
    case_id = _case(conn, boss_id)
    boss, sock = session(conn, boss_id), session(conn, sock_id)
    shared = client.post(
        f"{API}/cases/{case_id}/users", headers=boss,
        json={"user_id": str(sock_id), "role_key": "CASE_OWNER",
              "granted_at": "2020-01-01T00:00:00Z"})
    assert shared.status_code < 300, shared.text
    granted = _granted_at(conn, case_id, sock_id)
    assert granted > datetime.now(timezone.utc) - timedelta(minutes=5)
    assert _put(client, boss, case_id, dual_control_merge=True).status_code == 200
    epoch = _switch(conn, case_id)[1]
    raised = _raise_relax(client, boss, case_id, epoch)
    assert raised.status_code == 201, raised.text
    rid = raised.json()["id"]
    decided = client.post(f"{API}/cases/{case_id}/approvals/{rid}/decide",
                          headers=sock, json={"approve": True})
    assert decided.status_code == 409, decided.text
    said = decided.json()["detail"]
    assert ("The second person on a case's merge switch must have held "
            "case.update on the case for at least 7 days") in said
    assert f"You may approve this from {_utc(granted + timedelta(days=7))}" in said
    assert f"on {_utc(granted)}" in said
    assert "You may still reject it." in said
    # Nothing moved: the request is still waiting, the switch is still on,
    # and spending it is refused.
    assert ApprovalService(conn).get(rid).state == "PENDING"
    assert _switch(conn, case_id)[0] is True
    again = _put(client, boss, case_id, dual_control_merge=False,
                 approval_request_id=rid)
    assert again.status_code == 409
    assert _switch(conn, case_id)[0] is True


def test_the_refusal_is_audited_with_the_rule_the_window_and_the_date(conn):
    from noctornal_api.approvals import ApprovalError
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    req = _ask(conn, case_id, lead)
    with pytest.raises(ApprovalError):
        _decide(conn, req.id, deputy)
    (outcome, row_case, actor, detail), = _refusals(conn, req.id)
    assert (outcome, row_case, actor) == ("DENIED", case_id, deputy)
    assert detail["reason"] == "assignment_seasoning"
    assert detail["operation"] == RELAX and detail["permission"] == "case.update"
    assert detail["window_days"] == 7
    granted = _granted_at(conn, case_id, deputy)
    assert datetime.fromisoformat(detail["granted_at"]) == granted
    assert datetime.fromisoformat(detail["may_sign_after"]) == (
        granted + timedelta(days=7))


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------

def test_the_second_person_is_eligible_exactly_when_the_window_has_passed(conn):
    from noctornal_api.approvals import ApprovalError, ApprovalService
    lead, early, late = user(conn, "CASE_OWNER"), user(conn), user(conn)
    case_id = _case(conn, lead, early)
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'CASE_OWNER', %s)",
                 (case_id, late, lead))
    req = _ask(conn, case_id, lead)
    _age(conn, case_id, early, "6 days 23 hours")
    with pytest.raises(ApprovalError) as refused:
        _decide(conn, req.id, early)
    granted = _granted_at(conn, case_id, early)
    # An hour short: the sentence names the instant the last hour ends.
    assert f"from {_utc(granted + timedelta(days=7))}" in str(refused.value)
    assert ApprovalService(conn).get(req.id).state == "PENDING"
    _age(conn, case_id, late, "7 days 1 minute")
    approved = _decide(conn, req.id, late)
    assert approved.state == "APPROVED" and approved.decided_by == late


def test_the_age_is_the_database_clocks_not_this_process(conn):
    """The comparison that decides is made in SQL, against `now()` or the
    instant the database pinned on the decision, and the functions that ask
    never read this process's clock. Both halves: the reader answers by the
    instant it is given (so a spent approval is judged when it was signed),
    and no clock call sits in any of the four."""
    import inspect

    from noctornal_api import approvals
    from noctornal_api.approvals import assignment_block
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    now_block = assignment_block(conn, deputy, case_id, "case.update", days=7)
    assert now_block and now_block["kind"] == "seasoning"
    soon = conn.execute("SELECT now() + interval '8 days'").fetchone()[0]
    assert assignment_block(conn, deputy, case_id, "case.update", days=7,
                            as_of=soon) is None
    for fn in (assignment_block, approvals.ApprovalService.refuse_unseasoned_spend,
               approvals.ApprovalService._refuse_unseasoned_assignment,
               approvals.ApprovalService.signer_block_for):
        source = inspect.getsource(fn)
        for clock in ("datetime.now", "utcnow", "time.time", "monotonic",
                      "date.today"):
            assert clock not in source, (fn.__name__, clock)
    assert "coalesce(%(as_of)s::timestamptz, now())" in inspect.getsource(
        assignment_block)


def test_a_regrant_restarts_the_clock(conn, client):
    """`_grant` stamps `granted_at = now()` on every re-grant, so changing a
    colleague's role, or repeating a grant, makes them wait again. Nobody
    can move the date back by granting more."""
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    season(conn, case_id, deputy)
    old = _granted_at(conn, case_id, deputy)
    again = client.post(f"{API}/cases/{case_id}/users",
                        headers=session(conn, lead),
                        json={"user_id": str(deputy), "role_key": "CASE_OWNER"})
    assert again.status_code < 300, again.text
    assert _granted_at(conn, case_id, deputy) > old + timedelta(days=7)
    req = _ask(conn, case_id, lead)
    from noctornal_api.approvals import ApprovalError
    with pytest.raises(ApprovalError, match="You may approve this from"):
        _decide(conn, req.id, deputy)


def test_a_declared_window_replaces_the_default(conn, monkeypatch):
    from noctornal_api.approvals import ApprovalError
    monkeypatch.setenv(ENV, "3")
    lead, young, old = user(conn, "CASE_OWNER"), user(conn), user(conn)
    case_id = _case(conn, lead, young)
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'CASE_OWNER', %s)",
                 (case_id, old, lead))
    req = _ask(conn, case_id, lead)
    _age(conn, case_id, young, "2 days")
    _age(conn, case_id, old, "4 days")
    with pytest.raises(ApprovalError) as refused:
        _decide(conn, req.id, young)
    assert "for at least 3 days" in str(refused.value)
    granted = _granted_at(conn, case_id, young)
    assert f"from {_utc(granted + timedelta(days=3))}" in str(refused.value)
    assert _decide(conn, req.id, old).state == "APPROVED"


def test_a_window_of_one_day_is_said_in_the_singular(conn, monkeypatch):
    from noctornal_api.approvals import ApprovalError
    monkeypatch.setenv(ENV, "1")
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    req = _ask(conn, case_id, lead)
    with pytest.raises(ApprovalError, match="for at least 1 day,"):
        _decide(conn, req.id, deputy)


def test_zero_turns_the_rule_off_and_a_fresh_colleague_approves(conn, monkeypatch):
    """0 is the whole of the off switch, and it is the behaviour of every
    release before this one."""
    monkeypatch.setenv(ENV, "0")
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    req = _ask(conn, case_id, lead)
    assert _decide(conn, req.id, deputy).state == "APPROVED"
    assert _refusals(conn, req.id) == []


@pytest.mark.parametrize("declared", ["seven", "-1", "1.5", "366", "1e1", "7d",
                                      "٣", "0x7", "+7"])
def test_a_malformed_window_is_never_zero(conn, monkeypatch, declared):
    """A typo in the setting must not be the way the rule goes off: it is
    held to the default of 7 days, and the production boot refuses it."""
    from noctornal_api.approvals import ApprovalError, relax_seasoning
    monkeypatch.setenv(ENV, declared)
    days, problem = relax_seasoning()
    assert days == 7 and problem and ENV in problem
    assert declared not in problem
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    req = _ask(conn, case_id, lead)
    with pytest.raises(ApprovalError, match="for at least 7 days"):
        _decide(conn, req.id, deputy)


@pytest.mark.parametrize("declared,days", [
    ("", 7), ("  ", 7), ("7", 7), ("0", 0), ("1", 1), ("30", 30), ("365", 365),
    (" 14 ", 14), ("007", 7)])
def test_the_setting_reads_as_documented(declared, days):
    from noctornal_api.approvals import relax_seasoning
    assert relax_seasoning({ENV: declared}) == (days, None)
    assert relax_seasoning({}) == (7, None)


def test_the_production_boot_refuses_a_malformed_window_and_never_quotes_it():
    import base64

    from noctornal_api.config import verify_environment
    env = {
        "NOCTORNAL_ENV": "production",
        "DATABASE_URL":
            "postgresql+psycopg://noctornal_app:Xk9pQ@db:5432/noctornal",
        "REDIS_URL": "redis://:Zm4tR@redis:6379/0",
        "NOCTORNAL_TOTP_KEK": base64.b64encode(bytes(range(1, 33))).decode(),
        "NOCTORNAL_INGEST_PEPPER": "9f2c1ad4e6b8",
        "NOCTORNAL_BASE_URL": "https://noctornal.example.gov",
        "NOCTORNAL_SESSION_STRICT_BINDING": "1",
        "MINIO_ENDPOINT": "minio:9000", "MINIO_ACCESS_KEY": "evidence-writer",
        "MINIO_SECRET_KEY": "Qp7xL2vD", "MINIO_SECURE": "true",
        "SAMPLE_ACCESS_KEY": "sample-writer", "SAMPLE_SECRET_KEY": "Wr3nB8fH",
        "SAMPLE_SECURE": "true", "SMTP_HOST": "smtp.example.gov",
        "SMTP_PASSWORD": "Td5mJ1cV",
        "NOCTORNAL_MAX_EVIDENCE_BYTES": "268435456",
        "NOCTORNAL_WORKER_DATABASE_URL":
            "postgresql+psycopg://noctornal_worker:Rt8vWq@db:5432/noctornal",
    }
    assert verify_environment(env) == []
    for good in ("0", "7", "30"):
        assert verify_environment({**env, ENV: good}) == []
    problems = verify_environment({**env, ENV: "soonish"})
    assert len(problems) == 1 and ENV in problems[0]
    assert "soonish" not in problems[0]
    assert "default of 7 days" in problems[0]


# ---------------------------------------------------------------------------
# Rejecting is never blocked, and the rule is for this operation only
# ---------------------------------------------------------------------------

def test_a_colleague_who_is_not_seasoned_may_still_reject(conn):
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    req = _ask(conn, case_id, lead)
    refused = _decide(conn, req.id, deputy, approve=False)
    assert refused.state == "REJECTED" and refused.decided_by == deputy
    assert _refusals(conn, req.id) == []


def test_a_merge_approval_does_not_need_a_seasoned_second_person(conn):
    """The owner's decision names the case's merge switch. A merge itself
    keeps the second person it always had, however new to the case."""
    from noctornal_api.approvals import ApprovalService
    lead, deputy = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead, deputy)
    req = ApprovalService(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(uuid4()),
                 "target_node_id": str(uuid4()), "reason": "same handle"},
        justification="identical fingerprints", requested_by=lead)
    assert _decide(conn, req.id, deputy).state == "APPROVED"


def test_only_the_relax_operation_carries_the_rule():
    from noctornal_api.approvals import OPERATIONS
    seasoned = {k for k, op in OPERATIONS.items() if op.signer_assignment_seasoned}
    assert seasoned == {RELAX}


# ---------------------------------------------------------------------------
# Where the approval is spent
# ---------------------------------------------------------------------------

def _approved_over_http(conn, client, *, deputy_aged: bool):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead, deputy = session(conn, lead_id), session(conn, deputy_id)
    assert _put(client, lead, case_id, dual_control_merge=True).status_code == 200
    raised = _raise_relax(client, lead, case_id, _switch(conn, case_id)[1])
    assert raised.status_code == 201, raised.text
    rid = raised.json()["id"]
    if deputy_aged:
        season(conn, case_id, deputy_id)
    decided = client.post(f"{API}/cases/{case_id}/approvals/{rid}/decide",
                          headers=deputy, json={"approve": True})
    return lead_id, deputy_id, case_id, lead, rid, decided


def test_an_approval_given_while_the_rule_was_off_is_refused_when_it_is_on(
        conn, client, monkeypatch):
    """Decided with the window at 0 by a colleague a moment old, spent after
    the operator declared 7: judged at `decided_at`, so refused, recorded,
    and left unspent."""
    monkeypatch.setenv(ENV, "0")
    lead_id, deputy_id, case_id, lead, rid, decided = _approved_over_http(
        conn, client, deputy_aged=False)
    assert decided.status_code == 200, decided.text
    monkeypatch.setenv(ENV, "7")
    off = _put(client, lead, case_id, dual_control_merge=False,
               approval_request_id=rid)
    assert off.status_code == 409, off.text
    said = off.json()["detail"]
    assert said.startswith("This approval cannot be used: its second person "
                           "had held case.update on this case for less than "
                           "7 days when they approved it")
    assert "Ask again." in said
    assert _switch(conn, case_id)[0] is True
    from noctornal_api.approvals import ApprovalService
    assert ApprovalService(conn).get(rid).state == "APPROVED"
    (outcome, row_case, actor, detail), = _refusals(
        conn, rid, "DUAL_CONTROL_APPLY_REFUSED")
    assert (outcome, row_case, actor) == ("DENIED", case_id, lead_id)
    assert detail["reason"] == "assignment_seasoning"
    # With the rule off again it is spendable: the refusal was the rule's.
    monkeypatch.setenv(ENV, "0")
    assert _put(client, lead, case_id, dual_control_merge=False,
                approval_request_id=rid).status_code == 200


def test_an_approval_is_refused_when_the_colleague_was_granted_the_role_again(
        conn, client):
    lead_id, deputy_id, case_id, lead, rid, decided = _approved_over_http(
        conn, client, deputy_aged=True)
    assert decided.status_code == 200, decided.text
    # The lead changes the colleague's grant after they signed: the clock
    # restarts, and the approval was given by someone the rule would now
    # refuse.
    regrant = client.post(f"{API}/cases/{case_id}/users", headers=lead,
                          json={"user_id": str(deputy_id),
                                "role_key": "CASE_OWNER"})
    assert regrant.status_code < 300, regrant.text
    off = _put(client, lead, case_id, dual_control_merge=False,
               approval_request_id=rid)
    assert off.status_code == 409, off.text
    assert "was given the role Lead investigator on this case again" in (
        off.json()["detail"])
    assert "after they approved it" in off.json()["detail"]
    assert _switch(conn, case_id)[0] is True


def test_an_approval_is_refused_when_the_colleague_has_left_the_case(
        conn, client):
    from noctornal_api.cases import CaseService
    lead_id, deputy_id, case_id, lead, rid, decided = _approved_over_http(
        conn, client, deputy_aged=True)
    assert decided.status_code == 200, decided.text
    CaseService(conn).revoke_user(case_id, deputy_id, revoked_by=lead_id)
    off = _put(client, lead, case_id, dual_control_merge=False,
               approval_request_id=rid)
    assert off.status_code == 409, off.text
    assert "did not hold case.update on this case when they approved it, or " \
           "no longer does" in off.json()["detail"]
    assert _switch(conn, case_id)[0] is True


def test_a_seasoned_approval_is_spent_as_before(conn, client):
    lead_id, deputy_id, case_id, lead, rid, decided = _approved_over_http(
        conn, client, deputy_aged=True)
    assert decided.status_code == 200, decided.text
    off = _put(client, lead, case_id, dual_control_merge=False,
               approval_request_id=rid)
    assert off.status_code == 200, off.text
    assert off.json()["dual_control_merge"] is False
    assert _refusals(conn, rid, "DUAL_CONTROL_APPLY_REFUSED") == []


# ---------------------------------------------------------------------------
# What the console is told
# ---------------------------------------------------------------------------

def test_the_policy_read_counts_only_seasoned_colleagues_and_says_when_next(
        conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    lead = session(conn, lead_id)
    got = client.get(f"{API}/cases/{case_id}/policy", headers=lead).json()
    granted = _granted_at(conn, case_id, deputy_id)
    assert got["relax_signers"] == 0
    assert got["relax_seasoning_days"] == 7
    assert datetime.fromisoformat(got["relax_next_eligible"]) == (
        granted + timedelta(days=7))
    season(conn, case_id, deputy_id)
    got = client.get(f"{API}/cases/{case_id}/policy", headers=lead).json()
    assert got["relax_signers"] == 1 and got["relax_next_eligible"] is None


def test_the_policy_read_says_nothing_to_wait_for_when_nobody_else_holds_it(
        conn, client):
    lead_id = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead_id)
    got = client.get(f"{API}/cases/{case_id}/policy",
                     headers=session(conn, lead_id)).json()
    assert got["relax_signers"] == 0 and got["relax_next_eligible"] is None


def test_with_the_rule_off_every_colleague_counts(conn, client, monkeypatch):
    monkeypatch.setenv(ENV, "0")
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    got = client.get(f"{API}/cases/{case_id}/policy",
                     headers=session(conn, lead_id)).json()
    assert got["relax_signers"] == 1
    assert got["relax_seasoning_days"] == 0 and got["relax_next_eligible"] is None


def test_the_approvals_listing_tells_an_unseasoned_viewer_before_they_try(
        conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    req = _ask(conn, case_id, lead_id)
    granted = _granted_at(conn, case_id, deputy_id)

    def row(who):
        listed = client.get(f"{API}/cases/{case_id}/approvals",
                            headers=session(conn, who)).json()["approvals"]
        return next(a for a in listed if a["id"] == str(req.id))

    block = row(deputy_id)["signer_block"]
    assert block["reason"].startswith(
        f"You may approve this from {_utc(granted + timedelta(days=7))}")
    assert datetime.fromisoformat(block["may_sign_after"]) == (
        granted + timedelta(days=7))
    # Nothing to say to the one who asked, who has the self-approval
    # refusal, nor once the colleague has held the role long enough.
    assert row(lead_id)["signer_block"] is None
    season(conn, case_id, deputy_id)
    assert row(deputy_id)["signer_block"] is None


def test_a_decided_or_other_request_carries_no_signer_block(conn, client):
    lead_id, deputy_id = user(conn, "CASE_OWNER"), user(conn)
    case_id = _case(conn, lead_id, deputy_id)
    req = _ask(conn, case_id, lead_id)
    _decide(conn, req.id, deputy_id, approve=False)
    listed = client.get(f"{API}/cases/{case_id}/approvals",
                        headers=session(conn, deputy_id)).json()["approvals"]
    assert [a["signer_block"] for a in listed] == [None]


def test_the_two_person_screen_shows_the_window_for_the_relax_operation(conn):
    from noctornal_api.dual_control import DualControlPolicyService
    admin = user(conn, "SYS_ADMIN")
    overview = DualControlPolicyService(conn).overview(
        admin, clearance="AMBER", compartments=frozenset())
    by_key = {op["key"]: op for op in overview["operations"]}
    assert by_key[RELAX]["signer_seasoning"] == {
        "permission": "case.update", "days": 7, "problem": None}
    assert "signer_seasoning" not in by_key["node.merge"]


def test_the_two_person_screen_names_a_setting_it_could_not_use(conn, monkeypatch):
    from noctornal_api.dual_control import DualControlPolicyService
    monkeypatch.setenv(ENV, "a week")
    admin = user(conn, "SYS_ADMIN")
    overview = DualControlPolicyService(conn).overview(
        admin, clearance="AMBER", compartments=frozenset())
    seasoning = next(op for op in overview["operations"]
                     if op["key"] == RELAX)["signer_seasoning"]
    assert seasoning["days"] == 7 and ENV in seasoning["problem"]
    assert "a week" not in seasoning["problem"]
