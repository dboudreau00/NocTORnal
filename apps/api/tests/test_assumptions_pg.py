"""The assumptions register (docs/08 Phase 6, migration 0056).

docs/08 defines it in one paragraph: per case, list the load-bearing
assumptions explicitly, with a review flag, so that "the same PGP key means
the same operator" is written down where it can be challenged. Nothing
existed for it until 2026-09-02 -- no table, no service, no route, and a
report that stated its conclusions without stating what they rested on.

The tests that carry this file:

- the REVIEW rules, because a register whose flags can be flipped without
  a trace is a to-do list, not a register: a REFUTED assumption cannot be
  quietly re-opened, and a WITHDRAWN one stays withdrawn;
- WHO MAY WRITE, read from both the router and the seed: the register is
  gated on `case.update`, which ANALYST does not hold, so an analyst reads
  it and a 403 is the answer to their POST;
- the REPORT, because a disclosure document that does not say what it
  assumes is a document whose reader cannot tell a finding from a premise.

Env-gated on DATABASE_URL. Email prefix `asm-`, unique to this file.
"""
from __future__ import annotations

import os
import time
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; assumption tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-6"
EMAIL_LIKE = "asm-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # core.assumption rows go with their case (ON DELETE CASCADE), so
        # they are deliberately not deleted here: if the cascade is ever
        # lost, this teardown fails and says so.
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


def _user(conn, *global_roles, clearance="AMBER"):
    """A TOTP-enrolled user; returns (id, email, totp_secret)."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"asm-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Assumer", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _case(conn, owner, classification="AMBER"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-ASM-{uuid4().hex[:6]}", title="Operation Register",
        legal_basis="production order 2026-0006",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _svc(conn):
    from noctornal_api.assumptions import AssumptionService
    return AssumptionService(conn)


def _actions(conn, object_id) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s ORDER BY seq",
        (object_id,)).fetchall()]


# --- the service ----------------------------------------------------------

def test_the_register_lifecycle_through_the_service(conn):
    """Make, list, confirm, refute, withdraw -- each leaving an audit row
    and a reviewer's name and time on the row itself."""
    owner, _, _ = _user(conn)
    reviewer, _, _ = _user(conn)
    case_id = _case(conn, owner)
    svc = _svc(conn)

    a = svc.create(case_id, statement="The same PGP key means the same operator",
                   basis="Key reuse across three forums", made_by=owner)
    b = svc.create(case_id, statement="The escrow account is controlled by the group",
                   basis=None, made_by=owner)
    c = svc.create(case_id, statement="Entered in error", basis=None, made_by=owner)

    listed = svc.list(case_id)
    assert [x.id for x in listed] == [a, b, c]
    assert {x.status for x in listed} == {"OPEN"}
    assert all(x.reviewed_by is None and x.reviewed_at is None for x in listed)

    confirmed = svc.update_status(case_id, a, status="CONFIRMED",
                                  reviewed_by=reviewer,
                                  note="Confirmed by the seizure inventory")
    assert confirmed.status == "CONFIRMED"
    assert confirmed.reviewed_by == reviewer and confirmed.reviewed_at is not None
    assert confirmed.review_note == "Confirmed by the seizure inventory"

    refuted = svc.update_status(case_id, b, status="REFUTED",
                                reviewed_by=reviewer, note=None)
    assert refuted.status == "REFUTED" and refuted.reviewed_by == reviewer

    withdrawn = svc.withdraw(case_id, c, withdrawn_by=owner, note="duplicate")
    assert withdrawn.status == "WITHDRAWN"

    # Withdrawn rows leave the default listing and stay in the record.
    assert [x.id for x in svc.list(case_id)] == [a, b]
    assert [x.id for x in svc.list(case_id, include_withdrawn=True)] == [a, b, c]

    assert _actions(conn, a) == ["ASSUMPTION_MADE", "ASSUMPTION_REVIEWED"]
    assert _actions(conn, b) == ["ASSUMPTION_MADE", "ASSUMPTION_REVIEWED"]
    assert _actions(conn, c) == ["ASSUMPTION_MADE", "ASSUMPTION_WITHDRAWN"]
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_id = %s AND action = 'ASSUMPTION_REVIEWED'""",
        (a,)).fetchone()[0]
    assert detail["from"] == "OPEN" and detail["to"] == "CONFIRMED"


def test_a_refuted_assumption_cannot_be_reopened_without_a_note(conn):
    """Refuting is a finding. Un-refuting it in silence would erase the
    finding while leaving the assumption load-bearing again, which is the
    exact move the register exists to make visible."""
    from noctornal_api.assumptions import AssumptionError
    owner, _, _ = _user(conn)
    case_id = _case(conn, owner)
    svc = _svc(conn)
    a = svc.create(case_id, statement="The domain is operator-owned",
                   basis=None, made_by=owner)
    svc.update_status(case_id, a, status="REFUTED", reviewed_by=owner,
                      note="WHOIS shows a reseller")
    for status in ("OPEN", "CONFIRMED"):
        with pytest.raises(AssumptionError, match="note"):
            svc.update_status(case_id, a, status=status, reviewed_by=owner,
                              note=None)
        with pytest.raises(AssumptionError, match="note"):
            svc.update_status(case_id, a, status=status, reviewed_by=owner,
                              note="   ")
    assert svc.list(case_id)[0].status == "REFUTED"
    reopened = svc.update_status(case_id, a, status="OPEN", reviewed_by=owner,
                                 note="Reseller record was itself stale")
    assert reopened.status == "OPEN"
    assert reopened.review_note == "Reseller record was itself stale"


def test_a_withdrawn_assumption_is_terminal(conn):
    from noctornal_api.assumptions import AssumptionError
    owner, _, _ = _user(conn)
    case_id = _case(conn, owner)
    svc = _svc(conn)
    a = svc.create(case_id, statement="x", basis=None, made_by=owner)
    svc.withdraw(case_id, a, withdrawn_by=owner, note=None)
    with pytest.raises(AssumptionError, match="withdrawn"):
        svc.update_status(case_id, a, status="OPEN", reviewed_by=owner,
                          note="changed my mind")
    with pytest.raises(AssumptionError, match="withdrawn"):
        svc.withdraw(case_id, a, withdrawn_by=owner, note=None)


def test_an_assumption_is_reachable_only_through_its_own_case(conn):
    """Every write is keyed on (case_id, id): another case's id is "no
    such assumption", never a cross-case edit."""
    from noctornal_api.assumptions import AssumptionError
    owner, _, _ = _user(conn)
    case_a, case_b = _case(conn, owner), _case(conn, owner)
    svc = _svc(conn)
    a = svc.create(case_a, statement="belongs to A", basis=None, made_by=owner)
    with pytest.raises(AssumptionError, match="no such assumption"):
        svc.update_status(case_b, a, status="CONFIRMED", reviewed_by=owner,
                          note=None)
    with pytest.raises(AssumptionError, match="no such assumption"):
        svc.withdraw(case_b, a, withdrawn_by=owner, note=None)
    assert svc.list(case_b) == []
    with pytest.raises(AssumptionError, match="statement"):
        svc.create(case_a, statement="   ", basis=None, made_by=owner)


def test_the_review_pair_is_enforced_by_the_schema(conn):
    """`reviewed_by` and `reviewed_at` are one fact; a row with one and
    not the other would say "reviewed by X" with no when, or "reviewed at
    T" by nobody."""
    import psycopg
    owner, _, _ = _user(conn)
    case_id = _case(conn, owner)
    a = _svc(conn).create(case_id, statement="x", basis=None, made_by=owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "UPDATE core.assumption SET reviewed_by = %s WHERE id = %s",
            (owner, a))
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "UPDATE core.assumption SET status = 'MAYBE' WHERE id = %s", (a,))


# --- the router -----------------------------------------------------------

def test_the_register_over_http_and_who_may_write_to_it(conn, client):
    """The router is gated on `case.read` to list and `case.update` to
    write. Both halves are read here: the seed says ANALYST holds
    `case.read` and not `case.update`, so an assigned analyst lists the
    register and gets 403 on POST and PATCH -- problem+json, not a 500
    and not a silent 200."""
    owner_id, owner_email, owner_secret = _user(conn, "CASE_OWNER")
    analyst_id, analyst_email, analyst_secret = _user(conn)
    owner = _login(client, owner_email, owner_secret)
    r = client.post("/api/v1/cases", headers=_auth(owner), json={
        "code": f"OP-ASM-{uuid4().hex[:6]}", "title": "Operation Register",
        "legal_basis": "production order 2026-0006",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    from noctornal_api.cases import CaseService
    CaseService(conn).assign_user(case_id, analyst_id, "ANALYST",
                                  granted_by=owner_id)
    # The seed half of the contract, so a role change here fails THIS test
    # rather than making the 403 below pass for the wrong reason.
    held = {r[0] for r in conn.execute(
        "SELECT permission_key FROM iam.role_permission WHERE role_key = 'ANALYST'"
    ).fetchall()}
    assert "case.read" in held and "case.update" not in held

    made = client.post(f"/api/v1/cases/{case_id}/assumptions", headers=_auth(owner),
                       json={"statement": "The broker and the developer are one person",
                             "basis": "Shared typo in two ransom notes"})
    assert made.status_code == 201, made.text
    assumption_id = made.json()["id"]

    analyst = _login(client, analyst_email, analyst_secret)
    listed = client.get(f"/api/v1/cases/{case_id}/assumptions", headers=_auth(analyst))
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert [a["id"] for a in body["assumptions"]] == [assumption_id]
    assert body["assumptions"][0]["status"] == "OPEN"
    assert body["assumptions"][0]["made_by"] == str(owner_id)

    refused = client.post(f"/api/v1/cases/{case_id}/assumptions",
                          headers=_auth(analyst), json={"statement": "no"})
    assert refused.status_code == 403, refused.text
    assert refused.headers["content-type"].startswith("application/problem+json")
    assert client.patch(f"/api/v1/cases/{case_id}/assumptions/{assumption_id}",
                        headers=_auth(analyst),
                        json={"status": "CONFIRMED"}).status_code == 403
    assert client.get(f"/api/v1/cases/{case_id}/assumptions").status_code == 401

    confirmed = client.patch(
        f"/api/v1/cases/{case_id}/assumptions/{assumption_id}",
        headers=_auth(owner), json={"status": "CONFIRMED", "note": "Seizure"})
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["status"] == "CONFIRMED"
    assert confirmed.json()["reviewed_by"] == str(owner_id)

    # A bad status is a 400 that names the choices, and an unknown id in
    # this case is a 404, not a 500.
    bad = client.patch(f"/api/v1/cases/{case_id}/assumptions/{assumption_id}",
                       headers=_auth(owner), json={"status": "MAYBE"})
    assert bad.status_code == 400 and "REFUTED" in bad.text
    assert client.patch(f"/api/v1/cases/{case_id}/assumptions/{uuid4()}",
                        headers=_auth(owner),
                        json={"status": "REFUTED"}).status_code == 404

    withdrawn = client.patch(
        f"/api/v1/cases/{case_id}/assumptions/{assumption_id}",
        headers=_auth(owner), json={"status": "WITHDRAWN", "note": "dup"})
    assert withdrawn.status_code == 200, withdrawn.text
    assert client.get(f"/api/v1/cases/{case_id}/assumptions",
                      headers=_auth(owner)).json()["assumptions"] == []
    assert _actions(conn, assumption_id) == [
        "ASSUMPTION_MADE", "ASSUMPTION_REVIEWED", "ASSUMPTION_WITHDRAWN"]


# --- the report -----------------------------------------------------------

def test_the_report_states_what_it_assumes(conn):
    """OPEN and CONFIRMED assumptions go into the document with who made
    them and when; REFUTED and WITHDRAWN ones do not, because a report
    that lists an assumption it has already refuted is presenting a
    premise it knows to be false.

    The set of statuses the report includes is ONE constant shared by the
    service and the builder, and this reads it from both: a report that
    quietly disagreed with the register about what "still assumed" means
    would be two consistent halves wrong together.
    """
    from noctornal_api.assumptions import REPORTABLE_STATUSES
    from noctornal_api.reports import ReportBuilder, render_markdown
    owner, _, _ = _user(conn, clearance="RED")
    case_id = _case(conn, owner)
    svc = _svc(conn)
    kept_open = svc.create(case_id, statement="ASSUME-OPEN the key is the operator",
                           basis="Key reuse", made_by=owner)
    kept_confirmed = svc.create(case_id, statement="ASSUME-CONFIRMED escrow is theirs",
                                basis=None, made_by=owner)
    svc.update_status(case_id, kept_confirmed, status="CONFIRMED",
                      reviewed_by=owner, note="Ledger match")
    gone_refuted = svc.create(case_id, statement="ASSUME-REFUTED domain is theirs",
                              basis=None, made_by=owner)
    svc.update_status(case_id, gone_refuted, status="REFUTED", reviewed_by=owner,
                      note="Reseller")
    gone_withdrawn = svc.create(case_id, statement="ASSUME-WITHDRAWN duplicate",
                                basis=None, made_by=owner)
    svc.withdraw(case_id, gone_withdrawn, withdrawn_by=owner, note=None)

    assert set(REPORTABLE_STATUSES) == {"OPEN", "CONFIRMED"}
    report = ReportBuilder(conn).build(case_id, target_tlp="AMBER",
                                       generated_by=owner)
    statements = [a["statement"] for a in report.assumptions]
    assert statements == ["ASSUME-OPEN the key is the operator",
                          "ASSUME-CONFIRMED escrow is theirs"]
    # The rows themselves, in the order they were made -- not merely two
    # statements that happen to read the same.
    assert [a["id"] for a in report.assumptions] == [str(kept_open), str(kept_confirmed)]
    assert {a["status"] for a in report.assumptions} == set(REPORTABLE_STATUSES)
    first = report.assumptions[0]
    assert first["made_by"] == str(owner) and first["made_by_name"] == "Assumer"
    assert first["made_at"] and first["reviewed_by"] is None
    second = report.assumptions[1]
    assert second["reviewed_by"] == str(owner) and second["reviewed_at"]
    assert second["review_note"] == "Ledger match"

    as_dict = report.as_dict()
    assert [a["statement"] for a in as_dict["assumptions"]] == statements
    md = render_markdown(report)
    assert "## Assumptions" in md
    assert "ASSUME-OPEN" in md and "ASSUME-CONFIRMED" in md
    assert "ASSUME-REFUTED" not in md and "ASSUME-WITHDRAWN" not in md


def test_an_empty_register_is_said_out_loud(conn):
    """No assumptions recorded is a fact about the analysts, not about the
    case, and the document says so rather than leaving a heading out."""
    from noctornal_api.reports import ReportBuilder, render_markdown
    owner, _, _ = _user(conn)
    case_id = _case(conn, owner)
    report = ReportBuilder(conn).build(case_id, target_tlp="AMBER",
                                       generated_by=owner)
    assert report.assumptions == []
    md = render_markdown(report)
    assert "## Assumptions" in md
    assert "not that there are none" in md


def test_the_register_is_withheld_with_the_case_header(conn):
    """An assumption is free text an analyst wrote ABOUT the case -- "the
    OP-KESTREL key is the operator's" -- so it is case content at the
    case's own level, exactly like the title and summary (F19). A GREEN
    document built from a RED case must not carry it, and must say that
    it does not."""
    from noctornal_api.reports import ReportBuilder
    owner, _, _ = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="RED")
    _svc(conn).create(case_id, statement="SECRET-PREMISE names the operation",
                      basis=None, made_by=owner)
    report = ReportBuilder(conn).build(case_id, target_tlp="GREEN",
                                       generated_by=owner)
    assert report.redaction.header_withheld
    assert report.assumptions == []
    assert report.redaction.assumptions_withheld == 1
    assert "SECRET-PREMISE" not in repr(report.as_dict())
    assert "assumption" in report.redaction.statement()
