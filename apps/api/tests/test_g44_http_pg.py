"""Over HTTP, as the request role (unit g44, 2026-10-03):

- evidence-hold-lift-below-label: a lead cleared below an exhibit cannot lift
  its hold, and a lift without a reason is refused for everybody.
- evidence-case-hold-unreachable: `POST /retention/cases/{id}/legal-hold`
  places and lifts a case-level hold, with a reason and a gate.
- evidence-due-leaks-hold-reason: `/retention/due` shows nothing about an
  exhibit above the caller, for any date, and the free text of a hold only
  to a holder of retention.manage.
- evidence-report-case-raise-leak: a report built below a raised case's
  label excludes what predates the raise, and the egress gate sees the mark
  of what is included.
- evidence-report-release-in-app: a release goes to a destination outside
  the platform or is refused.
- the .eml, orphan and dedup fixes have their HTTP legs in
  `test_g44_evidence_ingest_pg.py`.

Accounts `g44t-*`.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"
REASON = "Court order 2026-0042: preserve, informant identity at issue"


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    from dataclasses import replace
    app = create_app()
    limits = dict(LIMITS)
    # The destroy limit is a burst of three per account, and these tests
    # place and lift holds more often than that.
    limits["retention.destroy"] = replace(limits["retention.destroy"],
                                          quota=1000, burst=1000)
    app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    return TestClient(app, raise_server_exceptions=False)


def _setup_red_exhibit(conn):
    """An AMBER case holding a RED exhibit, a RED officer and an AMBER lead
    who sees 0 exhibits in the register."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "RED")
    return boss, lead, case_id, exhibit


def _hold(client, headers, exhibit, on=True, reason=REASON):
    body = {"evidence_id": str(exhibit), "on": on}
    if reason is not None:
        body["reason"] = reason
    return client.post(f"{API}/retention/legal-hold", headers=headers, json=body)


def _is_held(conn, exhibit) -> bool:
    return conn.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                        (exhibit,)).fetchone()[0]


# --- evidence-hold-lift-below-label ----------------------------------------

def test_a_lead_cleared_below_an_exhibit_cannot_lift_its_hold(conn, client):
    boss, lead, case_id, exhibit = _setup_red_exhibit(conn)
    assert client.get(f"{API}/cases/{case_id}/evidence",
                      headers=g.token(conn, lead)).json()["total"] == 0
    assert _hold(client, g.token(conn, boss), exhibit).status_code == 200
    assert _is_held(conn, exhibit)

    r = _hold(client, g.token(conn, lead), exhibit, on=False,
              reason="lifting this hold on my own authority")
    assert r.status_code == 404, r.text
    assert "no such exhibit" in r.json()["detail"]
    assert _is_held(conn, exhibit), "the hold was lifted by somebody below the exhibit"
    # Indistinguishable from an exhibit that does not exist.
    missing = _hold(client, g.token(conn, lead), uuid4(), on=False,
                    reason="lifting this hold on my own authority")
    assert (missing.status_code, missing.json()["detail"]) == (404, "no such exhibit")


def test_a_lead_below_an_exhibit_may_still_place_a_hold_on_it(conn, client):
    """Preservation never waits for a clearance (decision 144)."""
    _boss, lead, _case_id, exhibit = _setup_red_exhibit(conn)
    r = _hold(client, g.token(conn, lead), exhibit)
    assert r.status_code == 200, r.text
    assert _is_held(conn, exhibit)


def test_somebody_cleared_for_the_exhibit_lifts_it_with_a_reason_that_is_kept(conn, client):
    boss, _lead, case_id, exhibit = _setup_red_exhibit(conn)
    _hold(client, g.token(conn, boss), exhibit)
    for reason in (None, "", "no"):
        r = _hold(client, g.token(conn, boss), exhibit, on=False, reason=reason)
        assert r.status_code in (400, 422), (reason, r.text)
        assert _is_held(conn, exhibit)
    r = _hold(client, g.token(conn, boss), exhibit, on=False,
              reason="order discharged by the court, ref 2026-0042/b")
    assert r.status_code == 200 and r.json()["legal_hold"] is False
    assert not _is_held(conn, exhibit)
    lifted = g.audit_rows(conn, "LEGAL_HOLD_LIFTED", case_id=case_id)
    assert lifted and lifted[-1][0]["prior_reason"] == REASON
    assert lifted[-1][0]["reason"].startswith("order discharged")


# --- evidence-case-hold-unreachable ----------------------------------------

def _case_hold(client, headers, case_id, on=True, reason=REASON):
    body = {"on": on}
    if reason is not None:
        body["reason"] = reason
    return client.post(f"{API}/retention/cases/{case_id}/legal-hold",
                       headers=headers, json=body)


def _case_held(conn, case_id) -> bool:
    return conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]


def test_a_case_hold_is_placed_and_lifted_through_the_product(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    headers = g.token(conn, boss)
    for bad in (None, "no"):
        assert _case_hold(client, headers, case_id, reason=bad).status_code in (400, 422)
    assert not _case_held(conn, case_id)

    r = _case_hold(client, headers, case_id)
    assert r.status_code == 200, r.text
    assert r.json() == {"case_id": str(case_id), "legal_hold": True,
                        "legal_hold_reason": REASON}
    assert _case_held(conn, case_id)
    assert g.audit_rows(conn, "LEGAL_HOLD_APPLIED", case_id=case_id)[-1][0]["scope"] == "case"

    assert _case_hold(client, headers, case_id, on=False, reason=None).status_code in (400, 422)
    r = _case_hold(client, headers, case_id, on=False, reason="order discharged, g44")
    assert r.status_code == 200 and r.json()["legal_hold"] is False
    assert not _case_held(conn, case_id)


def test_a_case_hold_needs_the_gate_on_that_case(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    stranger = g.user(conn, "RED", roles=("CASE_OWNER",))
    reader = g.user(conn, "AMBER", roles=("READ_ONLY",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, reader, "READ_ONLY")
    for who in (stranger, reader):
        r = _case_hold(client, g.token(conn, who), case_id)
        assert r.status_code in (403, 404), r.text
    assert _case_hold(client, g.token(conn, boss), uuid4()).status_code in (403, 404)
    assert not _case_held(conn, case_id)


def test_a_case_hold_needs_a_fresh_second_factor(conn, client):
    """retention.manage is a step-up permission: a session whose second
    factor is stale places and lifts nothing, for the case or an exhibit."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "AMBER")
    _, raw = s.session(conn, boss, mfa=False)
    stale = {"Authorization": f"Bearer {raw}"}
    r = _case_hold(client, stale, case_id)
    assert r.status_code == 403, r.text
    assert _hold(client, stale, exhibit).status_code == 403
    assert not _case_held(conn, case_id) and not _is_held(conn, exhibit)


def test_a_lead_below_something_in_the_case_places_the_hold_and_cannot_lift_it(conn, client):
    boss, lead, case_id, _exhibit = _setup_red_exhibit(conn)
    placed = _case_hold(client, g.token(conn, lead), case_id)
    assert placed.status_code == 200, placed.text
    r = _case_hold(client, g.token(conn, lead), case_id, on=False,
                   reason="lifting this on my own authority")
    assert r.status_code == 400, r.text
    assert "cleared for everything" in r.json()["detail"]
    assert _case_held(conn, case_id)
    assert _case_hold(client, g.token(conn, boss), case_id, on=False,
                      reason="order discharged, g44").status_code == 200
    assert not _case_held(conn, case_id)


def _document_held(conn, doc):
    from noctornal_api.retention import _held_sql
    return conn.execute(f"SELECT {_held_sql('d')} FROM collect.document d "
                        "WHERE d.id = %s", (doc,)).fetchone()[0]


def test_a_lead_below_a_cited_document_places_the_case_hold_and_cannot_lift_it(conn, client):
    """g44-case-hold-lift-documents: the lift gate counted exhibits, records,
    samples and lookups and not the collected documents the case cites, so an
    AMBER lead released a hold that was all that kept a RED document from the
    deployment-wide document sweep."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    doc, _source = g.collected_document(conn, case_id, classification="RED")

    assert _case_hold(client, g.token(conn, lead), case_id).status_code == 200
    assert _document_held(conn, doc) == "cited by a case under legal hold"
    r = _case_hold(client, g.token(conn, lead), case_id, on=False,
                   reason="lifting this on my own authority")
    assert r.status_code == 400, r.text
    assert "cleared for everything" in r.json()["detail"]
    assert _case_held(conn, case_id)
    assert _document_held(conn, doc) == "cited by a case under legal hold"

    assert _case_hold(client, g.token(conn, boss), case_id, on=False,
                      reason="order discharged, g44").status_code == 200
    assert not _case_held(conn, case_id)
    assert _document_held(conn, doc) is None


# --- evidence-due-leaks-hold-reason ----------------------------------------

def _due(client, headers, case_id, as_of="2099-01-01T00:00:00Z"):
    r = client.get(f"{API}/retention/due", headers=headers,
                   params={"case_id": str(case_id), "as_of": as_of})
    assert r.status_code == 200, r.text
    return r.json()


def test_the_due_list_shows_nothing_of_an_exhibit_above_the_caller(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, analyst, "ANALYST")
    exhibit = s.exhibit(conn, case_id, boss, "RED")
    _hold(client, g.token(conn, boss), exhibit)

    body = _due(client, g.token(conn, analyst), case_id)
    text = json.dumps(body)
    assert body["due"] == [] and body["count"] == 0 and body["on_legal_hold"] == 0
    assert str(exhibit) not in text and "informant" not in text
    assert body["withheld"] == [
        {"case_id": str(case_id), "mode": "PRESENCE", "incomplete": True}]

    # The case's own setting says how much is said about what is left out.
    conn.execute("UPDATE core.\"case\" SET withheld_disclosure = 'NONE' WHERE id = %s",
                 (case_id,))
    quiet = _due(client, g.token(conn, analyst), case_id)
    assert quiet["due"] == [] and "withheld" not in quiet
    conn.execute("UPDATE core.\"case\" SET withheld_disclosure = 'COUNT' WHERE id = %s",
                 (case_id,))
    counted = _due(client, g.token(conn, analyst), case_id)
    assert counted["withheld"] == [
        {"case_id": str(case_id), "mode": "COUNT", "incomplete": True, "items": 1}]

    # The same exhibit is on the officer's own list, reason and all.
    mine = _due(client, g.token(conn, boss), case_id)
    [row] = mine["due"]
    assert row["object_id"] == str(exhibit) and row["hold_reason"] == REASON


def test_the_due_list_leaves_out_a_compartmented_record_to_somebody_not_read_in(conn, client):
    """g44-due-labelled-records: a partner's record carries labels of its own,
    and its id, deadline and category (a stealer log) went to every
    retention.read holder of the case whatever its compartment."""
    boss = g.user(conn, "RED", ("STEALER-2026",), roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, analyst, "ANALYST")
    record_id, _ = g.record_in_case(conn, boss, case_id)
    assert conn.execute("SELECT compartments FROM ingest.record WHERE id = %s",
                        (record_id,)).fetchone()[0] == ["STEALER-2026"]

    body = _due(client, g.token(conn, analyst), case_id)
    assert body["due"] == [] and body["count"] == 0
    assert str(record_id) not in json.dumps(body) and "STEALER_LOG" not in json.dumps(body)
    assert body["withheld"] == [
        {"case_id": str(case_id), "mode": "PRESENCE", "incomplete": True}]

    # Somebody read into the compartment is told, with the category.
    mine = _due(client, g.token(conn, boss), case_id)
    [row] = mine["due"]
    assert (row["object_type"], row["object_id"], row["category"]) == (
        "ingest_record", str(record_id), "STEALER_LOG")


def test_the_due_list_leaves_out_a_sample_above_the_caller_as_well(conn, client, monkeypatch):
    """Samples joined the sweep with lab-4, so they join the list's rule."""
    from noctornal_api.cases import CaseService
    from noctornal_api.samples import DISPOSITION_ENV, SampleService
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    monkeypatch.setenv(DISPOSITION_ENV, "destroy")

    class Memory:
        def __init__(self):
            self.objects = {}

        def put(self, key, data):
            self.objects[key] = data

        def get(self, key):
            return self.objects[key]

        def delete(self, key):
            self.objects.pop(key, None)

    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, analyst, "ANALYST")
    CaseService(conn).transition_status(case_id, "ACTIVE", actor_id=boss)
    svc = SampleService(conn, Memory())
    red = svc.submit(b"MZ-g44-red-" + uuid4().bytes, submitted_by=boss, case_id=case_id,
                     original_filename="red.bin", classification="RED")
    amber = svc.submit(b"MZ-g44-amber-" + uuid4().bytes, submitted_by=boss, case_id=case_id,
                       original_filename="amber.bin", classification="AMBER")
    body = _due(client, g.token(conn, analyst), case_id)
    assert {r["object_id"] for r in body["due"]} == {str(amber.id)}
    assert str(red.id) not in json.dumps(body) and body["count"] == 1
    assert body["withheld"][0]["incomplete"] is True
    mine = _due(client, g.token(conn, boss), case_id)
    assert {r["object_id"] for r in mine["due"]} == {str(amber.id), str(red.id)}


def test_a_held_exhibit_within_reach_shows_its_reason_only_to_a_manager(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, analyst, "ANALYST")
    exhibit = s.exhibit(conn, case_id, boss, "AMBER")
    _hold(client, g.token(conn, boss), exhibit)
    seen_by_analyst = _due(client, g.token(conn, analyst), case_id)
    [row] = seen_by_analyst["due"]
    assert row["legal_hold"] is True
    assert row["hold_reason"] == "exhibit-level legal hold"
    assert "informant" not in json.dumps(seen_by_analyst)
    [mine] = _due(client, g.token(conn, boss), case_id)["due"]
    assert mine["hold_reason"] == REASON


def test_the_dry_run_lists_leave_out_an_exhibit_above_the_caller_too(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "RED")
    visible = s.exhibit(conn, case_id, boss, "AMBER")
    g.age_case(conn, case_id, g.expired())
    r = client.post(f"{API}/retention/purge", headers=g.token(conn, lead),
                    json={"case_id": str(case_id), "dry_run": True,
                          "authority": "g44 schedule review"})
    assert r.status_code == 200, r.text
    ids = {i["object_id"] for i in r.json()["items"]}
    assert ids == {str(visible)}, "the dry run named an exhibit above the caller"
    assert str(exhibit) not in json.dumps(r.json()["items"])


# --- evidence-report-case-raise-leak ---------------------------------------

def _raised_case(conn, client):
    """An AMBER case with an AMBER exhibit and an AMBER entity, then raised
    to RED: both predate the raise and keep their own AMBER labels."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    title = "G44-INFORMANT-INTERVIEW-" + uuid4().hex[:6]
    label = "g44-handle-" + uuid4().hex[:6]
    exhibit = s.exhibit(conn, case_id, boss, "AMBER")
    conn.execute("UPDATE core.evidence SET title = %s WHERE id = %s", (title, exhibit))
    s.node(conn, case_id, boss, label, "AMBER")
    headers = g.token(conn, boss)
    r = client.patch(f"{API}/cases/{case_id}", headers=headers,
                     json={"classification": "RED"})
    assert r.status_code == 200, r.text
    return boss, case_id, title, label


def _release(client, headers, case_id, target, destination="export"):
    return client.post(f"{API}/cases/{case_id}/report/release", headers=headers,
                       json={"target_tlp": target, "destination": destination})


def test_a_report_below_a_raised_case_carries_nothing_that_predates_the_raise(conn, client):
    boss, case_id, title, label = _raised_case(conn, client)
    r = _release(client, g.token(conn, boss), case_id, "AMBER")
    assert r.status_code == 200, r.text
    document = r.json()["document"]
    assert title not in document and label not in document
    assert r.json()["classification"] != "RED"
    assert "withheld" in r.json()["redaction"] or "above" in r.json()["redaction"]


def test_the_report_at_the_cases_own_level_is_marked_red_and_stopped_by_the_gate(conn, client):
    from noctornal_api.reports import ReportBuilder
    boss, case_id, title, label = _raised_case(conn, client)
    report = ReportBuilder(conn).build(case_id, target_tlp="RED", generated_by=boss,
                                       compartments=frozenset())
    assert report.redaction.built_at_tlp == "RED"
    assert title in json.dumps(report.evidence) and label in json.dumps(report.actors)
    r = _release(client, g.token(conn, boss), case_id, "RED")
    assert r.status_code == 403, r.text
    assert g.audit_rows(conn, "REPORT_RELEASE_REFUSED", case_id=case_id)


def test_an_unraised_case_still_reports_its_own_material_below_nothing(conn, client):
    """Both directions: a case that was never raised keeps its report."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    label = "g44-handle-" + uuid4().hex[:6]
    s.node(conn, case_id, boss, label, "AMBER")
    r = _release(client, g.token(conn, boss), case_id, "AMBER")
    assert r.status_code == 200, r.text
    assert label in r.json()["document"] and r.json()["classification"] == "AMBER"


# --- evidence-report-release-in-app ----------------------------------------

def test_a_release_goes_outside_the_platform_or_is_refused(conn, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss, classification="RED")
    s.assign(conn, case_id, boss, "CASE_OWNER")
    headers = g.token(conn, boss)
    for destination in ("in_app", "model_host", "nonsense"):
        r = _release(client, headers, case_id, "RED", destination)
        assert r.status_code == 400, (destination, r.status_code, r.text)
        assert "export" in r.json()["detail"]
    assert _release(client, headers, case_id, "RED", "export").status_code == 403
    assert _release(client, headers, case_id, "RED", "smtp").status_code == 403
    released = [r for r in g.audit_rows(conn, "REPORT_RELEASED", case_id=case_id)
                if r[1] == "SUCCESS"]
    assert released == [], "a RED document was recorded as released"
    refused = g.audit_rows(conn, "REPORT_RELEASE_REFUSED", case_id=case_id)
    assert {r[0]["destination"] for r in refused} == {"export", "smtp"}


def test_every_release_destination_is_a_gate_destination_that_crosses_the_boundary():
    from noctornal_api.egress import Destination
    from noctornal_api.http.routers.reports import RELEASE_DESTINATIONS
    assert set(RELEASE_DESTINATIONS) < set(Destination)
    assert Destination.IN_APP not in RELEASE_DESTINATIONS
