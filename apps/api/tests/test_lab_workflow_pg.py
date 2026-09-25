"""The Lab's own work over HTTP, and the refusals around it (review of
2026-09-22, closed 2026-09-23).

- gap-reject-step-up: a rejection needs a sign-in from the last 15
  minutes, because it moves the evidence into a store it cannot leave
  without two people, or destroys it;
- ux13-lab:no-assign-or-record-analysis: assign takes only an eligible
  analyst, the analysis comes back with who recorded it, and an extracted
  selector is proposed into the case's triage queue, derived and never
  repeated, with one answer whatever the case already holds (the
  verifier's existence oracle, 2026-09-23);
- assign, analysis, detonation and the people lists refuse a sample the
  caller cannot see, with the 404 `detail` gives;
- ux13-lab:detonation-authoriser-uuid: the sign-off is another lead
  investigator on the sample's case, never the requester;
- ux13-lab:label-chip-understates-handling: the queue carries the labels a
  sample is handled at;
- ux13-lab:legal-banner-copy and submit-form-ignores-refusal-and-scope:
  the policy says the notice once and carries the caller's own labels.

Email prefix `labw-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the Lab workflow is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

API = "/api/v1"
PREFIX = "labw-"


@pytest.fixture(autouse=True)
def declared_policy(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        # 0103 guards lab.detonation against DELETE.
        c.execute("ALTER TABLE lab.detonation DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.detonation WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.detonation ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'")
    c.close()


class MemoryStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, roles=(), clearance="RED", compartments=(), name="Lab"):
    from noctornal_api.stores import PgUserStore
    email = f"{PREFIX}{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(conn).create_user(email, name, "x" * 20)
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(compartments), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _token(conn, uid, *, fresh=True) -> str:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    if not fresh:
        # Signed in an hour ago: past STEP_UP_FRESHNESS, still a session.
        conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() - "
                     "interval '1 hour' WHERE user_id = %s", (uid,))
    return token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, *, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    return CaseService(conn).create(
        code=f"OP-LABW-{uuid4().hex[:6]}", title="Lab workflow",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


def _node(conn, case_id, owner, label, classification="RED"):
    """An INFRA entity already in the case, written as the graph writes one
    (invariant 1: never without its assertion)."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="INFRA", label=label, created_by=owner,
        classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner,
                                 reliability="B", credibility="2"))


def _sample(conn, store, submitter, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=submitter, original_filename="x.bin", **kw)


# --- gap-reject-step-up ------------------------------------------------------

def test_rejecting_needs_a_fresh_sign_in(conn, client, store):
    analyst = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _sample(conn, store, analyst)
    body = {"reason": "not ours", "purge_bytes": False}

    stale = _token(conn, analyst, fresh=False)
    r = client.post(f"{API}/samples/{sample.id}/reject", headers=_auth(stale),
                    json=body)
    assert r.status_code == 403, r.text
    assert "re-authenticate" in r.json()["detail"]
    assert conn.execute("SELECT state FROM lab.sample WHERE id = %s",
                        (sample.id,)).fetchone()[0] == "QUARANTINED", (
        "a stale session rejected the sample")

    conn.execute("DELETE FROM iam.session WHERE user_id = %s", (analyst,))
    fresh = _token(conn, analyst)
    r = client.post(f"{API}/samples/{sample.id}/reject", headers=_auth(fresh),
                    json=body)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "REJECTED"


# --- assign and record --------------------------------------------------------

def test_assign_offers_and_takes_only_an_eligible_analyst(conn, client, store):
    analyst = _user(conn, roles=("MALWARE_ANALYST",), name="Able Analyst")
    low = _user(conn, roles=("MALWARE_ANALYST",), clearance="GREEN")
    outsider = _user(conn)
    sample = _sample(conn, store, analyst, classification="AMBER")
    token = _token(conn, analyst)

    people = client.get(f"{API}/samples/{sample.id}/people", headers=_auth(token))
    assert people.status_code == 200, people.text
    offered = {p["id"] for p in people.json()["assignees"]}
    assert str(analyst) in offered
    assert str(low) not in offered, "an analyst who cannot see it is offered"
    assert str(outsider) not in offered, "an account outside the lab is offered"
    assert people.json()["selector_types"], "the record form has no types"

    for wrong in (low, outsider):
        r = client.post(f"{API}/samples/{sample.id}/assign", headers=_auth(token),
                        json={"analyst_id": str(wrong)})
        assert r.status_code == 400, r.text
    r = client.post(f"{API}/samples/{sample.id}/assign", headers=_auth(token),
                    json={"analyst_id": str(analyst)})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "ASSIGNED"
    assert r.json()["assigned_to_name"] == "Able Analyst"


def test_a_reader_without_the_lab_role_gets_no_directory(conn, client, store):
    reader = _user(conn, roles=("ANALYST",))
    sample = _sample(conn, store, reader)
    r = client.get(f"{API}/samples/{sample.id}/people",
                   headers=_auth(_token(conn, reader)))
    assert r.status_code == 200, r.text
    assert r.json()["assignees"] == [] and r.json()["detonation_authorisers"] == []
    assert r.json()["you_may"]["analyse"] is False


def test_the_lab_routes_refuse_a_sample_the_caller_cannot_see(conn, client, store):
    owner = _user(conn)
    sample = _sample(conn, store, owner, classification="RED")
    amber = _user(conn, roles=("MALWARE_ANALYST",), clearance="AMBER")
    token = _token(conn, amber)
    for method, path, body in (
            ("get", "people", None),
            ("post", "assign", {"analyst_id": str(amber)}),
            ("post", "analysis", {"kind": "STATIC"}),
            ("post", "detonation", {"target": "x", "exposure_level": "NONE"})):
        r = getattr(client, method)(f"{API}/samples/{sample.id}/{path}",
                                    headers=_auth(token),
                                    **({"json": body} if body else {}))
        assert r.status_code in (403, 404), (path, r.status_code, r.text)
        if path != "detonation":  # needs sample.detonate, which nobody holds
            assert r.status_code == 404, (path, r.text)
    assert conn.execute("SELECT count(*) FROM lab.sample_analysis "
                        "WHERE sample_id = %s", (sample.id,)).fetchone()[0] == 0


def test_an_analysis_comes_back_attributed_and_its_selector_is_proposed(
        conn, client, store):
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    analyst = _user(conn, roles=("MALWARE_ANALYST",), name="Ria Reverser")
    sample = _sample(conn, store, owner, case_id=case_id)
    token = _token(conn, analyst)

    untyped = client.post(f"{API}/samples/{sample.id}/analysis",
                          headers=_auth(token), json={
                              "kind": "STATIC",
                              "extracted_selectors": [{"value": "c2.example"}]})
    assert untyped.status_code == 400, "an untyped selector was recorded"

    r = client.post(f"{API}/samples/{sample.id}/analysis", headers=_auth(token),
                    json={"kind": "MANUAL_RE", "tool": "Ghidra",
                          "tool_version": "11.1",
                          "findings": {"packer": "none"},
                          "extracted_selectors": [
                              {"selector_type": "DOMAIN", "value": "C2.Example.",
                               "why": "beacon config"}],
                          "family_assessment": "Nightjar",
                          "confidence": "MODERATE"})
    assert r.status_code == 201, r.text
    analysis_id = r.json()["id"]

    detail = client.get(f"{API}/samples/{sample.id}", headers=_auth(token)).json()
    [a] = detail["analyses"]
    assert a["analyst_name"] == "Ria Reverser"
    assert a["tool_version"] == "11.1"
    assert a["findings"] == {"packer": "none"}
    assert detail["you_may"]["analyse"] is True

    url = f"{API}/samples/{sample.id}/analyses/{analysis_id}/propose"
    first = client.post(url, headers=_auth(token), json={"index": 0})
    assert first.status_code == 202, first.text
    assert first.json() == {"sent": True, "label": "c2.example"}
    row = conn.execute(
        "SELECT payload, origin, state FROM collect.proposal WHERE case_id = %s",
        (case_id,)).fetchone()
    assert row[0]["node_type"] == "INFRA"
    assert row[0]["label"] == "c2.example", "the value was not normalised"
    assert row[0]["attrs"]["selector_type"] == "DOMAIN"
    assert row[1] == "lab/analysis" and row[2] == "PROPOSED"
    # Nothing reached the graph.
    assert conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0

    again = client.post(url, headers=_auth(token), json={"index": 0})
    assert again.status_code == 202 and again.json() == first.json()
    assert conn.execute("SELECT count(*) FROM collect.proposal WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 1, "a second click queued twice"
    missing = client.post(url, headers=_auth(token), json={"index": 5})
    assert missing.status_code == 409


def test_proposing_says_nothing_about_what_the_case_already_holds(
        conn, client, store):
    """The verifier's existence oracle (2026-09-23): a malware analyst, who
    holds no case access, recorded values of their choosing and learnt from
    the answers which were entities in the case (with their node ids),
    which had been proposed and rejected, and the case's code. The answer
    is now one shape whatever the case holds; the audit trail says which."""
    from psycopg.types.json import Json

    from noctornal_api.samples import SampleService
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]
    node_id = _node(conn, case_id, owner, "known.example")
    conn.execute(
        "INSERT INTO collect.proposal (case_id, kind, payload, origin, "
        "rationale, state) VALUES (%s, 'NODE', %s, 'test', 'test', 'REJECTED')",
        (case_id, Json({"node_type": "INFRA", "label": "rejected.example",
                        "attrs": {"selector_type": "DOMAIN"}})))
    analyst = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _sample(conn, store, owner, case_id=case_id)
    aid = SampleService(conn, store).record_analysis(
        sample.id, analyst_id=analyst, kind="STATIC", extracted_selectors=[
            {"selector_type": "DOMAIN", "value": value}
            for value in ("new.example", "known.example", "rejected.example")])
    token = _token(conn, analyst)
    url = f"{API}/samples/{sample.id}/analyses/{aid}/propose"

    answers = [client.post(url, headers=_auth(token), json={"index": i})
               for i in range(3)]
    for r, value in zip(answers, ("new.example", "known.example",
                                  "rejected.example"), strict=True):
        assert r.status_code == 202, r.text
        assert r.json() == {"sent": True, "label": value}, (
            "the answer differs with what the case holds")
        assert code not in r.text and str(node_id) not in r.text
    assert conn.execute(
        "SELECT count(*) FROM collect.proposal WHERE case_id = %s "
        "AND payload->>'label' = 'new.example'", (case_id,)).fetchone()[0] == 1
    outcomes = [row[0] for row in conn.execute(
        "SELECT detail->>'outcome' FROM audit.event "
        "WHERE action = 'SAMPLE_SELECTOR_PROPOSED' AND object_id = %s "
        "ORDER BY (detail->>'index')::int", (sample.id,))]
    assert outcomes == ["queued", "already_in_graph", "already_proposed"], (
        "the audit trail does not say what became of each")


def test_proposing_refuses_an_unattached_sample_and_a_closed_case(
        conn, client, store):
    from noctornal_api.samples import SampleService
    owner = _user(conn, roles=("CASE_OWNER",))
    analyst = _user(conn, roles=("MALWARE_ANALYST",))
    token = _token(conn, analyst)
    svc = SampleService(conn, store)
    loose = _sample(conn, store, owner)
    aid = svc.record_analysis(loose.id, analyst_id=analyst, kind="STATIC",
                              extracted_selectors=[{"selector_type": "IPV4",
                                                    "value": "203.0.113.9"}])
    r = client.post(f"{API}/samples/{loose.id}/analyses/{aid}/propose",
                    headers=_auth(token), json={"index": 0})
    assert r.status_code == 409 and "not attached to a case" in r.json()["detail"]

    case_id = _case(conn, owner)
    held = _sample(conn, store, owner, case_id=case_id)
    aid = svc.record_analysis(held.id, analyst_id=analyst, kind="STATIC",
                              extracted_selectors=[{"selector_type": "IPV4",
                                                    "value": "203.0.113.9"}])
    conn.execute('UPDATE core."case" SET status = \'CLOSED\' WHERE id = %s',
                 (case_id,))
    r = client.post(f"{API}/samples/{held.id}/analyses/{aid}/propose",
                    headers=_auth(token), json={"index": 0})
    # The case's own refusal since c7 (2026-09-24): titled so the console
    # knows it, naming the state and never the case's code.
    assert r.status_code == 409 and r.json()["title"] == "Case is read-only"
    assert "CLOSED" in r.json()["detail"]


# --- detonation sign-off --------------------------------------------------------

def test_a_detonation_is_signed_off_by_another_lead_on_the_case(conn, store):
    from noctornal_api.samples import SampleError, SampleService
    lead = _user(conn, roles=("CASE_OWNER",), name="Lena Lead")
    case_id = _case(conn, lead)
    requester = _user(conn, roles=("MALWARE_ANALYST",))
    stranger = _user(conn, roles=("CASE_OWNER",))
    svc = SampleService(conn, store)
    sample = _sample(conn, store, lead, case_id=case_id)

    signers = svc.detonation_authorisers(sample.id, exclude=requester)
    assert [s["id"] for s in signers] == [str(lead)], (
        "somebody who is not a lead on this case can sign off")
    assert svc.detonation_authorisers(sample.id, exclude=lead) == [], (
        "a lead can sign off their own request")

    for who in (requester, stranger):
        with pytest.raises(SampleError):
            svc.request_detonation(sample.id, requested_by=requester,
                                   target="ANY_RUN", exposure_level="PUBLIC",
                                   authorised_by=who, note="needed")
    det = svc.request_detonation(sample.id, requested_by=requester,
                                 target="ANY_RUN", exposure_level="PUBLIC",
                                 authorised_by=lead, note="needed")
    assert det is not None
    [row] = svc.detonations(sample.id)
    assert row["authorised_by"] == conn.execute(
        "SELECT email FROM iam.app_user WHERE id = %s", (lead,)).fetchone()[0]


# --- handling labels -------------------------------------------------------------

def test_the_queue_carries_the_labels_a_sample_is_handled_at(conn, client, store):
    owner = _user(conn, roles=("CASE_OWNER",), compartments=("LABW-X",))
    case_id = _case(conn, owner, compartments=("LABW-X",))
    sample = _sample(conn, store, owner, case_id=case_id, classification="AMBER")
    # A sample from before its case was compartmented and raised: its own
    # labels no longer say how it is handled.
    conn.execute("UPDATE lab.sample SET compartments = '{}' WHERE id = %s",
                 (sample.id,))
    conn.execute('UPDATE core."case" SET classification = \'RED\' WHERE id = %s',
                 (case_id,))
    reader = _user(conn, roles=("MALWARE_ANALYST",), compartments=("LABW-X",))
    r = client.get(f"{API}/samples?case_id={case_id}",
                   headers=_auth(_token(conn, reader)))
    assert r.status_code == 200, r.text
    [row] = r.json()["samples"]
    assert row["classification"] == "AMBER"
    assert row["effective_classification"] == "RED"
    assert row["classification_inherited"] is True
    assert row["effective_compartments"] == ["LABW-X"]
    assert row["inherited_compartments"] == ["LABW-X"]


# --- the policy the Lab reads --------------------------------------------------------

def test_the_policy_says_the_notice_once_and_carries_the_callers_labels(
        conn, client):
    uid = _user(conn, roles=("ANALYST",), clearance="AMBER",
                compartments=("LABW-X",))
    body = client.get(f"{API}/samples/policy",
                      headers=_auth(_token(conn, uid))).json()
    assert "absolute sense" not in body["notice"]
    assert body["notice"].count("Counsel must review") == 1
    assert body["your_clearance"] == "AMBER"
    assert body["your_compartments"] == ["LABW-X"]
    assert body["designated_person"] == "the.dp@example.test"
