"""Triage and capture, held to the Alpha 6 release review (2026-09-24).

Each test fails on d0faa34 and names the finding it holds:

- c1: an ATTRIBUTE claim found in RED, compartmented material was accepted
  onto a CLEAR entity, where every CLEAR reader of it could read the claim.
  The route, the service and the card now share one refusal.
- c15: a capture was stored below its case's floor (the form defaulted to
  AMBER on every case), in a table the collection lists by label alone;
  a compartmented case could not keep its document inside the compartment.
  The fix round kept a re-paste from reaching into another case's queue
  and from naming, in its reply, a label above the analyst.
- u2: a closed case's pending proposals counted as waiting for ever.
- u6: an entity accepted from Triage had an undated claim, so its first
  and last seen stayed blank although its capture was dated.
- u12: the "waiting in triage" notice was labelled at the case, so an
  owner below the capture's label was told what it raised.

Email prefix `trr-`, document titles `trr-`, unique to this file.
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; triage review is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "trr-"
EMAIL_LIKE = f"{PREFIX}%@noctornal.test"
#: Registered once and left registered, as the other suites do: a key is a
#: closed-vocabulary word, and deleting one another run still uses fails.
KEY = "TRR-KEY"
TOX = "B2" * 38

SAMPLE = """
Thread: re: escrow terms
kestrel_vend wrote:
  Contact me at kestrel.vend@protonmail.com for terms.
"""


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
              "ON CONFLICT (key) DO NOTHING", (KEY, "Triage review test"))
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ours = (f"(SELECT id FROM notify.notification "
            f"  WHERE recipient_id IN {sub} OR actor_id IN {sub} "
            f"     OR case_id IN {csub})")
    # One transaction: the deferred invariant-1 triggers fire at commit, so
    # assertions and their elements must go together.
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {ours}")
        c.execute(f"DELETE FROM notify.notification WHERE id IN {ours}")
        c.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
                  f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"""DELETE FROM collect.extraction WHERE document_id IN
                      (SELECT id FROM collect.document WHERE title LIKE '{PREFIX}%')""")
        c.execute(f"DELETE FROM collect.document WHERE title LIKE '{PREFIX}%'")
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


def _user(conn, clearance="RED", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", "TRR", "x" * 20)
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(compartments), uid))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    return CaseService(conn).create(
        code=f"OP-TRR-{uuid4().hex[:6]}", title="Triage review",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification=classification,
        compartments=list(compartments))


def _assign(conn, case_id, user, role, by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user, role, by))


def _node(conn, case_id, owner, label, classification="AMBER", compartments=()):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner),
        classification=classification, compartments=list(compartments))


def _block(conn, case_id, owner, publisher, classification, compartments=()):
    """A contact block naming `publisher`, whose Tox line raises one
    ATTRIBUTE proposal about it. Returns that proposal's id."""
    from noctornal_api.contact_blocks import ContactBlockService
    # A fresh Tox ID each time: a block is idempotent on its text.
    tox = (uuid4().hex + uuid4().hex + uuid4().hex)[:76].upper()
    ContactBlockService(conn).parse_and_store(
        case_id=case_id, raw_text=f"TOX: {tox}",
        source_ref=f"https://forum.example/{PREFIX}{uuid4().hex[:6]}",
        created_by=owner, publisher_identity_node_id=publisher,
        classification=classification, compartments=frozenset(compartments))
    row = conn.execute(
        """SELECT id FROM collect.proposal
            WHERE case_id = %s AND kind = 'ATTRIBUTE'
              AND payload->>'node_id' = %s""",
        (case_id, str(publisher))).fetchone()
    assert row, "the block raised no ATTRIBUTE proposal"
    return row[0]


def _claims(conn, node_id) -> int:
    return conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s "
        "AND claim_path IS NOT NULL", (node_id,)).fetchone()[0]


def _state(conn, pid) -> str:
    return conn.execute("SELECT state FROM collect.proposal WHERE id = %s",
                        (pid,)).fetchone()[0]


def _capture_http(client, conn, case_id, user, classification, text=SAMPLE):
    return client.post(
        f"/api/v1/cases/{case_id}/proposals/capture", headers=_auth(conn, user),
        json={"text": text + f"\n[{uuid4().hex}]",
              "title": f"{PREFIX}{uuid4().hex[:6]}",
              "classification": classification})


def _document(conn, document_id) -> str:
    return conn.execute(
        "SELECT classification FROM collect.document WHERE id = %s",
        (document_id,)).fetchone()[0]


# ---------------------------------------------------------------------------
# c1: an ATTRIBUTE claim never lands below what it was found in
# ---------------------------------------------------------------------------

def test_a_compartmented_red_claim_is_refused_onto_a_clear_entity(conn, client):
    """The finding's reproduction: a RED contact block in a compartment,
    naming a CLEAR, compartment-free publisher. The card said TLP:RED,
    Accept wrote the Tox ID where every CLEAR reader of the entity reads
    it. Now the card says it cannot be accepted, and accept writes
    nothing, over HTTP and through the service."""
    from noctornal_api.proposals import ProposalError, ProposalReview
    owner = _user(conn, "RED", [KEY])
    case_id = _case(conn, owner, "CLEAR")
    publisher = _node(conn, case_id, owner, "trr publisher", "CLEAR")
    pid = _block(conn, case_id, owner, publisher, "RED", [KEY])
    h = _auth(conn, owner)

    r = client.post(f"/api/v1/cases/{case_id}/proposals/{pid}/accept",
                    headers=h, json={})
    assert r.status_code == 409, r.text
    assert "Nothing was written" in r.json()["detail"]
    assert _claims(conn, publisher) == 0, "the RED claim reached a CLEAR entity"
    assert _state(conn, pid) == "PROPOSED"

    body = client.get(f"/api/v1/cases/{case_id}/proposals", headers=h).json()
    card = next(p for p in body["proposals"] if p["id"] == str(pid))
    assert card["classification"] == "RED"
    blocked = card["accept_blocked"]
    assert blocked and "RED material in compartment TRR-KEY" in blocked
    assert "labelled CLEAR with no compartments" in blocked

    with pytest.raises(ProposalError, match="never accepted onto an entity"):
        ProposalReview(conn).accept(pid, reviewed_by=owner)
    assert _claims(conn, publisher) == 0 and _state(conn, pid) == "PROPOSED"


def test_a_claim_is_accepted_onto_an_entity_that_holds_its_labels(conn, client):
    """The door the refusal guards stays open: an entity at the material's
    label and compartments takes the claim, and a label alone (no
    compartments) is held the same way."""
    owner = _user(conn, "RED", [KEY])
    case_id = _case(conn, owner, "AMBER")
    h = _auth(conn, owner)

    low = _node(conn, case_id, owner, "trr amber only", "AMBER")
    pid2 = _block(conn, case_id, owner, low, "RED")
    r = client.post(f"/api/v1/cases/{case_id}/proposals/{pid2}/accept",
                    headers=h, json={})
    assert r.status_code == 409, r.text
    assert "found in RED material, and the entity" in r.json()["detail"]
    assert _claims(conn, low) == 0

    held = _node(conn, case_id, owner, "trr held", "RED", [KEY])
    pid = _block(conn, case_id, owner, held, "RED", [KEY])
    body = client.get(f"/api/v1/cases/{case_id}/proposals", headers=h).json()
    assert next(p for p in body["proposals"]
                if p["id"] == str(pid))["accept_blocked"] is None
    r = client.post(f"/api/v1/cases/{case_id}/proposals/{pid}/accept",
                    headers=h, json={})
    assert r.status_code == 200, r.text
    assert _claims(conn, held) == 1


def test_the_claim_rule_is_one_expression():
    """Pure: the route, the service and the card read one function."""
    from noctornal_api.proposals import SourceLabels, attribute_label_problem
    red_key = SourceLabels(source="RED", floor="CLEAR",
                           compartments=frozenset({"A", "B"}))
    said = attribute_label_problem({}, red_key, "RED", ["A"])
    assert said and "compartments A, B" in said and "compartment A." in said
    assert attribute_label_problem({}, red_key, "RED", ["A", "B"]) is None
    plain = SourceLabels(source=None, floor="AMBER", compartments=frozenset())
    assert attribute_label_problem({}, plain, "AMBER", []) is None
    assert attribute_label_problem({"classification": "RED"}, plain,
                                   "AMBER", []) is not None
    for text in (said,):
        assert "—" not in text and "–" not in text and "(s)" not in text


# ---------------------------------------------------------------------------
# c15: a capture is stored at no less than its case
# ---------------------------------------------------------------------------

def test_a_capture_is_stored_no_lower_than_its_case(conn, client):
    """The form's AMBER default on a RED case stored an AMBER document,
    listed to every AMBER collection reader in the deployment."""
    from noctornal_api.collection import CollectionService
    from noctornal_api.extraction import CaptureService
    owner = _user(conn, "RED")
    case_id = _case(conn, owner, "RED")
    r = _capture_http(client, conn, case_id, owner, "AMBER")
    assert r.status_code == 201, r.text
    out = r.json()
    doc = UUID(out["document_id"])
    source = CaptureService(conn).source_id()
    listed = CollectionService(conn).documents(clearance="AMBER",
                                               source_id=source, limit=500)
    assert str(doc) not in {str(d["id"]) for d in listed}, (
        "an AMBER collection reader could list a RED case's capture")
    assert _document(conn, doc) == "RED", "the document sat below its case"
    labels = {row[0] for row in conn.execute(
        "SELECT payload->>'classification' FROM collect.proposal "
        "WHERE document_id = %s", (doc,)).fetchall()}
    assert labels == {"RED"}
    assert out["classification"] == "RED"


def test_a_repaste_labels_its_own_proposals_and_leaves_the_shared_document(
        conn, client):
    """A re-paste into a stricter case labels the proposals it raises at
    that case, and leaves the one shared document where it was.

    The first fix raised the shared document as well (the verifier of the
    fix round, 2026-09-24). That protected nothing, since the same text
    was already stored at AMBER, and a proposal is read at the stricter of
    its own and its document's label: the AMBER case's pending proposals
    and their Open source view vanished from its own AMBER reviewer."""
    from noctornal_api.extraction import CaptureService
    amber_owner = _user(conn, "AMBER")
    red_owner = _user(conn, "RED")
    amber_case = _case(conn, amber_owner, "AMBER")
    red_case = _case(conn, red_owner, "RED")
    text = SAMPLE + f"\n[{uuid4().hex}]"
    svc = CaptureService(conn)
    first = svc.capture(case_id=amber_case, text=text,
                        title=f"{PREFIX}{uuid4().hex[:6]}",
                        classification="GREEN")
    assert _document(conn, first.document_id) == "AMBER"
    assert first.proposal_ids
    again = svc.capture(case_id=red_case, text=text, classification="AMBER")
    assert again.deduplicated and again.document_id == first.document_id

    # The AMBER case's own reviewer still has its queue and its source.
    h = _auth(conn, amber_owner)
    queued = {p["id"] for p in client.get(
        f"/api/v1/cases/{amber_case}/proposals", headers=h).json()["proposals"]}
    assert {str(p) for p in first.proposal_ids} <= queued, (
        "a RED case's re-paste took an AMBER case's proposals from its reviewer")
    src = client.get(f"/api/v1/cases/{amber_case}/proposals/"
                     f"{first.proposal_ids[0]}/source", headers=h)
    assert src.status_code == 200, src.text
    assert _document(conn, first.document_id) == "AMBER"

    # The re-paste's own proposals carry the stricter label, and the result
    # says which label is whose.
    assert (again.classification, again.document_classification) == (
        "RED", "AMBER")
    labels = {row[0] for row in conn.execute(
        "SELECT payload->>'classification' FROM collect.proposal "
        "WHERE case_id = %s", (red_case,)).fetchall()}
    assert labels == {"RED"}
    assert first.classification == first.document_classification == "AMBER"


def test_a_capture_reply_names_no_label_above_the_caller(conn, client):
    """The fix round's disclosure: an AMBER analyst re-pasting text first
    captured at RED (in any case) was told "RED", the label of a document
    the collection keeps from them. The labels come back null instead."""
    red_owner = _user(conn, "RED")
    amber_owner = _user(conn, "AMBER")
    red_case = _case(conn, red_owner, "RED")
    amber_case = _case(conn, amber_owner, "AMBER")
    text = SAMPLE + f"\n[{uuid4().hex}]"

    def paste(case_id, user, classification, body=text):
        return client.post(
            f"/api/v1/cases/{case_id}/proposals/capture",
            headers=_auth(conn, user),
            json={"text": body, "title": f"{PREFIX}{uuid4().hex[:6]}",
                  "classification": classification})

    first = paste(red_case, red_owner, "RED")
    assert first.status_code == 201, first.text

    r = paste(amber_case, amber_owner, "AMBER")
    assert r.status_code == 201, r.text
    assert "RED" not in r.text, "the reply named a label above its caller"
    out = r.json()
    assert out["deduplicated"] is True
    assert out["classification"] is None
    assert out["document_classification"] is None
    assert (first.json()["classification"],
            first.json()["document_classification"]) == ("RED", "RED")
    # The audit row keeps what was actually stored, for its own readers.
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE action = 'DOCUMENT_CAPTURED' AND case_id = %s""",
        (amber_case,)).fetchone()[0]
    assert detail["classification"] == "RED"

    # A caller who may read both is told both.
    other = SAMPLE + f"\n[{uuid4().hex}]"
    assert paste(amber_case, amber_owner, "AMBER", other).status_code == 201
    r = paste(red_case, red_owner, "RED", other)
    assert r.status_code == 201, r.text
    assert (r.json()["classification"],
            r.json()["document_classification"]) == ("RED", "AMBER")


def test_a_compartmented_case_refuses_a_capture(conn, client):
    """A document cannot carry compartments, so a capture into a
    compartmented case would be readable outside them at any label."""
    owner = _user(conn, "RED", [KEY])
    case_id = _case(conn, owner, "RED", [KEY])
    title = f"{PREFIX}{uuid4().hex[:6]}"
    text = SAMPLE + f"\n[{uuid4().hex}]"
    r = client.post(f"/api/v1/cases/{case_id}/proposals/capture",
                    headers=_auth(conn, owner),
                    json={"text": text, "title": title, "classification": "RED"})
    assert conn.execute("SELECT count(*) FROM collect.document WHERE title = %s",
                        (title,)).fetchone()[0] == 0, (
        "a compartmented case's capture was stored where the compartment "
        "does not reach")
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert "compartment TRR-KEY" in detail and "Nothing was captured" in detail
    from noctornal_api.extraction import CaptureRefused, CaptureService
    with pytest.raises(CaptureRefused):
        CaptureService(conn).capture(case_id=case_id, text=text, title=title,
                                     classification="RED")
    assert conn.execute("SELECT count(*) FROM collect.proposal WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0
    # The queue tells the console why its capture form is off: the case
    # record it holds does not name the case's compartments.
    q = client.get(f"/api/v1/cases/{case_id}/proposals",
                   headers=_auth(conn, owner)).json()
    assert "compartment TRR-KEY" in q["capture_refused"]
    open_case = _case(conn, owner, "RED")
    q = client.get(f"/api/v1/cases/{open_case}/proposals",
                   headers=_auth(conn, owner)).json()
    assert q["capture_refused"] is None


def test_an_unknown_capture_label_is_a_400(conn, client):
    owner = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    r = _capture_http(client, conn, case_id, owner, "PURPLE")
    assert r.status_code == 400, r.text


# ---------------------------------------------------------------------------
# u2: a read-only case waits for nobody
# ---------------------------------------------------------------------------

def test_a_closed_case_counts_nothing_as_waiting(conn, client):
    from noctornal_api.cases import CaseService
    from noctornal_api.extraction import CaptureService
    owner = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    made = CaptureService(conn).capture(
        case_id=case_id, text=SAMPLE + f"\n[{uuid4().hex}]",
        title=f"{PREFIX}{uuid4().hex[:6]}", classification="AMBER")
    assert made.proposal_ids
    h = _auth(conn, owner)
    before = client.get("/api/v1/notifications/waiting", headers=h).json()
    assert before["cases"][str(case_id)]["triage"] == len(made.proposal_ids)

    cases = CaseService(conn)
    cases.transition_status(case_id, "ACTIVE", actor_id=owner)
    cases.transition_status(case_id, "CLOSED", actor_id=owner)
    after = client.get("/api/v1/notifications/waiting", headers=h).json()
    assert after["cases"].get(str(case_id), {}).get("triage", 0) == 0, (
        "a closed case's queue, which nobody may clear, still counted as waiting")
    pid = made.proposal_ids[0]
    r = client.post(f"/api/v1/cases/{case_id}/proposals/{pid}/reject",
                    headers=h, json={"note": "closed"})
    assert r.status_code == 409, "the premise: nothing on a closed case clears it"
    # The queue itself still lists them: they are a record, not hidden.
    q = client.get(f"/api/v1/cases/{case_id}/proposals", headers=h).json()
    assert q["counts"]["PROPOSED"] == len(made.proposal_ids)


# ---------------------------------------------------------------------------
# u6: an accepted claim is dated by its capture
# ---------------------------------------------------------------------------

def test_an_entity_accepted_from_a_capture_has_a_first_seen(conn, client):
    from noctornal_api.extraction import CaptureService
    from noctornal_api.proposals import ProposalReview
    owner = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    posted = datetime(2025, 3, 2, 9, 30, tzinfo=timezone.utc)
    made = CaptureService(conn).capture(
        case_id=case_id, text=SAMPLE + f"\n[{uuid4().hex}]",
        title=f"{PREFIX}{uuid4().hex[:6]}", posted_at=posted,
        classification="AMBER")
    row = ProposalReview(conn).accept(made.proposal_ids[0], reviewed_by=owner)
    node = row.applied_node_id
    got = client.get(f"/api/v1/cases/{case_id}/nodes/{node}",
                     headers=_auth(conn, owner))
    assert got.status_code == 200, got.text
    assert got.json()["first_seen"].startswith("2025-03-02"), (
        "an entity accepted from a dated capture had no first seen")

    # A later capture's ATTRIBUTE onto the same entity moves its last seen,
    # and a capture with no posted date is dated by when it was captured.
    later = datetime(2025, 9, 1, tzinfo=timezone.utc)
    doc = CaptureService(conn).capture(
        case_id=case_id, text="nothing selector shaped " + uuid4().hex,
        title=f"{PREFIX}{uuid4().hex[:6]}", posted_at=later,
        classification="AMBER").document_id
    from noctornal_api.proposals import ProposalStore
    pid = ProposalStore(conn).propose(
        case_id=case_id, kind="ATTRIBUTE", origin="trr_test/1",
        rationale="raised by the triage review test", score=0.5,
        document_id=doc,
        payload={"node_id": str(node), "claim_path": "comms.tox",
                 "claim_value": TOX})
    ProposalReview(conn).accept(pid, reviewed_by=owner)
    got = client.get(f"/api/v1/cases/{case_id}/nodes/{node}",
                     headers=_auth(conn, owner)).json()
    assert got["last_seen"].startswith("2025-09-01"), "last seen did not move"

    undated = CaptureService(conn).capture(
        case_id=case_id, text="write to plover.trr@proton.me " + uuid4().hex,
        title=f"{PREFIX}{uuid4().hex[:6]}", classification="AMBER")
    row = ProposalReview(conn).accept(undated.proposal_ids[0], reviewed_by=owner)
    seen = conn.execute(
        "SELECT a.observed_at, d.captured_at FROM core.assertion a "
        "JOIN collect.document d ON d.id = a.document_id "
        "WHERE a.node_id = %s", (row.applied_node_id,)).fetchone()
    assert seen[0] is not None and seen[0] == seen[1]


# ---------------------------------------------------------------------------
# u12: the triage notice is labelled at the capture
# ---------------------------------------------------------------------------

def test_an_owner_below_the_capture_is_not_told_what_it_raised(conn, client):
    owner = _user(conn, "AMBER")
    analyst = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    _assign(conn, case_id, analyst, "ANALYST", owner)

    def queued():
        return conn.execute(
            "SELECT classification FROM notify.notification "
            "WHERE recipient_id = %s AND kind = 'PROPOSAL_QUEUED' "
            "AND case_id = %s", (owner, case_id)).fetchall()

    r = _capture_http(client, conn, case_id, analyst, "RED")
    assert r.status_code == 201, r.text
    assert r.json()["proposals_created"] > 0
    assert r.json()["owner_notified"] is False, (
        "an AMBER owner was told how many proposals RED material raised")
    assert queued() == []

    r = _capture_http(client, conn, case_id, analyst, "AMBER",
                      text="mail tern.trr@proton.me for terms")
    assert r.status_code == 201, r.text
    assert r.json()["owner_notified"] is True
    assert queued() == [("AMBER",)]


def test_a_red_owner_is_told_at_red(conn):
    from noctornal_api import notify_events
    owner = _user(conn, "RED")
    actor = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    assert notify_events.proposals_queued(conn, case_id=case_id, count=2,
                                          actor_id=actor, classification="RED")
    assert conn.execute(
        "SELECT classification FROM notify.notification WHERE recipient_id = %s "
        "AND kind = 'PROPOSAL_QUEUED'", (owner,)).fetchone()[0] == "RED"
