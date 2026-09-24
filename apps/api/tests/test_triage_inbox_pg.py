"""Triage, the inbox and dual control, held to what the 2026-09-22 review
found in them (the ux08-triage findings) and the owner's gap decision on
capture classification.

Each test fails on the base of 2026-09-23 and names the finding it holds:

- accept-downgrades-classification and gap-capture-classification: a
  capture's classification reaches every proposal it raises, Accept writes
  at it (never below the case), a lower label is refused, and the queue
  shows a reader only what their clearance reaches.
- graph-says-unreviewed-triage-says-nothing: the sociogram's ring is the
  queue's `pending_by_node`, and it clears when the proposal is decided.
- attribute-proposal-no-label-no-value: the queue names the entities a
  claim is about, for the ones the reader may see.
- source-document-not-reachable: a proposal carries its document and the
  source route returns the captured text with the match marked.
- stale-badges-and-list: a proposal write is announced on the live channel.
- approval-row-uuids-no-requester and approval-reach-warning-dropped: the
  listing names a merge's entities and says how many approvers were told.
- urgent-read-vs-ack-invisible: urgent and unacknowledged is counted apart
  from unread, pinned first, kept by "needs action", and says when it
  escalates.
- notifications-no-path-to-object: PROPOSAL_QUEUED names its queue, and an
  integrity alarm names its exhibit by title.
- no-work-waiting-at-sign-in: `/notifications/waiting` counts, per case,
  proposals to triage and requests this person could sign.
- quiet-hours-utc-not-local: the zone is saved with the window.

Email prefix `ti4-`, document titles `ti4-`, unique to this file.
Env-gated on DATABASE_URL; the exhibit leg also needs MINIO_ENDPOINT.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; triage and inbox are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "ti4-"
EMAIL_LIKE = f"{PREFIX}%@noctornal.test"

SAMPLE = """
Thread: re: escrow terms
spectre_lynx wrote:
  Contact me at spectre.lynx@protonmail.com or @spectre_lynx on tg.
  Payment to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, no exceptions.
  beacons to 185.220.101.42.
"""


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    ours = (f"(SELECT id FROM notify.notification "
            f"  WHERE recipient_id IN {sub} OR actor_id IN {sub} "
            f"     OR case_id IN {csub})")
    # One transaction: the deferred invariant-1 triggers fire at commit, so
    # assertions and their elements must go together.
    with c.transaction():
        esc = (f"(SELECT id FROM notify.notification WHERE kind = 'ESCALATION' "
               f"   AND object_type = 'notification' AND object_id IN {ours})")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {esc}")
        c.execute(f"DELETE FROM notify.notification WHERE id IN {esc}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {ours}")
        c.execute(f"DELETE FROM notify.notification WHERE id IN {ours}")
        c.execute(f"DELETE FROM notify.preference WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
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


def _user(conn, clearance="AMBER", name="TI4"):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", name, "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="AMBER"):
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    return CaseService(conn).create(
        code=f"OP-TI4-{uuid4().hex[:6]}", title="Triage and inbox",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification=classification)


def _assign(conn, case_id, user, role, by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user, role, by))


def _capture(conn, case_id, classification, text=SAMPLE):
    from noctornal_api.extraction import CaptureService
    # A salt makes each capture its own document: the content hash dedupes.
    return CaptureService(conn).capture(
        case_id=case_id, text=text + f"\n[{uuid4().hex}]",
        title=f"{PREFIX}{uuid4().hex[:6]}", classification=classification)


def _node(conn, case_id, owner, label, classification="AMBER"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner),
        classification=classification)


def _propose(conn, case_id, kind, payload):
    from noctornal_api.proposals import ProposalStore
    return ProposalStore(conn).propose(
        case_id=case_id, kind=kind, payload=payload, origin="ti4_test/1",
        rationale="raised by the triage and inbox test", score=0.5)


def _queue(client, conn, case_id, user, state="PROPOSED"):
    r = client.get(f"/api/v1/cases/{case_id}/proposals?state={state}",
                   headers=_auth(conn, user))
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# accept-downgrades-classification, gap-capture-classification
# ---------------------------------------------------------------------------

def test_a_capture_carries_its_classification_into_every_proposal(conn):
    owner = _user(conn, "RED")
    case_id = _case(conn, owner)
    result = _capture(conn, case_id, "RED")
    assert result.proposal_ids
    labels = {r[0] for r in conn.execute(
        "SELECT payload->>'classification' FROM collect.proposal WHERE id = ANY(%s)",
        (result.proposal_ids,)).fetchall()}
    assert labels == {"RED"}, "the capture's label never reached the payload"


def test_accept_writes_at_the_capture_and_refuses_anything_lower(conn, client):
    owner = _user(conn, "RED")
    case_id = _case(conn, owner)
    pid = _capture(conn, case_id, "RED").proposal_ids[0]
    base = f"/api/v1/cases/{case_id}/proposals/{pid}/accept"

    low = client.post(base, headers=_auth(conn, owner),
                      json={"classification": "GREEN"})
    assert low.status_code == 409, low.text
    assert "cannot be accepted at GREEN" in low.json()["detail"]
    assert conn.execute("SELECT state FROM collect.proposal WHERE id = %s",
                        (pid,)).fetchone()[0] == "PROPOSED"

    ok = client.post(base, headers=_auth(conn, owner), json={})
    assert ok.status_code == 200, ok.text
    node = ok.json()["applied_node_id"]
    assert conn.execute("SELECT classification FROM core.node WHERE id = %s",
                        (node,)).fetchone()[0] == "RED", (
        "a RED capture's selector was accepted at AMBER")


def test_accept_is_never_below_the_case_floor(conn):
    from noctornal_api.proposals import ProposalReview
    owner = _user(conn, "RED")
    case_id = _case(conn, owner, "AMBER")
    pid = _capture(conn, case_id, "GREEN").proposal_ids[0]
    row = ProposalReview(conn).accept(pid, reviewed_by=owner)
    assert conn.execute("SELECT classification FROM core.node WHERE id = %s",
                        (row.applied_node_id,)).fetchone()[0] == "AMBER"


def test_a_proposal_raised_before_the_fix_takes_its_documents_label(conn):
    """Rows already in a queue have no payload label; the document has one."""
    from noctornal_api.proposals import ProposalReview
    owner = _user(conn, "RED")
    case_id = _case(conn, owner)
    pid = _capture(conn, case_id, "RED").proposal_ids[0]
    conn.execute("UPDATE collect.proposal SET payload = payload - 'classification' "
                 "WHERE id = %s", (pid,))
    row = ProposalReview(conn).accept(pid, reviewed_by=owner)
    assert conn.execute("SELECT classification FROM core.node WHERE id = %s",
                        (row.applied_node_id,)).fetchone()[0] == "RED"


def test_the_queue_shows_a_reader_only_what_their_clearance_reaches(conn, client):
    owner = _user(conn, "RED")
    reviewer = _user(conn, "AMBER")
    case_id = _case(conn, owner)
    _assign(conn, case_id, reviewer, "REVIEWER", owner)
    red = set(_capture(conn, case_id, "RED").proposal_ids)
    amber = set(_capture(conn, case_id, "AMBER",
                         text="mail ledger.kite@proton.me for terms").proposal_ids)
    assert red and amber

    body = _queue(client, conn, case_id, reviewer)
    seen = {UUID(p["id"]) for p in body["proposals"]}
    assert seen == amber, "a RED capture's text was shown to an AMBER reader"
    assert body["counts"]["PROPOSED"] == len(amber), "the badge counts what it hides"
    assert all(p["classification"] == "AMBER" for p in body["proposals"])
    assert _queue(client, conn, case_id, owner)["counts"]["PROPOSED"] == \
        len(red) + len(amber)

    hidden = next(iter(red))
    h = _auth(conn, reviewer)
    r = client.post(f"/api/v1/cases/{case_id}/proposals/{hidden}/reject",
                    headers=h, json={"note": "never shown it"})
    assert r.status_code == 404, r.text
    r = client.get(f"/api/v1/cases/{case_id}/proposals/{hidden}/source", headers=h)
    assert r.status_code == 404, r.text
    # Accept is the same 404, whatever label is asked for. Asking for one
    # below the capture's was checked first and answered 409 "this proposal
    # came from RED material", naming the label the queue had hidden
    # (verifier's fix round, 2026-09-23).
    for asked in ({}, {"classification": "GREEN"}, {"classification": "RED"}):
        r = client.post(f"/api/v1/cases/{case_id}/proposals/{hidden}/accept",
                        headers=h, json=asked)
        assert r.status_code == 404, (asked, r.text)
        assert "RED" not in r.text, (asked, r.text)
    assert conn.execute("SELECT state FROM collect.proposal WHERE id = %s",
                        (hidden,)).fetchone()[0] == "PROPOSED"


# ---------------------------------------------------------------------------
# graph-says-unreviewed-triage-says-nothing, attribute-proposal-no-label
# ---------------------------------------------------------------------------

def test_the_ring_is_the_queue_and_clears_when_decided(conn, client):
    owner = _user(conn, "RED")
    reader = _user(conn, "AMBER")
    case_id = _case(conn, owner)
    _assign(conn, case_id, reader, "REVIEWER", owner)
    amber = _node(conn, case_id, owner, "ti4_meridian")
    red = _node(conn, case_id, owner, "ti4_bastion", "RED")
    # Every seeded edge is review=PROPOSED; none of them may ring anything.
    from noctornal_api.graph import AssertionInput, GraphWriteService
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=amber,
        dst_node_id=_node(conn, case_id, owner, "ti4_ash"), created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))
    assert _queue(client, conn, case_id, reader)["pending_by_node"] == {}

    on_amber = _propose(conn, case_id, "ATTRIBUTE",
                        {"node_id": str(amber), "claim_path": "comms.tox",
                         "claim_value": "A" * 64})
    _propose(conn, case_id, "ATTRIBUTE",
             {"node_id": str(red), "claim_path": "comms.tox",
              "claim_value": "B" * 64})
    body = _queue(client, conn, case_id, reader)
    assert body["pending_by_node"] == {str(amber): 1}, (
        "the ring named an entity the reader cannot see, or missed one")
    cards = {p["payload"]["node_id"]: p for p in body["proposals"]}
    assert cards[str(amber)]["refs"] == {
        str(amber): {"label": "ti4_meridian", "node_type": "IDENTITY"}}
    assert cards[str(red)]["refs"] == {}, "a RED entity was named to an AMBER reader"

    r = client.post(f"/api/v1/cases/{case_id}/proposals/{on_amber}/reject",
                    headers=_auth(conn, reader), json={"note": "shared service"})
    assert r.status_code == 200, r.text
    assert _queue(client, conn, case_id, reader)["pending_by_node"] == {}


def test_an_accepted_attribute_reports_its_assertion_for_undo(conn, client):
    owner = _user(conn, "RED")
    case_id = _case(conn, owner)
    node = _node(conn, case_id, owner, "ti4_kite")
    pid = _propose(conn, case_id, "ATTRIBUTE",
                   {"node_id": str(node), "claim_path": "comms.tox",
                    "claim_value": "C" * 64})
    r = client.post(f"/api/v1/cases/{case_id}/proposals/{pid}/accept",
                    headers=_auth(conn, owner), json={})
    assert r.status_code == 200, r.text
    aid = r.json()["applied_assertion_id"]
    assert aid, "nothing to undo an attribute claim with"
    undo = client.post(f"/api/v1/cases/{case_id}/assertions/{aid}/retract",
                       headers=_auth(conn, owner),
                       json={"reason": "accepted in error"})
    assert undo.status_code == 204, undo.text


# ---------------------------------------------------------------------------
# source-document-not-reachable
# ---------------------------------------------------------------------------

def test_a_proposal_opens_its_capture_at_the_match(conn, client):
    owner = _user(conn, "RED")
    case_id = _case(conn, owner)
    result = _capture(conn, case_id, "AMBER")
    body = _queue(client, conn, case_id, owner)
    card = next(p for p in body["proposals"]
                if p["payload"]["attrs"]["selector_type"] == "EMAIL")
    assert card["document_id"] == str(result.document_id)
    assert card["document_title"].startswith(PREFIX)

    r = client.get(f"/api/v1/cases/{case_id}/proposals/{card['id']}/source",
                   headers=_auth(conn, owner))
    assert r.status_code == 200, r.text
    src = r.json()
    m = src["match"]
    assert src["text"][m["start"]:m["end"]] == card["payload"]["attrs"]["raw_value"]
    assert src["title"] == card["document_title"] and src["classification"] == "AMBER"


# ---------------------------------------------------------------------------
# stale-badges-and-list
# ---------------------------------------------------------------------------

def test_a_proposal_write_is_announced_on_the_live_channel(conn):
    from noctornal_api.db import connect
    from noctornal_api.http.routers.live import CHANNEL
    from noctornal_api.proposals import CHANGE_CHANNEL
    assert CHANGE_CHANNEL == CHANNEL

    owner = _user(conn, "RED")
    case_id = _case(conn, owner)
    listener = connect()
    try:
        listener.execute(f"LISTEN {CHANNEL}")
        _capture(conn, case_id, "AMBER")
        import json
        got = [json.loads(n.payload) for n in listener.notifies(timeout=3.0,
                                                                stop_after=20)]
    finally:
        listener.close()
    mine = [g for g in got if g.get("case_id") == str(case_id)
            and g.get("kind") == "proposal"]
    assert len(mine) == 1, (
        f"a capture must announce its proposals once, not once per selector: {got}")


# ---------------------------------------------------------------------------
# approval-row-uuids-no-requester, approval-reach-warning-dropped
# ---------------------------------------------------------------------------

def test_the_approvals_listing_names_the_merge_and_its_reach(conn, client):
    from noctornal_api.approvals import ApprovalService
    owner = _user(conn, "RED", name="Ada Owner")
    analyst = _user(conn, "AMBER")
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, "ANALYST", owner)
    a = _node(conn, case_id, owner, "ti4_meridian_crew")
    b = _node(conn, case_id, owner, "ti4_bastion_crew", "RED")
    req = ApprovalService(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(a), "target_node_id": str(b),
                 "reason": "renamed", "basis_selector_id": None},
        justification="same crew, renamed", requested_by=owner)
    assert req.approvers_notified == 1

    r = client.get(f"/api/v1/cases/{case_id}/approvals",
                   headers=_auth(conn, analyst))
    assert r.status_code == 200, r.text
    row = r.json()["approvals"][0]
    assert row["subjects"]["source"] == {"label": "ti4_meridian_crew",
                                         "node_type": "IDENTITY"}
    assert row["subjects"]["target"] is None, "a RED entity was named"
    assert row["requested_by_name"] == "Ada Owner"
    assert row["approvers_notified"] == 1
    assert row["operation_description"] == "Fold one entity into another"

    # A case with nobody else who could sign: the listing keeps saying so.
    lonely = _case(conn, owner)
    c = _node(conn, lonely, owner, "ti4_x")
    d = _node(conn, lonely, owner, "ti4_y")
    req2 = ApprovalService(conn).request(
        operation="node.merge", case_id=lonely,
        payload={"source_node_id": str(c), "target_node_id": str(d),
                 "reason": "r", "basis_selector_id": None},
        justification="j", requested_by=owner)
    assert req2.approvers_notified == 0
    r = client.get(f"/api/v1/cases/{lonely}/approvals", headers=_auth(conn, owner))
    assert r.json()["approvals"][0]["approvers_notified"] == 0


# ---------------------------------------------------------------------------
# no-work-waiting-at-sign-in
# ---------------------------------------------------------------------------

def test_waiting_counts_triage_and_signatures_per_case(conn, client):
    from noctornal_api.approvals import ApprovalService
    owner = _user(conn, "AMBER")
    analyst = _user(conn, "RED")
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, "ANALYST", owner)
    amber = len(_capture(conn, case_id, "AMBER").proposal_ids)
    _capture(conn, case_id, "RED", text="write to hidden.red@proton.me")
    a = _node(conn, case_id, owner, "ti4_a")
    b = _node(conn, case_id, owner, "ti4_b")
    ApprovalService(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(a), "target_node_id": str(b),
                 "reason": "r", "basis_selector_id": None},
        justification="j", requested_by=analyst)

    r = client.get("/api/v1/notifications/waiting", headers=_auth(conn, owner))
    assert r.status_code == 200, r.text
    assert r.json()["cases"][str(case_id)] == {"triage": amber, "signatures": 1}, (
        "the RED capture was counted for an AMBER owner, or the signature missed")
    # The requester is not asked to sign their own request.
    r = client.get("/api/v1/notifications/waiting", headers=_auth(conn, analyst))
    assert r.json()["cases"][str(case_id)]["signatures"] == 0


# ---------------------------------------------------------------------------
# urgent-read-vs-ack-invisible
# ---------------------------------------------------------------------------

def test_an_urgent_item_read_but_not_acknowledged_stays_in_view(conn, client):
    from noctornal_api.notifications import NotificationService
    owner = _user(conn, "RED")
    actor = _user(conn, "RED")
    case_id = _case(conn, owner)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]
    svc = NotificationService(conn)
    alarm = svc.notify(recipient_id=owner, case_id=case_id,
                       kind="EVIDENCE_INTEGRITY_ALARM", subject=f"{code}: alarm",
                       summary="s", body="b", classification="AMBER",
                       actor_id=actor)
    later = svc.notify(recipient_id=owner, case_id=case_id, kind="MERGE_PERFORMED",
                       subject=f"{code}: merged", summary="s", body="b",
                       classification="AMBER", actor_id=actor)
    assert alarm and later
    svc.mark_read(alarm.id, owner)

    h = _auth(conn, owner)
    body = client.get("/api/v1/notifications", headers=h).json()
    assert body["notifications"][0]["id"] == str(alarm.id), (
        "the urgent item was not pinned above a newer normal one")
    top = body["notifications"][0]
    assert top["escalates_at"] and top["case_code"] == code
    assert body["unread"] == 1 and body["urgent_unacknowledged"] == 1
    count = client.get("/api/v1/notifications/unread-count", headers=h).json()
    assert count == {"unread": 1, "urgent_unacknowledged": 1}, (
        "the badge dropped to the unread count alone")

    unread = client.get("/api/v1/notifications?unread_only=true", headers=h).json()
    assert str(alarm.id) not in {n["id"] for n in unread["notifications"]}
    needs = client.get("/api/v1/notifications?needs_action=true", headers=h).json()
    assert {n["id"] for n in needs["notifications"]} == {str(alarm.id), str(later.id)}

    assert client.post(f"/api/v1/notifications/{alarm.id}/acknowledge",
                       headers=h).status_code == 204
    after = client.get("/api/v1/notifications?needs_action=true", headers=h).json()
    assert {n["id"] for n in after["notifications"]} == {str(later.id)}
    assert after["urgent_unacknowledged"] == 0
    ack = next(n for n in client.get("/api/v1/notifications", headers=h)
               .json()["notifications"] if n["id"] == str(alarm.id))
    assert ack["escalates_at"] is None


def test_escalates_at_is_the_sweeps_own_window():
    from datetime import datetime, timezone

    from noctornal_api.notifications import ESCALATE_AFTER, Notification, escalates_at
    at = datetime(2026, 9, 23, 13, 5, tzinfo=timezone.utc)
    n = Notification(id=uuid4(), recipient_id=uuid4(), case_id=None,
                     kind="EVIDENCE_INTEGRITY_ALARM", priority=1, subject="s",
                     summary="s", body="b", classification="AMBER",
                     compartments=frozenset(), object_type=None, object_id=None,
                     actor_id=None, created_at=at, read_at=None,
                     acknowledged_at=None)
    assert escalates_at(n) == at + ESCALATE_AFTER
    from dataclasses import replace
    assert escalates_at(replace(n, priority=2)) is None
    assert escalates_at(replace(n, kind="ESCALATION")) is None
    assert escalates_at(replace(n, acknowledged_at=at)) is None


# ---------------------------------------------------------------------------
# notifications-no-path-to-object
# ---------------------------------------------------------------------------

def test_the_queued_notice_names_its_queue(conn):
    from noctornal_api import notify_events
    owner = _user(conn, "RED")
    actor = _user(conn, "RED")
    case_id = _case(conn, owner)
    assert notify_events.proposals_queued(conn, case_id=case_id, count=2,
                                          actor_id=actor)
    row = conn.execute(
        "SELECT object_type, object_id FROM notify.notification "
        "WHERE recipient_id = %s AND kind = 'PROPOSAL_QUEUED'", (owner,)).fetchone()
    assert row == ("triage", case_id)


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_the_integrity_alarm_names_its_exhibit_by_title(conn, client):
    from noctornal_api import notify_events
    owner = _user(conn, "RED")
    actor = _user(conn, "RED")
    case_id = _case(conn, owner)
    up = client.post(
        f"/api/v1/cases/{case_id}/evidence", headers=_auth(conn, owner),
        files={"file": ("shot.png", b"exhibit-" + uuid4().hex.encode(), "image/png")},
        data={"title": "ti4 ransom note", "acquisition_method": "MANUAL_UPLOAD"})
    assert up.status_code == 201, up.text
    ev = UUID(up.json()["evidence_id"])
    n = notify_events.evidence_integrity_alarm(
        conn, case_id=case_id, evidence_id=ev, actor_id=actor, on_read=False)
    assert n is not None
    assert n.body.startswith(f"Exhibit 'ti4 ransom note' ({ev}) failed"), n.body
    assert "ti4 ransom note" not in n.summary, "the emailed line names no exhibit"


# ---------------------------------------------------------------------------
# quiet-hours-utc-not-local
# ---------------------------------------------------------------------------

def test_the_quiet_window_is_saved_with_its_zone(conn, client):
    from datetime import datetime, time, timezone

    from noctornal_api.notifications import NORMAL, NotificationService, deliver_after
    owner = _user(conn, "RED")
    h = _auth(conn, owner)
    r = client.put("/api/v1/notifications/preferences/SMTP", headers=h,
                   json={"enabled": True, "min_priority": 2, "digest": False,
                         "quiet_from": "22:00", "quiet_to": "07:00",
                         "timezone": "America/New_York"})
    assert r.status_code == 200, r.text
    assert r.json()["timezone"] == "America/New_York"
    pref = NotificationService(conn).preferences(owner)["SMTP"]
    # 23:30 in New York is 03:30 UTC the next day: inside the window there,
    # outside it in UTC, which is where the console's words used to put it.
    now = datetime(2026, 9, 24, 3, 30, tzinfo=timezone.utc)
    due = deliver_after(NORMAL, pref, now)
    assert due.astimezone(timezone.utc).time() == time(11, 0), due
