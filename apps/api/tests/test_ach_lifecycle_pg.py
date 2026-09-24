"""The ACH matrix over HTTP: what the usability review found it could not
say or do (ux11-ach, 2026-09-23).

- A stance's note was never returned, and a second save wiped it
  (stance-note-erased-on-rescore). It is now returned with who wrote it
  and when, kept unless the save carries a new one, and every replaced
  text is kept in the audit trail and read back as an earlier note.
- A cell scored by mistake could not go back to "not assessed", and a
  hypothesis could not be rejected, reworded or reopened from the console
  (no-hypothesis-lifecycle-in-console). Rejecting, and taking a rejection
  back, now need a reason; a rejected hypothesis is scored for the record
  and never ranked.
- The columns were numbered by rank (h-numbers-unstable-and-unlabelled).
  Each hypothesis now carries the number of its place in writing order.
- A row was a bare name (evidence-row-is-a-name-not-a-claim). It now
  carries the claim, both ends of a tie and the grade and weight.
- The report never printed a note. It now prints the notes of the cells
  it may show, and no other, and the reason recorded with each
  hypothesis's current status.
- A tie's row names both its ends, so the report's mark and compartments
  count both ends as well as the tie (the verifier's regression: a GREEN
  tie to a deleted AMBER node put the AMBER label in a GREEN document).

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ACH tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "achl-%@noctornal.test"
PASSWORD = "correct horse battery staple 1"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.hypothesis_evidence WHERE hypothesis_id IN "
                  f"(SELECT id FROM core.hypothesis WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.hypothesis WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
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


def _user(conn, name="Ada Analyst", clearance="RED"):
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"achl-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, name, PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="GREEN"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-ACHL-{uuid4().hex[:6]}", title="ACH lifecycle",
        legal_basis="production order 2026-0042",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)


def _node(conn, case_id, actor, label, *, classification="GREEN",
          grade=("C", "3"), rationale=None, compartments=None):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification, compartments=compartments,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability=grade[0], credibility=grade[1],
                                 rationale=rationale))


def _edge(conn, case_id, actor, src, dst, rationale):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=src,
        dst_node_id=dst, created_by=actor, classification="GREEN",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2",
                                 rationale=rationale))


def _assertion(conn, *, node_id=None, edge_id=None):
    column = "node_id" if node_id else "edge_id"
    return conn.execute(
        f"SELECT id FROM core.assertion WHERE {column} = %s",
        (node_id or edge_id,)).fetchone()[0]


def _add(client, auth, case_id, statement):
    r = client.post(f"/api/v1/cases/{case_id}/ach/hypotheses",
                    json={"statement": statement, "confidence": "MODERATE"},
                    headers=auth)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _put(client, auth, case_id, hid, aid, stance, **note):
    r = client.put(f"/api/v1/cases/{case_id}/ach/hypotheses/{hid}/stance",
                   json={"assertion_id": str(aid), "stance": stance, **note},
                   headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def _get(client, auth, case_id, **params):
    r = client.get(f"/api/v1/cases/{case_id}/ach", params=params, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


def _cell(body, hid, aid):
    found = [c for c in body["cells"]
             if c["hypothesis_id"] == str(hid) and c["assertion_id"] == str(aid)]
    return found[0] if found else None


def _setup(conn, client):
    owner, auth = _user(conn)
    case_id = _case(conn, owner)
    actor = _node(conn, case_id, owner, "vellum_ram",
                  rationale="handle vellum_ram posting in Meridian crew threads")
    aid = _assertion(conn, node_id=actor)
    h1 = _add(client, auth, case_id, "the same operator")
    h2 = _add(client, auth, case_id, "separate operators")
    return owner, auth, case_id, aid, h1, h2


# --- the note is shown, kept and versioned ----------------------------------

def test_a_second_save_without_a_note_keeps_the_note(conn, client):
    """The console cleared the box on every open and sent the emptiness, and
    the router wrote it: re-saving a stance erased its reasoning."""
    _, auth, case_id, aid, h1, _ = _setup(conn, client)
    _put(client, auth, case_id, h1, aid, -1, note="posting pattern breaks at the split")
    again = _put(client, auth, case_id, h1, aid, -2)          # no note field
    assert again["note"] == "posting pattern breaks at the split"

    cell = _cell(_get(client, auth, case_id), h1, aid)
    assert cell["stance"] == -2
    assert cell["note"] == "posting pattern breaks at the split"
    assert cell["note_by_name"] == "Ada Analyst"
    assert cell["note_at"].endswith("+00:00"), "an instant, in UTC"
    assert cell["earlier_notes"] == []

    details = [r[0] for r in conn.execute(
        """SELECT detail FROM audit.event WHERE object_id = %s
              AND action = 'HYPOTHESIS_STANCE' ORDER BY seq""", (h1,)).fetchall()]
    assert details[0]["note_action"] == "WRITTEN"
    assert details[0]["note"] == "posting pattern breaks at the split"
    assert details[1]["note_action"] == "KEPT" and "note" not in details[1]


def test_a_replaced_note_is_kept_as_an_earlier_version(conn, client):
    _, auth, case_id, aid, h1, _ = _setup(conn, client)
    _put(client, auth, case_id, h1, aid, -1, note="first reading")
    _put(client, auth, case_id, h1, aid, -1, note="second reading")
    cell = _cell(_get(client, auth, case_id), h1, aid)
    assert cell["note"] == "second reading"
    assert [v["note"] for v in cell["earlier_notes"]] == ["first reading"]
    assert cell["earlier_notes"][0]["by"] == "Ada Analyst"

    last = conn.execute(
        """SELECT detail FROM audit.event WHERE object_id = %s
              AND action = 'HYPOTHESIS_STANCE' ORDER BY seq DESC LIMIT 1""",
        (h1,)).fetchone()[0]
    assert last["note_was"] == "first reading" and last["note"] == "second reading"


def test_an_emptied_note_clears_it_and_the_trail_keeps_the_text(conn, client):
    _, auth, case_id, aid, h1, _ = _setup(conn, client)
    _put(client, auth, case_id, h1, aid, 1, note="a reason")
    _put(client, auth, case_id, h1, aid, 1, note="")
    cell = _cell(_get(client, auth, case_id), h1, aid)
    assert cell["note"] is None and cell["note_by_name"] is None
    assert [v["note"] for v in cell["earlier_notes"]] == ["a reason"]


# --- a cell can go back to not assessed -------------------------------------

def test_a_cell_can_be_cleared_back_to_not_assessed(conn, client):
    """"Neutral" counts as assessed and hides the gap; clearing does not,
    and the stance and its note stay in the audit trail."""
    _, auth, case_id, aid, h1, h2 = _setup(conn, client)
    _put(client, auth, case_id, h1, aid, 2, note="scored by mistake")
    _put(client, auth, case_id, h2, aid, 1)
    url = f"/api/v1/cases/{case_id}/ach/hypotheses/{h1}/stance/{aid}"
    r = client.delete(url, headers=auth)
    assert r.status_code == 200, r.text

    body = _get(client, auth, case_id)
    assert _cell(body, h1, aid) is None
    scored = {h["id"]: h for h in body["hypotheses"]}
    assert scored[h1]["assessed"] == 0 and scored[h1]["unassessed"] == 1

    cleared = conn.execute(
        """SELECT detail FROM audit.event WHERE object_id = %s
              AND action = 'HYPOTHESIS_STANCE_CLEARED'""", (h1,)).fetchone()[0]
    assert cleared["was"] == 2 and cleared["note_was"] == "scored by mistake"
    assert client.delete(url, headers=auth).status_code == 404


# --- the lifecycle ------------------------------------------------------------

def test_rejecting_needs_a_reason_and_so_does_taking_it_back(conn, client):
    _, auth, case_id, aid, h1, h2 = _setup(conn, client)
    # h1 has nothing against it, so it would lead if it were ranked.
    _put(client, auth, case_id, h1, aid, 2)
    _put(client, auth, case_id, h2, aid, -2)
    status = f"/api/v1/cases/{case_id}/ach/hypotheses/{h1}/status"

    refused = client.post(status, json={"status": "REJECTED"}, headers=auth)
    assert refused.status_code == 400 and "rules it out" in refused.text
    ok = client.post(status, json={"status": "REJECTED",
                                   "note": "the handle predates the split"},
                     headers=auth)
    assert ok.status_code == 200, ok.text

    live = _get(client, auth, case_id)
    assert [h["id"] for h in live["hypotheses"]] == [h2]
    assert _cell(live, h1, aid) is None, "a hidden column's cells are not sent"

    shown = _get(client, auth, case_id, include_rejected="true")
    by_id = {h["id"]: h for h in shown["hypotheses"]}
    assert by_id[h1]["retired"] is True and by_id[h1]["status"] == "REJECTED"
    assert by_id[h1]["status_note"] == "the handle predates the split"
    assert by_id[h1]["status_by_name"] == "Ada Analyst"
    assert shown["least_inconsistent"] == h2, (
        "a ruled-out hypothesis with nothing against it headed the ranking")
    assert shown["hypotheses"][-1]["id"] == h1, "the record follows the ranking"

    back = client.post(status, json={"status": "PROPOSED"}, headers=auth)
    assert back.status_code == 400 and "no longer stands" in back.text
    back = client.post(status, json={"status": "PROPOSED",
                                     "note": "new evidence reopens it"},
                       headers=auth)
    assert back.status_code == 200, back.text
    events = [r[0] for r in conn.execute(
        """SELECT detail FROM audit.event WHERE object_id = %s
              AND action = 'HYPOTHESIS_STATUS' ORDER BY seq""", (h1,)).fetchall()]
    assert [(e["from"], e["status"]) for e in events] == [
        ("PROPOSED", "REJECTED"), ("REJECTED", "PROPOSED")]


def test_the_numbers_follow_writing_order_not_rank(conn, client):
    """H1 is the first hypothesis written, whatever leads; and a rejected
    one keeps its number, so nobody else takes it."""
    _, auth, case_id, aid, h1, h2 = _setup(conn, client)
    h3 = _add(client, auth, case_id, "an imitator")
    _put(client, auth, case_id, h1, aid, -2)
    _put(client, auth, case_id, h2, aid, 1)
    _put(client, auth, case_id, h3, aid, 2)
    body = _get(client, auth, case_id)
    assert body["hypotheses"][0]["id"] != h1, "h1 must not lead in this setup"
    number = {h["id"]: h["number"] for h in body["hypotheses"]}
    assert number == {h1: 1, h2: 2, h3: 3}
    confidence = {h["id"]: h["confidence"] for h in body["hypotheses"]}
    assert set(confidence.values()) == {"MODERATE"}, "the confidence sent is shown"

    client.post(f"/api/v1/cases/{case_id}/ach/hypotheses/{h2}/status",
                json={"status": "REJECTED", "note": "ruled out"}, headers=auth)
    after = {h["id"]: h["number"] for h in _get(client, auth, case_id)["hypotheses"]}
    assert after == {h1: 1, h3: 3}


def test_a_hypothesis_can_be_reworded_until_it_is_scored(conn, client):
    owner, auth, case_id, aid, h1, h2 = _setup(conn, client)
    url = f"/api/v1/cases/{case_id}/ach/hypotheses/{h1}"
    r = client.patch(url, json={"statement": "the same operator, rebranded"},
                     headers=auth)
    assert r.status_code == 200, r.text
    statement = conn.execute("SELECT statement FROM core.hypothesis WHERE id = %s",
                             (h1,)).fetchone()[0]
    assert statement == "the same operator, rebranded"
    reworded = conn.execute(
        """SELECT detail FROM audit.event WHERE object_id = %s
              AND action = 'HYPOTHESIS_REWORDED'""", (h1,)).fetchone()[0]
    assert reworded == {"from": "the same operator",
                        "to": "the same operator, rebranded"}

    _put(client, auth, case_id, h1, aid, 1)
    refused = client.patch(url, json={"statement": "something else"}, headers=auth)
    assert refused.status_code == 409 and "superseded" in refused.text

    # A ruled-out hypothesis keeps the words it was ruled out in.
    client.post(f"/api/v1/cases/{case_id}/ach/hypotheses/{h2}/status",
                json={"status": "REJECTED", "note": "ruled out"}, headers=auth)
    kept = client.patch(f"/api/v1/cases/{case_id}/ach/hypotheses/{h2}",
                        json={"statement": "a softer version"}, headers=auth)
    assert kept.status_code == 409 and "as it was ruled out" in kept.text


# --- a row says what it claims ------------------------------------------------

def test_a_row_carries_its_claim_its_ends_and_its_weight(conn, client):
    owner, auth, case_id, aid, h1, h2 = _setup(conn, client)
    crew = _node(conn, case_id, owner, "Meridian crew")
    ram = conn.execute("SELECT node_id FROM core.assertion WHERE id = %s",
                       (aid,)).fetchone()[0]
    tie = _edge(conn, case_id, owner, ram, crew, "vellum_ram directing Meridian crew")
    tie_aid = _assertion(conn, edge_id=tie)
    _put(client, auth, case_id, h1, aid, 1)
    _put(client, auth, case_id, h1, tie_aid, 2)

    rows = {e["assertion_id"]: e for e in _get(client, auth, case_id)["evidence"]}
    node_row = rows[str(aid)]
    assert node_row["kind"] == "node" and node_row["subject_label"] == "vellum_ram"
    assert node_row["grade"] == "C3" and node_row["weight"] == 0.49
    assert node_row["rationale"] == "handle vellum_ram posting in Meridian crew threads"
    tie_row = rows[str(tie_aid)]
    assert tie_row["kind"] == "edge"
    assert (tie_row["src_label"], tie_row["dst_label"]) == ("vellum_ram", "Meridian crew")
    assert tie_row["edge_type"] == "COMMUNICATES_WITH" and tie_row["edge_type_name"]
    # The label the report prints names both ends, not the type alone.
    assert tie_row["label"] == (
        f"vellum_ram → {tie_row['edge_type_name']} → Meridian crew")
    assert tie_row["grade"] == "B2" and tie_row["weight"] == 0.7225
    assert tie_row["rationale"] == "vellum_ram directing Meridian crew"


# --- the report carries the notes it may show ---------------------------------

def test_the_report_prints_the_notes_of_the_cells_it_shows(conn, client):
    from noctornal_api.reports import ReportBuilder, render_markdown
    owner, auth, case_id, aid, h1, h2 = _setup(conn, client)
    hidden = _node(conn, case_id, owner, "A. Petrov (assessed identity)",
                   classification="RED")
    hidden_aid = _assertion(conn, node_id=hidden)
    _put(client, auth, case_id, h1, aid, -2, note="open reason on record")
    _put(client, auth, case_id, h2, hidden_aid, 1, note="red reason, not for GREEN")

    def build(target):
        return ReportBuilder(conn).build(case_id, target_tlp=target,
                                         generated_by=owner,
                                         include_hypotheses=True)

    green = render_markdown(build("GREEN"))
    assert "Why each stance stands where it does" in green
    assert "open reason on record" in green
    assert "red reason, not for GREEN" not in green
    assert "red reason, not for GREEN" in render_markdown(build("RED"))


def test_a_rejected_hypothesis_is_in_the_report_and_out_of_the_ranking(conn, client):
    from noctornal_api.reports import ReportBuilder
    owner, auth, case_id, aid, h1, h2 = _setup(conn, client)
    _put(client, auth, case_id, h1, aid, 2)
    _put(client, auth, case_id, h2, aid, -2)
    client.post(f"/api/v1/cases/{case_id}/ach/hypotheses/{h1}/status",
                json={"status": "REJECTED", "note": "ruled out"}, headers=auth)
    report = ReportBuilder(conn).build(case_id, target_tlp="GREEN",
                                       generated_by=owner, include_hypotheses=True)
    section = report.hypotheses
    assert {h["id"] for h in section["hypotheses"]} == {h1, h2}
    assert section["least_inconsistent"] == h2
    assert section["statuses"][h1] == "REJECTED"


def test_the_report_prints_why_a_hypothesis_was_ruled_out(conn, client):
    """The console's Reject sheet says the reason is "printed in the
    report", and the report printed only the word REJECTED: the reason sat
    in the audit trail and on the card (verifier of ux11-ach:no-hypothesis-
    lifecycle-in-console, 2026-09-23). Only the reason given with the
    CURRENT status is printed, and a SUPERSEDED hypothesis is not in the
    report at all."""
    from noctornal_api.reports import ReportBuilder, render_markdown
    owner, auth, case_id, aid, h1, h2 = _setup(conn, client)
    h3 = _add(client, auth, case_id, "an imitator")
    _put(client, auth, case_id, h1, aid, 2)
    _put(client, auth, case_id, h2, aid, -2)

    def status(hid, **body):
        r = client.post(f"/api/v1/cases/{case_id}/ach/hypotheses/{hid}/status",
                        json=body, headers=auth)
        assert r.status_code == 200, r.text

    status(h1, status="REJECTED", note="the handle | predates the split")
    # A reason given with an EARLIER status does not stand for the current one.
    status(h2, status="DISPUTED", note="two analysts read it differently")
    status(h2, status="ACCEPTED")
    status(h3, status="SUPERSEDED", note="reworded as a narrower hypothesis")

    report = ReportBuilder(conn).build(case_id, target_tlp="GREEN",
                                       generated_by=owner, include_hypotheses=True)
    assert report.hypotheses["status_notes"] == {
        h1: "the handle | predates the split"}
    md = render_markdown(report)
    assert "### The reason recorded with each status" in md
    assert ("| the same operator | REJECTED | "
            "the handle \\| predates the split |") in md, "one row, pipe escaped"
    assert "two analysts read it differently" not in md
    assert "reworded as a narrower hypothesis" not in md


# --- a tie's row marks the report with both its ends ---------------------------

def test_a_tie_row_marks_the_report_with_both_its_ends(conn, client):
    """A row names a tie as "src → type → dst", so the report's mark and
    compartments must count both ends and not the tie alone. The ends the
    projection drops (a deleted, merged or dissolved node) are counted
    nowhere else: a GREEN tie to a deleted AMBER node printed the AMBER
    label in a document marked GREEN, which the egress check then cleared
    for a GREEN destination (verifier of ux11-ach, 2026-09-23)."""
    from datetime import datetime, timezone

    from noctornal_api.graph import GraphWriteService
    from noctornal_api.reports import ReportBuilder, render_markdown
    key = "OP-ACHL"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                 "ON CONFLICT (key) DO NOTHING", (key, f"{key} (ACH test)"))
    owner, auth = _user(conn)
    case_id = _case(conn, owner)
    amber = _node(conn, case_id, owner, "Amber end of the tie",
                  classification="AMBER", compartments=[key])
    green = _node(conn, case_id, owner, "green end of the tie")
    tie = _edge(conn, case_id, owner, amber, green, "a tie between the two")
    tie_aid = _assertion(conn, edge_id=tie)
    h1 = _add(client, auth, case_id, "the same operator")
    h2 = _add(client, auth, case_id, "separate operators")
    _put(client, auth, case_id, h1, tie_aid, -2, note="the tie breaks it")
    _put(client, auth, case_id, h2, tie_aid, 2)
    GraphWriteService(conn).soft_delete_node(
        amber, case_id=case_id, deleted_by=owner, at=datetime.now(timezone.utc),
        clearance="RED", compartments=frozenset({key}))

    def build(target, read_in=frozenset()):
        return ReportBuilder(conn).build(case_id, target_tlp=target,
                                         generated_by=owner,
                                         include_hypotheses=True,
                                         compartments=read_in)

    amber_report = build("AMBER", frozenset({key}))
    md = render_markdown(amber_report)
    assert "Amber end of the tie" in md, "the row names both ends"
    assert amber_report.redaction.built_at_tlp == "AMBER", (
        "the document carries an AMBER label and is marked below it")
    assert key in amber_report.compartments
    # Below the end's level, or outside its compartment, the row is not
    # read at all, as before.
    for report in (build("GREEN", frozenset({key})), build("AMBER")):
        assert "Amber end of the tie" not in render_markdown(report)
        assert report.redaction.built_at_tlp == "GREEN"
