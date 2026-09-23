"""The competing hypotheses travel with the case header, and the matrix is
read at the reader's level.

Final review C2 (2026-09-23). `ReportBuilder.build` added the ACH section
whenever `include_hypotheses` was on, which is the default on both routes
and in the console, and three things followed:

- The section went in whether or not the case header did. A hypothesis
  statement ("OP-KESTREL is run by Ivan Petrov") is free text about the
  case with no label of its own, so a RED case prepared at GREEN with the
  console's defaults saved a TLP:CLEAR file naming the operation and its
  suspect, and the egress gate permitted it.
- The document's mark ignored the section entirely.
- The matrix's cells were read with no classification or compartment
  filter, in the report and in GET /ach alike: an AMBER analyst received
  a RED node's label as `evidence[].label` while the graph hid it, and
  above-ceiling stances moved the printed scores.

The F19 laundering test passed `include_hypotheses=False`, so none of this
was reachable from a test. Every test here builds with it ON.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; report tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "rhy-%@noctornal.test"
PASSWORD = "correct horse battery staple 1"
SUSPECT = "OP-HYPOTHESIS is run by Ivan Petrov"
SECRET_LABEL = "A. Petrov (assessed identity)"


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


def _user(conn, clearance="RED", compartments=()):
    """A TOTP-enrolled analyst with a fresh sign-in; returns (id, token)."""
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    for key in compartments:
        conn.execute(
            "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
            "ON CONFLICT (key) DO NOTHING", (key, f"{key} (report test)"))
    email = f"rhy-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Reporter", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="GREEN"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-RHY-{uuid4().hex[:6]}", title="Hypotheses",
        legal_basis="production order 2026-0042",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)


def _node(conn, case_id, actor, label, classification="GREEN", compartments=None):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification, compartments=compartments,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"))


def _edge(conn, case_id, actor, src, dst, classification="GREEN"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=src,
        dst_node_id=dst, created_by=actor, classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"))


def _assertion(conn, *, node_id=None, edge_id=None):
    column = "node_id" if node_id else "edge_id"
    return conn.execute(
        f"SELECT id FROM core.assertion WHERE {column} = %s",
        (node_id or edge_id,)).fetchone()[0]


def _hypothesis(conn, case_id, actor, statement):
    return conn.execute(
        """INSERT INTO core.hypothesis (case_id, statement, created_by)
           VALUES (%s, %s, %s) RETURNING id""",
        (case_id, statement, actor)).fetchone()[0]


def _stance(conn, hypothesis_id, assertion_id, stance):
    conn.execute(
        """INSERT INTO core.hypothesis_evidence
               (hypothesis_id, assertion_id, stance) VALUES (%s, %s, %s)""",
        (hypothesis_id, assertion_id, stance))


def _build(conn, case_id, owner, target, compartments=frozenset()):
    from noctornal_api.reports import ReportBuilder
    return ReportBuilder(conn).build(
        case_id, target_tlp=target, generated_by=owner,
        include_hypotheses=True, compartments=compartments)


# --- the statements go with the header ------------------------------------

def test_a_red_case_prepared_at_green_does_not_carry_its_hypotheses(conn):
    """The finding's own reproduction, with hypotheses ON."""
    from noctornal_api.egress import Destination
    from noctornal_api.reports import check_egress, render_markdown

    owner, _ = _user(conn)
    case_id = _case(conn, owner, classification="RED")
    _hypothesis(conn, case_id, owner, SUSPECT)
    _hypothesis(conn, case_id, owner, "a second, rival theory")

    report = _build(conn, case_id, owner, "GREEN")
    document = render_markdown(report)

    assert report.redaction.header_withheld
    assert SUSPECT not in document, "the hypothesis left with the header withheld"
    assert SUSPECT not in repr(report.as_dict())
    assert report.hypotheses == {}
    # Counted, and said where the section would be, so a reader does not
    # take the missing section for "no alternatives were considered".
    assert report.redaction.hypotheses_withheld == 2
    assert "2 competing hypothes" in report.redaction.statement()
    assert "## Competing hypotheses" in document
    assert "withheld with the case header" in document
    # Nothing of the case's own is in it, so it may still leave: what must
    # not happen is the case's material leaving under that mark.
    assert report.redaction.built_at_tlp == "CLEAR"
    assert check_egress(report, Destination.EXPORT).allowed


def test_a_superseded_hypothesis_is_not_counted(conn):
    owner, _ = _user(conn)
    case_id = _case(conn, owner, classification="RED")
    hid = _hypothesis(conn, case_id, owner, SUSPECT)
    conn.execute("UPDATE core.hypothesis SET status = 'SUPERSEDED' WHERE id = %s",
                 (hid,))
    assert _build(conn, case_id, owner, "GREEN").redaction.hypotheses_withheld == 0


def test_left_out_by_choice_is_not_reported_as_withheld(conn):
    """A document prepared with hypotheses OFF withheld nothing: saying so
    would misstate why the section is missing."""
    from noctornal_api.reports import ReportBuilder
    owner, _ = _user(conn)
    case_id = _case(conn, owner, classification="RED")
    _hypothesis(conn, case_id, owner, SUSPECT)
    report = ReportBuilder(conn).build(
        case_id, target_tlp="GREEN", generated_by=owner,
        include_hypotheses=False)
    assert report.redaction.hypotheses_withheld == 0


def test_a_case_whose_header_goes_in_keeps_its_hypotheses(conn):
    """The counterpart, without which the test above passes on a builder
    that never includes hypotheses."""
    from noctornal_api.reports import render_markdown
    owner, _ = _user(conn)
    case_id = _case(conn, owner, classification="AMBER")
    _hypothesis(conn, case_id, owner, SUSPECT)
    report = _build(conn, case_id, owner, "AMBER")
    assert not report.redaction.header_withheld
    assert SUSPECT in render_markdown(report)
    assert report.redaction.hypotheses_withheld == 0
    assert report.redaction.built_at_tlp == "AMBER"


def test_the_release_with_the_console_defaults_saves_no_statement(conn, client):
    """End to end on the one route to a file: a Lead investigator on a RED
    case asks for GREEN, export, hypotheses on (the console's defaults)."""
    owner, token = _user(conn)
    case_id = _case(conn, owner, classification="RED")
    _hypothesis(conn, case_id, owner, SUSPECT)
    r = client.post(f"/api/v1/cases/{case_id}/report/release",
                    json={"target_tlp": "GREEN", "destination": "export",
                          "include_hypotheses": True, "preset": "all"},
                    headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert SUSPECT not in body["document"]
    assert "withheld with the case header" in body["document"]
    assert "competing hypothes" in body["redaction"]


# --- the matrix is read at the reader's level ------------------------------

def _matrix_with_a_red_stance(conn):
    """A GREEN case: an open actor, a RED one, two hypotheses. The RED
    assertion strongly contradicts the first hypothesis; the open one is
    scored against both."""
    owner, token = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    visible = _node(conn, case_id, owner, "open_actor")
    hidden = _node(conn, case_id, owner, SECRET_LABEL, classification="RED")
    h1 = _hypothesis(conn, case_id, owner, "the broker is the developer")
    h2 = _hypothesis(conn, case_id, owner, "the broker is a reseller")
    _stance(conn, h1, _assertion(conn, node_id=visible), 1)
    _stance(conn, h2, _assertion(conn, node_id=visible), 1)
    _stance(conn, h1, _assertion(conn, node_id=hidden), -2)
    _stance(conn, h2, _assertion(conn, node_id=hidden), 1)
    return owner, token, case_id, h1


def test_an_above_ceiling_stance_neither_labels_nor_scores(conn):
    from noctornal_api.reports import render_markdown
    owner, _, case_id, h1 = _matrix_with_a_red_stance(conn)

    green = _build(conn, case_id, owner, "GREEN")
    labels = {e["label"] for e in green.hypotheses["evidence"]}
    assert labels == {"open_actor"}
    assert SECRET_LABEL not in repr(green.as_dict())
    scored = {h["id"]: h for h in green.hypotheses["hypotheses"]}
    assert scored[str(h1)]["inconsistency"] == 0.0, (
        "a RED stance moved a score printed in a GREEN document")
    assert green.redaction.hypothesis_evidence_withheld == 1
    assert "hypothesis matrix" in green.redaction.statement()
    assert SECRET_LABEL not in render_markdown(green)

    # The counterpart: a reader at RED sees it and it counts.
    red = _build(conn, case_id, owner, "RED")
    assert SECRET_LABEL in {e["label"] for e in red.hypotheses["evidence"]}
    scored = {h["id"]: h for h in red.hypotheses["hypotheses"]}
    assert scored[str(h1)]["inconsistency"] > 0
    assert red.redaction.hypothesis_evidence_withheld == 0


def test_a_case_that_discloses_nothing_still_filters_but_does_not_count(conn):
    """Under the case's NONE setting (0030) the entity counts are never
    computed, so the matrix count is not either; the filter itself does
    not depend on the setting."""
    owner, _, case_id, h1 = _matrix_with_a_red_stance(conn)
    conn.execute("""UPDATE core."case" SET withheld_disclosure = 'NONE'
                     WHERE id = %s""", (case_id,))
    green = _build(conn, case_id, owner, "GREEN")
    assert SECRET_LABEL not in repr(green.as_dict())
    scored = {h["id"]: h for h in green.hypotheses["hypotheses"]}
    assert scored[str(h1)]["inconsistency"] == 0.0
    assert green.redaction.hypothesis_evidence_withheld == 0


def test_a_tie_to_an_above_ceiling_end_is_left_out(conn):
    """The projection admits a tie only when both ends are visible, and a
    rationale written about a tie can name either end."""
    owner, _ = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    a = _node(conn, case_id, owner, "open_actor")
    b = _node(conn, case_id, owner, SECRET_LABEL, classification="RED")
    edge = _edge(conn, case_id, owner, a, b, classification="GREEN")
    h1 = _hypothesis(conn, case_id, owner, "they are one person")
    _stance(conn, h1, _assertion(conn, edge_id=edge), 2)

    green = _build(conn, case_id, owner, "GREEN")
    assert green.hypotheses["evidence"] == []
    assert green.redaction.hypothesis_evidence_withheld == 1
    red = _build(conn, case_id, owner, "RED")
    assert len(red.hypotheses["evidence"]) == 1


def test_a_compartmented_stance_follows_the_read_in(conn):
    """And what it draws on joins the document's compartments, so the gate
    can refuse it."""
    owner, _ = _user(conn, compartments=("OP-RHY",))
    case_id = _case(conn, owner, classification="GREEN")
    node = _node(conn, case_id, owner, "compartmented_actor",
                 compartments=["OP-RHY"])
    h1 = _hypothesis(conn, case_id, owner, "a theory")
    _stance(conn, h1, _assertion(conn, node_id=node), -1)

    outside = _build(conn, case_id, owner, "RED")
    assert outside.hypotheses["evidence"] == []
    assert outside.redaction.hypothesis_evidence_withheld == 1
    inside = _build(conn, case_id, owner, "RED", frozenset({"OP-RHY"}))
    assert [e["label"] for e in inside.hypotheses["evidence"]] == [
        "compartmented_actor"]
    assert "OP-RHY" in inside.compartments


def test_the_mark_counts_an_element_only_the_matrix_carries(conn):
    """A stance can rest on an element the projection does not return: a
    retired node keeps its live assertion. Its label is in the matrix, so
    its classification is in the mark."""
    from noctornal_api.graph import GraphWriteService
    owner, _ = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    node = _node(conn, case_id, owner, "retired_actor", classification="AMBER")
    h1 = _hypothesis(conn, case_id, owner, "a theory")
    _stance(conn, h1, _assertion(conn, node_id=node), -1)
    GraphWriteService(conn).soft_delete_node(
        node, case_id=case_id, deleted_by=owner,
        at=datetime.now(timezone.utc), clearance="RED", compartments=[])

    report = _build(conn, case_id, owner, "AMBER")
    assert report.actors == []
    assert [e["label"] for e in report.hypotheses["evidence"]] == ["retired_actor"]
    assert report.redaction.built_at_tlp == "AMBER"


# --- GET /ach reads through the same filter -------------------------------

def test_the_live_matrix_hides_what_the_graph_hides(conn, client):
    """An AMBER analyst on the case received the RED node's label here while
    every graph, list and search view hid it."""
    owner, owner_token, case_id, h1 = _matrix_with_a_red_stance(conn)
    analyst, analyst_token = _user(conn, clearance="AMBER")
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, analyst, owner))

    seen = client.get(f"/api/v1/cases/{case_id}/ach",
                      headers=_auth(analyst_token))
    assert seen.status_code == 200, seen.text
    body = seen.json()
    assert SECRET_LABEL not in seen.text
    assert {e["label"] for e in body["evidence"]} == {"open_actor"}
    assert len(body["cells"]) == 2
    scored = {h["id"]: h for h in body["hypotheses"]}
    assert scored[str(h1)]["inconsistency"] == 0.0

    full = client.get(f"/api/v1/cases/{case_id}/ach",
                      headers=_auth(owner_token)).json()
    assert SECRET_LABEL in {e["label"] for e in full["evidence"]}
    assert len(full["cells"]) == 4
