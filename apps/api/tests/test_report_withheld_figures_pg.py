"""The report builder states each figure as the case's withheld-disclosure
setting allows, and tells `Redaction` which setting it built under.

Beta 1.1 group C (2026-10-08), the report residuals:

- the builder did not pass the setting on, so a statement could not tell
  "nothing was above the ceiling" from "this case says nothing about it";
- under PRESENCE the entity count, the relationship count and the hypothesis
  matrix's evidence count were still printed exactly;
- under NONE a document that had left entities, ties or exhibits out opened
  with "nothing has been withheld".

The rules of the sentence itself are in `test_report_redaction_statement.py`; this
file holds them to what the builder does with a real case. The case has 3
entities, 4 ties and 2 exhibits above a GREEN ceiling, and one stance in the
hypothesis matrix that rests on them, so every figure differs from every
other and a number cannot be read from the wrong place.

Env-gated on DATABASE_URL. Accounts `g79r-*`.
"""
from __future__ import annotations

import json
import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; report tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "g79r-%@noctornal.test"
PASSWORD = "correct horse battery staple 1"
SECRET = "the assessed identity behind OP-FIGURES"
HIDDEN_NODES, HIDDEN_EDGES, HIDDEN_EXHIBITS = 3, 4, 2


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
    pinned_users = (
        "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
        " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
        ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
        ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL)')
    with c.transaction():
        c.execute(f"DELETE FROM core.hypothesis_evidence WHERE hypothesis_id IN "
                  f"(SELECT id FROM core.hypothesis WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.hypothesis WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}' "
                  f"AND id NOT IN {pinned_users}")
    c.close()


@pytest.fixture
def builder(conn):
    from noctornal_api.reports import ReportBuilder
    return ReportBuilder(conn)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn):
    """A TOTP-enrolled analyst cleared to RED with a fresh sign-in. Returns
    (id, session token)."""
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    store = PgUserStore(conn)
    uid = store.create_user(f"g79r-{uuid4().hex[:8]}@noctornal.test",
                            "Reporter", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, token


def _case(conn, owner, classification="GREEN"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-G79R-{uuid4().hex[:6]}", title="Figures",
        legal_basis="production order 2026-0042",
        authority_ref="WARRANT-2026-79",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)


def _node(conn, case_id, actor, label, classification="GREEN"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"))


def _tie(conn, case_id, actor, src, dst):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=src,
        dst_node_id=dst, created_by=actor, classification="GREEN",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"))


def _exhibits(conn, case_id, owner, *classifications):
    for i, tlp in enumerate(classifications):
        conn.execute(
            """INSERT INTO core.evidence
                   (case_id, title, media_type, byte_size, sha256, blake3,
                    storage_key, storage_bucket, acquired_by, acquired_at,
                    acquisition_method, classification)
               VALUES (%s, %s, 'text/plain', 1, %s, %s, 'k', 'b', %s, now(),
                       'MANUAL_UPLOAD', %s)""",
            (case_id, f"exhibit {i}", os.urandom(32), os.urandom(32), owner,
             tlp))


def _world(conn, *, hidden: bool = True):
    """A GREEN case with one open entity and, when `hidden`, material above
    a GREEN ceiling: 3 entities, 4 ties and 2 exhibits, and a stance in the
    hypothesis matrix that rests on one of the entities. Returns (owner id,
    session token, case id)."""
    owner, token = _user(conn)
    case_id = _case(conn, owner)
    open_node = _node(conn, case_id, owner, "open actor")
    _exhibits(conn, case_id, owner, "GREEN")
    if not hidden:
        return owner, token, case_id
    reds = [_node(conn, case_id, owner, f"{SECRET} {i}", "RED")
            for i in range(HIDDEN_NODES)]
    for end in reds:
        _tie(conn, case_id, owner, open_node, end)
    _tie(conn, case_id, owner, reds[0], reds[1])
    _exhibits(conn, case_id, owner, *["RED"] * HIDDEN_EXHIBITS)
    hypothesis = conn.execute(
        """INSERT INTO core.hypothesis (case_id, statement, created_by)
           VALUES (%s, 'a theory the above-ceiling material bears on', %s)
           RETURNING id""", (case_id, owner)).fetchone()[0]
    assertion = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s",
        (reds[0],)).fetchone()[0]
    conn.execute(
        """INSERT INTO core.hypothesis_evidence
               (hypothesis_id, assertion_id, stance) VALUES (%s, %s, 2)""",
        (hypothesis, assertion))
    return owner, token, case_id


def _set(conn, case_id, mode):
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 (mode, case_id))


def _build(builder, case_id, owner, ceiling="GREEN"):
    return builder.build(case_id, target_tlp=ceiling, generated_by=owner,
                         include_hypotheses=True)


# --- the three settings ---------------------------------------------------------

def test_under_count_every_figure_is_the_number(conn, builder):
    owner, _, case_id = _world(conn)
    _set(conn, case_id, "COUNT")
    r = _build(builder, case_id, owner).redaction

    assert r.disclosure == "COUNT"
    assert (r.nodes_withheld, r.edges_withheld, r.evidence_withheld) == (
        HIDDEN_NODES, HIDDEN_EDGES, HIDDEN_EXHIBITS)
    assert r.hypothesis_evidence_withheld == 1
    assert not (r.nodes_some_withheld or r.edges_some_withheld
                or r.evidence_some_withheld
                or r.hypothesis_evidence_some_withheld), (
        "COUNT states the figure, so no 'some' flag is raised beside it")
    text = r.statement()
    assert "3 entities, 4 relationships and 2 exhibits are above that level" in text
    assert "1 item of evidence in the hypothesis matrix rests on that material" in text


def test_under_presence_every_figure_is_that_there_are_some(conn, builder):
    """Before 2026-10-08 the exhibit figure was 'some' and the entity,
    relationship and matrix figures were still 3, 4 and 1."""
    owner, _, case_id = _world(conn)
    _set(conn, case_id, "PRESENCE")
    report = _build(builder, case_id, owner)
    r = report.redaction

    assert r.disclosure == "PRESENCE"
    assert (r.nodes_withheld, r.edges_withheld, r.evidence_withheld,
            r.hypothesis_evidence_withheld) == (0, 0, 0, 0), (
        "a figure was stated exactly under PRESENCE")
    assert (r.nodes_some_withheld, r.edges_some_withheld, r.evidence_some_withheld,
            r.hypothesis_evidence_some_withheld) == (True, True, True, True)
    text = r.statement()
    assert ("Some entities, some relationships and some exhibits are above "
            "that level and have been withheld.") in text
    assert "Some items of evidence in the hypothesis matrix rest" in text
    # Neither the number of any kind nor a number at all.
    for figure in (HIDDEN_NODES, HIDDEN_EDGES, HIDDEN_EXHIBITS):
        assert f"{figure} " not in text
    block = report.as_dict()["redaction"]
    assert [block[k] for k in ("nodes_withheld", "edges_withheld",
                               "evidence_withheld",
                               "hypothesis_evidence_withheld")] == [0, 0, 0, 0]


def test_under_none_the_statement_says_neither_that_something_was_nor_that_nothing_was(
        conn, builder):
    owner, _, case_id = _world(conn)
    _set(conn, case_id, "NONE")
    r = _build(builder, case_id, owner).redaction

    assert r.disclosure == "NONE"
    assert (r.nodes_withheld, r.edges_withheld, r.evidence_withheld,
            r.hypothesis_evidence_withheld) == (0, 0, 0, 0)
    assert not (r.nodes_some_withheld or r.edges_some_withheld
                or r.evidence_some_withheld
                or r.hypothesis_evidence_some_withheld)
    assert not r.anything_withheld
    text = r.statement()
    assert "nothing has been withheld" not in text, (
        "the document said nothing was withheld, with material left out of it")
    assert "have been withheld" not in text
    assert "does not say whether any material above it exists" in text


def test_the_none_statement_is_the_same_whether_or_not_anything_is_hidden(
        conn, builder):
    """The one property that makes NONE mean nothing: a reader cannot tell
    a case holding material above their ceiling from one that does not."""
    owner, _, hidden_case = _world(conn)
    _set(conn, hidden_case, "NONE")
    plain_owner, _, plain_case = _world(conn, hidden=False)
    _set(conn, plain_case, "NONE")

    hidden = _build(builder, hidden_case, owner)
    plain = _build(builder, plain_case, plain_owner)

    assert hidden.redaction.statement() == plain.redaction.statement()
    a, b = hidden.as_dict()["redaction"], plain.as_dict()["redaction"]
    assert a == b, {k: (a[k], b[k]) for k in a if a[k] != b[k]}


@pytest.mark.parametrize("mode", ["PRESENCE", "COUNT"])
def test_nothing_has_been_withheld_is_said_only_of_a_document_that_withheld_nothing(
        conn, builder, mode):
    owner, _, plain_case = _world(conn, hidden=False)
    _set(conn, plain_case, mode)
    clean = _build(builder, plain_case, owner).redaction
    assert not clean.anything_withheld
    assert "nothing has been withheld from it" in clean.statement()

    owner, _, hidden_case = _world(conn)
    _set(conn, hidden_case, mode)
    partial = _build(builder, hidden_case, owner).redaction
    assert partial.anything_withheld
    assert "nothing has been withheld" not in partial.statement()


def test_a_ceiling_that_reaches_everything_withholds_nothing_in_any_setting(
        conn, builder):
    for mode in ("NONE", "PRESENCE", "COUNT"):
        owner, _, case_id = _world(conn)
        _set(conn, case_id, mode)
        r = _build(builder, case_id, owner, ceiling="RED").redaction
        assert (r.nodes_withheld, r.edges_withheld, r.evidence_withheld) == (0, 0, 0)
        assert not (r.nodes_some_withheld or r.edges_some_withheld
                    or r.evidence_some_withheld
                    or r.hypothesis_evidence_some_withheld), mode


# --- what the document and its audit row hold ------------------------------------

@pytest.mark.parametrize("mode", ["NONE", "PRESENCE", "COUNT"])
def test_the_rendered_document_carries_no_figure_the_setting_does_not_allow(
        conn, builder, mode):
    from noctornal_api.reports import render_markdown
    owner, _, case_id = _world(conn)
    _set(conn, case_id, mode)
    report = _build(builder, case_id, owner)
    document = render_markdown(report)
    body = json.dumps(report.as_dict()["redaction"])

    assert SECRET not in document and SECRET not in body
    for mark in (chr(0x2014), chr(0x2013), "(s)"):
        assert mark not in document, (mode, mark)
    counted = "3 entities, 4 relationships and 2 exhibits"
    assert (counted in report.redaction.statement()) is (mode == "COUNT")
    assert (counted in document) is (mode == "COUNT")


def test_the_generation_audit_row_records_the_setting_beside_the_figures(
        conn, client):
    """`REPORT_GENERATED` records the three figures the document stated. A 0
    under NONE or PRESENCE is 'not stated', so the setting is on the row and
    a reviewer does not read 'nothing was withheld' out of it."""
    owner, token, case_id = _world(conn)
    _set(conn, case_id, "PRESENCE")

    answer = client.post(
        f"/api/v1/cases/{case_id}/report",
        params={"target_tlp": "GREEN", "preset": "all",
                "include_hypotheses": "true"},
        headers={"Authorization": f"Bearer {token}"})
    assert answer.status_code == 200, answer.text
    redaction = answer.json()["redaction"]
    assert redaction["disclosure"] == "PRESENCE"
    assert redaction["nodes_withheld"] == 0
    assert redaction["nodes_some_withheld"] is True
    assert redaction["edges_some_withheld"] is True

    [(detail,)] = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'REPORT_GENERATED' "
        "AND case_id = %s", (case_id,)).fetchall()
    assert detail["disclosure"] == "PRESENCE"
    assert (detail["nodes_withheld"], detail["edges_withheld"],
            detail["evidence_withheld"]) == (0, 0, 0)
