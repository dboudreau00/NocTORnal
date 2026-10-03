"""`valid_to` can be set where the console says it can
(graph-valid-to-cannot-be-set-after-creation, review 2026-10-03).

The Retire dialog and the docstrings of the retirement endpoint told the
analyst that to say "this stopped being true in March" they should set
`valid_to`, and no endpoint could: `valid_from` and `valid_to` were taken
by `POST /nodes` and `POST /edges` only, and a `PATCH` carrying one was
dropped by pydantic. The one thing left was retiring the element, which
removes it from every as-of view and which the same dialog says is the
wrong tool.

The decision (2026-10-03): the date is a correction like any
other. `PATCH /graph/nodes/{id}` and `PATCH /graph/edges/{id}` take
`valid_to`; it is recorded as a graded claim (`claim_path` `valid_to`) with
the previous value in the audit row and in the claim's `prior_value`, so
retracting it puts the old date back. A date is sent with its UTC offset
(it is the instant the as-of view and trust decay are drawn from), `null`
clears it, leaving it out leaves it alone.

Email prefix `g43e-`. Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import review_graph_support as g
import rls_support as s

pytestmark = s.GATED

PREFIX = "g43e-"
MARCH = "2026-03-01T23:59:59Z"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    g.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def w(owner):
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    s.assign(owner, case_id, analyst, "ANALYST")
    alpha = s.node(owner, case_id, boss, "alpha")
    beta = s.node(owner, case_id, boss, "beta")
    tie = s.edge(owner, case_id, boss, alpha, beta)
    return {"case": case_id, "boss": boss, "analyst": analyst, "alpha": alpha,
            "beta": beta, "tie": tie, "owner": owner, "client": g.make_client(),
            "h": g.auth(owner, boss), "ha": g.auth(owner, analyst)}


def _patch(w, kind: str, element, body: dict, rationale="ended in March", headers=None):
    return w["client"].patch(
        f"/api/v1/cases/{w['case']}/graph/{kind}s/{element}",
        headers=headers or w["h"], json={**body, "assertion": g.grade(rationale)})


def _node_end(w, node=None):
    return w["owner"].execute("SELECT valid_to FROM core.node WHERE id = %s",
                              (node or w["alpha"],)).fetchone()[0]


def _tie_end(w):
    return w["owner"].execute("SELECT valid_to FROM core.edge WHERE id = %s",
                              (w["tie"],)).fetchone()[0]


def _march():
    return datetime(2026, 3, 1, 23, 59, 59, tzinfo=timezone.utc)


# --- a node ------------------------------------------------------------------

def test_a_node_end_date_is_set_by_a_correction_and_recorded_as_a_claim(w):
    """Before: 400 'nothing to update: pass label and/or attrs' for a body
    carrying only valid_to, and the date silently dropped beside a label."""
    claims_before = g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                          (w["alpha"],))
    r = _patch(w, "node", w["alpha"], {"valid_to": MARCH})
    assert r.status_code == 200, r.text
    assert r.json()["updated"] == ["valid_to"]
    assert _node_end(w) == _march()
    assert w["owner"].execute("SELECT label FROM core.node WHERE id = %s",
                              (w["alpha"],)).fetchone()[0] == "alpha"
    claim = w["owner"].execute(
        """SELECT claim_path, claim_value, prior_value, rationale, created_by
             FROM core.assertion WHERE node_id = %s AND claim_path = 'valid_to'""",
        (w["alpha"],)).fetchone()
    assert claim == ("valid_to", {"valid_to": "2026-03-01T23:59:59+00:00"},
                     {"valid_to": None}, "ended in March", w["boss"])
    assert g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                 (w["alpha"],)) == claims_before + 1
    audit = w["owner"].execute(
        "SELECT detail FROM audit.event WHERE action = 'NODE_UPDATED' AND object_id = %s",
        (w["alpha"],)).fetchone()[0]
    assert audit == {"fields": ["valid_to"], "previous": {"valid_to": None}}


def test_a_label_and_an_end_date_are_one_correction(w):
    r = _patch(w, "node", w["alpha"], {"label": "alpha ended", "valid_to": MARCH})
    assert r.status_code == 200, r.text
    assert r.json()["updated"] == ["label", "valid_to"]
    path, value = w["owner"].execute(
        "SELECT claim_path, claim_value FROM core.assertion WHERE node_id = %s "
        "AND claim_value IS NOT NULL", (w["alpha"],)).fetchone()
    assert path is None and set(value) == {"label", "valid_to"}


def test_the_end_date_moves_and_clears_and_is_otherwise_left_alone(w):
    assert _patch(w, "node", w["alpha"], {"valid_to": MARCH}).status_code == 200
    # a correction that does not mention it leaves it
    assert _patch(w, "node", w["alpha"], {"label": "renamed"}).status_code == 200
    assert _node_end(w) == _march()
    # a new date replaces it, and the audit row keeps the old one
    assert _patch(w, "node", w["alpha"], {"valid_to": "2026-05-01T00:00:00Z"}
                  ).status_code == 200
    previous = [r[0]["previous"] for r in w["owner"].execute(
        "SELECT detail FROM audit.event WHERE action = 'NODE_UPDATED' "
        "AND object_id = %s ORDER BY seq", (w["alpha"],)).fetchall()]
    assert previous == [{"valid_to": None}, {"label": "alpha"},
                        {"valid_to": "2026-03-01T23:59:59+00:00"}]
    # null clears it
    r = _patch(w, "node", w["alpha"], {"valid_to": None})
    assert r.status_code == 200, r.text
    assert _node_end(w) is None


def test_the_as_of_view_keeps_the_past_and_the_live_view_keeps_the_entity(w):
    """The point of the date: unlike a retirement, an as-of query into the
    period when the entity was true still shows it."""
    from noctornal_api.projections import GraphService, Projection
    assert _patch(w, "node", w["alpha"], {"valid_to": MARCH}).status_code == 200
    service = GraphService(w["owner"], clearance="RED", compartments=frozenset())

    def shown(as_of):
        sub = service.project(Projection(case_id=w["case"], as_of=as_of))
        return {n["id"] for n in sub.nodes}

    february = datetime(2026, 2, 1, tzinfo=timezone.utc)
    april = datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert w["alpha"] in shown(february)
    assert w["alpha"] not in shown(april)
    assert w["alpha"] in shown(None)
    assert w["beta"] in shown(april)


def test_a_date_before_the_entity_began_is_refused_and_writes_nothing(w):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    started = GraphWriteService(w["owner"]).create_node(
        case_id=w["case"], node_type="IDENTITY", label="began in April",
        created_by=w["boss"], valid_from=datetime(2026, 4, 1, tzinfo=timezone.utc),
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=w["boss"]))
    claims = g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                   (started,))
    r = _patch(w, "node", started, {"valid_to": MARCH})
    assert r.status_code == 400, r.text
    assert "valid_to is before valid_from" in r.json()["detail"]
    assert _node_end(w, started) is None
    assert g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                 (started,)) == claims


def test_a_date_without_an_offset_is_refused_not_guessed(w):
    r = _patch(w, "node", w["alpha"], {"valid_to": "2026-03-01T23:59:59"})
    assert r.status_code == 400, r.text
    assert "UTC offset" in r.json()["detail"]
    assert _node_end(w) is None


def test_an_empty_correction_is_still_refused_whole(w):
    claims = g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                   (w["alpha"],))
    r = _patch(w, "node", w["alpha"], {})
    assert r.status_code == 400, r.text
    assert "valid_to" in r.json()["detail"]
    assert g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                 (w["alpha"],)) == claims


def test_an_entity_the_caller_cannot_see_reads_as_it_does_for_any_correction(w):
    """The same gate as every other PATCH: a RED entity is refused to an
    AMBER analyst in the same words whether the body carries a label or a
    date."""
    red = s.node(w["owner"], w["case"], w["boss"], "a red entity", "RED")
    by_label = _patch(w, "node", red, {"label": "x"}, headers=w["ha"])
    by_date = _patch(w, "node", red, {"valid_to": MARCH}, headers=w["ha"])
    assert by_label.status_code == by_date.status_code in (403, 404)
    assert by_label.text == by_date.text
    assert _node_end(w, red) is None


# --- a tie -------------------------------------------------------------------

def test_a_tie_end_date_is_a_correction_that_does_not_grade_the_tie(w):
    before = w["owner"].execute("SELECT confidence::text FROM core.edge WHERE id = %s",
                                (w["tie"],)).fetchone()[0]
    r = w["client"].patch(
        f"/api/v1/cases/{w['case']}/graph/edges/{w['tie']}", headers=w["h"],
        json={"valid_to": MARCH, "assertion": g.grade(
            "ended in March", confidence="HIGH" if before != "HIGH" else "LOW")})
    assert r.status_code == 200, r.text
    assert r.json()["updated"] == ["valid_to"] and r.json()["confidence"] == before
    assert _tie_end(w) == _march()
    claim = w["owner"].execute(
        "SELECT claim_path, claim_value, prior_value FROM core.assertion "
        "WHERE edge_id = %s AND claim_path = 'valid_to'", (w["tie"],)).fetchone()
    assert claim == ("valid_to", {"valid_to": "2026-03-01T23:59:59+00:00"},
                     {"valid_to": None})
    audit = w["owner"].execute(
        "SELECT detail FROM audit.event WHERE action = 'EDGE_UPDATED' AND object_id = %s",
        (w["tie"],)).fetchone()[0]
    assert audit == {"fields": ["valid_to"], "previous": {"valid_to": None}}


def test_a_tie_end_date_moves_clears_and_is_checked_like_a_nodes(w):
    assert _patch(w, "edge", w["tie"], {"valid_to": MARCH}).status_code == 200
    assert _patch(w, "edge", w["tie"], {"weight": 4}).status_code == 200
    assert _tie_end(w) == _march()
    assert _patch(w, "edge", w["tie"], {"valid_to": None}).status_code == 200
    assert _tie_end(w) is None
    naive = _patch(w, "edge", w["tie"], {"valid_to": "2026-03-01T00:00:00"})
    assert naive.status_code == 400 and "UTC offset" in naive.json()["detail"]
    empty = _patch(w, "edge", w["tie"], {})
    assert empty.status_code == 400 and "valid_to" in empty.json()["detail"]


def test_a_tie_ended_in_march_is_in_the_february_view_and_not_the_april_one(w):
    from noctornal_api.projections import GraphService, Projection
    assert _patch(w, "edge", w["tie"], {"valid_to": MARCH}).status_code == 200
    service = GraphService(w["owner"], clearance="RED", compartments=frozenset())

    def ties(as_of):
        sub = service.project(Projection(case_id=w["case"], as_of=as_of,
                                         preset="all"))
        return {e["id"] for e in sub.edges}

    assert w["tie"] in ties(datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert w["tie"] not in ties(datetime(2026, 4, 1, tzinfo=timezone.utc))


def test_the_correction_is_given_back_by_retracting_it(w):
    assert _patch(w, "edge", w["tie"], {"valid_to": MARCH}).status_code == 200
    claim = w["owner"].execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s AND claim_path = 'valid_to'",
        (w["tie"],)).fetchone()[0]
    r = w["client"].post(f"/api/v1/cases/{w['case']}/assertions/{claim}/retract",
                         headers=w["h"], json={"reason": "wrong month"})
    assert r.status_code == 204, r.text
    assert _tie_end(w) is None


# --- both directions: what was accepted still is ------------------------------

def test_create_still_takes_both_dates_and_a_plain_patch_is_unchanged(w):
    r = w["client"].post(f"/api/v1/cases/{w['case']}/nodes", headers=w["h"], json={
        "node_type": "IDENTITY", "label": "bounded", "valid_from": "2026-01-01T00:00:00Z",
        "valid_to": MARCH, "assertion": g.grade()})
    assert r.status_code == 201, r.text
    node = r.json()["id"]
    assert _patch(w, "node", node, {"label": "bounded renamed"}).status_code == 200
    row = w["owner"].execute("SELECT label, valid_from, valid_to FROM core.node WHERE id = %s",
                             (node,)).fetchone()
    assert row == ("bounded renamed", datetime(2026, 1, 1, tzinfo=timezone.utc), _march())


def test_the_retirement_endpoint_says_where_the_date_is_set(w):
    """The docstring that sent the analyst to a field that did not exist now
    names the one that does."""
    from noctornal_api.http.routers import graph as router
    doc = router.soft_delete_node.__doc__
    assert "PATCH" in doc and "valid_to" in doc and "until then no endpoint" in doc
    assert "valid_to" in router.__doc__ and "correction" in router.__doc__
