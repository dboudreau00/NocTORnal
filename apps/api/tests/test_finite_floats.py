"""A number from the caller is finite, or it is refused.

JSON as Python reads it takes `NaN`, `Infinity` and `-Infinity` as bare words and `1e999` as infinity, and
a query string takes `nan` and `inf`. A float field with no bound let each of them through:

- a saved layout stored them in `analytics.layout_position` (double precision holds both), and the read
  answered them as `null` coordinates, which the response model's own `x: float` does not allow and the
  console reads as 0;
- a decay half-life was checked with `<= 0`, which is False for NaN and for infinity, so it passed the
  check, ran the analysis, and was refused only where the run's parameters were written as JSON (a 422
  that said the value "cannot be stored"), or not at all on the routes that read.

The model refuses both now (a 422 for a layout, a 400 for the half-life, the answer the neighbouring `<= 0`
check always gave), nothing is stored, and a layout row that is already non-finite is left out of the read
and said so in the log. The other float inputs are bounded on both sides, which refuses NaN and infinity
without a flag, and a test below holds that to the list.

Gated tests run as the request role. Account prefix `finflt-`.
"""
from __future__ import annotations

import inspect
import json
import logging
import math
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

import rls_support as s
from noctornal_api.analytics import AnalyticsError, _decay_factor
from noctornal_api.http.errors import Problem
from noctornal_api.http.routers import analytics as analytics_router
from noctornal_api.http.routers.analytics import _params
from noctornal_api.http.routers.collection import SourceCreate
from noctornal_api.http.routers.collection_telegram import ChatCreate
from noctornal_api.http.routers.graph import UpdateEdgeBody
from noctornal_api.http.routers.graphview import LayoutBody, LayoutPosition

PREFIX = "finflt-"

#: What a caller can send for "not a finite number". The JSON words are not JSON, and Python's parser reads
#: them anyway; `1e999` is valid JSON and overflows to infinity.
NON_FINITE_JSON = ("NaN", "Infinity", "-Infinity", "1e999", "-1e999")
NON_FINITE_QUERY = ("nan", "NaN", "inf", "-inf", "Infinity", "1e999")


# --- the model and the parameter check, no database ----------------------

@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
@pytest.mark.parametrize("axis", ["x", "y"])
def test_a_layout_position_refuses_nan_and_infinity(axis, bad):
    fields = {"node_id": uuid4(), "x": 1.0, "y": 2.0, axis: bad}
    with pytest.raises(ValidationError):
        LayoutPosition(**fields)
    with pytest.raises(ValidationError):
        LayoutBody(positions=[fields])


def test_a_layout_position_still_takes_every_finite_number():
    for value in (0.0, -0.0, 1.5, -1e6, 1e308, -1e308, 5e-324):
        p = LayoutPosition(node_id=uuid4(), x=value, y=value, is_pinned=True)
        assert (p.x, p.y) == (value, value)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, 0, 0.0, -1, -12.5])
def test_a_half_life_is_a_positive_finite_number(bad):
    with pytest.raises(Problem) as err:
        _params(bad, 1.0)
    assert err.value.status == 400
    assert "decay_half_life_months" in err.value.detail


@pytest.mark.parametrize("good", [None, 1, 12, 12.0, 0.5, 1e308, 5e-324])
def test_a_half_life_that_is_none_or_positive_and_finite_is_kept(good):
    params = _params(good, 1.0)
    assert params.decay_half_life_months == good
    # What is echoed and stored on the run must be valid JSON.
    json.dumps(params.describe(), allow_nan=False)


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, 0.0, -1.0])
def test_the_decay_factor_refuses_a_half_life_that_is_not_positive_and_finite(bad):
    with pytest.raises(AnalyticsError):
        _decay_factor(10.0, bad)


def test_the_decay_factor_of_a_valid_half_life_is_unchanged():
    assert _decay_factor(0.0, 6.0) == 1.0
    assert _decay_factor(6.0 * 30.4375, 6.0) == pytest.approx(0.5, rel=1e-3)


@pytest.mark.parametrize("model, field, kwargs", [
    (SourceCreate, "max_rps", dict(kind="FORUM", name="a source", parser_key="p",
                                   classification="AMBER")),
    (ChatCreate, "max_rps", dict(persona_id=uuid4(), ref="r", name="a chat",
                                 classification="AMBER")),
    (UpdateEdgeBody, "weight", dict(assertion=dict(basis="DIRECT_OBSERVATION",
                                                  reliability="F", credibility="6",
                                                  confidence="LOW"))),
])
@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_the_other_float_inputs_are_bounded_and_so_refuse_nan_and_infinity(
        model, field, kwargs, bad):
    """The float body fields besides the layout. Each carries a `gt` or `ge` and a `le`, which NaN fails
    both of and infinity fails the upper one of, so none needed the flag. Held here so a bound dropped
    from one of them is a failing test, not a stored NaN."""
    with pytest.raises(ValidationError):
        model(**{**kwargs, field: bad})


# --- over HTTP, as the request role -------------------------------------

@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    projections = f"(SELECT id FROM analytics.projection WHERE case_id IN {cases})"
    c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN {projections}")
    c.execute(f"DELETE FROM analytics.metric_run WHERE projection_id IN {projections}")
    c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {cases}")
    s.cleanup(c, PREFIX)
    c.close()


def _fresh_limiter(app) -> None:
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))


@pytest.fixture
def api():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    app = create_app()
    _fresh_limiter(app)
    return TestClient(app)


def _world(owner):
    """An analyst on a case with two ties, the token they hold, and the case's node ids."""
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, analyst)
    s.assign(owner, case_id, analyst)
    nodes = [s.node(owner, case_id, analyst, label) for label in ("alpha", "bravo", "charlie")]
    s.edge(owner, case_id, analyst, nodes[0], nodes[1])
    s.edge(owner, case_id, analyst, nodes[1], nodes[2])
    _, raw = s.session(owner, analyst)
    return case_id, nodes, {"Authorization": f"Bearer {raw}"}


def _stored(owner, case_id: UUID) -> list[tuple]:
    return owner.execute(
        """SELECT lp.node_id, lp.x, lp.y FROM analytics.layout_position lp
             JOIN analytics.projection p ON p.id = lp.projection_id
            WHERE p.case_id = %s AND p.name = '__layout__'""", (case_id,)).fetchall()


def _put_raw(api, case_id, headers, node_id, x: str, y: str = "0"):
    """The body is written by hand: a client library refuses to serialise a NaN, a caller does not have to."""
    body = ('{"positions":[{"node_id":"%s","x":%s,"y":%s,"is_pinned":false}]}'
            % (node_id, x, y)).encode()
    return api.put(f"/api/v1/cases/{case_id}/graph/layout", content=body,
                   headers={**headers, "Content-Type": "application/json"})


@s.GATED
@pytest.mark.parametrize("axis", ["x", "y"])
@pytest.mark.parametrize("bad", NON_FINITE_JSON)
def test_a_saved_layout_with_a_non_finite_position_is_a_422_that_stores_nothing(
        owner, api, axis, bad):
    case_id, nodes, headers = _world(owner)
    r = _put_raw(api, case_id, headers, nodes[0], *((bad, "0") if axis == "x" else ("0", bad)))
    assert r.status_code == 422, r.text
    assert _stored(owner, case_id) == [], "a refused layout left a row behind"
    # The read still answers, and a finite layout still saves and reads back.
    assert api.get(f"/api/v1/cases/{case_id}/graph/layout", headers=headers).json() == []
    ok = _put_raw(api, case_id, headers, nodes[0], "12.5", "-3")
    assert ok.status_code == 204, ok.text
    read = api.get(f"/api/v1/cases/{case_id}/graph/layout", headers=headers)
    assert read.status_code == 200, read.text
    assert [(p["node_id"], p["x"], p["y"]) for p in read.json()] == [(str(nodes[0]), 12.5, -3.0)]


@s.GATED
def test_one_non_finite_position_refuses_the_whole_layout(owner, api):
    """A body is all or nothing: the finite positions beside a refused one are not stored either, so the
    canvas an analyst saved is never half of it."""
    case_id, nodes, headers = _world(owner)
    body = ('{"positions":[{"node_id":"%s","x":1,"y":2},{"node_id":"%s","x":NaN,"y":2}]}'
            % (nodes[0], nodes[1])).encode()
    r = api.put(f"/api/v1/cases/{case_id}/graph/layout", content=body,
                headers={**headers, "Content-Type": "application/json"})
    assert r.status_code == 422, r.text
    assert _stored(owner, case_id) == []


@s.GATED
def test_a_layout_row_already_stored_non_finite_is_left_out_of_the_read(
        owner, api, caplog):
    """A row written before the model refused it. The read leaves it out and not as a `null` position,
    says how many in the log (never the values, never a node), and the next save of that node replaces
    it."""
    case_id, nodes, headers = _world(owner)
    analyst = owner.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                            (case_id,)).fetchone()[0]
    projection = owner.execute(
        """INSERT INTO analytics.projection (case_id, name, edge_types, created_by)
           VALUES (%s, '__layout__', '{}', %s) RETURNING id""", (case_id, analyst)).fetchone()[0]
    for node, x, y in ((nodes[0], "NaN", "1"), (nodes[1], "1", "Infinity"),
                       (nodes[2], "-Infinity", "-Infinity")):
        owner.execute("""INSERT INTO analytics.layout_position
                             (projection_id, node_id, x, y, is_pinned)
                         VALUES (%s, %s, %s::float8, %s::float8, false)""",
                      (projection, node, x, y))
    extra = s.node(owner, case_id, analyst, "delta")
    owner.execute("""INSERT INTO analytics.layout_position
                         (projection_id, node_id, x, y, is_pinned)
                     VALUES (%s, %s, 4, 5, true)""", (projection, extra))

    url = f"/api/v1/cases/{case_id}/graph/layout"
    with caplog.at_level(logging.WARNING, logger="noctornal.graphview"):
        r = api.get(url, headers=headers)
    assert r.status_code == 200, r.text
    assert [(p["node_id"], p["x"], p["y"], p["is_pinned"]) for p in r.json()] == [
        (str(extra), 4.0, 5.0, True)]
    said = [rec.getMessage() for rec in caplog.records if rec.name == "noctornal.graphview"]
    assert len(said) == 1 and "3" in said[0] and str(case_id) in said[0], said
    assert not any(str(n) in said[0] for n in nodes), "the log named a node"

    # Saving the node again replaces the bad row, and the log is quiet.
    assert _put_raw(api, case_id, headers, nodes[0], "7", "8").status_code == 204
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="noctornal.graphview"):
        again = api.get(url, headers=headers)
    assert {p["node_id"] for p in again.json()} == {str(extra), str(nodes[0])}
    assert len([rec for rec in caplog.records if rec.name == "noctornal.graphview"]) == 1, (
        "two bad rows are still stored")


@s.GATED
def test_a_layout_of_finite_rows_reads_in_full_and_the_log_is_quiet(owner, api, caplog):
    case_id, nodes, headers = _world(owner)
    body = {"positions": [{"node_id": str(n), "x": float(i), "y": -float(i), "is_pinned": i == 1}
                          for i, n in enumerate(nodes)]}
    assert api.put(f"/api/v1/cases/{case_id}/graph/layout", json=body,
                   headers=headers).status_code == 204
    with caplog.at_level(logging.WARNING, logger="noctornal.graphview"):
        r = api.get(f"/api/v1/cases/{case_id}/graph/layout", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) == 3
    assert [rec for rec in caplog.records if rec.name == "noctornal.graphview"] == []


def _half_life_paths() -> list[str]:
    """Every analytics route that takes a half-life, read from the router itself so one added later is
    held to the same refusal. The router is read and not the app: FastAPI keeps an included router
    unexpanded in `app.routes`."""
    return sorted(
        "/api/v1" + route.path for route in analytics_router.router.routes
        if "decay_half_life_months" in inspect.signature(route.endpoint).parameters)


@s.GATED
def test_every_analytics_route_that_takes_a_half_life_refuses_a_non_finite_one(owner, api):
    case_id, _, headers = _world(owner)
    paths = _half_life_paths()
    assert len(paths) >= 10 and "/api/v1/cases/{case_id}/analytics" in paths, paths
    for template in paths:
        url = template.format(case_id=case_id, run_id=uuid4(), node_id=uuid4())
        for bad in NON_FINITE_QUERY:
            # A refused request is still metered, and some of these routes admit four in a burst.
            _fresh_limiter(api.app)
            # `run_id` is required by one route and ignored by the rest.
            r = api.get(url, params={"decay_half_life_months": bad, "run_id": str(uuid4())},
                        headers=headers)
            assert r.status_code == 400, (template, bad, r.status_code, r.text)
            assert "decay_half_life_months" in r.json()["detail"], (template, bad, r.text)
    stored = owner.execute(
        """SELECT count(*) FROM analytics.metric_run r JOIN analytics.projection p
             ON p.id = r.projection_id WHERE p.case_id = %s""", (case_id,)).fetchone()[0]
    assert stored == 0, "a refused half-life left a run behind"


@s.GATED
def test_a_finite_half_life_still_runs_and_is_echoed_as_valid_json(owner, api):
    case_id, _, headers = _world(owner)
    r = api.get(f"/api/v1/cases/{case_id}/analytics",
                params={"decay_half_life_months": "12"}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["params"]["decay_half_life_months"] == 12.0
    assert api.get(f"/api/v1/cases/{case_id}/analytics/latest",
                   params={"decay_half_life_months": "12"},
                   headers=headers).status_code == 200


@s.GATED
@pytest.mark.parametrize("bad", ["nan", "inf", "1e999"])
def test_the_leiden_resolution_is_bounded_and_refuses_them_without_the_flag(owner, api, bad):
    case_id, _, headers = _world(owner)
    r = api.get(f"/api/v1/cases/{case_id}/analytics",
                params={"leiden_resolution": bad}, headers=headers)
    assert r.status_code == 422, r.text
