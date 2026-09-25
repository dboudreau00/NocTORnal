"""F2 over HTTP (2026-09-24): venues projected to entities through the
analysis routes, their meter, the too-large answer and batched currency.

- `one_mode` is a repeated query parameter; a run under it is found again
  under the same parameters.
- "conversation" and unknown families or weightings are a 400 (docs/00
  decision 73); a size out of range is FastAPI's 422.
- A view over the derived-tie limit is a 422 "Cannot compute" on the
  compute routes and never a 500, while the stored reads
  answer 200 with current false: a stored run exists only for a view that
  was within the limit.
- One-mode reads spend `analytics.one_mode` beside their own meter; plain
  reads do not (the transform's cost is metered apart from graph.view
  reads).
- `/currency` projects ONCE for every run it is asked about, and says why
  a run cannot be compared.
- The sociogram's `/graph` never sees any of it.

Borrows test_analytics_latest_pg's fixtures and helpers (teardown of `al-`
accounts). Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
import test_analytics_latest_pg as al
from test_analytics_latest_pg import (
    DATABASE_URL,
    _auth,
    _create_case,
    _make_user,
    _seed_small_graph,
    _session,
)

conn = al.conn
client = al.client

pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; HTTP e2e is gated")


def _setup(conn, client):
    """The small graph, plus a forum all three personas post on."""
    _, email, _secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    a = {"basis": "DIRECT_OBSERVATION", "reliability": "B", "credibility": "2",
         "confidence": "LOW"}
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
        "node_type": "FORUM", "label": "board", "assertion": a})
    assert r.status_code == 201, r.text
    forum = r.json()["id"]
    nodes = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token)).json()["nodes"]
    for n in nodes:
        if n["node_type"] != "IDENTITY":
            continue
        r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
            "edge_type": "POSTS_ON", "src_node_id": n["id"], "dst_node_id": forum,
            "assertion": {**a, "rationale": "posts there"}})
        assert r.status_code == 201, r.text
    return token, case_id


def _get(client, token, case_id, path="", params=None):
    return client.get(f"/api/v1/cases/{case_id}/analytics{path}",
                      headers=_auth(token), params=params or {})


OM = [("one_mode", "forum")]


def test_one_mode_is_a_repeated_query_parameter_and_latest_finds_the_run(conn, client):
    token, case_id = _setup(conn, client)
    both = [("one_mode", "wallet"), ("one_mode", "forum")]
    run = _get(client, token, case_id, "", both)
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["projection"]["one_mode"]["families"] == ["forum", "wallet"]
    assert body["one_mode"]["derived_ties"]["forum"] == 3
    assert "board" not in {n["label"] for n in body["nodes"]}
    # The same question in another order names the same projection.
    latest = _get(client, token, case_id, "/latest", list(reversed(both)))
    assert latest.status_code == 200 and latest.json()["run_id"] == body["run_id"]
    assert _get(client, token, case_id, "/latest").status_code == 404


def test_conversation_and_unknown_families_are_a_400_and_out_of_range_sizes_a_422(conn, client):
    token, case_id = _setup(conn, client)
    for bad in ([("one_mode", "conversation")], [("one_mode", "people")],
                OM + [("one_mode_weighting", "LOG")]):
        r = _get(client, token, case_id, "", bad)
        assert r.status_code == 400, (bad, r.text)
    r = _get(client, token, case_id, "", [("one_mode", "conversation")])
    assert "one of forum, wallet" in r.json()["detail"]
    for bad in (OM + [("max_venue_size", "1")], OM + [("max_venue_size", "501")],
                OM + [("one_mode_min_shared", "0")]):
        assert _get(client, token, case_id, "", bad).status_code == 422, bad


def test_too_many_derived_ties_is_a_422_not_a_500(conn, client, monkeypatch):
    from noctornal_api import affiliation
    token, case_id = _setup(conn, client)
    suite = _get(client, token, case_id, "", OM).json()
    kpp = _get(client, token, case_id, "/key-player", OM + [("n", "1")]).json()
    roles = _get(client, token, case_id, "/concor", OM + [("depth", "1")]).json()
    monkeypatch.setattr(affiliation, "MAX_DERIVED_TIES", 1)
    for path, extra in (("", []), ("/key-player", [("n", "1")]),
                        ("/concor", [("depth", "1")])):
        r = _get(client, token, case_id, path, OM + extra + [("force", "true")])
        assert r.status_code == 422, (path, r.text)
        assert r.json()["title"] == "Cannot compute"
        assert "over the limit of 1" in r.json()["detail"]
    for path, extra in (("/latest", []), ("/key-player/latest", [("n", "1")]),
                        ("/concor/latest", [("depth", "1")]),
                        (f"/runs/{suite['run_id']}/current", [])):
        r = _get(client, token, case_id, path, OM + extra)
        assert r.status_code == 200, (path, r.text)
        assert r.json()["current"] is False, path
    batch = _get(client, token, case_id, "/currency",
                 OM + [("run_id", x["run_id"]) for x in (suite, kpp, roles)]).json()
    assert [x["current"] for x in batch["runs"]] == [False, False, False]
    # With nothing stored, the read is still a 404, not a 422.
    assert _get(client, token, case_id, "/latest",
                OM + [("max_venue_size", "10")]).status_code == 404


def test_too_many_dated_period_comparisons_is_a_422_too(conn, client, monkeypatch):
    """The period limit (2026-09-24) is answered like the tie
    limit: a 422 on a compute, current false on a stored read."""
    from noctornal_api import affiliation
    token, case_id = _setup(conn, client)
    suite = _get(client, token, case_id, "", OM).json()
    monkeypatch.setattr(affiliation, "MAX_PERIOD_STEPS", 0)
    r = _get(client, token, case_id, "", OM + [("force", "true")])
    assert r.status_code == 422, r.text
    assert r.json()["title"] == "Cannot compute"
    assert "comparisons of dated periods, over the limit of 0" in r.json()["detail"]
    r = _get(client, token, case_id, f"/runs/{suite['run_id']}/current", OM)
    assert r.status_code == 200 and r.json()["current"] is False, r.text


def _limit(client, **overrides):
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, Limit, RateLimiter
    limits = dict(LIMITS)
    for name, (quota, burst) in overrides.items():
        base = LIMITS[name]
        limits[name] = Limit(name, quota=quota, per_seconds=300, scope=base.scope,
                             burst=burst, on_backend_failure=base.on_backend_failure)
    client.app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)


def test_one_mode_reads_spend_the_one_mode_meter_and_plain_reads_do_not(conn, client):
    token, case_id = _setup(conn, client)
    _limit(client, **{"analytics.one_mode": (2, 2)})
    codes = [_get(client, token, case_id, "/latest", OM).status_code for _ in range(3)]
    assert codes == [404, 404, 429], codes
    refused = _get(client, token, case_id, "/latest", OM)
    assert "analytics.one_mode" in refused.json()["detail"]
    # Plain reads and plain runs are charged exactly as before.
    for _ in range(3):
        assert _get(client, token, case_id, "/latest").status_code == 404
    assert _get(client, token, case_id, "").status_code == 200
    # And a one-mode run is refused too, although its own meter has room.
    assert _get(client, token, case_id, "", OM).status_code == 429


def test_the_batched_currency_check_projects_once_and_answers_each_run(conn, client, monkeypatch):
    from noctornal_api import projections
    token, case_id = _setup(conn, client)
    suite = _get(client, token, case_id).json()
    kpp = _get(client, token, case_id, "/key-player", [("n", "1")]).json()
    roles = _get(client, token, case_id, "/concor", [("depth", "1")]).json()
    other = _get(client, token, case_id, "", [("preset", "trust")]).json()
    calls = []
    real = projections.GraphService.project

    def counting(self, *a, **kw):
        calls.append(a)
        return real(self, *a, **kw)

    monkeypatch.setattr(projections.GraphService, "project", counting)
    ghost = str(uuid4())
    r = _get(client, token, case_id, "/currency",
             [("run_id", x) for x in (suite["run_id"], kpp["run_id"], roles["run_id"],
                                      other["run_id"])])
    assert r.status_code == 200, r.text
    assert len(calls) == 1
    runs = r.json()["runs"]
    assert [x["run_id"] for x in runs] == [suite["run_id"], kpp["run_id"],
                                           roles["run_id"], other["run_id"]]
    assert [x["current"] for x in runs[:3]] == [True, True, True]
    assert [x["algorithm"] for x in runs[:3]] == ["sna_suite", "kpp_neg", "concor"]
    assert runs[3] == {"run_id": other["run_id"], "current": None,
                       "reason": "other_projection"}
    calls.clear()
    r = _get(client, token, case_id, "/currency", [("run_id", ghost)])
    assert r.json()["runs"] == [{"run_id": ghost, "current": None, "reason": "not_found"}]
    assert calls == [], "nothing comparable, so nothing is projected"
    too_many = [("run_id", str(uuid4())) for _ in range(5)]
    assert _get(client, token, case_id, "/currency", too_many).status_code == 422


def test_the_graph_routes_never_see_one_mode(conn, client):
    token, case_id = _setup(conn, client)
    plain = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token)).json()
    asked = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token),
                       params=OM).json()
    assert asked == plain
    assert "board" in {n["label"] for n in plain["nodes"]}
    for e in plain["edges"]:
        assert not {"derived", "family", "in_preset"} & set(e)
