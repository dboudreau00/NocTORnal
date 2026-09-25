"""L3 over HTTP (2026-09-24): the accepted-ties scope through the API, and
the one projection dependency every analysis route now shares.

- An accepted-only run is stored under its own projection, and `/latest`
  finds it under the same parameters and never under the default.
- An unknown review scope or confidence floor is a 400 on EVERY analysis
  route, before any lookup: `/latest` answered 404 to an unknown floor,
  from a name lookup that could never match.
- A proposal added beside an accepted-only run makes that run not current
  although no accepted tie changed (the left-out counts are in the
  payload, so they are in the key).
- The run's audit event names the scope, and a default run's has no key.

Borrows test_analytics_latest_pg's fixtures and helpers, so its teardown of
`al-` accounts covers what these tests make. Env-gated on DATABASE_URL.
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

ROUTES = ("", "/latest", "/key-player", "/key-player/latest",
          "/runs/{run}/current", "/currency", "/concor", "/concor/latest")


def _setup(conn, client):
    _, email, _secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    return token, case_id


def _get(client, token, case_id, path, **params):
    return client.get(f"/api/v1/cases/{case_id}/analytics{path}",
                      headers=_auth(token), params=params)


def _proposed_tie(client, token, case_id, src="alpha", dst="charlie"):
    """A tie added through the API and put back to PROPOSED by tie review:
    a proposal beside the accepted ones, which the accepted scope leaves
    out and counts."""
    nodes = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token)).json()["nodes"]
    by = {n["label"]: n["id"] for n in nodes}
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "VOUCHED_FOR", "src_node_id": by[src],
        "dst_node_id": by[dst],
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "F",
                      "credibility": "6", "confidence": "LOW",
                      "rationale": "vouched in a thread"}})
    assert r.status_code == 201, r.text
    edge_id = r.json()["id"]
    r = client.post(f"/api/v1/cases/{case_id}/graph/edges/{edge_id}/review",
                    headers=_auth(token),
                    json={"review": "PROPOSED", "note": "only one source for it"})
    assert r.status_code == 200, r.text
    return edge_id


def test_an_accepted_only_run_is_stored_under_its_own_projection_and_latest_finds_it(conn, client):
    token, case_id = _setup(conn, client)
    run = _get(client, token, case_id, "", review_scope="accepted")
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["projection"]["review_scope"] == "accepted"
    assert body["review_scope"]["scope"] == "accepted"
    latest = _get(client, token, case_id, "/latest", review_scope="accepted")
    assert latest.status_code == 200 and latest.json()["run_id"] == body["run_id"]
    assert _get(client, token, case_id, "/latest").status_code == 404


@pytest.mark.parametrize("bad", [{"review_scope": "reviewed"},
                                 {"min_confidence": "CERTAIN"},
                                 {"preset": "social"}])
def test_an_unknown_review_scope_or_confidence_is_a_400_on_every_analysis_route(
        conn, client, bad):
    token, case_id = _setup(conn, client)
    run_id = str(uuid4())
    for path in ROUTES:
        extra = {"run_id": run_id} if path == "/currency" else {}
        r = _get(client, token, case_id, path.format(run=run_id), **bad, **extra)
        assert r.status_code == 400, (path, r.status_code, r.text)
        assert "unknown" in r.json()["detail"], path


def test_adding_a_proposed_tie_makes_an_accepted_only_run_not_current(conn, client):
    token, case_id = _setup(conn, client)
    _proposed_tie(client, token, case_id)
    run = _get(client, token, case_id, "", review_scope="accepted").json()
    assert run["review_scope"]["left_out"]["ties"]["proposed"] == 1
    edges_before = run["edge_count"]
    _proposed_tie(client, token, case_id, src="charlie", dst="alpha")
    latest = _get(client, token, case_id, "/latest", review_scope="accepted").json()
    assert latest["run_id"] == run["run_id"] and latest["edge_count"] == edges_before
    assert latest["current"] is False
    cur = _get(client, token, case_id, f"/runs/{run['run_id']}/current",
               review_scope="accepted").json()
    assert cur["current"] is False


def test_the_run_audit_event_names_the_review_scope(conn, client):
    token, case_id = _setup(conn, client)
    scoped = _get(client, token, case_id, "", review_scope="accepted").json()
    plain = _get(client, token, case_id, "").json()
    rows = dict(conn.execute(
        """SELECT object_id::text, detail FROM audit.event
            WHERE action = 'ANALYTICS_RUN' AND object_id = ANY(%s)""",
        ([scoped["run_id"], plain["run_id"]],)).fetchall())
    assert rows[scoped["run_id"]]["review_scope"] == "accepted"
    assert "review_scope" not in rows[plain["run_id"]]
