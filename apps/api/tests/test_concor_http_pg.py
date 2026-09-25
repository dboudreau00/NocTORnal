"""F1 over HTTP (2026-09-24): the role-analysis routes.

- `/concor/latest` is a 404 before a run and the run afterwards, per depth.
- A role run can be asked whether it still holds, alone and in a batch.
- It is metered on its own bucket, `analytics.concor`, and a one-mode role
  run spends `analytics.one_mode` too.
- A depth outside 1 to 4 is FastAPI's 422.

Borrows test_analytics_latest_pg's fixtures and helpers (teardown of `al-`
accounts). Env-gated on DATABASE_URL.
"""
from __future__ import annotations

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
from test_one_mode_http_pg import _limit

conn = al.conn
client = al.client

pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; HTTP e2e is gated")


def _setup(conn, client):
    _, email, _secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    return token, case_id


def _get(client, token, case_id, path="", params=None):
    return client.get(f"/api/v1/cases/{case_id}/analytics{path}",
                      headers=_auth(token), params=params or {})


def test_concor_latest_is_404_before_a_run_and_the_run_after(conn, client):
    token, case_id = _setup(conn, client)
    before = _get(client, token, case_id, "/concor/latest")
    assert before.status_code == 404
    assert "role analysis" in before.json()["detail"]
    run = _get(client, token, case_id, "/concor")
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["concor"]["depth"] == 2
    assert {n["label"] for n in body["nodes"]} == {"alpha", "bravo", "charlie"}
    after = _get(client, token, case_id, "/concor/latest").json()
    assert after["run_id"] == body["run_id"] and after["current"] is True
    assert "computed_at" in after
    assert _get(client, token, case_id, "/concor/latest",
                [("depth", "1")]).status_code == 404


def test_a_concor_run_can_be_asked_whether_it_still_holds_alone_and_in_a_batch(conn, client):
    token, case_id = _setup(conn, client)
    run = _get(client, token, case_id, "/concor", [("depth", "1")]).json()
    alone = _get(client, token, case_id, f"/runs/{run['run_id']}/current").json()
    assert alone == {"run_id": run["run_id"], "algorithm": "concor",
                     "computed_at": alone["computed_at"], "current": True}
    batch = _get(client, token, case_id, "/currency", [("run_id", run["run_id"])]).json()
    assert batch["runs"][0]["current"] is True
    nodes = client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(token)).json()["nodes"]
    by = {n["label"]: n["id"] for n in nodes}
    client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "VOUCHED_FOR", "src_node_id": by["charlie"],
        "dst_node_id": by["alpha"],
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "F",
                      "credibility": "6", "confidence": "LOW", "rationale": "vouched"}})
    assert _get(client, token, case_id, f"/runs/{run['run_id']}/current").json()[
        "current"] is False
    assert _get(client, token, case_id, "/currency",
                [("run_id", run["run_id"])]).json()["runs"][0]["current"] is False


def test_concor_is_metered_on_its_own_bucket(conn, client):
    from noctornal_api.ratelimit import LIMITS
    limit = LIMITS["analytics.concor"]
    assert limit.quota <= LIMITS["analytics.suite"].quota
    assert limit.on_backend_failure == LIMITS["analytics.suite"].on_backend_failure
    token, case_id = _setup(conn, client)
    _limit(client, **{"analytics.concor": (1, 1)})
    assert _get(client, token, case_id, "/concor").status_code == 200
    refused = _get(client, token, case_id, "/concor", [("force", "true")])
    assert refused.status_code == 429
    assert "analytics.concor" in refused.json()["detail"]
    # The suite's budget is untouched.
    assert _get(client, token, case_id).status_code == 200


def test_a_depth_outside_one_to_four_is_a_422(conn, client):
    token, case_id = _setup(conn, client)
    for depth in ("0", "5"):
        assert _get(client, token, case_id, "/concor",
                    [("depth", depth)]).status_code == 422
        assert _get(client, token, case_id, "/concor/latest",
                    [("depth", depth)]).status_code == 422


def test_a_one_mode_concor_spends_the_one_mode_meter_too(conn, client):
    token, case_id = _setup(conn, client)
    _limit(client, **{"analytics.one_mode": (1, 1)})
    om = [("one_mode", "wallet")]
    assert _get(client, token, case_id, "/concor", om).status_code == 200
    refused = _get(client, token, case_id, "/concor", om + [("force", "true")])
    assert refused.status_code == 429
    assert "analytics.one_mode" in refused.json()["detail"]
    assert _get(client, token, case_id, "/concor", [("force", "true")]).status_code == 200
