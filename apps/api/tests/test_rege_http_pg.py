"""REGE over HTTP (ROADMAP-REMAINING phase 3, 2026-10-02): the regular-role
routes, held to CONCOR's (test_concor_http_pg.py).

- `/rege/latest` is a 404 before a run and the run afterwards, per number
  of roles and per weighting.
- A regular-role run can be asked whether it still holds, alone and in the
  pane's one batch beside the suite, key player and CONCOR runs.
- It is metered on its own bucket, `analytics.rege`, which spends neither
  CONCOR's nor the suite's, and a one-mode run spends `analytics.one_mode`
  too.
- Roles outside 2 to 8 and an unknown weighting are FastAPI's 422.
- The gate is `analytics.run` on the case, on both routes: a caller with no
  assignment to the case, or a Security Officer, gets nothing; so does a
  caller assigned as READ_ONLY, REVIEWER, CONTRIBUTOR or LIAISON, who may
  read the case and may not run analytics; an ANALYST gets through. None
  leaves a run behind.
- The routes serve a run's role-to-role blocks (alpha, density, tied, regular)
  to the number.

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


def _setup_with_owner(conn, client):
    owner_id, email, _secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    return owner_id, token, case_id


def _setup(conn, client):
    _owner_id, token, case_id = _setup_with_owner(conn, client)
    return token, case_id


def _assigned(conn, case_id, owner_id, role) -> str:
    """A signed-in caller with no global role, assigned to the case as `role`
    and nothing else."""
    uid, email, _secret = _make_user(conn, global_roles=())
    conn.execute("""INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
                    VALUES (%s, %s, %s, %s)""", (case_id, uid, role, owner_id))
    return _session(conn, email)


def _get(client, token, case_id, path="", params=None):
    return client.get(f"/api/v1/cases/{case_id}/analytics{path}",
                      headers=_auth(token), params=params or {})


def _runs(conn, case_id) -> int:
    return conn.execute(
        """SELECT count(*) FROM analytics.metric_run r
             JOIN analytics.projection pr ON pr.id = r.projection_id
            WHERE pr.case_id = %s AND r.algorithm = 'rege'""", (case_id,)).fetchone()[0]


def test_rege_latest_is_404_before_a_run_and_the_run_after(conn, client):
    token, case_id = _setup(conn, client)
    before = _get(client, token, case_id, "/rege/latest")
    assert before.status_code == 404
    assert "regular-role analysis" in before.json()["detail"]
    run = _get(client, token, case_id, "/rege")
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["rege"]["roles_asked"] == 4 and body["rege"]["weighting"] == "presence"
    assert {n["label"] for n in body["nodes"]} == {"alpha", "bravo", "charlie"}
    after = _get(client, token, case_id, "/rege/latest").json()
    assert after["run_id"] == body["run_id"] and after["current"] is True
    assert "computed_at" in after
    assert _get(client, token, case_id, "/rege/latest",
                [("roles", "3")]).status_code == 404
    assert _get(client, token, case_id, "/rege/latest",
                [("weighting", "weight")]).status_code == 404


def test_a_rege_run_can_be_asked_whether_it_still_holds_alone_and_in_the_batch(conn, client):
    token, case_id = _setup(conn, client)
    suite = _get(client, token, case_id).json()
    kpp = _get(client, token, case_id, "/key-player", [("n", "1")]).json()
    concor = _get(client, token, case_id, "/concor", [("depth", "1")]).json()
    run = _get(client, token, case_id, "/rege", [("roles", "2")]).json()
    alone = _get(client, token, case_id, f"/runs/{run['run_id']}/current").json()
    assert alone == {"run_id": run["run_id"], "algorithm": "rege",
                     "computed_at": alone["computed_at"], "current": True}
    # The pane's one request: four runs on screen, the most it may ask.
    ids = [suite["run_id"], kpp["run_id"], concor["run_id"], run["run_id"]]
    batch = _get(client, token, case_id, "/currency", [("run_id", i) for i in ids])
    assert batch.status_code == 200, batch.text
    assert [r["current"] for r in batch.json()["runs"]] == [True] * 4
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


def test_rege_is_metered_on_its_own_bucket(conn, client):
    from noctornal_api.ratelimit import LIMITS
    limit = LIMITS["analytics.rege"]
    assert limit.quota <= LIMITS["analytics.suite"].quota
    assert limit.on_backend_failure == LIMITS["analytics.concor"].on_backend_failure
    token, case_id = _setup(conn, client)
    _limit(client, **{"analytics.rege": (1, 1)})
    assert _get(client, token, case_id, "/rege").status_code == 200
    refused = _get(client, token, case_id, "/rege", [("force", "true")])
    assert refused.status_code == 429
    assert "analytics.rege" in refused.json()["detail"]
    # CONCOR's budget and the suite's are untouched, and a stored read is
    # charged to the graph view, not to the run's bucket.
    assert _get(client, token, case_id, "/concor").status_code == 200
    assert _get(client, token, case_id).status_code == 200
    assert _get(client, token, case_id, "/rege/latest").status_code == 200


def test_roles_outside_two_to_eight_and_an_unknown_weighting_are_a_422(conn, client):
    token, case_id = _setup(conn, client)
    for path in ("/rege", "/rege/latest"):
        for bad in ([("roles", "1")], [("roles", "9")], [("weighting", "decayed")]):
            assert _get(client, token, case_id, path, bad).status_code == 422, (path, bad)
    assert _runs(conn, case_id) == 0


@pytest.mark.parametrize("name, value, text", [
    ("REGE_MAX_PAIRS", 1, "capped at 1 tied pairs"),
    ("REGE_MAX_TIES", 1, "capped at 1 tie directions"),
    ("REGE_MAX_NODES", 2, "capped at 2 entities")])
def test_a_view_over_a_cap_is_a_422_that_names_it_and_leaves_no_run(
        conn, client, monkeypatch, name, value, text):
    """Each cap over HTTP, the ties cap in its direction wording (2026-10-03): a
    problem+json refusal naming the cap and the count,
    no run row, no audit event, no trace, and no stored run to read back."""
    from noctornal_api import rege
    token, case_id = _setup(conn, client)
    monkeypatch.setattr(rege, name, value)
    for query in ([], [("weighting", "weight")]):
        got = _get(client, token, case_id, "/rege", query)
        assert got.status_code == 422, (got.status_code, got.text[:300])
        assert got.headers["content-type"].startswith("application/problem+json")
        assert text in got.text and "Narrow the view first" in got.text, got.text
        assert "Traceback" not in got.text
    assert _runs(conn, case_id) == 0
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE case_id = %s AND object_type = 'metric_run'",
        (case_id,)).fetchone()[0] == 0
    assert _get(client, token, case_id, "/rege/latest").status_code == 404


def test_a_one_mode_rege_spends_the_one_mode_meter_too(conn, client):
    token, case_id = _setup(conn, client)
    _limit(client, **{"analytics.one_mode": (1, 1)})
    om = [("one_mode", "wallet")]
    assert _get(client, token, case_id, "/rege", om).status_code == 200
    refused = _get(client, token, case_id, "/rege", om + [("force", "true")])
    assert refused.status_code == 429
    assert "analytics.one_mode" in refused.json()["detail"]
    assert _get(client, token, case_id, "/rege", [("force", "true")]).status_code == 200


def test_a_caller_without_the_case_or_a_security_officer_gets_nothing(conn, client):
    token, case_id = _setup(conn, client)
    _, other_email, _ = _make_user(conn)
    outsider = _session(conn, other_email)
    _, so_email, _ = _make_user(conn, global_roles=("SECURITY_OFFICER",))
    officer = _session(conn, so_email)
    for who in (outsider, officer):
        for path in ("/rege", "/rege/latest"):
            got = _get(client, who, case_id, path)
            assert got.status_code in (403, 404), (path, got.status_code, got.text)
            assert "alpha" not in got.text
    assert _runs(conn, case_id) == 0


@pytest.mark.parametrize("role", ["READ_ONLY", "REVIEWER", "CONTRIBUTOR", "LIAISON"])
def test_a_role_that_may_read_the_case_but_not_run_analytics_is_refused_on_both_routes(
        conn, client, role):
    """The unassigned caller and the Security Officer are refused by ANY
    case-level gate, so they could not tell `analytics.run` from `case.read`
    (weakening either route to `case.read` passed every test: 2026-10-02). These roles hold
    `case.read` and not `analytics.run`
    (migration 0021): the assignment works, the read is theirs, and the
    analysis is not."""
    owner_id, token, case_id = _setup_with_owner(conn, client)
    # The owner's run is what a weaker gate on /rege/latest would serve.
    assert _get(client, token, case_id, "/rege").status_code == 200
    who = _assigned(conn, case_id, owner_id, role)
    assert client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(who)).status_code == 200
    for path in ("/rege", "/rege/latest"):
        got = _get(client, who, case_id, path)
        assert got.status_code == 403, (role, path, got.status_code, got.text[:200])
        assert "alpha" not in got.text
    assert _runs(conn, case_id) == 1


def test_an_analyst_assigned_to_the_case_gets_through_on_both_routes(conn, client):
    """The control for the refusals above: the same assignment, with the role
    that holds `analytics.run`."""
    owner_id, _token, case_id = _setup_with_owner(conn, client)
    who = _assigned(conn, case_id, owner_id, "ANALYST")
    run = _get(client, who, case_id, "/rege")
    assert run.status_code == 200, run.text
    latest = _get(client, who, case_id, "/rege/latest")
    assert latest.status_code == 200 and latest.json()["run_id"] == run.json()["run_id"]


def test_the_routes_serve_the_role_to_role_blocks_to_the_number(conn, client):
    """alpha, then bravo, then charlie, each vouching for the next. Two roles:
    two entities together hold half the ties they could (the view's own
    density is a third), so the block is tied and, with one of them sending
    nothing back into the role, not regular. Which two is the ids' choice, a
    tie in the data that the card's limits name (2026-10-02), so each
    cut is held to its own numbers. Four roles asked of three entities: each
    alone, and each single tie a full block, so tied and regular. Served by
    the run, and again by the stored read, null for a block of nobody."""
    token, case_id = _setup(conn, client)
    two = _get(client, token, case_id, "/rege", [("roles", "2")]).json()
    four = _get(client, token, case_id, "/rege", [("roles", "4")]).json()
    g = two["rege"]
    cut = [{m["label"] for m in r["members"]} for r in g["roles"]]
    assert g["alpha"] == {"positive": pytest.approx(1 / 3, abs=1e-6)}
    if cut == [{"alpha", "bravo"}, {"charlie"}]:
        density = [[0.5, 0.5], [0.0, None]]
        image = [[1, 1], [0, 0]]
    else:
        assert cut == [{"bravo", "charlie"}, {"alpha"}], cut
        density = [[0.5, 0.0], [0.5, None]]
        image = [[1, 0], [1, 0]]
    assert g["density"] == {"positive": density}
    assert g["image"] == {"positive": image}
    assert g["regular"] == {"positive": [[0, 0], [0, 0]]}
    g = four["rege"]
    assert [[m["label"] for m in r["members"]] for r in g["roles"]] == [
        ["alpha"], ["bravo"], ["charlie"]]
    assert g["density"] == {"positive": [[None, 1.0, 0.0], [0.0, None, 1.0],
                                         [0.0, 0.0, None]]}
    assert g["image"] == {"positive": [[0, 1, 0], [0, 0, 1], [0, 0, 0]]}
    assert g["regular"] == {"positive": [[0, 1, 0], [0, 0, 1], [0, 0, 0]]}
    for roles, ran in (("2", two), ("4", four)):
        stored = _get(client, token, case_id, "/rege/latest", [("roles", roles)]).json()
        for part in ("alpha", "density", "image", "regular"):
            assert stored["rege"][part] == ran["rege"][part], (roles, part)
