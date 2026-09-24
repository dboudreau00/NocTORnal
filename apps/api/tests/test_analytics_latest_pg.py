"""`GET /cases/{case_id}/analytics/latest`: the run an analyst expects to
see on opening the pane.

Until 2026-09-02 the analytics pane was empty until somebody pressed "Run
analysis", although every completed run was already on
`analytics.metric_run` with its full `result` payload -- the persistence
was written for cache hits and time series and never read back as "what
was the last answer". So an analyst opening a case saw nothing, ran the
suite again, and was served the cached row anyway.

`latest` returns the most recent COMPLETE `sna_suite` run for the case
and projection (preset + include_inferred) in the same shape the suite
endpoint returns, plus `computed_at`, or 404 when there is none. It is
scoped to the caller's own visibility exactly as `history` and the cache
lookup are: a run computed over a better-cleared analyst's graph is never
served to a lesser one, because the score's explanation would lie in
nodes they may not see.

Email prefix `al-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; analytics latest e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'al-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    psub = f"(SELECT id FROM analytics.projection WHERE case_id IN {csub})"
    rsub = f"(SELECT id FROM analytics.metric_run WHERE projection_id IN {psub})"
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE case_id IN {csub}"
                  f" OR recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}"
                  f" OR recipient_id IN {sub} OR actor_id IN {sub}")
        c.execute(f"DELETE FROM analytics.node_metric WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.community_assignment WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.metric_run WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'al-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, clearance="RED", global_roles=("CASE_OWNER",)):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"al-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "AL", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _session(conn, email) -> str:
    """A signed-in caller, minted the way `scripts/bootstrap.py session`
    mints one: the account looked up by email, then `SessionService`
    against the same store the API validates against. Unbound -- no
    address, no User-Agent, because nothing here has one to give -- which
    0058 records and only `NOCTORNAL_SESSION_STRICT_BINDING` refuses; it
    is off in these tests.

    Not `POST /auth/login`, which since 2026-09-10 answers 204 and leaves
    the token only in `__Host-session`. Nothing in this file is about the
    sign-in path, so this takes the short honest route to a session
    rather than driving a login and unpicking a Set-Cookie header for a
    value it would hand straight back as a Bearer. It also drops the
    constraint the login helper carried: TOTP codes are single-use, so
    two sign-ins for one account inside one 30-second step failed on the
    code, not on the thing under test.
    """
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    # mfa_satisfied=True, as both real mint sites pass: a session that
    # never satisfied MFA is refused by every step-up gated route, which
    # would make this helper quietly narrower than the login it replaces.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-AL-{uuid4().hex[:6]}", "title": "Operation Latest",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _seed_small_graph(client, token, case_id) -> None:
    """Three actors and two ties: the suite over an EMPTY case is a 422,
    which is correct and useless here."""
    ids = []
    for label in ("alpha", "bravo", "charlie"):
        r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
            "node_type": "IDENTITY", "label": label,
            "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                          "credibility": "2", "confidence": "LOW"}})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    for src, dst in ((0, 1), (1, 2)):
        r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
            "edge_type": "VOUCHED_FOR", "src_node_id": ids[src],
            "dst_node_id": ids[dst],
            "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "F",
                          "credibility": "6", "confidence": "LOW",
                          "rationale": "vouched"}})
        assert r.status_code == 201, r.text


def _latest(client, token, case_id, **params):
    return client.get(f"/api/v1/cases/{case_id}/analytics/latest",
                      headers=_auth(token), params=params)


def test_latest_is_404_before_any_run_and_the_run_afterwards(conn, client):
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)

    before = _latest(client, token, case_id)
    assert before.status_code == 404, before.text
    assert "run" in before.json()["detail"].lower()

    run = client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token))
    assert run.status_code == 200, run.text
    suite = run.json()

    after = _latest(client, token, case_id)
    assert after.status_code == 200, after.text
    latest = after.json()
    assert latest["run_id"] == suite["run_id"]
    # Same shape as the suite endpoint, plus when it was computed. Read
    # from both responses so a field added to one and not the other shows
    # up here rather than in the pane.
    assert set(latest) == set(suite) | {"computed_at"}
    assert latest["nodes"] == suite["nodes"]
    assert latest["projection"] == suite["projection"]
    # `cached` says only where the bytes came from -- storage, not a fresh
    # computation, and that is true of both responses here. The currency
    # verdict is `current`, and since 2026-09-23 `latest` establishes it by
    # re-projecting: nothing has changed, so it is True. See
    # test_latest_says_whether_the_graph_has_moved.
    assert latest["cached"] is True
    assert latest["current"] is True
    datetime.fromisoformat(latest["computed_at"])   # parses, and is not a duration


def test_latest_follows_the_projection_not_the_case(conn, client):
    """Two presets are two projections; a run under one says nothing about
    the other, and the pane asks for the one it is showing."""
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    assert client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token),
                      params={"preset": "trust"}).status_code == 200
    assert _latest(client, token, case_id, preset="trust").status_code == 200
    assert _latest(client, token, case_id, preset="all").status_code == 404
    assert _latest(client, token, case_id, preset="trust",
                   include_inferred=True).status_code == 404


def test_latest_returns_the_most_recent_run_not_the_first(conn, client):
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    first = client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token)).json()
    second = client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token),
                        params={"force": True}).json()
    assert second["run_id"] != first["run_id"]
    assert second["cached"] is False
    assert _latest(client, token, case_id).json()["run_id"] == second["run_id"]


def test_latest_never_crosses_a_clearance_boundary(conn, client):
    """The rule the whole module is built around, applied to the new read
    path: a run computed at RED is not the latest run for an AMBER analyst
    on the same case, even when both graphs happen to be identical."""
    owner_id, email, secret = _make_user(conn, clearance="RED")
    owner = _session(conn, email)
    case_id = _create_case(client, owner)
    _seed_small_graph(client, owner, case_id)
    assert client.get(f"/api/v1/cases/{case_id}/analytics",
                      headers=_auth(owner)).status_code == 200

    amber_id, amber_email, amber_secret = _make_user(conn, clearance="AMBER",
                                                     global_roles=())
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""",
        (case_id, amber_id, owner_id))
    amber = _session(conn, amber_email)

    assert _latest(client, amber, case_id).status_code == 404
    # ...and not because the analyst cannot reach the case: they can run
    # the suite themselves, after which THEIR run is their latest.
    own = client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(amber))
    assert own.status_code == 200, own.text
    theirs = _latest(client, amber, case_id)
    assert theirs.status_code == 200
    assert theirs.json()["run_id"] == own.json()["run_id"]
    assert theirs.json()["run_id"] != _latest(client, owner, case_id).json()["run_id"]


def test_latest_rejects_an_unknown_preset_like_the_suite_does(conn, client):
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    r = _latest(client, token, case_id, preset="nonsense")
    assert r.status_code == 400
    assert "unknown preset" in r.json()["detail"]


# --- `cached` must not mean two things -----------------------------------

def _add_a_tie(client, token, case_id) -> None:
    """Move the graph so its hash moves with it: two more actors and the
    tie between them, which is what an analyst does between opening the
    pane and looking at it again."""
    ids = []
    for label in ("delta", "echo"):
        r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
            "node_type": "IDENTITY", "label": label,
            "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                          "credibility": "2", "confidence": "LOW"}})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "VOUCHED_FOR", "src_node_id": ids[0], "dst_node_id": ids[1],
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "F",
                      "credibility": "6", "confidence": "LOW",
                      "rationale": "vouched"}})
    assert r.status_code == 201, r.text


def test_latest_says_whether_the_graph_has_moved(conn, client):
    """Reads BOTH sides of what `cached` and `current` mean, across the
    file boundary they cross.

    On the suite endpoint `cached: true` can only come from
    `AnalyticsRunService._lookup`, whose WHERE clause matches on
    `graph_hash`. `latest` reads the newest COMPLETE run back by projection
    name. Until 2026-09-02 both answers went onto the wire as the same
    `cached: true`, and the only renderer of the field printed "unchanged
    since the last run": staleness reported as freshness, this codebase's
    signature defect.

    From 2026-09-02 `latest` answered `current: null`, not checked, which
    was honest and left the pane able to say only "not recomputed"
    (ux10-analytics:stored-run-currency-and-timestamp). Since 2026-09-23 it
    re-projects the caller's graph and compares hashes, so `current` is a
    checked verdict: True on the unchanged graph, False once it has moved,
    and never True over a graph that moved.
    """
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)

    def _suite(**params):
        r = client.get(f"/api/v1/cases/{case_id}/analytics",
                       headers=_auth(token), params=params)
        assert r.status_code == 200, r.text
        return r.json()

    first = _suite()
    assert first["cached"] is False
    assert first["current"] is True, "a run just computed describes the graph now"

    # Same graph: `_lookup`'s graph_hash matches, so the suite's `cached`
    # DOES carry a currency claim here.
    again = _suite()
    assert again["run_id"] == first["run_id"]
    assert again["cached"] is True
    assert again["current"] is True

    unchanged = _latest(client, token, case_id).json()
    assert unchanged["run_id"] == first["run_id"]
    assert unchanged["current"] is True

    # Now move the graph.
    _add_a_tie(client, token, case_id)

    stale = _latest(client, token, case_id).json()
    assert stale["run_id"] == first["run_id"], "still the old run"
    assert stale["cached"] is True, "the bytes did come out of storage"
    assert stale["current"] is False, (
        "/latest compared the hash and the graph has moved: it must say so")

    # The other half of the contract, read here rather than assumed: the
    # suite's `cached` really is driven by the hash filter, so the graph
    # this run was computed over is provably not the graph now. That is
    # what makes the assertion above load-bearing rather than pedantic.
    moved = _suite()
    assert moved["cached"] is False, (
        "the graph changed, so _lookup's graph_hash filter must miss")
    assert moved["run_id"] != first["run_id"]
    assert moved["current"] is True


def test_the_currency_verdict_is_on_every_analytics_response(conn, client):
    """`current` is not an optional extra on one endpoint. A field that is
    present only sometimes sends a client back to inferring currency from
    whichever other keys happen to be there, which is the habit that
    produced the defect."""
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)

    suite = client.get(f"/api/v1/cases/{case_id}/analytics",
                       headers=_auth(token)).json()
    kpp = client.get(f"/api/v1/cases/{case_id}/analytics/key-player",
                     headers=_auth(token), params={"n": 1}).json()
    latest = _latest(client, token, case_id).json()
    kpp_latest = client.get(f"/api/v1/cases/{case_id}/analytics/key-player/latest",
                            headers=_auth(token), params={"n": 1}).json()
    for name, body in (("suite", suite), ("key-player", kpp), ("latest", latest),
                       ("key-player latest", kpp_latest)):
        assert "current" in body, f"{name} carries no currency verdict"
        assert body["current"] in (True, False), (name, body["current"])


# --- 2026-09-23: the stored key player, and asking about one run ---------

def _get(client, token, case_id, suffix, **params):
    return client.get(f"/api/v1/cases/{case_id}/analytics{suffix}",
                      headers=_auth(token), params=params)


def test_the_stored_key_player_is_read_back_by_its_size(conn, client):
    """ux10-analytics:kpp-blank-on-stored-run. The pane opened on the
    stored suite and left the key-player heading empty, although the run
    was on the table. It is read back for the size asked, and checked."""
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)

    assert _get(client, token, case_id, "/key-player/latest", n=1).status_code == 404
    ran = _get(client, token, case_id, "/key-player", n=1)
    assert ran.status_code == 200, ran.text

    back = _get(client, token, case_id, "/key-player/latest", n=1)
    assert back.status_code == 200, back.text
    body = back.json()
    assert body["run_id"] == ran.json()["run_id"]
    assert body["key_player"]["n_remove"] == 1
    assert body["current"] is True
    datetime.fromisoformat(body["computed_at"])
    # A 1-actor set says nothing about a 2-actor one.
    assert _get(client, token, case_id, "/key-player/latest", n=2).status_code == 404
    # Nor about another projection.
    assert _get(client, token, case_id, "/key-player/latest", n=1,
                preset="trust").status_code == 404

    _add_a_tie(client, token, case_id)
    assert _get(client, token, case_id, "/key-player/latest",
                n=1).json()["current"] is False


def test_one_run_can_be_asked_whether_it_still_holds(conn, client):
    """ux10-analytics:analysis-survives-graph-changes. After an edit the
    pane asks about the run on screen, by id, instead of guessing."""
    owner_id, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    suite = _get(client, token, case_id, "").json()
    kpp = _get(client, token, case_id, "/key-player", n=2).json()

    for run in (suite, kpp):
        r = _get(client, token, case_id, f"/runs/{run['run_id']}/current")
        assert r.status_code == 200, r.text
        assert r.json()["current"] is True
        assert r.json()["run_id"] == run["run_id"]

    # Asked under another projection, it is a different question.
    wrong = _get(client, token, case_id, f"/runs/{suite['run_id']}/current",
                 preset="trust")
    assert wrong.status_code == 422, wrong.text
    assert _get(client, token, case_id,
                f"/runs/{uuid4()}/current").status_code == 404

    _add_a_tie(client, token, case_id)
    for run in (suite, kpp):
        r = _get(client, token, case_id, f"/runs/{run['run_id']}/current")
        assert r.json()["current"] is False

    # A lesser clearance cannot ask about a run it could never be served.
    amber_id, amber_email, _ = _make_user(conn, clearance="AMBER", global_roles=())
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""",
        (case_id, amber_id, owner_id))
    amber = _session(conn, amber_email)
    assert _get(client, amber, case_id,
                f"/runs/{suite['run_id']}/current").status_code == 404


def test_the_trend_says_what_each_point_measured(conn, client):
    """ux10-analytics:trend-mixes-run-time-and-world-time. A point carries
    the world time it measured and the projection it was measured under,
    so the chart can plot on the one and refuse to join across the other."""
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    as_of = "2030-01-01T00:00:00+00:00"
    assert _get(client, token, case_id, "", min_confidence="MODERATE").status_code == 200
    assert _get(client, token, case_id, "", as_of=as_of).status_code == 200
    node = next(n for n in _get(client, token, case_id, "").json()["nodes"]
                if n["label"] == "bravo")
    series = _get(client, token, case_id, f"/history/{node['id']}").json()["series"]
    assert len(series) == 3
    for point in series:
        for key in ("as_of", "min_confidence", "include_inferred",
                    "decay_half_life_months", "run_id"):
            assert key in point, key
    assert {p["min_confidence"] for p in series} == {"LOW", "MODERATE"}
    assert sorted(str(p["as_of"]) for p in series).count("None") == 2
    assert any(p["as_of"] and p["as_of"].startswith("2030-01-01") for p in series)


def test_a_run_stored_before_the_fix_is_served_by_the_current_rules(conn, client):
    """A payload computed when the constraint percentile ran the other way,
    and the node_metric rows it wrote, come back in the current direction:
    one column must mean one thing whatever year the run is from."""
    _, email, secret = _make_user(conn)
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    # Isolates, and a fourth actor so the constraints differ: "100 minus the
    # old percentile" is exact only without isolates, and this test used to
    # fabricate the old rows as exactly that on a graph with none, so it
    # could not see the trend table disagree with the actor table (found
    # reviewing the 2026-09-23 fix).
    labels = {n["label"]: n["id"] for n in _get(client, token, case_id, "").json()["nodes"]}
    for label in ("delta", "echo", "foxtrot"):
        r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
            "node_type": "IDENTITY", "label": label,
            "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                          "credibility": "2", "confidence": "MODERATE"}})
        assert r.status_code == 201, r.text
        labels[label] = r.json()["id"]
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "VOUCHED_FOR", "src_node_id": labels["bravo"],
        "dst_node_id": labels["delta"],
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                      "credibility": "2", "confidence": "MODERATE",
                      "rationale": "vouched"}})
    assert r.status_code == 201, r.text
    suite = _get(client, token, case_id, "").json()
    by = {n["label"]: n for n in suite["nodes"]}
    assert by["echo"]["constraint"] is None and by["foxtrot"]["constraint"] is None

    # Make it look like a run from before 2026-09-23, by the rule it was
    # computed with then: the percentile over the raw constraint, isolates
    # at the bottom.
    from noctornal_api.analytics import _rank_and_percentile
    _, raw = _rank_and_percentile([n["constraint"] if n["constraint"] is not None
                                   else float("-inf") for n in suite["nodes"]])
    old_pct = {n["id"]: p for n, p in zip(suite["nodes"], raw, strict=True)}
    old_nodes = []
    for n in suite["nodes"]:
        m = dict(n)
        m["constraint_percentile"] = old_pct[n["id"]]
        m.pop("broker_kind", None)
        old_nodes.append(m)
    result = conn.execute("SELECT result FROM analytics.metric_run WHERE id = %s",
                          (suite["run_id"],)).fetchone()[0]
    result = {k: v for k, v in result.items()
              if k not in ("constraint_order", "broker_rule")}
    result["nodes"] = old_nodes
    from psycopg.types.json import Json
    conn.execute("UPDATE analytics.metric_run SET result = %s WHERE id = %s",
                 (Json(result), suite["run_id"]))
    for nid, pct in old_pct.items():
        conn.execute(
            """UPDATE analytics.node_metric SET percentile = %s
                WHERE metric_run_id = %s AND node_id = %s AND metric = 'constraint'""",
            (pct, suite["run_id"], nid))

    back = _latest(client, token, case_id).json()
    assert "constraint_percentile" in back["upgraded"]
    for n in back["nodes"]:
        assert n["constraint_percentile"] == by[n["label"]]["constraint_percentile"]
        assert n["broker_kind"] == by[n["label"]]["broker_kind"]

    # The trend table says what the actor table says, for every actor with
    # a constraint, and rank 1 sits at the top percentile in both.
    for label in ("alpha", "bravo", "charlie", "delta"):
        series = _get(client, token, case_id, f"/history/{by[label]['id']}",
                      metric="constraint").json()["series"]
        assert series[0]["percentile"] == by[label]["constraint_percentile"], label
        assert series[0]["percentile"] != round(100.0 - old_pct[by[label]["id"]], 2), (
            "the fixture no longer has the isolates that make the turn-round wrong")
    assert by["bravo"]["constraint_rank"] == 1
    assert by["bravo"]["constraint_percentile"] > 80
