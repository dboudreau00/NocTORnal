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
import time
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


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


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
                          "credibility": "2"}})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    for src, dst in ((0, 1), (1, 2)):
        r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
            "edge_type": "VOUCHED_FOR", "src_node_id": ids[src],
            "dst_node_id": ids[dst],
            "assertion": {"basis": "DIRECT_OBSERVATION", "rationale": "vouched"}})
        assert r.status_code == 201, r.text


def _latest(client, token, case_id, **params):
    return client.get(f"/api/v1/cases/{case_id}/analytics/latest",
                      headers=_auth(token), params=params)


def test_latest_is_404_before_any_run_and_the_run_afterwards(conn, client):
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
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
    # computation -- and that is true of both responses here. It used to
    # carry a currency claim as well, which `latest` could not honour; the
    # currency verdict is `current`, and `latest` never establishes one.
    # See test_latest_never_claims_the_graph_is_unchanged.
    assert latest["cached"] is True
    assert latest["current"] is None
    datetime.fromisoformat(latest["computed_at"])   # parses, and is not a duration


def test_latest_follows_the_projection_not_the_case(conn, client):
    """Two presets are two projections; a run under one says nothing about
    the other, and the pane asks for the one it is showing."""
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
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
    token = _login(client, email, secret)
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
    owner = _login(client, email, secret)
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
    amber = _login(client, amber_email, amber_secret)

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
    token = _login(client, email, secret)
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
                          "credibility": "2"}})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "VOUCHED_FOR", "src_node_id": ids[0], "dst_node_id": ids[1],
        "assertion": {"basis": "DIRECT_OBSERVATION", "rationale": "vouched"}})
    assert r.status_code == 201, r.text


def test_latest_never_claims_the_graph_is_unchanged(conn, client):
    """Reads BOTH sides of what `cached` means, across the file boundary
    it crosses.

    On the suite endpoint `cached: true` can only come from
    `AnalyticsRunService._lookup`, whose WHERE clause matches on
    `graph_hash`, so it carries a currency claim: nothing the caller can
    see has changed since that run. `latest` reads the newest COMPLETE run
    back by projection name and makes no hash comparison at all --
    deliberately, because the question it answers is "what did the last run
    say", not "is the last run still true".

    Until 2026-09-02 both answers went onto the wire as the same
    `cached: true` with nothing to tell them apart, and the only renderer
    of the field prints "unchanged since the last run, served from cache".
    So the first client to call the endpoint that exists for opening the
    pane would have told an analyst the case graph was unchanged while it
    had moved underneath them -- staleness reported as freshness, this
    codebase's signature defect built into a new endpoint and pinned by its
    own test.

    `current` is now the currency verdict and `cached` says only where the
    bytes came from. `latest` answers `current: null` -- NOT CHECKED.
    """
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
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

    # Now move the graph.
    _add_a_tie(client, token, case_id)

    stale = _latest(client, token, case_id).json()
    assert stale["run_id"] == first["run_id"], "still the old run"
    assert stale["cached"] is True, "the bytes did come out of storage"
    assert stale["current"] is None, (
        "/latest does not compare graph hashes, so it must not report a "
        "currency verdict it never established")

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
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)

    suite = client.get(f"/api/v1/cases/{case_id}/analytics",
                       headers=_auth(token)).json()
    kpp = client.get(f"/api/v1/cases/{case_id}/analytics/key-player",
                     headers=_auth(token), params={"n": 1}).json()
    latest = _latest(client, token, case_id).json()
    for name, body in (("suite", suite), ("key-player", kpp), ("latest", latest)):
        assert "current" in body, f"{name} carries no currency verdict"
        assert body["current"] in (True, None), (name, body["current"])
