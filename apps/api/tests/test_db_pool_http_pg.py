"""docs/17, "a connection for every request", through the real routes: the request pool (decision 233)
on a pool of ONE connection, in production's shape (`NOCTORNAL_TEST_ASSUME_ROLE`: the request role,
bound by the session), so every request below runs on the same backend, one after another.

What these hold:

- two analysts in turn on that one backend each see only their own cases, and every request is handed
  the connection bound to nobody, whoever had it before;
- a request with no session after one with a session is bound to nobody;
- without the reset the next request WOULD be handed a connection still bound to the previous user (the
  control);
- a request the pool cannot serve in time is a 503 problem with `Retry-After`;
- the application's shutdown closes the pool.

Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE (rls_support).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import rls_support as s
from noctornal_api import db, db_pool
from noctornal_api.http.errors import POOL_UNAVAILABLE_DETAIL

pytestmark = s.GATED

PREFIX = "poolh-"


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    monkeypatch.setenv(db.ASSUME_ROLE_ENV, "1")
    monkeypatch.setenv(db_pool.POOL_ENV, "on")
    monkeypatch.setenv(db_pool.POOL_MIN_ENV, "1")
    monkeypatch.setenv(db_pool.POOL_MAX_ENV, "1")
    monkeypatch.setenv(db_pool.POOL_TIMEOUT_ENV, "10")
    db_pool.close_pools()
    c = s.owner_conn()
    yield c
    db_pool.close_pools()
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def client():
    from noctornal_api.http.app import app
    return TestClient(app)


@pytest.fixture
def checkouts(monkeypatch):
    """What each request's connection is when the pool hands it over: its backend and whom it is
    bound to. Read in the refusal every pooled checkout passes through, before the route runs."""
    seen: list[tuple] = []
    refuse = db.refuse_privileged_request_role

    def recording(conn):
        refuse(conn)
        actor, proof, ticket = conn.execute(
            "SELECT iam.rls_actor(), nullif(current_setting('noctornal.rls_proof', true), ''), "
            "nullif(current_setting('noctornal.rls_ticket', true), '')").fetchone()
        seen.append((conn.info.backend_pid, actor, proof is not None or ticket is not None))

    monkeypatch.setattr(db, "refuse_privileged_request_role", recording)
    return seen


def _auth(owner, uid) -> dict:
    _, raw = s.session(owner, uid)
    return {"Authorization": f"Bearer {raw}"}


def _ids(response) -> list[str]:
    assert response.status_code == 200, response.text
    return [c["id"] for c in response.json()]


def test_two_analysts_in_turn_on_one_physical_connection_see_only_their_own_cases(
        owner, client, checkouts):
    boss = s.user(owner, "RED", prefix=PREFIX)
    first = s.user(owner, "AMBER", prefix=PREFIX)
    second = s.user(owner, "AMBER", prefix=PREFIX)
    theirs = s.case(owner, boss)
    mine = s.case(owner, boss)
    s.assign(owner, theirs, first)
    s.assign(owner, mine, second)
    as_first, as_second = _auth(owner, first), _auth(owner, second)

    assert _ids(client.get("/api/v1/cases", headers=as_first)) == [str(theirs)]
    assert _ids(client.get("/api/v1/cases", headers=as_second)) == [str(mine)]
    assert client.get(f"/api/v1/cases/{theirs}", headers=as_second).status_code in (403, 404)
    assert client.get(f"/api/v1/cases/{theirs}", headers=as_first).status_code == 200
    assert _ids(client.get("/api/v1/cases", headers=as_second)) == [str(mine)]

    assert len(checkouts) == 5
    assert len({pid for pid, _, _ in checkouts}) == 1, "the requests ran on more than one backend"
    assert all(actor is None and not bound for _, actor, bound in checkouts), checkouts


def test_an_unauthenticated_request_after_an_authenticated_one_is_bound_to_nobody(
        owner, client, checkouts):
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    s.assign(owner, s.case(owner, boss), analyst)
    assert len(_ids(client.get("/api/v1/cases", headers=_auth(owner, analyst)))) == 1
    refused = client.post("/api/v1/auth/login",
                          json={"email": f"{PREFIX}nobody@noctornal.test",
                                "password": "not the password", "totp_code": "000000"})
    assert refused.status_code in (400, 401, 422), refused.text
    assert len(checkouts) == 2 and checkouts[0][0] == checkouts[1][0]
    assert checkouts[1][1:] == (None, False), "the sign-in ran bound to the previous user"


def test_without_the_reset_the_next_request_would_be_bound_to_the_previous_user(
        owner, client, checkouts, monkeypatch):
    """The control for the two tests above."""
    monkeypatch.setattr(db_pool, "_reset", lambda conn, assume: None)
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    s.assign(owner, s.case(owner, boss), analyst)
    client.get("/api/v1/cases", headers=_auth(owner, analyst))
    client.post("/api/v1/auth/login",
                json={"email": f"{PREFIX}nobody@noctornal.test",
                      "password": "not the password", "totp_code": "000000"})
    assert checkouts[1][0] == checkouts[0][0]
    assert checkouts[1][1] == analyst


def test_pool_exhaustion_answers_503_with_retry_after_and_problem_json(owner, client, monkeypatch):
    monkeypatch.setenv(db_pool.POOL_TIMEOUT_ENV, "1")
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    headers = _auth(owner, analyst)
    pool = db_pool._request_pool()
    held = pool.getconn(timeout=10)
    try:
        r = client.get("/api/v1/cases", headers=headers)
    finally:
        pool.putconn(held)
    assert r.status_code == 503, r.text
    assert r.headers["content-type"] == "application/problem+json"
    assert r.headers["retry-after"] == "1"
    assert r.json()["detail"].startswith(POOL_UNAVAILABLE_DETAIL)
    assert client.get("/api/v1/cases", headers=headers).status_code == 200


def test_requests_beyond_the_threadpool_do_not_starve_those_holding_a_connection(
        owner, monkeypatch):
    """The threadpool is the scarce thing: a request waiting for a connection holds one of its
    tokens, and the request holding the connection needs another to finish. With 6 tokens, 2
    connections and 30 requests at once, every request is answered within the wait: a 200 or an
    instant 503, never a 503 that waited the whole timeout while holders could not run."""
    import asyncio
    import time

    import anyio.to_thread
    import httpx
    from fastapi import Depends, FastAPI

    from noctornal_api.http import deps
    from noctornal_api.http.errors import install_error_handlers

    monkeypatch.setattr(db_pool, "THREADPOOL_TOKENS", 6)
    monkeypatch.setenv(db_pool.POOL_MAX_ENV, "2")
    monkeypatch.setenv(db_pool.POOL_TIMEOUT_ENV, "4")
    db_pool.close_pools()
    scratch = FastAPI()
    install_error_handlers(scratch)

    @scratch.get("/slow")
    def slow(conn=Depends(deps.get_conn)):
        conn.execute("SELECT pg_sleep(0.3)")
        return {}

    async def drive():
        anyio.to_thread.current_default_thread_limiter().total_tokens = 6
        transport = httpx.ASGITransport(app=scratch, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            started = time.monotonic()
            answers = await asyncio.gather(*(http.get("/slow") for _ in range(30)))
            return [a.status_code for a in answers], time.monotonic() - started

    codes, took = asyncio.run(drive())
    assert db_pool.PoolSettings(1, 2, 4).max_waiting == 3
    # The stall is the failure: without the cap on waiters every token is held by one, the holders cannot
    # run, and the batch lasts the whole wait. How many requests are answered 200 is not fixed (the pool
    # opens its second connection while requests queue, so the count that fits the queue varies), so it is
    # only held to the connections the pool has: each of them answers at least one request.
    assert took < 3.5, f"the requests stalled for {took:.1f} s: {sorted(set(codes))}"
    assert codes.count(200) >= 2, codes
    assert set(codes) <= {200, 503}, codes


def test_the_application_shutdown_closes_every_pool(owner):
    from noctornal_api.http.app import create_app
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    headers = _auth(owner, analyst)
    with TestClient(create_app()) as running:
        assert running.get("/api/v1/cases", headers=headers).status_code == 200
        pools = list(db_pool._POOLS.values())
        assert len(pools) == 1 and not pools[0].closed
    assert pools[0].closed and not db_pool._POOLS
