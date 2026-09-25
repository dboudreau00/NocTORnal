"""Static triage and similarity over HTTP (F11 K, 2026-09-24).

The on-demand route enqueues and answers 202 without waiting for a child;
the run starts after the response when a slot is free ("now") or waits for
the next pass. Its refusals: 404 for a sample the caller cannot see, the
case's 409 for a closed case, 451 without a declared policy, 409 for a
rejected sample, one above the analysis maximum or one already running.
The sample-origin process answers neither route.

Email prefix `sth-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    auth,
    client,
    declare_policy,
    left_behind,
    make_case,
    make_user,
    pe_image,
    teardown,
    token,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

API = "/api/v1"
PREFIX = "sth-"


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    declare_policy(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    assert left_behind(c, PREFIX)["users"] == 0
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


@pytest.fixture
def http():
    """The app, with the triage limit's burst widened: the refusal test
    makes more requests in a second than an analyst would, and the limit
    itself is held by test_the_routes_are_metered_by_their_own_limits."""
    from dataclasses import replace

    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    c = client()
    limits = dict(LIMITS)
    limits["sample.triage"] = replace(LIMITS["sample.triage"], burst=50, quota=500)
    c.app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    return c


def _analyst(conn, **kw):
    uid = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), **kw)
    return uid, auth(token(conn, uid))


def _sample(conn, store, who, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(pe_image() + uuid4().bytes,
                                             submitted_by=who, **kw)


def _post(http, sample_id, headers):
    return http.post(f"{API}/samples/{sample_id}/static-triage", headers=headers)


def test_on_demand_answers_202_now_when_a_slot_is_free_and_next_pass_when_not(conn, store, http):
    from noctornal_api import lab_triage
    from noctornal_api.db import connect
    who, headers = _analyst(conn)
    s = _sample(conn, store, who)
    r = _post(http, s.id, headers)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["will_run"] == "now" and body["run"]["trigger_kind"] == "requested"
    # The background task ran after the response: the run is done, and
    # custody names the analyst who asked.
    status = conn.execute("SELECT status FROM lab.static_run WHERE id = %s",
                          (body["run"]["id"],)).fetchone()[0]
    assert status == "DONE"
    # The run absorbed the submission's, so the read is recorded twice:
    # as the analyst's request and as the product's own.
    readers = {r[0] for r in conn.execute(
        "SELECT actor_id FROM lab.sample_access WHERE sample_id = %s "
        "AND action = 'SCANNED'", (s.id,)).fetchall()}
    assert readers == {who, None}
    other = connect()
    try:
        held = lab_triage.take_slot(other, 1)
        assert held == 0
        t = _sample(conn, store, who)
        r = _post(http, t.id, headers)
        assert r.status_code == 202 and r.json()["will_run"] == "next_pass"
        assert conn.execute("SELECT status FROM lab.static_run WHERE sample_id = %s "
                            "ORDER BY queued_at DESC LIMIT 1",
                            (t.id,)).fetchone()[0] == "QUEUED"
    finally:
        other.close()


def test_on_demand_refusals(conn, store, http, monkeypatch):
    from noctornal_api import lab_triage
    from noctornal_api.db import connect
    from noctornal_api.samples import SampleService
    who, headers = _analyst(conn)
    # 404 for a sample the caller cannot see, the same as a random id.
    red = _sample(conn, store, who, classification="RED")
    amber_uid, amber = _analyst(conn, clearance="AMBER")
    hidden = _post(http, red.id, amber)
    missing = _post(http, uuid4(), amber)
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json()["detail"] == missing.json()["detail"]
    # Rejected.
    gone = _sample(conn, store, who)
    SampleService(conn, store).reject(gone.id, actor_id=who, reason="no",
                                      purge_bytes=False)
    r = _post(http, gone.id, headers)
    assert r.status_code == 409 and "rejected sample" in r.json()["detail"]
    # Too large, naming the setting.
    big = _sample(conn, store, who)
    monkeypatch.setenv(lab_triage.MAX_BYTES_ENV, "1024")
    r = _post(http, big.id, headers)
    assert r.status_code == 409 and lab_triage.MAX_BYTES_ENV in r.json()["detail"]
    monkeypatch.delenv(lab_triage.MAX_BYTES_ENV)
    # Running now.
    busy = _sample(conn, store, who)
    owner = connect()
    try:
        claimed, _ = lab_triage.claim(owner, lab_triage.settings_or_default(),
                                      run_id=conn.execute(
                                          "SELECT id FROM lab.static_run WHERE "
                                          "sample_id = %s", (busy.id,)
                                      ).fetchone()[0])
        assert claimed is not None
        r = _post(http, busy.id, headers)
        assert r.status_code == 409 and "already running" in r.json()["detail"]
    finally:
        owner.close()
    lab_triage.sweep_abandoned(conn)
    # The case's own refusal for a closed case.
    case = make_case(conn, who)
    shut = _sample(conn, store, who, case_id=case)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 "WHERE id = %s", (case,))
    r = _post(http, shut.id, headers)
    from noctornal_api.http.deps import CASE_READ_ONLY_TITLE
    assert r.status_code == 409 and r.json()["title"] == CASE_READ_ONLY_TITLE
    # 451 without a declared policy.
    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY")
    r = _post(http, busy.id, headers)
    assert r.status_code == 451
    reasons = [row[0] for row in conn.execute(
        """SELECT detail->>'reason' FROM audit.event
            WHERE action = 'SAMPLE_STATIC_TRIAGE_REFUSED' AND actor_id = %s
            ORDER BY seq""", (who,)).fetchall()]
    assert reasons == ["rejected", "too_large", "running", "policy"]


def test_the_sample_origin_process_refuses_static_triage_and_similarity(conn, store, http, monkeypatch):
    who, headers = _analyst(conn)
    s = _sample(conn, store, who)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", "https://app.example")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", "https://samples.example")
    assert _post(http, s.id, headers).status_code == 404
    r = http.get(f"{API}/samples/{s.id}/similar", headers=headers)
    assert r.status_code == 404
    r = http.post(f"{API}/samples/similar", headers=headers,
                  json={"by": "imphash", "value": "a" * 32})
    assert r.status_code == 404


def test_the_routes_are_metered_by_their_own_limits():
    from noctornal_api.http.routers import samples as router
    from noctornal_api.ratelimit import LIMITS, Scope
    assert LIMITS["sample.triage"].scope == Scope.USER
    assert (LIMITS["sample.triage"].quota, LIMITS["sample.triage"].per_seconds) == (12, 300)
    assert (LIMITS["sample.similar"].quota, LIMITS["sample.similar"].per_seconds) == (30, 60)
    assert LIMITS["sample.similar"].quota < LIMITS["search"].quota
    src = open(router.__file__, encoding="utf-8").read()
    triage = src[src.index('@router.post("/{sample_id}/static-triage"'):]
    assert 'rate_limit("sample.triage")' in triage[:300]
    similar = src[src.index('@router.get("/{sample_id}/similar"'):]
    assert 'rate_limit("sample.similar")' in similar[:300]
    by_value = src[src.index('@router.post("/similar"'):]
    assert 'rate_limit("sample.similar")' in by_value[:300]


def test_the_detail_carries_runs_the_engine_and_the_verb(conn, store, http):
    who, headers = _analyst(conn)
    s = _sample(conn, store, who)
    body = http.get(f"{API}/samples/{s.id}", headers=headers).json()
    assert body["you_may"]["static_triage"] is True
    assert set(body["yara_engine"]) == {"installed", "version"}
    assert body["static_runs"][0]["status"] == "queued"
    assert body["sample"]["static_triage"]["status"] == "queued"
    row = http.get(f"{API}/samples", headers=headers,
                   params={"state": "QUARANTINED"}).json()["samples"]
    mine = [x for x in row if x["id"] == str(s.id)][0]
    assert {"imphash", "rich_header_hash", "ssdeep", "tlsh", "imphash_common",
            "static_triage"} <= set(mine)
