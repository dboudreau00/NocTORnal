"""Similar samples (F11 J, 2026-09-24).

Found in SQL under the Lab's one gate, so a sample the caller may not see
is neither listed nor counted; the query sample is 404'd first; the
ssdeep token filter and the TLSH bucket
window are exact (they equal brute force); candidates are ordered before
any cap; a capped or time-limited answer says so; a searched value is
validated before any work, travels in the body and is never logged or
audited.

Email prefix `ssm-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import logging
import os
import random
from pathlib import Path
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    auth,
    client,
    declare_policy,
    left_behind,
    make_user,
    teardown,
    token,
)

from noctornal_api import fuzzyhash, lab_similarity

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

API = "/api/v1"
PREFIX = "ssm-"
VECTORS = json.loads((Path(__file__).resolve().parent / "data"
                      / "fuzzy_vectors.json").read_text(encoding="utf-8"))


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


def _sample(conn, who, *, imphash=None, ssdeep=None, tlsh=None, **kw):
    from noctornal_api.samples import SampleService
    s = SampleService(conn, MemoryStore()).submit(
        b"MZ" + uuid4().bytes * 4, submitted_by=who, **kw)
    conn.execute(
        """UPDATE lab.sample SET imphash = %s, ssdeep = %s, ssdeep_tokens = %s,
                  tlsh = %s, tlsh_lvalue = %s WHERE id = %s""",
        (imphash, ssdeep, fuzzyhash.ssdeep_tokens(ssdeep) if ssdeep else None,
         tlsh, fuzzyhash.tlsh_lvalue(tlsh) if tlsh else None, s.id))
    return s


def _similar(conn, *, by, clearance="RED", exclude=None, **hashes):
    t = lab_similarity.Thresholds(
        ssdeep_min=hashes.pop("ssdeep_min", 50),
        tlsh_max=hashes.pop("tlsh_max", 100),
        limit=100, include_rejected=hashes.pop("include_rejected", False))
    return lab_similarity.similar(conn, hashes=hashes, by=by, thresholds=t,
                                  clearance=clearance, compartments=frozenset(),
                                  exclude=exclude)


def test_similar_on_a_hidden_sample_is_404_identical_to_a_random_id(conn):
    who = make_user(conn, PREFIX)
    red = _sample(conn, who, classification="RED", imphash="c" * 32)
    amber = make_user(conn, PREFIX, clearance="AMBER",
                      roles=("MALWARE_ANALYST",))
    http = client()
    headers = auth(token(conn, amber))
    hidden = http.get(f"{API}/samples/{red.id}/similar", headers=headers)
    random_id = http.get(f"{API}/samples/{uuid4()}/similar", headers=headers)
    assert hidden.status_code == random_id.status_code == 404
    assert hidden.json() == random_id.json()


def test_a_red_sample_with_the_same_imphash_is_invisible_to_an_amber_caller_and_uncounted(conn):
    who = make_user(conn, PREFIX)
    imp = uuid4().hex
    a = _sample(conn, who, imphash=imp)
    b = _sample(conn, who, imphash=imp, classification="RED")
    amber = _similar(conn, by="imphash", clearance="AMBER", exclude=a.id,
                     imphash=imp)
    assert amber["results"] == [] and amber["candidates_capped"] is False
    red = _similar(conn, by="imphash", exclude=a.id, imphash=imp)
    assert [r["sample"]["id"] for r in red["results"]] == [str(b.id)]


def test_ssdeep_candidates_equal_brute_force(conn):
    who = make_user(conn, PREFIX)
    digests = [i["ssdeep"] for i in VECTORS["inputs"]
               if not fuzzyhash.ssdeep_is_degenerate(i["ssdeep"])]
    rng = random.Random(8)
    chosen = rng.sample(digests, 60)
    for d in chosen:
        _sample(conn, who, ssdeep=d)
    everything = conn.execute("SELECT id, ssdeep FROM lab.sample "
                              "WHERE ssdeep IS NOT NULL AND state <> 'REJECTED'"
                              ).fetchall()
    for query in chosen[:15]:
        for floor in (1, 50):
            got = {r["sample"]["id"]: r["matched"][0]["score"] for r in _similar(
                conn, by="ssdeep", ssdeep=query, ssdeep_min=floor)["results"]}
            want = {str(i): fuzzyhash.ssdeep_compare(query, d)
                    for i, d in everything
                    if fuzzyhash.ssdeep_compare(query, d) >= floor}
            assert got == want, query


def test_tlsh_threshold_and_lvalue_window_agree_with_brute_force(conn):
    who = make_user(conn, PREFIX)
    digests = sorted({i["tlsh"] for i in VECTORS["inputs"] if i["tlsh"]})
    for d in digests:
        _sample(conn, who, tlsh=d)
    everything = conn.execute("SELECT id, tlsh FROM lab.sample "
                              "WHERE tlsh IS NOT NULL AND state <> 'REJECTED'"
                              ).fetchall()
    for query in digests[::7]:
        for limit in (20, 100, 250):
            got = {r["sample"]["id"] for r in _similar(
                conn, by="tlsh", tlsh=query, tlsh_max=limit)["results"]}
            want = {str(i) for i, d in everything
                    if fuzzyhash.tlsh_distance(query, d) <= limit}
            assert got == want, (query, limit)


def test_value_search_validates_before_any_work(conn, monkeypatch):
    who = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",))
    headers = auth(token(conn, who))
    http = client()

    def untouched(*a, **k):
        raise AssertionError("work was done for an invalid value")

    monkeypatch.setattr(lab_similarity, "similar", untouched)
    for by, value in (("imphash", "zz"), ("tlsh", "T1" + "A" * 10),
                      ("ssdeep", "5:abc:de"), ("rich_header", "x" * 32),
                      ("nope", "a" * 32)):
        r = http.post(f"{API}/samples/similar", headers=headers,
                      json={"by": by, "value": value})
        assert r.status_code == 400, (by, r.text)
        assert value not in r.text or by == "nope"
    r = http.post(f"{API}/samples/similar",
                  headers={**headers, "content-type": "application/json"},
                  content=b'{"by":"imphash","value":"' + b"a" * (2 << 20) + b'"}')
    assert r.status_code == 413


def test_value_search_takes_the_value_in_the_body_never_the_url_and_never_logs_it(conn, caplog):
    who = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",))
    headers = auth(token(conn, who))
    value = uuid4().hex
    before = conn.execute("SELECT count(*) FROM audit.event").fetchone()[0]
    with caplog.at_level(logging.DEBUG):
        r = client().post(f"{API}/samples/similar", headers=headers,
                          json={"by": "imphash", "value": value})
    assert r.status_code == 200, r.text
    assert value not in caplog.text
    assert conn.execute("SELECT count(*) FROM audit.event").fetchone()[0] == before
    assert conn.execute("SELECT count(*) FROM audit.event WHERE detail::text "
                        "LIKE %s", (f"%{value}%",)).fetchone()[0] == 0


def test_rejected_samples_are_excluded_unless_asked(conn):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    imp = uuid4().hex
    a = _sample(conn, who, imphash=imp)
    b = _sample(conn, who, imphash=imp)
    SampleService(conn).reject(b.id, actor_id=who, reason="no", purge_bytes=False)
    assert _similar(conn, by="imphash", exclude=a.id, imphash=imp)["results"] == []
    got = _similar(conn, by="imphash", exclude=a.id, imphash=imp,
                   include_rejected=True)["results"]
    assert [r["sample"]["id"] for r in got] == [str(b.id)]


def test_candidate_cap_and_partial_are_reported(conn, monkeypatch):
    who = make_user(conn, PREFIX)
    imp = uuid4().hex
    samples = [_sample(conn, who, imphash=imp) for _ in range(3)]
    monkeypatch.setattr(lab_similarity, "CANDIDATE_CAP", 1)
    out = _similar(conn, by="imphash", imphash=imp)
    assert out["candidates_capped"] is True
    # Ordered newest first BEFORE the cap: the same row every time.
    assert [r["sample"]["id"] for r in out["results"]] == [str(samples[-1].id)]
    digest = next(i["ssdeep"] for i in VECTORS["inputs"]
                  if not fuzzyhash.ssdeep_is_degenerate(i["ssdeep"]))
    _sample(conn, who, ssdeep=digest)
    monkeypatch.setattr(lab_similarity, "COMPARE_BUDGET_S", -1)
    out = _similar(conn, by="ssdeep", ssdeep=digest)
    assert out["partial"] is True and out["partial_reason"]


def test_a_common_imphash_ranks_below_a_distinctive_match(conn):
    who = make_user(conn, PREFIX)
    common = next(iter(fuzzyhash.COMMON_IMPHASHES))
    q = _sample(conn, who, imphash=common)
    other = _sample(conn, who, imphash=common)
    out = _similar(conn, by="imphash", exclude=q.id, imphash=common)
    match = [r for r in out["results"] if r["sample"]["id"] == str(other.id)][0]
    assert match["matched"][0]["common"] is True
