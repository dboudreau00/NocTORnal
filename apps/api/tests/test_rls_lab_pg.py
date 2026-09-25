"""Row-level security on the Lab (S1, 2026-09-25).

0121 puts samples and everything hanging off them, and the YARA rule sets,
under policy. Run as the request role, bound by a real session's proof,
with the fixtures seeded as the owner:

- a sample is visible at its own labels composed with its case's, against
  the reader's CASE-LESS ceiling, with no case assignment (the Lab is
  global under sample.read); its static runs follow it; unbound sees
  nothing; nothing calls a row-security helper per row;
- the work that must see every sample still does: a duplicate of a sample
  the submitter may not see is refused and not stored twice, the Security
  Officer's label-free record lists and reviews a match above the officer,
  and a lookup of a hash held only by a never-screened sample the caller
  cannot see is refused;

Gated like the other row-security tests. Account prefix `rlslab-`.
"""
from __future__ import annotations

import hashlib
import io

import pytest

import rls_support as s
from lab_static_fixtures import MemoryStore, auth, client, make_case, make_user, token
from screening_fixtures import assert_scrubbed, declare, import_list, listed, payload, scrub

pytestmark = s.GATED

API = "/api/v1"
PREFIX = "rlslab-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    declare(monkeypatch)
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


def _submit(conn, store, who, data: bytes | None = None, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(data or payload(), submitted_by=who, **kw)


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def test_a_sample_is_held_to_its_composed_labels_without_an_assignment(conn, store):
    analyst = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    amber_case = make_case(conn, owner)
    red_case = make_case(conn, owner, classification="RED")
    free = _submit(conn, store, owner).id
    in_amber = _submit(conn, store, owner, case_id=amber_case).id
    in_red = _submit(conn, store, owner, case_id=red_case,
                     classification="AMBER").id
    red_own = _submit(conn, store, owner, classification="RED").id
    everything = [free, in_amber, in_red, red_own]

    app = s.app_conn(token(conn, analyst))
    try:
        assert _ids(app, "SELECT id FROM lab.sample WHERE id = ANY(%s)",
                    (everything,)) == {free, in_amber}, (
            "an AMBER sample of a RED case composes to RED")
        runs = _ids(app, "SELECT sample_id FROM lab.static_run "
                         "WHERE sample_id = ANY(%s)", (everything,))
        assert runs and runs <= {free, in_amber}
        assert s.per_row_definer_calls(
            app, "SELECT id FROM lab.sample WHERE submitted_by = %s", (owner,)) == []
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        assert s.count(unbound, "SELECT count(*) FROM lab.sample WHERE id = ANY(%s)",
                       (everything,)) == 0
    finally:
        unbound.close()


def test_a_duplicate_the_submitter_cannot_see_is_refused_and_not_stored_twice(conn, store):
    submitter = make_user(conn, PREFIX, roles=("ANALYST",), clearance="AMBER")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    red_case = make_case(conn, owner, classification="RED")
    data = payload("dup")
    _submit(conn, store, owner, data, case_id=red_case)
    r = client().post(f"{API}/samples", headers=auth(token(conn, submitter)),
                      files={"file": ("again.bin", io.BytesIO(data),
                                      "application/octet-stream")},
                      data={"classification": "AMBER"})
    assert r.status_code == 409, r.text
    assert "was not accepted" in r.json()["detail"]
    assert s.count(conn, "SELECT count(*) FROM lab.sample WHERE sha256 = %s",
                   (hashlib.sha256(data).digest(),)) == 1


def test_the_officers_record_lists_and_reviews_a_match_above_the_officer(conn, store):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",), clearance="AMBER")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    red_case = make_case(conn, owner, classification="RED")
    data = payload("match")
    sample = _submit(conn, store, owner, data, case_id=red_case)
    import_list(conn, officer, listed(data))
    result = conn.execute(
        "SELECT id FROM lab.screening_result WHERE sample_id = %s AND outcome = 'MATCH'",
        (sample.id,)).fetchone()
    assert result is not None, "the pass matched the sample"
    http, headers = client(), auth(token(conn, officer))
    r = http.get(f"{API}/samples/screening", headers=headers)
    assert r.status_code == 200, r.text
    mine = [m for m in r.json()["matches"] if m["result_id"] == str(result[0])]
    assert len(mine) == 1 and mine[0]["you_may_open"] is False
    assert r.json()["counts"]["matches"] >= 1
    r = http.post(f"{API}/samples/screening/results/{result[0]}/reviews",
                  headers=headers, json={"action": "ACKNOWLEDGED"})
    assert r.status_code == 201, r.text


def test_the_hash_of_a_never_screened_sample_nobody_here_can_see_does_not_leave(conn, store):
    from noctornal_api.lookups import LookupService, Subject

    analyst = make_user(conn, PREFIX, roles=("ANALYST",), clearance="AMBER")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    red_case = make_case(conn, owner, classification="RED")
    their_case = make_case(conn, owner)
    data = payload("unscreened")
    sample = _submit(conn, store, owner, data, case_id=red_case)
    conn.execute("UPDATE lab.sample SET screening_outcome = 'NOT_SCREENED', "
                 "screened_at = NULL, screening_list_seq = NULL WHERE id = %s",
                 (sample.id,))
    digest = hashlib.sha256(data).hexdigest()
    subject = Subject("VALUE", their_case, None, None, None, "HASH_SHA256", digest,
                      "AMBER", frozenset(), frozenset())
    app = s.app_conn(token(conn, analyst))
    try:
        assert app.execute("SELECT 1 FROM lab.sample WHERE id = %s",
                           (sample.id,)).fetchone() is None
        why = LookupService(app)._sample_hashes(subject, "AMBER", frozenset())
    finally:
        app.close()
    assert why == "value_restricted"

