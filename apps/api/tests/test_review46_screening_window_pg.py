"""lab-2 (review of 2026-10-03): a newly imported prohibited-content list
did not bind the Lab until a screening pass reached the sample. With the
import's own pass skipped (another pass held the lock), the download ticket
was minted, the archive served, static triage claimed the run and a NONE
sandbox accepted the send, for a sample the list named.

Fails on dc28ffa: the ticket is minted and the triage run is claimed.

Email prefix `r46w-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import capev2_stub
from lab_static_fixtures import MemoryStore, make_user
from screening_fixtures import assert_scrubbed, declare, import_list, listed, payload, scrub

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46w-"
APP, SAMPLES = "https://app.r46w.example", "https://samples.r46w.example"
LOCK = "SELECT pg_try_advisory_lock(hashtextextended('noctornal.sample_screen', 0))"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    declare(monkeypatch)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    monkeypatch.delenv("NOCTORNAL_PUBLIC_ORIGIN", raising=False)
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def running_pass():
    """A second session holding the screening lock, as a pass already
    running would: the import's own pass then skips."""
    from noctornal_api.db import connect
    other = connect()
    assert other.execute(LOCK).fetchone()[0], "a pass is already running here"
    yield other
    other.execute("SELECT pg_advisory_unlock(hashtextextended('noctornal.sample_screen', 0))")
    other.close()


def _world(conn, store):
    from noctornal_api.samples import SampleService
    lab = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    submitter = make_user(conn, PREFIX, roles=("ANALYST",))
    svc = SampleService(conn, store)
    bad_bytes, clean_bytes = payload("listed"), payload("clean")
    bad = svc.submit(bad_bytes, submitted_by=submitter, classification="GREEN")
    clean = svc.submit(clean_bytes, submitted_by=submitter, classification="GREEN")
    return lab, officer, svc, bad, clean, bad_bytes


def test_a_list_imported_while_a_pass_runs_binds_the_download_at_once(conn, running_pass):
    from noctornal_api.samples import SampleError, SampleService
    store = MemoryStore()
    lab, officer, svc, bad, clean, bad_bytes = _world(conn, store)
    out = import_list(conn, officer, listed(bad_bytes), samples=svc)
    assert "skipped" in out["rescan"], "the in-request pass ran, so this proves nothing"

    with pytest.raises(SampleError, match="no such sample"):
        SampleService(conn).issue_download_ticket(
            bad.id, actor_id=lab, clearance="AMBER", compartments=frozenset(),
            request_origin=APP)
    with pytest.raises(SampleError, match="no such sample"):
        svc.download(bad.id, actor_id=lab, request_origin=SAMPLES,
                     clearance="AMBER", compartments=frozenset())
    # A sample the new list does not name is still served: the check
    # screens just in time rather than refusing everything behind.
    ticket = SampleService(conn).issue_download_ticket(
        clean.id, actor_id=lab, clearance="AMBER", compartments=frozenset(),
        request_origin=APP)
    assert ticket.raw


def test_triage_does_not_decrypt_a_sample_a_new_list_names(conn, running_pass):
    from noctornal_api import lab_triage
    store = MemoryStore()
    _lab, officer, svc, bad, _clean, bad_bytes = _world(conn, store)
    queued = conn.execute("SELECT count(*) FROM lab.static_run WHERE sample_id = %s "
                          "AND status = 'QUEUED'", (bad.id,)).fetchone()[0]
    assert queued == 1, "submit queued no triage run, so this proves nothing"
    import_list(conn, officer, listed(bad_bytes), samples=svc)

    claimed, skipped = lab_triage.claim(conn, lab_triage.settings_or_default(),
                                        among=[bad.id])
    assert claimed is None and skipped == 1
    assert conn.execute("SELECT status FROM lab.static_run WHERE sample_id = %s",
                        (bad.id,)).fetchone()[0] == "SKIPPED"


def test_a_none_sandbox_does_not_take_a_sample_a_new_list_names(conn, running_pass,
                                                                tmp_path, monkeypatch):
    from noctornal_api import sandbox
    stub, port, ca, server = capev2_stub.start(tmp_path)
    try:
        capev2_stub.configure(monkeypatch, port, ca)
        settings, problem = sandbox.sandbox_settings()
        assert problem is None, problem
        store = MemoryStore()
        _lab, officer, svc, bad, clean, bad_bytes = _world(conn, store)
        assert sandbox.eligibility(conn, bad.id, settings) == (True, "eligible")
        import_list(conn, officer, listed(bad_bytes), samples=svc)
        assert sandbox.eligibility(conn, bad.id, settings) == (False, "no such sample")
        assert sandbox.eligibility(conn, clean.id, settings) == (True, "eligible")
    finally:
        server.shutdown()
        server.server_close()


def test_no_active_list_leaves_the_download_as_it_was(conn):
    """Nothing to screen against is not a refusal: the bytes paths answered
    so before and still do."""
    from noctornal_api import screening
    store = MemoryStore()
    _lab, _officer, _svc, bad, _clean, _b = _world(conn, store)
    active = conn.execute("SELECT count(*) FROM lab.screening_list "
                          "WHERE retired_at IS NULL").fetchone()[0]
    if active:
        pytest.skip("this database holds an active list")
    assert screening.bytes_may_move(conn, bad.id) is True
    assert screening.bytes_may_move(conn, uuid4()) is True
