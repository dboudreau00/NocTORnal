"""When the isolated analysis worker fails during a pass, nothing is
spent and nothing is misread (docs/17 F42 review, 2026-10-02).

The review found three: a triage step the worker never ran was stored as
a crashed step on the sample, a compile the worker never ran spent one of
its three attempts, and a forum page the worker never parsed was parser
drift on a healthy parser. Now a run goes back to the queue at the same
attempt with nothing written, a compile keeps its attempts, and a poll is
BLOCKED (no failure counted, no drift) and keeps its cursor. Each test
has a control that shows the child's own failure is still the child's.

Email prefixes `anx-` (the Lab) and `test-anxc-` (collection).
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import collection_helpers as h
import forum_helpers as fh
from lab_static_fixtures import (
    MemoryStore,
    declare_policy,
    drain,
    left_behind,
    make_user,
    pe_image,
    teardown,
)

from noctornal_api import analysis_runner as ar
from noctornal_api import forum_adapters as fa
from noctornal_api import lab_triage

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "anx-"
P = "test-anxc-"
RULE = b'rule r_1 { strings: $a = "needle-1" condition: $a }\n'


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    declare_policy(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    h.teardown(c, P)
    h.retire_users(c, P)
    assert left_behind(c, PREFIX) == {"users": 0, "rulesets": 0}
    c.close()


def _failing(reason):
    return lambda *_a, **_k: ar.ChildResult(False, failure=reason)


def _runs(conn, sample_id):
    return conn.execute(
        """SELECT status, trigger, attempt, failure FROM lab.static_run
            WHERE sample_id = %s ORDER BY queued_at, id""", (sample_id,)).fetchall()


# --- a triage run -------------------------------------------------------------

@pytest.mark.parametrize("reason", ["worker_busy", "worker_unavailable",
                                    "worker_refused"])
def test_a_run_the_worker_could_not_run_waits_at_the_same_attempt(conn, monkeypatch,
                                                                  reason):
    from noctornal_api.samples import SampleService
    store = MemoryStore()
    who = make_user(conn, PREFIX)
    sample = SampleService(conn, store).submit(
        pe_image() + uuid4().bytes, submitted_by=who, original_filename="x.bin")
    queued = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                          "AND status = 'QUEUED'", (sample.id,)).fetchone()[0]
    real = lab_triage.run_child
    monkeypatch.setattr(lab_triage, "run_child", _failing(reason))
    assert drain(conn, store, run_id=queued) == [lab_triage.INTERRUPTED]
    assert _runs(conn, sample.id) == [
        ("FAILED", "SUBMIT", 1, lab_triage.CHILD_FAILURES[reason]),
        ("QUEUED", "RETRY", 1, None)]
    assert conn.execute("SELECT count(*) FROM lab.sample_analysis WHERE "
                        "sample_id = %s", (sample.id,)).fetchone()[0] == 0, \
        "nothing a run the worker interrupted found is written"
    # The worker is back: the same request runs, still at attempt 1.
    monkeypatch.setattr(lab_triage, "run_child", real)
    retry = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                         "AND status = 'QUEUED'", (sample.id,)).fetchone()[0]
    assert drain(conn, store, run_id=retry) == ["DONE"]
    assert [r[:3] for r in _runs(conn, sample.id)] == [
        ("FAILED", "SUBMIT", 1), ("DONE", "RETRY", 1)]


def test_a_run_the_worker_refused_for_its_size_is_skipped_and_not_queued_again(
        conn, monkeypatch):
    """docs/17, "an oversize sample is re-queued every pass": a worker whose
    own limit (NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES) is under this deployment's
    refused the same sample on every pass, and every pass decrypted it and
    sent it again. When the worker's own report of its limit explains the
    refusal, the run ends SKIPPED with the reason, its steps are gaps that
    say so, and nothing is queued."""
    from noctornal_api.samples import SampleService
    store = MemoryStore()
    who = make_user(conn, PREFIX)
    data = pe_image() + uuid4().bytes
    sample = SampleService(conn, store).submit(data, submitted_by=who,
                                               original_filename="x.bin")
    queued = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                          "AND status = 'QUEUED'", (sample.id,)).fetchone()[0]
    cap = len(data) - 1
    monkeypatch.setattr(lab_triage, "run_child", _failing("worker_refused"))
    monkeypatch.setattr(ar, "worker_request_cap", lambda *_a, **_k: cap)
    assert drain(conn, store, run_id=queued) == ["SKIPPED"]
    reason = lab_triage.WORKER_TOO_LARGE_REASON.format(cap=cap)
    assert _runs(conn, sample.id) == [("SKIPPED", "SUBMIT", 1, reason)]
    assert "NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES" in reason and str(cap) in reason
    gaps = conn.execute("SELECT triage_gaps FROM lab.sample WHERE id = %s",
                        (sample.id,)).fetchone()[0]
    by_step = {g["step"]: g for g in gaps}
    for step in ("imphash", "rich_header_hash", "ssdeep", "tlsh"):
        assert by_step[step]["status"] == "skipped" and by_step[step]["reason"] == reason
    assert conn.execute("SELECT count(*) FROM lab.sample_analysis WHERE sample_id = %s",
                        (sample.id,)).fetchone()[0] == 0


def test_a_refusal_the_workers_limit_does_not_explain_still_waits_at_the_same_attempt(
        conn, monkeypatch):
    """The controls: a worker that is silent about its limit, one whose limit
    is above the sample, and a sample under it that the worker refused for
    another reason, are the sandbox's state and not a fact about the sample."""
    from noctornal_api.samples import SampleService
    store = MemoryStore()
    who = make_user(conn, PREFIX)
    data = pe_image() + uuid4().bytes
    sample = SampleService(conn, store).submit(data, submitted_by=who,
                                               original_filename="x.bin")
    monkeypatch.setattr(lab_triage, "run_child", _failing("worker_refused"))
    for cap in (None, len(data), len(data) * 10):
        monkeypatch.setattr(ar, "worker_request_cap", lambda *_a, cap=cap, **_k: cap)
        queued = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                              "AND status = 'QUEUED'", (sample.id,)).fetchone()[0]
        assert drain(conn, store, run_id=queued) == [lab_triage.INTERRUPTED], cap
    assert [r[0] for r in _runs(conn, sample.id)] == ["FAILED", "FAILED", "FAILED",
                                                      "QUEUED"]
    # And a refusal that is not a refusal, with a limit under the sample, is
    # the child's own failure as ever.
    monkeypatch.setattr(lab_triage, "run_child", _failing("crashed"))
    monkeypatch.setattr(ar, "worker_request_cap", lambda *_a, **_k: 1)
    queued = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                          "AND status = 'QUEUED'", (sample.id,)).fetchone()[0]
    assert drain(conn, store, run_id=queued) == ["DONE"]


def test_the_runner_asks_the_worker_for_its_limit_and_only_the_isolated_runner_has_one(
        monkeypatch, tmp_path):
    sock = str(tmp_path / "w.sock")
    env = {ar.SOCKET_ENV: sock, "NOCTORNAL_ENV": "production"}
    monkeypatch.setattr(ar, "runner_choice", lambda _e=None: ar.RunnerChoice(
        "isolated", socket_path=sock, production=True))
    monkeypatch.setattr(ar, "hello", lambda *_a, **_k: {"max_request_bytes": 1 << 30})
    assert ar.worker_request_cap(env) == 1 << 30
    for said in ({}, {"max_request_bytes": 0}, {"max_request_bytes": "big"},
                 {"max_request_bytes": True}):
        monkeypatch.setattr(ar, "hello", lambda *_a, _said=said, **_k: _said)
        assert ar.worker_request_cap(env) is None, said

    def gone(*_a, **_k):
        raise ar.WorkerUnavailable("unreachable")

    monkeypatch.setattr(ar, "hello", gone)
    assert ar.worker_request_cap(env) is None
    monkeypatch.setattr(ar, "runner_choice", lambda _e=None: ar.RunnerChoice(
        "local", production=False))
    assert ar.worker_request_cap() is None


def test_a_step_whose_child_crashed_is_still_a_failed_step(conn, monkeypatch):
    """The control: the child's own failure finishes the run DONE with a
    failed gap, as before the review."""
    from noctornal_api.samples import SampleService
    store = MemoryStore()
    who = make_user(conn, PREFIX)
    sample = SampleService(conn, store).submit(
        pe_image() + uuid4().bytes, submitted_by=who, original_filename="x.bin")
    queued = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                          "AND status = 'QUEUED'", (sample.id,)).fetchone()[0]
    monkeypatch.setattr(lab_triage, "run_child", _failing("crashed"))
    assert drain(conn, store, run_id=queued) == ["DONE"]


# --- a compile ----------------------------------------------------------------

@pytest.mark.parametrize("reason, spent", [("worker_busy", 0),
                                           ("worker_unavailable", 0),
                                           ("worker_bad_answer", 0),
                                           ("crashed", 1)])
def test_a_compile_the_worker_could_not_run_keeps_its_attempts(conn, monkeypatch,
                                                               reason, spent):
    from noctornal_api.yara_rules import RulesetService, build_key, parse_bundle
    key = build_key()
    if key is None:
        pytest.skip("yara-x is not installed")
    lab = make_user(conn, PREFIX)
    rulesets = RulesetService(conn)
    set_id = rulesets.create(key=f"anx-{uuid4().hex[:8]}", display_name="Test set",
                             description=None, classification="AMBER",
                             compartments=(), actor_id=lab)["id"]
    version = rulesets.add_version(
        set_id, parse_bundle("r.yar", RULE), licence="MIT",
        licence_review_required=False, provenance={"via": "upload"}, note=None,
        uploaded_by=lab, host_user=None, key=key)
    monkeypatch.setattr(lab_triage, "run_child", _failing(reason))
    settings = lab_triage.settings_or_default()
    if reason in ar.SANDBOX_FAILURES:
        with pytest.raises(lab_triage.AnalysisInterrupted) as caught:
            lab_triage.compile_pending(conn, settings, limit=1,
                                       version_id=version["id"])
        assert caught.value.failure == reason
    else:
        assert lab_triage.compile_pending(conn, settings, limit=1,
                                          version_id=version["id"]) == (0, 0)
    assert conn.execute(
        "SELECT status, attempts, last_error FROM lab.yara_compile_job "
        "WHERE version_id = %s", (version["id"],)).fetchone() == \
        ("QUEUED", spent, reason)


# --- a forum poll -------------------------------------------------------------

def test_a_poll_the_worker_failed_is_blocked_not_drift_and_keeps_its_cursor(
        conn, monkeypatch):
    from noctornal_api.collection import CollectionService
    from noctornal_api.rawstore import InMemoryDocumentRawStorage
    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_FORUM_ALLOW_DIRECT", "1")
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    h.refuse_remote_sockets(monkeypatch)
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    egress = h.egress_profile(conn, P)
    source = h.source(conn, P, kind="XENFORO", parser="xenforo",
                      base_url=fh.XF_THREAD, egress=egress, max_rps=999)
    h.authority(conn, recorder=recorder, confirmer=confirmer,
                source_ids=[source], adapters=fh.registry())

    def poll(registry):
        return CollectionService(
            conn, registry, fetcher=fh.xf_thread_site(),
            raw_store=InMemoryDocumentRawStorage(),
            sleep=lambda _s: None).run_once(source, actor_id=None)

    def last_run():
        return conn.execute(
            """SELECT status::text, error_class, error_detail, cursor
                 FROM collect.collection_run WHERE source_id = %s
                ORDER BY started_at DESC, id DESC LIMIT 1""", (source,)).fetchone()

    assert poll(fh.registry()).status == "OK"
    before = last_run()[3]

    def busy(*_a, **_k):
        raise fa.ParseAbandoned("worker_busy")

    result = poll(fh.registry(parse=busy))
    status, error_class, detail, cursor = last_run()
    assert (result.status, status, error_class) == ("BLOCKED", "BLOCKED",
                                                    "AnalysisUnavailable")
    assert "had no free slot in time" in detail
    assert cursor == before, "the next poll reads the same pages again"
    failures, blocked = conn.execute(
        "SELECT consecutive_failures, blocked_reason FROM collect.source "
        "WHERE id = %s", (source,)).fetchone()
    assert failures == 0, "the sandbox's state is not the source's ill health"
    assert "the parser is not at fault" in blocked
    # The control: a child that crashed is drift, PARTIAL, as before.

    def crashed(*_a, **_k):
        raise fa.ParseAbandoned("crashed")

    assert poll(fh.registry(parse=crashed)).status == "PARTIAL"
    assert last_run()[1] == "ParserDrift"
