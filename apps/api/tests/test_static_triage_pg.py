"""The static-triage runner against the database (F11, 2026-09-24).

What these hold: one queued run per sample, merged requests that name
every requester in custody; claim, verify, custody, children, results,
in that order; a tamper alarm that survives and is never retried;
findings discarded when the sample is rejected or its case closed
mid-run; liveness by advisory lock with the lock taken before the claim
commits; slots across connections; nothing written to the graph; machine rows that
name their run and no analyst, and whose selectors an analyst proposes.

Email prefix `stt-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import builtins
import importlib.util
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    declare_policy,
    drain,
    imphash_of,
    left_behind,
    make_case,
    make_user,
    pe_image,
    teardown,
    varied,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

PREFIX = "stt-"
MIGRATIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    declare_policy(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    assert left_behind(c, PREFIX) == {"users": 0, "rulesets": 0}
    c.close()


@pytest.fixture
def store():
    return MemoryStore()


def _submit(conn, store, who, data=None, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(
        data if data is not None else pe_image() + uuid4().bytes,
        submitted_by=who, original_filename="x.bin", **kw)


def _runs(conn, sample_id):
    return conn.execute(
        """SELECT id, status, trigger, requested_by, attempt, requests, steps
             FROM lab.static_run WHERE sample_id = %s
            ORDER BY queued_at, id""", (sample_id,)).fetchall()


def _scanned(conn, sample_id):
    return conn.execute(
        """SELECT actor_id, actor_kind, detail FROM lab.sample_access
            WHERE sample_id = %s AND action = 'SCANNED'
            ORDER BY id""", (sample_id,)).fetchall()


def _one_run(conn, store, sample):
    """Run the sample's queued run, and only it."""
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                       "AND status = 'QUEUED'", (sample.id,)).fetchone()
    assert run, "nothing queued"
    return drain(conn, store, run_id=run[0])


# --- the queue ---------------------------------------------------------------

def test_submit_enqueues_one_run_in_the_same_transaction(conn, store):
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    runs = _runs(conn, s.id)
    assert [(r[1], r[2]) for r in runs] == [("QUEUED", "SUBMIT")]

    class Broken(MemoryStore):
        def put(self, key, data):
            raise RuntimeError("the bucket refused")

    data = pe_image() + uuid4().bytes
    with pytest.raises(RuntimeError):
        _submit(conn, Broken(), who, data=data)
    import hashlib
    assert conn.execute("SELECT count(*) FROM lab.sample WHERE sha256 = %s",
                        (hashlib.sha256(data).digest(),)).fetchone()[0] == 0


def test_one_queued_run_per_sample_and_requests_merge(conn, store):
    from noctornal_api import lab_triage
    alice = make_user(conn, PREFIX)
    bob = make_user(conn, PREFIX)
    s = _submit(conn, store, alice)
    first = lab_triage.enqueue(conn, s.id, trigger="ON_DEMAND",
                               requested_by=alice)
    assert first.merged
    vid = uuid4()
    lab_triage.enqueue(conn, s.id, trigger="RETROHUNT", requested_by=bob,
                       steps=("yara",), yara_version_ids=(vid,))
    runs = _runs(conn, s.id)
    assert len(runs) == 1
    _id, status, trigger, by, _attempt, requests, steps = runs[0]
    # The analyst's request upgraded the scheduled run and names her; the
    # retrohunt only unioned, and both are recorded.
    assert (status, trigger, by) == ("QUEUED", "ON_DEMAND", alice)
    assert [r["trigger"] for r in requests] == ["SUBMIT", "ON_DEMAND",
                                                "RETROHUNT"]
    assert {r["requested_by"] for r in requests} == {None, str(alice), str(bob)}
    assert sorted(steps) == ["fuzzy", "pe", "yara"]
    # Every open activation (the SUBMIT's empty list) absorbs a list.
    assert conn.execute("SELECT yara_version_ids FROM lab.static_run "
                        "WHERE id = %s", (runs[0][0],)).fetchone()[0] == []


def test_merged_requests_name_every_requester_in_custody(conn, store):
    """A retrohunt merged into an analyst's queued run, which
    had absorbed the submission's, reads the bytes once and says so three
    times: once for each person, once as the product."""
    from noctornal_api import lab_triage
    alice = make_user(conn, PREFIX)
    bob = make_user(conn, PREFIX)
    s = _submit(conn, store, alice)
    lab_triage.enqueue(conn, s.id, trigger="ON_DEMAND", requested_by=alice)
    lab_triage.enqueue(conn, s.id, trigger="RETROHUNT", requested_by=bob,
                       steps=("yara",), yara_version_ids=(uuid4(),))
    assert _one_run(conn, store, s) == ["DONE"]
    rows = _scanned(conn, s.id)
    assert {(r[0], r[1]) for r in rows} == {(alice, "USER"), (bob, "USER"),
                                            (None, "SYSTEM")}
    assert len({r[2]["run_id"] for r in rows}) == 1
    for _a, _k, detail in rows:
        assert set(detail) == {"event", "run_id", "bytes", "sha256_verified"}


def test_scheduled_reads_are_system_and_requested_reads_name_the_requester(conn, store):
    from noctornal_api import lab_triage
    alice = make_user(conn, PREFIX)
    s = _submit(conn, store, alice)
    assert _one_run(conn, store, s) == ["DONE"]
    assert [(r[0], r[1]) for r in _scanned(conn, s.id)] == [(None, "SYSTEM")]
    lab_triage.enqueue(conn, s.id, trigger="ON_DEMAND", requested_by=alice)
    assert _one_run(conn, store, s) == ["DONE"]
    assert [(r[0], r[1]) for r in _scanned(conn, s.id)][-1] == (alice, "USER")


def test_an_on_demand_request_is_claimed_before_a_backlog(conn, store):
    """A retrohunt or a backfill queued first does not hold an
    analyst's request back."""
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX)
    older = [_submit(conn, store, who) for _ in range(3)]
    for s in older:
        conn.execute("UPDATE lab.static_run SET trigger = 'BACKFILL', "
                     "priority = 2 WHERE sample_id = %s", (s.id,))
    newest = _submit(conn, store, who)
    lab_triage.enqueue(conn, newest.id, trigger="ON_DEMAND", requested_by=who)
    # Among this test's samples only: another suite's queue is not ours.
    claimed, _ = lab_triage.claim(conn, lab_triage.settings_or_default(),
                                  among=[s.id for s in older] + [newest.id])
    try:
        assert claimed.sample_id == newest.id
    finally:
        lab_triage.run_claimed(conn, store, claimed,
                               lab_triage.settings_or_default())


# --- one run -------------------------------------------------------------------

def test_scanned_custody_is_written_only_after_verification(conn, store, monkeypatch):
    from noctornal_api import lab_triage
    from noctornal_api.db import connect
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    seen = []
    real = lab_triage.run_child

    def spy(header, payloads=(), **kw):
        if header.get("mode") in ("pe", "fuzzy") and not seen:
            other = connect()
            try:
                seen.append(other.execute(
                    """SELECT detail FROM lab.sample_access WHERE sample_id = %s
                        AND action = 'SCANNED'""", (s.id,)).fetchall())
            finally:
                other.close()
        return real(header, payloads, **kw)

    monkeypatch.setattr(lab_triage, "run_child", spy)
    assert _one_run(conn, store, s) == ["DONE"]
    assert seen and seen[0], "no committed SCANNED row when the first child started"
    assert seen[0][0][0]["sha256_verified"] is True


def test_integrity_mismatch_raises_the_alarm_fails_the_run_and_is_never_retried(conn, store):
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    key = next(iter(store.objects))
    store.objects[key] = b"substituted" + store.objects[key]
    assert _one_run(conn, store, s) == ["FAILED"]
    runs = _runs(conn, s.id)
    assert [r[1] for r in runs] == ["FAILED"], "a tamper was queued again"
    assert _scanned(conn, s.id) == [], "custody recorded a read that never verified"
    alarm = conn.execute(
        """SELECT actor_kind, detail FROM lab.sample_access WHERE sample_id = %s
            AND detail->>'event' = 'integrity_check_failed'""", (s.id,)).fetchone()
    assert alarm and alarm[0] == "SYSTEM" and alarm[1]["run_id"] == str(runs[0][0])
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'SAMPLE_INTEGRITY_ALARM' "
        "AND object_id = %s", (s.id,)).fetchone()[0] == 1
    failure = conn.execute("SELECT failure FROM lab.static_run WHERE id = %s",
                           (runs[0][0],)).fetchone()[0]
    assert failure.startswith("integrity check failed")


def test_a_rejected_sample_is_never_materialised(conn, store):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    SampleService(conn, store).reject(s.id, actor_id=who, reason="prohibited",
                                      purge_bytes=False)
    from noctornal_api import lab_triage
    claimed, skipped = lab_triage.claim(conn, lab_triage.settings_or_default(),
                                        among=[s.id])
    assert claimed is None and skipped == 1
    assert _runs(conn, s.id)[0][1] == "SKIPPED"
    assert _scanned(conn, s.id) == []


def test_a_sample_rejected_mid_run_has_its_findings_discarded(conn, store, monkeypatch):
    from noctornal_api import lab_triage
    from noctornal_api.db import connect
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    real = lab_triage._step_child

    def reject_then_run(mode, data, settings, gaps):
        other = connect()
        try:
            other.execute("UPDATE lab.sample SET state = 'REJECTED', "
                          "reject_reason = 'while triage ran' WHERE id = %s",
                          (s.id,))
        finally:
            other.close()
        return real(mode, data, settings, gaps)

    monkeypatch.setattr(lab_triage, "_step_child", reject_then_run)
    assert _one_run(conn, store, s) == ["SKIPPED"]
    row = conn.execute("SELECT imphash, ssdeep, tlsh FROM lab.sample "
                       "WHERE id = %s", (s.id,)).fetchone()
    assert row == (None, None, None)
    assert conn.execute("SELECT count(*) FROM lab.sample_analysis "
                        "WHERE sample_id = %s", (s.id,)).fetchone()[0] == 0
    assert "findings discarded" in conn.execute(
        "SELECT failure FROM lab.static_run WHERE sample_id = %s",
        (s.id,)).fetchone()[0]


def test_a_closed_case_sample_is_skipped_not_analysed(conn, store):
    who = make_user(conn, PREFIX)
    case = make_case(conn, who)
    s = _submit(conn, store, who, case_id=case)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 "WHERE id = %s", (case,))
    from noctornal_api import lab_triage
    claimed, skipped = lab_triage.claim(conn, lab_triage.settings_or_default(),
                                        among=[s.id])
    assert claimed is None and skipped == 1
    assert _runs(conn, s.id)[0][1] == "SKIPPED"
    assert _scanned(conn, s.id) == []


def test_triage_moves_quarantined_to_triaged_and_nothing_else(conn, store):
    from noctornal_api import lab_triage
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",))
    s = _submit(conn, store, who)
    assert _one_run(conn, store, s) == ["DONE"]
    got = SampleService(conn).get(s.id)
    assert got.state == "TRIAGED"
    assert got.imphash == imphash_of("KERNEL32.dll", "ExitProcess")
    assert got.ssdeep and got.tlsh and got.rich_header_hash
    other = _submit(conn, store, who)
    SampleService(conn).assign(other.id, analyst_id=who, actor_id=who)
    lab_triage.enqueue(conn, other.id, trigger="ON_DEMAND", requested_by=who)
    drain(conn, store, prefix=PREFIX)
    assert SampleService(conn).get(other.id).state == "ASSIGNED"


def test_the_machine_row_names_its_run_and_no_analyst(conn, store):
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    _one_run(conn, store, s)
    row = conn.execute(
        """SELECT origin, analyst_id, run_id, kind, tool, extracted_selectors
             FROM lab.sample_analysis WHERE sample_id = %s""", (s.id,)).fetchone()
    assert row[0] == "machine" and row[1] is None and row[2] is not None
    assert row[3] == "STATIC" and row[4] == "noctornal static triage"
    kinds = {e["selector_type"] for e in row[5]}
    assert kinds == {"IMPHASH", "RICH_HEADER", "SSDEEP", "TLSH"}
    from psycopg.errors import CheckViolation
    with pytest.raises(CheckViolation):
        conn.execute("""INSERT INTO lab.sample_analysis (sample_id, kind, origin,
                        analyst_id, run_id) VALUES (%s, 'STATIC', 'machine', %s,
                        %s)""", (s.id, who, row[2]))
    with pytest.raises(CheckViolation):
        conn.execute("""INSERT INTO lab.sample_analysis (sample_id, kind, origin)
                        VALUES (%s, 'STATIC', 'machine')""", (s.id,))


def test_static_triage_writes_nothing_to_the_graph(conn, store):
    def counts():
        return conn.execute(
            """SELECT (SELECT count(*) FROM core.node),
                      (SELECT count(*) FROM core.edge),
                      (SELECT count(*) FROM core.assertion),
                      (SELECT count(*) FROM collect.proposal)""").fetchone()
    who = make_user(conn, PREFIX)
    case = make_case(conn, who)
    s = _submit(conn, store, who, case_id=case)
    before = counts()
    _one_run(conn, store, s)
    assert counts() == before


def test_machine_selectors_propose_through_the_existing_path_with_the_machine_origin_and_rationale(conn, store):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    case = make_case(conn, who)
    s = _submit(conn, store, who, case_id=case)
    _one_run(conn, store, s)
    svc = SampleService(conn)
    sample = svc.get(s.id)
    row = next(a for a in svc.analyses(s.id) if a["origin"] == "machine")
    assert row["produced_by"] == "NocTORnal static triage (automated)"
    index = next(i for i, e in enumerate(row["extracted_selectors"])
                 if e["selector_type"] == "IMPHASH")
    assert svc.propose_extracted_selector(sample, row["id"], index,
                                          actor_id=who, clearance="RED") == {
        "sent": True, "label": sample.imphash}
    origin, rationale = conn.execute(
        "SELECT origin, rationale FROM collect.proposal WHERE case_id = %s",
        (case,)).fetchone()
    assert origin == "lab/static-triage"
    assert rationale.startswith("Computed by NocTORnal static triage (automated)")
    assert "(UTC)" in rationale


def test_gaps_are_rewritten_only_for_the_steps_that_ran(conn, store):
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who, data=varied(21, 6000))
    conn.execute("UPDATE lab.static_run SET steps = '{pe}' WHERE sample_id = %s",
                 (s.id,))
    _one_run(conn, store, s)
    gaps = {g["step"]: g for g in conn.execute(
        "SELECT triage_gaps FROM lab.sample WHERE id = %s", (s.id,)).fetchone()[0]}
    assert gaps["imphash"]["status"] == "not_applicable"
    assert gaps["imphash"]["reason"] == "not a PE image"
    for step in ("ssdeep", "tlsh", "yara"):
        assert gaps[step]["status"] == "pending", step
    lab_triage.enqueue(conn, s.id, trigger="ON_DEMAND", requested_by=who,
                       steps=("fuzzy",))
    _one_run(conn, store, s)
    gaps = {g["step"]: g for g in conn.execute(
        "SELECT triage_gaps FROM lab.sample WHERE id = %s", (s.id,)).fetchone()[0]}
    assert "ssdeep" not in gaps and "tlsh" not in gaps
    assert gaps["imphash"]["status"] == "not_applicable"


def test_the_summary_exposes_trigger_kind_only(conn, store):
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX, name="Requester")
    s = _submit(conn, store, who)
    lab_triage.enqueue(conn, s.id, trigger="ON_DEMAND", requested_by=who,
                       steps=("yara",), yara_version_ids=(uuid4(),))
    summary = lab_triage.static_triage_summaries(conn, [s.id])[str(s.id)]
    assert summary["trigger_kind"] == "requested"
    assert summary["requested_by_name"] == "Requester"
    for leak in ("trigger", "steps", "yara_version_ids", "requests", "yara",
                 "outcome"):
        assert leak not in summary


def test_plaintext_crosses_on_stdin_only(conn, store, monkeypatch):
    """No temporary file, no write-mode open, and no sample byte in the
    child's arguments or environment."""
    who = make_user(conn, PREFIX)
    marker = b"PLAINTEXT-MARKER-" + uuid4().hex.encode()
    s = _submit(conn, store, who, data=pe_image() + marker * 20)
    writes = []
    real_open = builtins.open

    def watched_open(file, mode="r", *a, **kw):
        if any(ch in str(mode) for ch in "wax+"):
            writes.append((file, mode))
        return real_open(file, mode, *a, **kw)

    def refused(*a, **kw):
        writes.append(("tempfile", a))
        raise AssertionError("a temporary file was made")

    spawned = []
    real_popen = subprocess.Popen

    def watched_popen(argv, *a, **kw):
        spawned.append((list(argv), dict(kw.get("env") or {})))
        return real_popen(argv, *a, **kw)

    monkeypatch.setattr(builtins, "open", watched_open)
    for name in ("NamedTemporaryFile", "TemporaryFile", "mkstemp",
                 "SpooledTemporaryFile"):
        monkeypatch.setattr(tempfile, name, refused)
    monkeypatch.setattr(subprocess, "Popen", watched_popen)
    assert _one_run(conn, store, s) == ["DONE"]
    monkeypatch.undo()
    assert writes == []
    assert spawned
    for argv, env in spawned:
        assert not any("PLAINTEXT-MARKER" in str(x) for x in argv)
        assert not any("PLAINTEXT-MARKER" in str(v) for v in env.values())


# --- liveness, retries, slots --------------------------------------------------

def test_a_dead_runner_is_swept_through_its_run_lock_and_requeued(conn, store):
    from noctornal_api import lab_triage
    from noctornal_api.db import connect
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    lab_triage.enqueue(conn, s.id, trigger="ON_DEMAND", requested_by=who)
    dying = connect()
    claimed, _ = lab_triage.claim(dying, lab_triage.settings_or_default(),
                                  run_id=_runs(conn, s.id)[0][0])
    assert claimed is not None
    # A live owner holds the lock: the sweep leaves the run alone. (Asked
    # of this run, not counted: another suite may leave its own.)
    lab_triage.sweep_abandoned(conn)
    assert _runs(conn, s.id)[0][1] == "RUNNING"
    dying.close()
    assert lab_triage.sweep_abandoned(conn) >= 1
    runs = _runs(conn, s.id)
    assert [r[1] for r in runs] == ["ABANDONED", "QUEUED"]
    retry = runs[1]
    assert retry[2] == "RETRY" and retry[3] == who and retry[4] == 2
    gaps = {g["step"]: g for g in conn.execute(
        "SELECT triage_gaps FROM lab.sample WHERE id = %s", (s.id,)).fetchone()[0]}
    assert gaps["imphash"]["status"] == "failed"


def test_a_retried_yara_scoped_request_keeps_its_versions_when_it_merges(conn, store):
    """Found 2026-09-24: the RETRY a sweep queues unioned the
    steps of the queued run it merged into but not the rule set versions,
    so a retried yara-scoped request lost its version, or had its scope
    widened to every open set, while its requester was still named in
    custody. A RETRY now merges by the rule `enqueue` merges by."""
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX)
    asker = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    v1, v2 = uuid4(), uuid4()
    retry = {"sample_id": s.id, "requested_by": asker,
             "requests": [{"trigger": "RETROHUNT",
                           "requested_by": str(asker)}],
             "priority": lab_triage.TRIGGER_PRIORITY["RETROHUNT"],
             "steps": ["yara"], "yara_version_ids": [v1], "attempt": 1}
    for steps, versions, want in (
            # The queued run has no yara step: the retry brings its own.
            (("fuzzy", "pe"), (), [v1]),
            # Both name versions: the union.
            (("yara",), (v2,), [v1, v2]),
            # The queued run already scans every open version.
            (("yara",), (), [])):
        conn.execute("DELETE FROM lab.static_run WHERE sample_id = %s", (s.id,))
        lab_triage.enqueue(conn, s.id, trigger="SUBMIT", steps=steps,
                           yara_version_ids=versions)
        lab_triage._requeue(conn, retry, 2)
        got = conn.execute(
            """SELECT steps, yara_version_ids, requests FROM lab.static_run
                WHERE sample_id = %s AND status = 'QUEUED'""",
            (s.id,)).fetchone()
        assert "yara" in got[0], steps
        assert sorted(map(str, got[1])) == sorted(map(str, want)), steps
        assert str(asker) in {r.get("requested_by") for r in got[2]}


def test_failed_runs_retry_up_to_the_limit_and_step_failures_do_not(conn, store, monkeypatch):
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)

    class Down(MemoryStore):
        def get(self, key):
            raise ConnectionError("the store did not answer")

    down = Down()
    for _ in range(lab_triage.MAX_ATTEMPTS + 1):
        drain(conn, down, prefix=PREFIX)
    statuses = [r[1] for r in _runs(conn, s.id)]
    assert statuses == ["FAILED"] * lab_triage.MAX_ATTEMPTS
    assert [r[4] for r in _runs(conn, s.id)] == list(range(1, lab_triage.MAX_ATTEMPTS + 1))
    # A step that fails inside a finished run is a failed gap, not a retry.
    other = _submit(conn, store, who)
    monkeypatch.setattr(lab_triage, "run_child",
                        lambda *a, **k: lab_triage.ChildResult(False, failure="crashed"))
    assert _one_run(conn, store, other) == ["DONE"]
    assert [r[1] for r in _runs(conn, other.id)] == ["DONE"]
    gaps = {g["step"]: g for g in conn.execute(
        "SELECT triage_gaps FROM lab.sample WHERE id = %s", (other.id,)).fetchone()[0]}
    assert gaps["imphash"]["status"] == "failed"
    assert gaps["imphash"]["reason"] == lab_triage.CHILD_FAILURES["crashed"]


def test_concurrency_slots_hold_across_processes(conn):
    from noctornal_api import lab_triage
    from noctornal_api.db import connect
    other = connect()
    try:
        mine = lab_triage.take_slot(conn, 1)
        assert mine == 0
        assert lab_triage.take_slot(other, 1) is None
        assert not lab_triage.slot_free(other, 1)
        assert lab_triage.take_slot(other, 2) == 1
        lab_triage.release_slot(other, 1)
        lab_triage.release_slot(conn, mine)
        assert lab_triage.slot_free(other, 1)
    finally:
        other.close()


def test_runs_refuse_until_the_policy_is_declared(conn, store, monkeypatch):
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", raising=False)
    counts = lab_triage.run_due(conn, store)
    assert "refused" in counts and counts["done"] == 0
    assert _runs(conn, s.id)[0][1] == "QUEUED"
    assert _scanned(conn, s.id) == []


def test_backfill_is_recorded_as_the_operators_decision(conn, store):
    from noctornal_api import lab_triage
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    conn.execute("DELETE FROM lab.static_run WHERE sample_id = %s", (s.id,))
    n = lab_triage.backfill(conn, host_user="operator-x")
    assert n >= 1
    run = _runs(conn, s.id)[0]
    assert run[2] == "BACKFILL"
    assert run[5][0]["via"] == "lab_triage.py --backfill"
    detail = conn.execute(
        """SELECT detail FROM audit.event WHERE action = 'SAMPLE_STATIC_TRIAGE_BACKFILL'
            ORDER BY seq DESC LIMIT 1""").fetchone()[0]
    assert detail["host_user"] == "operator-x" and detail["count"] == n
    # Leave the rest of the estate's queue as it was.
    conn.execute("DELETE FROM lab.static_run WHERE trigger = 'BACKFILL' AND "
                 "status = 'QUEUED' AND requests->0->>'via' = "
                 "'lab_triage.py --backfill'")


# --- the migrations refuse on the facts they would lose ------------------------

def _migration(name):
    path = next(MIGRATIONS.glob(f"{name}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_r1_and_r2_downgrades_refuse_after_a_run_started_naming_both_counts(conn, store, monkeypatch):
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    _one_run(conn, store, s)
    for name in ("0079", "0078"):
        m = _migration(name)
        ran: list = []
        monkeypatch.setattr(m, "query", lambda sql: conn.execute(sql).fetchall())
        monkeypatch.setattr(m, "run", lambda *a, _ran=ran, **k: _ran.append(a))
        with pytest.raises(RuntimeError) as err:
            m.downgrade()
        assert ran == [], "the downgrade changed something before refusing"
        message = str(err.value)
        assert message.startswith(f"refusing to downgrade {name}")
        # Both counts are named, each with its noun agreeing.
        if name == "0079":
            assert "static triage run has started" in message \
                or "static triage runs have started" in message
            assert "machine analys" in message
        else:
            assert "(SYSTEM)" in message and "(SCANNED)" in message


def test_r2_legacy_gap_strings_round_trip():
    m = _migration("0079")
    steps = [g["step"] for g in m.GAPS_BEFORE]
    assert steps == ["imphash", "rich_header_hash", "ssdeep", "tlsh", "yara",
                     "archive_expansion", "prohibited_content_screening"]
    assert "pending" in m.UPGRADE_SQL and "prohibited_content_screening" in m.UPGRADE_SQL
