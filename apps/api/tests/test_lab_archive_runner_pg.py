"""Archive expansion goes through the isolated analysis runner, as every
static triage step does (phase 8 merged with docs/17 F42, 2026-10-03).

Until the merge the expansion child was started by one direct call to the
local bounded runner. It is now `analysis_runner`'s kind `lab_archive_child`,
so in production it runs in the isolated worker (no secrets, no network, a
read-only root and a tmpfs of a mebibyte, which is also why it never
extracts to a path), and the runner's refusals are the expansion's:

- a worker that is busy, gone, refusing or answering garbage, and a
  production with no worker at all, INTERRUPT the run, which waits at the
  same attempt with nothing written. They are never recorded as a fact
  about the archive: no member, no ARCHIVE finding, no failure on the
  archive, and never an archive read as expanded or as clean (the "members
  were not compared" gap stays). The same request expands it once the
  worker is back.
- a failure that is the archive's own (a child that crashed) is still
  recorded as the archive's, as before.
- what the worker answers is the answer the local child gives, byte for
  byte, and a setting that asks for more output than the worker hands back
  is refused by name, not found out as a worker that refuses every request.

Email prefix `arch-` (test_lab_archive_pg's). DATABASE_URL-gated, except the
tests that need no database.
"""
from __future__ import annotations

# Fixtures imported from the suites whose worlds these tests reuse.
# ruff: noqa: F811

import os
import socket
import threading
from contextlib import contextmanager

import pytest

from lab_static_fixtures import drain, make_user
from test_lab_archive_pg import (  # noqa: F401  (fixtures and helpers)
    PREFIX,
    _finding,
    _gap,
    _members,
    _submit,
    authorities,
    conn,
    member_bytes,
    store,
    zip_of,
)

from noctornal_api import analysis_runner as ar
from noctornal_api import analysis_worker as aw
from noctornal_api import lab_archive, lab_triage

DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
SOCK = "/run/noctornal-analysis/worker.sock"

SANDBOX = ["worker_busy", "worker_unavailable", "worker_bad_answer",
           "worker_refused", "isolation_refused"]


@contextmanager
def tcp_worker(**kw):
    """The real Worker on a loopback listener, and a connector for it (the
    Unix socket's stand-in, as test_analysis_runner does)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    worker = aw.Worker(listener, **kw)
    thread = threading.Thread(target=worker.serve_forever, daemon=True)
    thread.start()
    addr = listener.getsockname()
    try:
        yield lambda _path: socket.create_connection(addr, timeout=5)
    finally:
        worker.stop()
        thread.join(5)
        listener.close()


def _spy(monkeypatch, *, fail_archive_with: str | None = None):
    """Record the kind of every child the triage starts; optionally make the
    archive child, and only it, fail as the runner would."""
    seen: list[str] = []
    real = lab_triage.run_child

    def run_child(header, payloads=(), **kw):
        kind = kw.get("kind", "lab_static")
        seen.append(kind)
        if fail_archive_with and kind == lab_archive.CHILD_KIND:
            return ar.ChildResult(False, failure=fail_archive_with)
        return real(header, payloads, **kw)

    monkeypatch.setattr(lab_triage, "run_child", run_child)
    return seen


def _runs(conn, sample_id):
    """The runs in the order they were asked for: the submit's, then its
    retries (not by clock alone: the WSL clock steps backwards)."""
    return conn.execute(
        """SELECT status, trigger, attempt, failure FROM lab.static_run
            WHERE sample_id = %s
            ORDER BY (trigger = 'RETRY'), queued_at, id""", (sample_id,)).fetchall()


def _queued(conn, sample_id):
    return conn.execute(
        "SELECT id FROM lab.static_run WHERE sample_id = %s AND status = 'QUEUED'",
        (sample_id,)).fetchone()[0]


def _analyses(conn, sample_id):
    return conn.execute("SELECT count(*) FROM lab.sample_analysis WHERE sample_id = %s",
                        (sample_id,)).fetchone()[0]


# --- the seam -----------------------------------------------------------------

def test_the_archive_child_is_a_kind_of_the_runner_and_of_the_worker():
    assert lab_archive.CHILD_KIND in ar.KINDS
    argv = aw.KIND_ARGV[lab_archive.CHILD_KIND]
    assert argv[1:] == ["-m", "noctornal_api.lab_archive_child"]
    assert lab_archive.CHILD_ARGV[1:] == argv[1:]


def test_the_defaults_fit_inside_what_the_worker_hands_back():
    settings, problem = lab_archive.archive_settings({})
    assert problem is None
    assert lab_archive.stdout_cap(settings) <= ar.MAX_OUTPUT_BYTES


def test_a_setting_that_asks_for_more_than_the_runner_returns_is_refused_by_name():
    # Room enough in the child's memory, too much for the runner to return.
    env = {lab_triage.MEMORY_ENV: "8GiB", lab_archive.TOTAL_ENV: "400MiB"}
    settings, problem = lab_archive.archive_settings(env)
    assert settings is None
    assert lab_archive.TOTAL_ENV in problem and lab_archive.MEMBERS_ENV in problem


def test_the_expansion_asks_the_runner_for_its_own_kind(monkeypatch):
    asked = {}

    def run(kind, header, payloads=(), *, wall_s, stdout_cap, argv, **_kw):
        asked.update(kind=kind, argv=argv, cap=stdout_cap, wall=wall_s)
        return ar.ChildResult(False, failure="crashed")

    monkeypatch.setattr(ar, "run", run)
    settings = lab_archive.settings_or_default()
    analysis = lab_triage.settings_or_default()
    lab_archive._expand_child(zip_of([("a.bin", b"x" * 40)]), settings, analysis)
    assert asked["kind"] == "lab_archive_child"
    assert asked["argv"] == lab_archive.CHILD_ARGV
    assert asked["cap"] == lab_archive.stdout_cap(settings)
    assert asked["wall"] == lab_archive.wall_s(settings)


def test_the_worker_answers_what_the_local_child_answers(monkeypatch):
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    settings = lab_archive.settings_or_default()
    analysis = lab_triage.settings_or_default()
    data = zip_of([("a.bin", b"first member " * 8), ("sub/b.bin", b"second " * 9),
                   ("../escape.bin", b"x" * 30)])
    here = lab_archive._clean(lab_archive._expand_child(data, settings, analysis),
                              settings)
    assert here.failure is None and len(here.members) == 2
    with tcp_worker() as connect:
        monkeypatch.setattr(ar, "HAS_UNIX", True)
        monkeypatch.setattr(ar, "_connect_unix", connect)
        monkeypatch.setenv(ar.SOCKET_ENV, SOCK)
        result = lab_archive._expand_child(data, settings, analysis)
        assert result.ok, result.failure
        there = lab_archive._clean(result, settings)
    assert there.failure is None
    assert [(m.path, m.sha256) for m in there.members] == [
        (m.path, m.sha256) for m in here.members]
    assert [(r["path"], r["code"]) for r in there.refused] == [
        (r["path"], r["code"]) for r in here.refused]


@pytest.mark.parametrize("reason", SANDBOX)
def test_a_sandbox_failure_under_the_child_is_raised_and_never_turned_into_a_verdict(
        monkeypatch, reason):
    monkeypatch.setattr(lab_triage, "run_child",
                        lambda *_a, **_k: ar.ChildResult(False, failure=reason))
    settings = lab_archive.settings_or_default()
    analysis = lab_triage.settings_or_default()
    with pytest.raises(lab_triage.AnalysisInterrupted) as stop:
        lab_archive._ask_child(b"PK", settings, analysis)
    assert stop.value.failure == reason


@pytest.mark.parametrize("reason", ["crashed", "timeout", "output_too_large"])
def test_a_failure_that_is_the_childs_own_is_still_an_answer(monkeypatch, reason):
    monkeypatch.setattr(lab_triage, "run_child",
                        lambda *_a, **_k: ar.ChildResult(False, failure=reason))
    settings = lab_archive.settings_or_default()
    analysis = lab_triage.settings_or_default()
    result = lab_archive._ask_child(b"PK", settings, analysis)
    assert result.failure == reason
    assert lab_archive._clean(result, settings).failure


def test_production_with_no_worker_never_starts_a_local_child(monkeypatch):
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")

    def never(*_a, **_k):
        raise AssertionError("a local child was started in production")

    monkeypatch.setattr(ar, "run_local", never)
    settings = lab_archive.settings_or_default()
    analysis = lab_triage.settings_or_default()
    with pytest.raises(lab_triage.AnalysisInterrupted) as stop:
        lab_archive._ask_child(zip_of([("a.bin", b"x" * 40)]), settings, analysis)
    assert stop.value.failure == "isolation_refused"


# --- a run, against the database ------------------------------------------------

@needs_db
def test_the_run_asks_for_the_archive_child_through_the_seam(conn, store, monkeypatch):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    seen = _spy(monkeypatch)
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]))
    assert drain(conn, store, run_id=_queued(conn, parent.id)) == ["DONE"]
    assert seen.count("lab_archive_child") == 1
    assert [m[1] for m in _members(conn, parent.id)] == ["a.exe"]


@needs_db
@pytest.mark.parametrize("reason", SANDBOX)
def test_a_run_the_sandbox_failed_under_the_archive_child_waits_at_the_same_attempt(
        conn, store, monkeypatch, reason):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a")),
                                                  ("b.exe", member_bytes("b"))]))
    queued = _queued(conn, parent.id)
    real = lab_triage.run_child
    _spy(monkeypatch, fail_archive_with=reason)
    assert drain(conn, store, run_id=queued) == [lab_triage.INTERRUPTED]
    assert _runs(conn, parent.id) == [
        ("FAILED", "SUBMIT", 1, lab_triage.CHILD_FAILURES[reason]),
        ("QUEUED", "RETRY", 1, None)]
    # Nothing was written: no finding of any step, no member, and no ARCHIVE
    # row that could read as an expansion that ran.
    assert _analyses(conn, parent.id) == 0
    assert _members(conn, parent.id) == []
    assert _finding(conn, parent.id) is None
    # The archive is not read as expanded or as clean: its members are still
    # not compared, and no stored gap says otherwise.
    gap = _gap(conn, parent.id)
    assert gap is None or gap["status"] != "done"
    from screening_fixtures import service
    svc = service(conn, store)
    sample = svc.visible(parent.id, clearance="RED", compartments=frozenset())
    derived = {g["step"] for g in svc.derived_gaps([sample])[str(parent.id)]}
    assert "prohibited_content_archive_members" in derived
    # The worker is back: the same request runs, still at attempt 1, and
    # expands the archive.
    monkeypatch.setattr(lab_triage, "run_child", real)
    retry = _queued(conn, parent.id)
    assert drain(conn, store, run_id=retry) == ["DONE"]
    assert [r[:3] for r in _runs(conn, parent.id)] == [
        ("FAILED", "SUBMIT", 1), ("DONE", "RETRY", 1)]
    assert [m[1] for m in _members(conn, parent.id)] == ["a.exe", "b.exe"]
    assert _finding(conn, parent.id) is not None


@needs_db
def test_a_child_that_crashed_is_still_a_failed_expansion_of_the_archive(
        conn, store, monkeypatch):
    """The control: the child's own failure finishes the run DONE and is
    recorded on the archive, a finding with a failure that the next run
    resumes (it is not an end), as before the merge."""
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]))
    _spy(monkeypatch, fail_archive_with="crashed")
    assert drain(conn, store, run_id=_queued(conn, parent.id)) == ["DONE"]
    assert _members(conn, parent.id) == []
    findings = _finding(conn, parent.id)[0]
    assert findings["failure"] == lab_triage.CHILD_FAILURES["crashed"]
    assert _gap(conn, parent.id)["status"] == "failed"
    assert [r[:3] for r in _runs(conn, parent.id)] == [("DONE", "SUBMIT", 1)]
