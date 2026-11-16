"""The two readiness rows static triage and YARA add.

`sample_static_analysis` fails on a settings problem, a child that will not start, or a queue that nothing
drains, and passes a draining backfill; it says what the child could still reach. `yara_rules_active`
fails when an active rule set has no build this host can load after a full pass, in counts only: readiness
has no caller, so it names no set and no person.

Email prefix `rsq-` (rst- is test_retention_storage_pg's). Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    declare_policy,
    left_behind,
    make_user,
    pe_image,
    teardown,
)

from noctornal_api import readiness

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

PREFIX = "rsq-"


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


@contextmanager
def _own_queue(conn):
    """A transaction that is always rolled back, in which the static-triage queue holds only what the test
    puts there.

    `_sample_static_analysis` reads the whole of `lab.static_run`, so runs other suites left queued go stale
    during a long full run and fail these tests. Every run already there that the check reads is set aside,
    ended a day ago, for the test's duration; the rollback restores it untouched.
    """
    with conn.transaction(force_rollback=True):
        conn.execute("""UPDATE lab.static_run
                           SET status = 'ABANDONED',
                               started_at = coalesce(started_at,
                                                     now() - interval '1 day'),
                               finished_at = now() - interval '1 day',
                               failure = coalesce(failure, 'set aside by a test')
                         WHERE status <> 'RUNNING'""")
        yield


@pytest.fixture
def queue(conn):
    with _own_queue(conn):
        yield conn


def _sample(conn, who):
    from noctornal_api.samples import SampleService
    return SampleService(conn, MemoryStore()).submit(pe_image() + uuid4().bytes,
                                                     submitted_by=who)


def test_the_rows_are_not_blocking_and_follow_the_rows_at_the_base():
    names = list(readiness.CHECK_NAMES)
    assert "sample_static_analysis" in names and "yara_rules_active" in names
    assert names.index("sample_static_analysis") > names.index("triage_claims_dated")
    assert names.index("yara_rules_active") > names.index("triage_claims_dated")
    for name in ("sample_static_analysis", "yara_rules_active"):
        assert name not in readiness.BLOCKING_CHECKS
        assert name not in readiness.UI_TARGETS


def test_it_fails_only_when_the_queue_is_stale(queue):
    conn = queue
    who = make_user(conn, PREFIX)
    s = _sample(conn, who)
    fresh = readiness._sample_static_analysis(conn)
    assert fresh.ok, fresh.evidence
    conn.execute("UPDATE lab.static_run SET queued_at = now() - interval "
                 "'2 hours' WHERE sample_id = %s", (s.id,))
    stale = readiness._sample_static_analysis(conn)
    assert not stale.ok and "schedule scripts/lab_triage.py" in stale.action
    # A pass finished within the hour: the queue is draining.
    t = _sample(conn, who)
    conn.execute("""UPDATE lab.static_run SET status = 'DONE',
                        started_at = now(), finished_at = now()
                     WHERE sample_id = %s""", (t.id,))
    assert readiness._sample_static_analysis(conn).ok


@pytest.mark.parametrize("status", ["FAILED", "SKIPPED", "ABANDONED"])
def test_a_run_that_ended_otherwise_within_the_hour_is_a_drainer_too(queue, status):
    """Only lab_triage ends a run, so a run it FAILED, SKIPPED or ABANDONED within the hour proves a
    drainer ran as much as a DONE one; reading only DONE would tell an operator whose drainer is working
    through refusals to schedule one."""
    conn = queue
    who = make_user(conn, PREFIX)
    s = _sample(conn, who)
    conn.execute("UPDATE lab.static_run SET queued_at = now() - interval "
                 "'2 hours' WHERE sample_id = %s", (s.id,))
    assert not readiness._sample_static_analysis(conn).ok
    t = _sample(conn, who)
    conn.execute("""UPDATE lab.static_run SET status = %s, started_at = now(),
                        finished_at = now(), failure = 'refused'
                     WHERE sample_id = %s""", (status, t.id))
    check = readiness._sample_static_analysis(conn)
    assert check.ok, check.evidence


def test_a_stale_run_left_by_another_suite_cannot_reach_these_tests(conn):
    """The isolation above, shown: a committed queued run older than the
    stale window (what a long full run left behind) does not reach a check
    inside `_own_queue`, and the rollback gives the run back unchanged."""
    left = _sample(conn, make_user(conn, PREFIX))
    conn.execute("UPDATE lab.static_run SET queued_at = now() - interval "
                 "'2 hours' WHERE sample_id = %s", (left.id,))
    before = conn.execute("SELECT status, queued_at FROM lab.static_run "
                          "WHERE sample_id = %s", (left.id,)).fetchone()
    with _own_queue(conn):
        assert readiness._sample_static_analysis(conn).ok
    after = conn.execute("SELECT status, queued_at FROM lab.static_run "
                         "WHERE sample_id = %s", (left.id,)).fetchone()
    assert after == before and before[0] == "QUEUED"


def test_it_fails_on_a_settings_problem_and_on_a_selftest_failure(conn, monkeypatch):
    from noctornal_api import lab_triage
    monkeypatch.setenv(lab_triage.TIMEOUT_ENV, "5")
    check = readiness._sample_static_analysis(conn)
    assert not check.ok and lab_triage.TIMEOUT_ENV in check.evidence
    assert "5" not in check.evidence.replace(lab_triage.TIMEOUT_ENV, "").split()
    monkeypatch.delenv(lab_triage.TIMEOUT_ENV)

    def broken(*a, **k):
        raise RuntimeError(lab_triage.CHILD_FAILURES["start_failed"])

    monkeypatch.setattr(lab_triage, "selftest", broken)
    check = readiness._sample_static_analysis(conn)
    assert not check.ok and "selftest" in check.evidence


def test_it_passes_with_a_caveat_on_other_platforms_and_without_yara_x(queue, monkeypatch):
    conn = queue
    from noctornal_api import lab_static, lab_triage, yara_rules
    real = lab_triage.selftest

    def as_windows(settings, **kw):
        out = real(settings, **kw)
        out["capabilities"]["limits"] = "wall_clock_only"
        out["exposure"] = {"proc_environ_readable": True,
                           "database_reachable": True}
        return out

    monkeypatch.setattr(lab_triage, "selftest", as_windows)
    monkeypatch.setattr(yara_rules, "engine_version", lambda: None)
    check = readiness._sample_static_analysis(conn)
    assert check.ok
    assert "wall-clock only" in check.caveat
    assert "YARA is not installed" in check.caveat
    assert "secrets" in check.caveat and "database host" in check.caveat
    assert lab_static.LIMITS_WORDS["wall_clock_only"] in check.caveat


def _selftest_saying(monkeypatch, yara):
    """The real selftest, with its `yara` fact replaced (or removed, for None)."""
    from noctornal_api import lab_triage
    real = lab_triage.selftest

    def reporting(settings, **kw):
        out = real(settings, **kw)
        out.pop("yara", None)
        if yara is not None:
            out["yara"] = dict(yara)
        return out

    monkeypatch.setattr(lab_triage, "selftest", reporting)


def test_the_row_reports_the_yara_engine_version_and_no_caveat_when_installed(queue):
    """docs/17 "YARA in the worker": with the engine installed and its selftest scan working, the row names
    the version and says nothing about YARA being absent."""
    pytest.importorskip("yara_x")
    from noctornal_api.yara_rules import engine_version
    check = readiness._sample_static_analysis(queue)
    assert check.ok, check
    assert f"yara-x {engine_version()}. Limits:" in check.evidence
    assert "YARA is not installed" not in (check.caveat or "")
    assert "up -d --build" not in (check.caveat or "")


def test_the_row_fails_when_the_engine_is_installed_but_the_workers_selftest_scan_failed(
        queue, monkeypatch):
    """An installed engine that cannot run under the child's limits would fail every YARA step and record
    each sample unscanned, so the row is red and says which limits to look at; the failure is named by
    its class alone, and a class that is not one is not repeated."""
    from noctornal_api import lab_triage, yara_rules
    monkeypatch.setattr(yara_rules, "engine_version", lambda: "1.20.0")
    _selftest_saying(monkeypatch, {"ok": False, "installed": True, "error_class": "MemoryError"})
    check = readiness._sample_static_analysis(queue)
    assert not check.ok
    assert "yara-x 1.20.0" in check.evidence and "(MemoryError)" in check.evidence
    assert "could not compile a one-rule test and scan with it" in check.evidence
    assert lab_triage.MEMORY_ENV in check.action
    _selftest_saying(monkeypatch, {"ok": False, "installed": True,
                                   "error_class": "Error: <b>quoted</b> bytes"})
    check = readiness._sample_static_analysis(queue)
    assert not check.ok and "quoted" not in check.evidence


@pytest.mark.parametrize("yara", [None, {"ok": None, "installed": False}])
def test_an_installed_engine_with_no_selftest_failure_does_not_fail_the_row(queue, monkeypatch, yara):
    """Only a scan that ran and failed fails the row: a selftest that says nothing about YARA, or that the
    engine is absent where this process has it, is no new failure (the second is a version mismatch the
    runner already refuses)."""
    from noctornal_api import yara_rules
    monkeypatch.setattr(yara_rules, "engine_version", lambda: "1.20.0")
    _selftest_saying(monkeypatch, yara)
    assert readiness._sample_static_analysis(queue).ok


def test_the_row_passes_with_the_rebuild_caveat_when_yara_is_absent(queue, monkeypatch):
    """Absent is a caveat, as before, and it now says how a container deployment gets the engine."""
    from noctornal_api import yara_rules
    monkeypatch.setattr(yara_rules, "engine_version", lambda: None)
    _selftest_saying(monkeypatch, {"ok": None, "installed": False})
    check = readiness._sample_static_analysis(queue)
    assert check.ok
    assert "YARA is not installed, so static triage scans with no rules" in check.caveat
    assert readiness._YARA_REBUILD in check.caveat
    assert "NOCTORNAL_EXTRAS set empty" in check.caveat and "up -d --build" in check.caveat


def test_yara_rules_active_names_the_rebuild_when_the_engine_is_absent(conn, monkeypatch):
    from noctornal_api import yara_rules
    monkeypatch.setattr(yara_rules, "build_key", lambda: None)
    check = readiness._yara_rules_active(conn)
    assert check.ok
    assert check.caveat.startswith("The YARA engine (yara-x) is not installed")
    assert check.caveat.endswith(readiness._YARA_REBUILD)


def test_yara_rules_active_has_no_engine_caveat_when_installed(conn):
    pytest.importorskip("yara_x")
    from noctornal_api.yara_rules import build_key
    check = readiness._yara_rules_active(conn)
    assert check.ok
    assert f"for {build_key().engine} on" in check.evidence
    assert "not installed" not in (check.caveat or "")


@pytest.mark.parametrize("exposure,says,never", [
    ({"proc_environ_readable": True, "database_reachable": False},
     "secrets", "database host"),
    ({"proc_environ_readable": False, "database_reachable": True},
     "database host", "environment"),
    ({"proc_environ_readable": None, "database_reachable": None}, None,
     "parser exploit"),
])
def test_the_exposure_caveat_names_only_what_applies_and_agrees(
        queue, monkeypatch, exposure, says, never):
    """Each exposure fact is named only when the selftest reported it, and the sentence reads the same for
    one or two."""
    conn = queue
    from noctornal_api import lab_triage
    real = lab_triage.selftest

    def reporting(settings, **kw):
        out = real(settings, **kw)
        out["exposure"] = dict(exposure)
        return out

    monkeypatch.setattr(lab_triage, "selftest", reporting)
    check = readiness._sample_static_analysis(conn)
    assert check.ok
    caveat = check.caveat or ""
    if says:
        assert says in caveat
        assert "could do the same" in caveat
    assert never not in caveat
    assert " them" not in caveat and " they " not in caveat


def test_yara_rules_active_speaks_in_counts_and_fails_on_an_unbuildable_active_set(conn):
    pytest.importorskip("yara_x")
    from noctornal_api import lab_triage
    from noctornal_api.yara_rules import RulesetService, build_key, parse_bundle
    lab = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    svc = RulesetService(conn)
    key = f"rsq-{uuid4().hex[:8]}"
    set_id = svc.create(key=key, display_name="Readiness set", description=None,
                        classification="AMBER", compartments=(),
                        actor_id=lab)["id"]
    v = svc.add_version(set_id, parse_bundle(
        "r.yar", b'rule r { strings: $a = "zz" condition: $a }'),
        licence="MIT", licence_review_required=False,
        provenance={"via": "upload"}, note=None, uploaded_by=lab,
        key=build_key())
    lab_triage.compile_pending(conn, lab_triage.settings_or_default())
    svc.activate(v["id"], actor_id=officer, licence_acknowledgement=None,
                 replace_open=False, key=build_key())
    check = readiness._yara_rules_active(conn)
    assert check.ok and "Readiness set" not in check.evidence
    assert key not in check.evidence
    # The engine moves on: no build for the new engine, and its compile
    # has failed for good.
    k = build_key()
    conn.execute("""INSERT INTO lab.yara_compile_job (version_id, engine,
                        platform, fingerprint, status, attempts)
                    VALUES (%s, 'yara-x 99.0.0', %s, %s, 'FAILED', 3)""",
                 (v["id"], k.platform, k.fingerprint))
    import noctornal_api.yara_rules as yr
    real_key = yr.build_key
    try:
        yr.build_key = lambda: yr.BuildKey("yara-x 99.0.0", k.platform,
                                           k.fingerprint)
        check = readiness._yara_rules_active(conn)
    finally:
        yr.build_key = real_key
    assert not check.ok and "no build this host can load" in check.action
    assert key not in check.evidence + check.action
