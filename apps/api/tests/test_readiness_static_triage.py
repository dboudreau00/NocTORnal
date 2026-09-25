"""The two readiness rows static triage and YARA add (F11 N and F12 M,
2026-09-24).

`sample_static_analysis` fails on a settings problem, a child that will
not start, or a queue that nothing drains, and passes a draining backfill;
it says what the child could still reach. `yara_rules_active` fails when
an active rule set has no build this host can load after a full pass, in
counts only: readiness has no caller, so it names no set and no person.

Email prefix `rsq-` (rst- is test_retention_storage_pg's). Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
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


def test_it_fails_only_when_the_queue_is_stale(conn):
    who = make_user(conn, PREFIX)
    s = _sample(conn, who)
    fresh = readiness._sample_static_analysis(conn)
    assert fresh.ok, fresh.evidence
    conn.execute("UPDATE lab.static_run SET queued_at = now() - interval "
                 "'2 hours' WHERE sample_id = %s", (s.id,))
    done_recently = conn.execute(
        """SELECT count(*) FROM lab.static_run WHERE status = 'DONE'
            AND finished_at > now() - interval '60 minutes'""").fetchone()[0]
    stale = readiness._sample_static_analysis(conn)
    if done_recently:
        # A pass finished within the hour: the queue is draining.
        assert stale.ok
    else:
        assert not stale.ok and "schedule scripts/lab_triage.py" in stale.action
    t = _sample(conn, who)
    conn.execute("""UPDATE lab.static_run SET status = 'DONE',
                        started_at = now(), finished_at = now()
                     WHERE sample_id = %s""", (t.id,))
    assert readiness._sample_static_analysis(conn).ok


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


def test_it_passes_with_a_caveat_on_other_platforms_and_without_yara_x(conn, monkeypatch):
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


@pytest.mark.parametrize("exposure,says,never", [
    ({"proc_environ_readable": True, "database_reachable": False},
     "secrets", "database host"),
    ({"proc_environ_readable": False, "database_reachable": True},
     "database host", "environment"),
    ({"proc_environ_readable": None, "database_reachable": None}, None,
     "parser exploit"),
])
def test_the_exposure_caveat_names_only_what_applies_and_agrees(
        conn, monkeypatch, exposure, says, never):
    """The verifier saw "the database host: ... would reach them" with one
    exposure (F11, 2026-09-24). Each fact is named only when the selftest
    reported it, and the sentence reads the same for one or two."""
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
