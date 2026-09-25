"""F1 roles: the readiness row that says whether role analysis (CONCOR)
runs on one BLAS thread per process (2026-09-24).

The row matters wherever the cap does not take: threadpoolctl
is not pinned, so `blockmodel` caps through it when it is installed and
otherwise through the OpenBLAS numpy bundles, and on a numpy with neither
(Apple's Accelerate) nothing is capped. Four worker processes each running
a worst case took about 50 s apiece uncapped against 6 s capped.

- the row is registered, never blocks and names no console target;
- it passes in a fresh process on this host, where the cap took;
- it fails, with an action, for every way the cap can be missing: no BLAS
  to tell, a count read back above one, a count that cannot be read, and
  threadpoolctl finding nothing it can cap;
- a crash while loading the module is a failed row, never an exception.

Pure: no database (the probe never touches its connection).
"""
from __future__ import annotations

import os
import subprocess
import sys
import types

import pytest

from noctornal_api import blockmodel, readiness

NAME = "role_analysis_thread_capped"


def _probe():
    (probe,) = [p for n, p, _ in readiness._CHECKS if n == NAME]
    return probe(None)


def test_the_row_is_registered_and_never_blocks():
    assert NAME in readiness.CHECK_NAMES
    assert NAME not in readiness.BLOCKING_CHECKS
    assert NAME not in readiness.CONSEQUENCES and NAME not in readiness.UI_TARGETS


@pytest.mark.skipif(sys.platform == "darwin",
                    reason="the macOS arm64 numpy wheels use Accelerate, which "
                           "nothing here can cap; production is Linux with OpenBLAS")
def test_it_passes_in_a_fresh_process_where_the_cap_took():
    code = ("from noctornal_api import readiness as r; "
            "c = [p for n, p, _ in r._CHECKS if n == 'role_analysis_thread_capped'][0](None); "
            "print(c.ok); print(c.evidence)")
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env=dict(os.environ), timeout=120)
    assert res.returncode == 0, res.stderr
    ok, evidence = res.stdout.splitlines()[:2]
    assert ok == "True", evidence
    assert evidence.startswith("capped to 1 BLAS thread per process through ")


def test_no_blas_to_tell_is_a_failed_row_with_an_action(monkeypatch):
    monkeypatch.setattr(blockmodel, "BLAS_CAP", "none")
    check = _probe()
    assert not check.ok
    assert "runs a thread per core" in check.evidence
    assert "threadpoolctl==3.7.0" in check.action and "restart the API" in check.action


@pytest.mark.parametrize("now, words", [
    (16, "it now reports 16 threads"),
    (None, "its thread count cannot be read back"),
])
def test_an_openblas_cap_that_does_not_read_back_as_one_fails(monkeypatch, now, words):
    monkeypatch.setattr(blockmodel, "BLAS_CAP", "openblas")
    monkeypatch.setattr(blockmodel, "blas_threads", lambda: now)
    check = _probe()
    assert not check.ok and words in check.evidence and check.action


def test_an_openblas_cap_at_one_passes(monkeypatch):
    monkeypatch.setattr(blockmodel, "BLAS_CAP", "openblas")
    monkeypatch.setattr(blockmodel, "blas_threads", lambda: 1)
    check = _probe()
    assert check.ok and check.action == ""
    assert "threadpoolctl is not installed" in check.evidence


@pytest.mark.parametrize("info, ok, words", [
    ([], False, "finds no BLAS it can cap"),
    ([{"user_api": "openmp", "num_threads": 1}], False, "finds no BLAS it can cap"),
    ([{"user_api": "blas", "num_threads": 1}, {"user_api": "openmp", "num_threads": 8}],
     True, "through threadpoolctl"),
    ([{"user_api": "blas", "num_threads": 1}, {"user_api": "blas", "num_threads": 4}],
     False, "a BLAS now runs 1, 4 threads"),
])
def test_threadpoolctl_must_find_every_blas_at_one(monkeypatch, info, ok, words):
    fake = types.ModuleType("threadpoolctl")
    fake.threadpool_info = lambda: info
    monkeypatch.setitem(sys.modules, "threadpoolctl", fake)
    monkeypatch.setattr(blockmodel, "BLAS_CAP", "threadpoolctl")
    check = _probe()
    assert check.ok is ok and words in check.evidence
    assert bool(check.action) is not ok


def test_a_crash_loading_the_module_is_a_failed_row(monkeypatch):
    def boom():
        raise ImportError("numpy")

    monkeypatch.setattr(blockmodel, "blas_cap_report", boom)
    (row,) = [readiness._register_facts(n, readiness._guarded(n, a, lambda p=p: p(None)))
              for n, p, a in readiness._CHECKS if n == NAME]
    assert not row.ok and row.evidence.startswith("ImportError")
    assert "reinstall with -c constraints.txt" in row.action
    assert row.blocking is False and row.consequence == "" and row.ui_target == ""


def test_every_string_obeys_the_copy_rules(monkeypatch):
    texts = [a for n, _, a in readiness._CHECKS if n == NAME]
    for cap, now in (("none", None), ("openblas", 16), ("openblas", None), ("openblas", 1)):
        monkeypatch.setattr(blockmodel, "BLAS_CAP", cap)
        monkeypatch.setattr(blockmodel, "blas_threads", lambda now=now: now)
        check = _probe()
        texts += [check.evidence, check.action]
    for text in texts:
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in text, text
