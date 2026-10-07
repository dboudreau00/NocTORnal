"""A watch pattern the sandbox did not run is not told as a crashed matcher
(beta 1 gate 6, 2026-10-07). analysis_runner says the runner's own failures
(no worker, a busy one, an answer that is not one) are the sandbox's state
and never a crashed step; watch_regex read every one of them as "the
matching process stopped without an answer". Pure: the runner is replaced.
"""
from __future__ import annotations

import pytest

from noctornal_api import analysis_runner, lab_triage, watch_regex


@pytest.mark.parametrize("failure", analysis_runner.SANDBOX_FAILURES)
def test_a_sandbox_failure_is_named_as_the_sandbox(monkeypatch, failure):
    monkeypatch.setattr(lab_triage, "run_child", lambda *_a, **_kw: analysis_runner.ChildResult(
        False, failure=failure))
    verdicts = watch_regex.run({"needle": ["a haystack"]})
    kind, sentence = verdicts.failed["needle"]
    assert kind == watch_regex.LIMIT
    assert sentence.startswith(lab_triage.CHILD_FAILURES[failure])
    assert "stopped without an answer" not in sentence


def test_a_crashed_matcher_is_still_a_crashed_matcher(monkeypatch):
    monkeypatch.setattr(lab_triage, "run_child", lambda *_a, **_kw: analysis_runner.ChildResult(
        False, failure="crashed", returncode=-9))
    verdicts = watch_regex.run({"needle": ["a haystack"]})
    assert verdicts.failed["needle"] == (watch_regex.LIMIT, watch_regex._LIMIT_SENTENCES["crashed"])
