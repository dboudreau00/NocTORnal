"""The console's side of the Beta 1 release gate 61 sweep (2026-10-07).

A reader or a liaison opening a case had the console ask for three things
their role cannot have, on every case open: the projection metrics
(`analytics.run`), the Lab badge (`sample.read`) and the Feeds badge
(`ingest.read`). Each refusal is a permanent AUTHZ_DENIED row in an
append-only log, so ordinary browsing hummed denials and buried the probing
signal the row exists for. The Feeds badge already stopped asking after one
refusal; the other two now do as well: the metrics are not asked for when
the case record says the role lacks the verb, and the Lab badge latches on
its first 403 as the Feeds badge does.

Pure: no database, no browser.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def test_the_metrics_are_not_asked_for_by_a_role_without_the_verb():
    body = _code(_fn("refreshMetrics"))
    guard = body.find("caseCan(state.caseRec, 'analytics.run')")
    ask = body.find("/graph/metrics?")
    assert guard != -1, "refreshMetrics asks whatever the role on the case"
    assert guard < ask, "the role is checked after the request was made"
    # The degraded view is the one a refusal gives, said the same way.
    assert "roleWords('they need analytics.run on this case')" in body[guard:ask]
    assert "state.metricsDown" in body[guard:ask]


def test_the_lab_badge_is_refused_once_per_session():
    body = _code(_fn("refreshSampleBadge"))
    assert "SAMPLE_BADGE.refusedFor = state.userId" in body, (
        "a refused Lab badge is asked again on every case open, humming "
        "AUTHZ_DENIED")
    early = body.find("SAMPLE_BADGE.refusedFor === state.userId")
    ask = body.find("api('/samples'")
    assert early != -1 and early < ask, "the latch is not read before asking"
    assert "err.status === 403" in body, "only a refusal latches, not an outage"


def test_the_feeds_badge_still_latches():
    """The precedent the two above follow, held so the three stay alike."""
    assert "badgeRefusedFor = state.userId" in _code(_fn("refreshFeedsBadge"))
