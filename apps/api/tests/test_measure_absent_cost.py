"""The timing harness's arithmetic (`measure_absent_cost.summarise`), on series made up for it.

The harness itself never runs in CI: it times requests, and a timing is evidence, not a verdict
(decision 230). What it reports must still be right, so the statistics are one pure function, held
here on synthetic, seeded data: a known gap is reported with an interval around it that leaves out
zero, and no gap with an interval that holds zero.

Pure: no database.
"""
from __future__ import annotations

import random

import pytest

from measure_absent_cost import summarise


def _series(base_ms: float, gap_ms: float, n: int = 60, seed: int = 7):
    rng = random.Random(seed)
    missing = [int((base_ms + rng.gauss(0, 2)) * 1e6) for _ in range(n)]
    hidden = [m + int((gap_ms + rng.gauss(0, 2)) * 1e6) for m in missing]
    return hidden, missing


def test_the_timing_harness_reports_a_known_gap():
    hidden, missing = _series(66.5, 15.0)
    got = summarise(hidden, missing)
    assert abs(got.difference_ms - 15.0) < 1.5, got
    assert got.low_ms <= got.difference_ms <= got.high_ms
    assert got.low_ms > 0 and got.low_ms < 15.0 < got.high_ms, got
    assert abs(got.missing_ms - 66.5) < 2 and abs(got.hidden_ms - 81.5) < 2.5, got
    # The same series give the same figures: the resampling is seeded.
    assert summarise(hidden, missing) == got


def test_the_timing_harness_reports_no_gap_where_there_is_none():
    hidden, missing = _series(80.0, 0.0)
    got = summarise(hidden, missing)
    assert got.low_ms < 0 < got.high_ms, got
    with pytest.raises(ValueError):
        summarise(hidden, missing[:-1])
    with pytest.raises(ValueError):
        summarise([], [])
