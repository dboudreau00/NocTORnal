"""A socket timeout capped at the time left can wake a few milliseconds
before the allowance's end (Windows' socket timer is coarser than the
monotonic clock). It is still the allowance running out, and is reported
as DeadlineExceeded, not as an uncertain request (found under load,
2026-09-24). Nothing else near the end is.
"""
from __future__ import annotations

from noctornal_api import pinned_http


class _Clock:
    def __init__(self, now: float):
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_a_timeout_just_before_the_end_is_the_allowance_running_out(monkeypatch):
    clock = _Clock(100.0)
    monkeypatch.setattr(pinned_http.time, "monotonic", clock)
    d = pinned_http.Deadline(1.0)            # ends at 101.0
    clock.now = 101.0 - pinned_http.TIMEOUT_SLACK / 2
    assert not d.spent()
    assert d.ran_out(TimeoutError("timed out"))


def test_a_timeout_well_before_the_end_is_not(monkeypatch):
    clock = _Clock(100.0)
    monkeypatch.setattr(pinned_http.time, "monotonic", clock)
    d = pinned_http.Deadline(1.0)
    clock.now = 100.2
    assert not d.ran_out(TimeoutError("timed out"))


def test_another_error_near_the_end_is_not(monkeypatch):
    clock = _Clock(100.0)
    monkeypatch.setattr(pinned_http.time, "monotonic", clock)
    d = pinned_http.Deadline(1.0)
    clock.now = 101.0 - pinned_http.TIMEOUT_SLACK / 2
    assert not d.ran_out(ConnectionResetError("reset"))


def test_anything_after_the_end_is(monkeypatch):
    clock = _Clock(100.0)
    monkeypatch.setattr(pinned_http.time, "monotonic", clock)
    d = pinned_http.Deadline(1.0)
    clock.now = 101.5
    assert d.ran_out(ConnectionResetError("reset"))
    assert d.ran_out(TimeoutError("timed out"))
