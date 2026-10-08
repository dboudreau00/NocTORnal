"""`db_clock.py`: the wait that makes a write order a precondition (2026-10-08).

Five tests failed in a full run and passed when their file ran alone, and
none of them had state left by another suite. The development machine's
WSL2 VM steps its clock: for a tenth of a second in five, every row is
stamped five or six seconds ahead of the rows around it (Hyper-V time sync
against systemd-timesyncd, the Windows host's own clock being out). A test
that writes two rows a moment apart, and then reads "the newest" or "the
oldest" of them, finds them in the wrong order about one run in fifty, alone
as well as in the suite. The suites that do so wait on the clock before the
second write (`db_clock.wait_until_after`).

What these hold: the wait does not end on a reading taken INSIDE the step
that stamped the row, which would let the next write land after the step and
be stamped before it; it ends once the clock reads later outside any step; it
says so when the clock never does; it costs nothing where the database's
clock and the host's agree; and the measurement it decides that on is the
database's own. The wait is run against scripted readings, which is the only
way to place a reading inside a step on a machine that has none.
Env-gated on DATABASE_URL, except the scripted ones.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import pytest

import db_clock

STAMP = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


def _seconds(value: float) -> datetime:
    return STAMP + timedelta(seconds=value)


class _Scripted:
    """A connection whose `SELECT clock_timestamp()` answers from a script."""

    def __init__(self, *readings: datetime):
        self.readings = list(readings)
        self.reads = 0
        self._value = None

    def execute(self, sql, params=None):
        assert "clock_timestamp()" in sql, sql
        self.reads += 1
        self._value = self.readings.pop(0)
        return self

    def fetchone(self):
        return (self._value,)


@pytest.fixture
def no_sleep(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _n: None)


def test_the_wait_does_not_end_inside_the_step_that_stamped_the_row(no_sleep):
    """The row was stamped inside a step, so the stamp is 5.6 s ahead of the
    clock the next write will read. The first reading is inside the same step
    and is past the stamp; the second, a step's length later, is not."""
    conn = _Scripted(_seconds(0.05), _seconds(-5.3),     # inside the step, then outside it
                     _seconds(0.1), _seconds(0.35))      # the clock has caught up
    db_clock.wait_steadily_past(conn, STAMP)
    assert conn.reads == 4, "it waited for the clock outside the step to pass the stamp"


def test_a_clock_that_has_passed_the_stamp_ends_the_wait_after_one_pair(no_sleep):
    conn = _Scripted(_seconds(1.0), _seconds(1.25))
    db_clock.wait_steadily_past(conn, STAMP)
    assert conn.reads == 2


def test_a_clock_that_never_passes_the_stamp_is_an_error_that_says_so(no_sleep):
    conn = _Scripted(_seconds(-1.0), _seconds(-0.75))
    with pytest.raises(AssertionError, match="did not pass 2026-10-08T12:00:00"):
        db_clock.wait_steadily_past(conn, STAMP, timeout=0.0)


def test_nothing_is_waited_for_where_the_database_clock_agrees_with_the_hosts(monkeypatch):
    monkeypatch.setattr(db_clock, "_offset", 0.002)

    class Untouched:
        def execute(self, *args, **kwargs):
            raise AssertionError("the database was asked")

    db_clock.wait_until_after(Untouched(), datetime.now(timezone.utc) + timedelta(hours=1))
    db_clock.wait_until_after(Untouched(), None)


def test_a_clock_that_disagrees_is_waited_on_and_none_is_nothing_to_wait_for(
        monkeypatch, no_sleep):
    monkeypatch.setattr(db_clock, "_offset", 5.6)
    db_clock.wait_until_after(_Scripted(), None)
    conn = _Scripted(_seconds(2.0), _seconds(2.25))
    db_clock.wait_until_after(conn, STAMP)
    assert conn.reads == 2


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="needs a database")
def test_the_wait_returns_only_when_the_databases_clock_is_past_the_stamp(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setattr(db_clock, "_offset", 5.6)
    with connect() as conn:
        stamp = conn.execute(
            "SELECT clock_timestamp() + interval '0.6 seconds'").fetchone()[0]
        began = time.monotonic()
        db_clock.wait_until_after(conn, stamp)
        elapsed = time.monotonic() - began
        assert conn.execute("SELECT clock_timestamp() > %s", (stamp,)).fetchone()[0]
    assert 0.5 < elapsed < 15, elapsed


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="needs a database")
def test_the_offset_is_measured_once_against_the_database(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setattr(db_clock, "_offset", None)
    with connect() as conn:
        first = db_clock.clock_offset(conn)
        assert isinstance(first, float) and first >= 0.0
        assert db_clock.clock_offset(conn) == first
        assert db_clock.clock_disagrees(conn) == (first > db_clock.DISAGREEMENT_SECONDS)
