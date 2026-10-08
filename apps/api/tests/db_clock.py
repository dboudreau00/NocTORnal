"""Waiting on the database server's own clock (docs/17, test isolation, Beta
1.1). Not a test module: the suites import it.

Several suites assert an order that the server's timestamps give: a claim
older than the one recorded after it, a ledger row newer than another, an
authority confirmed after the route last changed. Each holds whenever the
server's clock only moves forward, and on a host where something steps it,
the suite fails with nothing wrong. The development machine's WSL2 VM is
such a host: Hyper-V time sync sets the VM's clock to the Windows host's every
five seconds and systemd-timesyncd sets it back to NTP time as soon as an NTP
exchange has finished (a tenth to a third of a second later; the host's own
clock is out by some seconds, Windows Time being stopped), so for that long in
every five every row is stamped five or six seconds AHEAD of the rows written
just before and just after it. A test that writes two rows a few
milliseconds apart finds them in the wrong order about one run in fifty,
alone as well as in the suite.

`wait_until_after` makes the order a precondition: the test that depends on
one write being stamped later than another waits, before it makes the
second, until the clock reads later than the first stamp OUTSIDE a step. On a
host whose clock agrees with the database's (every CI runner, and any machine
without that fault) it returns at once.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import psycopg

#: Longer than a step lasts (a tenth to a third of a second on the machine
#: described above, the length of an NTP exchange), so two readings this far
#: apart cannot both be inside one.
STEP_SECONDS = 0.6

#: The most the database's clock and this host's may differ before the clock
#: is taken to be stepped or unsynchronised. Docker on a machine that does not
#: sleep or drift keeps both within milliseconds.
DISAGREEMENT_SECONDS = 1.0

_offset: float | None = None


def clock_offset(conn: psycopg.Connection) -> float:
    """The most, in seconds, that the database's clock and this host's differed
    in three readings spread over a fraction of a second (so that a reading
    taken inside a step does not hide the disagreement); once per process."""
    global _offset
    if _offset is None:
        worst = 0.0
        for attempt in range(3):
            if attempt:
                time.sleep(STEP_SECONDS / 2)
            before = datetime.now(timezone.utc)
            database = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            after = datetime.now(timezone.utc)
            worst = max(worst, abs((database - (before + (after - before) / 2))
                                   .total_seconds()))
        _offset = worst
    return _offset


def clock_disagrees(conn: psycopg.Connection) -> bool:
    """Whether the database's clock and this host's differ by more than
    `DISAGREEMENT_SECONDS`."""
    return clock_offset(conn) > DISAGREEMENT_SECONDS


def wait_until_after(conn: psycopg.Connection, stamp: datetime | None, *,
                     timeout: float = 30.0) -> None:
    """Return once the database's clock reads later than `stamp` and will not
    read earlier again; at once when the clock agrees with the host's, which
    on a clock that only moves forward is every call. `None` is nothing to
    wait for. A stamp the clock does not pass within `timeout` seconds is an
    error that says so, not a hang."""
    if stamp is None or not clock_disagrees(conn):
        return
    wait_steadily_past(conn, stamp, timeout=timeout)


def wait_steadily_past(conn: psycopg.Connection, stamp: datetime, *,
                       timeout: float = 30.0) -> None:
    """The wait itself. The clock is read twice, `STEP_SECONDS` apart, and the
    smaller of the two (the later one less the time between them) is the
    reading from outside any step; the wait ends when THAT is past `stamp`.
    One reading alone would end it inside the step that stamped the row, and
    the next write, after the step, would be stamped before it."""
    deadline = time.monotonic() + timeout
    while True:
        first_at = time.monotonic()
        first = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        time.sleep(STEP_SECONDS)
        second = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        steady = min(first, second - timedelta(seconds=time.monotonic() - first_at))
        if steady > stamp:
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the database clock ({steady.isoformat()}) did not pass "
                f"{stamp.isoformat()} within {timeout:g} seconds")
