"""A database that is down must FAIL, not hang.

`db.connect()` used to call `psycopg.connect(dsn(), autocommit=True)` with
no `connect_timeout`. libpq's default on a host that does not answer is
effectively unbounded, so with Postgres down every request, every test and
every script sat in TCP connect until something external killed it. On
2026-09-01 a read-only audit sat for five minutes with no message before a
300s harness timeout ended it -- the codebase's signature shape again: a
failure that does not report itself as one.

This test is deliberately DB-free: it points at an address that swallows
SYNs and asserts that `connect()` gives up. On the unpatched code it would
itself hang, which is a useless regression test, so the call runs on a
daemon thread under a watchdog and a hang is reported as a failure.
"""
from __future__ import annotations

import threading
import time

import pytest


#: TEST-NET-1 (RFC 5737): reserved for documentation, never routed. A SYN
#: to it goes nowhere and gets no RST, which is the exact "host does not
#: answer" case the timeout exists for. (A refused port fails fast on its
#: own and would prove nothing.)
BLACKHOLE = "postgresql://u:p@192.0.2.1:5432/x"


def test_a_connect_to_a_silent_host_gives_up_instead_of_hanging(monkeypatch):
    from noctornal_api import db

    monkeypatch.setenv("DATABASE_URL", BLACKHOLE)
    monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", "1")

    outcome: dict = {}

    def attempt():
        t0 = time.monotonic()
        try:
            db.connect()
            outcome["result"] = "connected"        # impossible; documents intent
        except Exception as exc:                   # noqa: BLE001 - any refusal is the point
            outcome["result"] = type(exc).__name__
        outcome["elapsed"] = time.monotonic() - t0

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=8.0)

    assert not worker.is_alive(), (
        "db.connect() is still blocked after 8s against a host that never "
        "answers: connect_timeout is not being applied, so a down database "
        "hangs the caller instead of failing it")
    assert outcome["result"] != "connected"
    # The configured budget was 1s. Allow generous slack for a slow box, but
    # it must be nowhere near the watchdog -- that is the whole property.
    assert outcome["elapsed"] < 6.0, outcome


def test_the_timeout_is_never_unbounded(monkeypatch):
    """`connect_timeout=0` means "no limit" to libpq. The parser must not
    let a config typo reintroduce the hang."""
    from noctornal_api import db
    for raw in ("0", "-5", "", "nonsense"):
        monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", raw)
        assert db.connect_timeout_seconds() >= 1, raw
    monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", "37")
    assert db.connect_timeout_seconds() == 37
    monkeypatch.delenv("NOCTORNAL_DB_CONNECT_TIMEOUT")
    assert db.connect_timeout_seconds() == 10


@pytest.mark.parametrize("raw", ["1", "10", "300"])
def test_positive_values_pass_through(monkeypatch, raw):
    from noctornal_api import db
    monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", raw)
    assert db.connect_timeout_seconds() == int(raw)
