"""egress-ledger-withheld-oracle (review of 2026-10-03).

The connection log returns `withheld`, how many rows the caller's clearance
hides. It was counted under the caller's own route, event and `since`
filters, and the overview returns a hidden profile's id, so a reader below a
profile's label could read the timing and volume of its (RED) activity
exactly: `?route_id=persona:<id>&since=T`, then move T.

Fails on dc28ffa: the count for the hidden route is the number of its rows,
and a far-future `since` empties it.

Every row is written inside a transaction that is rolled back (the ledger is
append-only, so nothing could remove them afterwards). Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import egress_support as es
from noctornal_api import egress_ledger
from noctornal_api.egress_ledger import Row

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46l-"


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.collection_standin(c):
        yield c
    c.close()


def _write(conn, route, source, label, event="OPEN"):
    return egress_ledger.write(conn, Row(
        event=event, route_id=route, reason="allowed" if event == "OPEN" else "above_route_ceiling",
        connection_id=uuid4(), protocol="SOCKS5", route_kind="persona",
        dest_host="forum.example", dest_port=443, exit_kind="SOCKS5",
        source_id=source, classification=label, context_kind="run", context_id=uuid4()))


def _world(conn):
    red = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url="http://forum.example/", classification="RED")
    green = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                      base_url="http://forum.example/", classification="GREEN")
    hidden_route = "persona:" + str(uuid4())
    other_route = "persona:" + str(uuid4())
    for _ in range(3):
        _write(conn, hidden_route, red, "RED")
    for _ in range(2):
        _write(conn, hidden_route, green, "GREEN")
    _write(conn, other_route, red, "RED", event="REFUSED")
    return hidden_route, other_route


def test_the_withheld_count_does_not_move_with_the_route_or_the_window(conn):
    with conn.transaction(force_rollback=True):
        hidden, other = _world(conn)
        whole = egress_ledger.listing(conn, clearance="GREEN", limit=500)
        total = whole["withheld"]
        assert total >= 4, "the RED rows written here were not counted"
        future = datetime.now(timezone.utc) + timedelta(days=365)
        unknown = "persona:" + str(uuid4())
        for filters in ({"route_id": hidden}, {"route_id": other}, {"route_id": unknown},
                        {"since": future}, {"route_id": hidden, "since": future},
                        {"route_id": hidden, "event": "REFUSED"}, {"event": "REFUSED"}):
            got = egress_ledger.listing(conn, clearance="GREEN", limit=500, **filters)
            assert got["withheld"] == total, (filters, got["withheld"], total)


def test_a_hidden_route_answers_as_one_that_does_not_exist(conn):
    with conn.transaction(force_rollback=True):
        _hidden, other = _world(conn)
        got = egress_ledger.listing(conn, clearance="GREEN", route_id=other, limit=500)
        nothing = egress_ledger.listing(conn, clearance="GREEN",
                                        route_id="persona:" + str(uuid4()), limit=500)
        assert got == nothing


def test_what_the_caller_may_see_is_unchanged(conn):
    """Both directions: the filters still select the visible rows, and a
    reader cleared for the label sees the rows the other is told are
    withheld."""
    with conn.transaction(force_rollback=True):
        hidden, other = _world(conn)
        green = egress_ledger.listing(conn, clearance="GREEN", route_id=hidden, limit=500)
        assert len(green["rows"]) == 2
        assert {r["classification"] for r in green["rows"]} == {"GREEN"}
        red = egress_ledger.listing(conn, clearance="RED", route_id=hidden, limit=500)
        assert len(red["rows"]) == 5
        assert egress_ledger.listing(conn, clearance="RED", route_id=other,
                                     event="REFUSED", limit=500)["rows"][0]["event"] == "REFUSED"
        assert red["withheld"] == egress_ledger.listing(
            conn, clearance="RED", limit=500)["withheld"]
