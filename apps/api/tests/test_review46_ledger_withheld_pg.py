"""The connection log says only that some rows are withheld, and that is not an oracle.

The connection log once returned `withheld`, how many rows the caller's clearance hides. Counted under the
caller's own route, event and `since` filters, and with the overview returning a hidden profile's id, a
reader below a profile's label could read the timing and volume of its (RED) activity exactly:
`?route_id=persona:<id>&since=T`, then move T. Counted over the whole log it was still one number, so a
reader who polled it and subtracted successive answers learnt when hidden rows arrived and roughly how many.
The listing now answers `some_withheld`, a flag over the whole log: it does not move with the filters, and
hidden rows written after the first change nothing a reader below their label is told. The chain's sequence
number gave the same volume through the gaps between the rows shown, so it goes only to a reader the log
hides nothing from.

Every row is written inside a transaction that is rolled back (the ledger is append-only, so nothing could
remove them afterwards). Env-gated on DATABASE_URL.
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


def _sources(conn):
    red = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url="http://forum.example/", classification="RED")
    green = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                      base_url="http://forum.example/", classification="GREEN")
    return red, green


def _world(conn):
    red, green = _sources(conn)
    hidden_route = "persona:" + str(uuid4())
    other_route = "persona:" + str(uuid4())
    for _ in range(3):
        _write(conn, hidden_route, red, "RED")
    for _ in range(2):
        _write(conn, hidden_route, green, "GREEN")
    _write(conn, other_route, red, "RED", event="REFUSED")
    return hidden_route, other_route


def test_the_withheld_flag_does_not_move_with_the_route_or_the_window(conn):
    with conn.transaction(force_rollback=True):
        hidden, other = _world(conn)
        whole = egress_ledger.listing(conn, clearance="GREEN", limit=500)
        assert whole["some_withheld"] is True, "the RED rows written here were not seen as withheld"
        future = datetime.now(timezone.utc) + timedelta(days=365)
        unknown = "persona:" + str(uuid4())
        for filters in ({"route_id": hidden}, {"route_id": other}, {"route_id": unknown},
                        {"since": future}, {"route_id": hidden, "since": future},
                        {"route_id": hidden, "event": "REFUSED"}, {"event": "REFUSED"}):
            got = egress_ledger.listing(conn, clearance="GREEN", limit=500, **filters)
            assert got["some_withheld"] is True, filters
            assert "withheld" not in got, filters


def test_the_listing_carries_no_count_of_what_it_withheld(conn):
    with conn.transaction(force_rollback=True):
        _world(conn)
        for clearance in ("GREEN", "RED"):
            got = egress_ledger.listing(conn, clearance=clearance, limit=500)
            assert set(got) == {"rows", "some_withheld"}
            assert type(got["some_withheld"]) is bool


def test_hidden_rows_arriving_between_two_polls_change_nothing_a_reader_below_the_label_can_see(conn):
    """The oracle itself: a reader below the label polls, hidden rows arrive, the reader polls again.
    The two answers must be equal whole, whatever the number of rows that arrived in between."""
    with conn.transaction(force_rollback=True):
        hidden, _other = _world(conn)
        red, _green = _sources(conn)
        for k in (1, 5, 40):
            before = egress_ledger.listing(conn, clearance="GREEN", limit=500)
            for _ in range(k):
                _write(conn, hidden, red, "RED")
            after = egress_ledger.listing(conn, clearance="GREEN", limit=500)
            assert after == before, k


def test_the_flag_turns_on_at_the_first_hidden_row_and_further_rows_change_nothing(conn):
    with conn.transaction(force_rollback=True):
        es.empty_ledger(conn)
        red, green = _sources(conn)
        route = "persona:" + str(uuid4())
        _write(conn, route, green, "GREEN")
        assert egress_ledger.listing(conn, clearance="GREEN", limit=500)["some_withheld"] is False
        _write(conn, route, red, "RED")
        first = egress_ledger.listing(conn, clearance="GREEN", limit=500)
        assert first["some_withheld"] is True
        for _ in range(10):
            _write(conn, route, red, "RED")
        assert egress_ledger.listing(conn, clearance="GREEN", limit=500) == first


def test_a_reader_the_log_hides_nothing_from_gets_the_flag_false_and_the_sequence_numbers(conn):
    with conn.transaction(force_rollback=True):
        es.empty_ledger(conn)
        red, green = _sources(conn)
        route = "persona:" + str(uuid4())
        first = _write(conn, route, green, "GREEN")
        second = _write(conn, route, red, "RED")
        got = egress_ledger.listing(conn, clearance="RED", limit=500)
        assert got["some_withheld"] is False
        assert [r["seq"] for r in got["rows"]] == [second, first]


def test_a_reader_with_withheld_rows_gets_no_sequence_numbers(conn):
    with conn.transaction(force_rollback=True):
        hidden, _other = _world(conn)
        got = egress_ledger.listing(conn, clearance="GREEN", route_id=hidden, limit=500)
        assert got["some_withheld"] is True
        assert len(got["rows"]) == 2
        assert all(r["seq"] is None for r in got["rows"])
        # Still newest first, and each row still has its own citation.
        times = [r["occurred_at"] for r in got["rows"]]
        assert times == sorted(times, reverse=True)
        assert len({r["connection_id"] for r in got["rows"]}) == 2


def _as_seen(listing):
    """What a reader is told, less what differs between two runs by construction: the random ids, the
    route and source made for each run, and the clock."""
    drawn = ("connection_id", "context_id", "occurred_at", "route_id", "source_id")
    return {"some_withheld": listing["some_withheld"],
            "rows": [{k: v for k, v in r.items() if k not in drawn} for r in listing["rows"]]}


def test_the_gap_between_two_visible_rows_says_nothing_of_the_hidden_rows_between_them(conn):
    """The sequence number channel: a row shown before and a row shown after k hidden rows. If the
    numbers were given, the second less the first would be k + 1."""
    seen = {}
    for k in (1, 40):
        with conn.transaction(force_rollback=True):
            _world(conn)
            red, green = _sources(conn)
            route = "persona:" + str(uuid4())
            _write(conn, route, green, "GREEN")
            for _ in range(k):
                _write(conn, route, red, "RED")
            _write(conn, route, green, "GREEN")
            got = egress_ledger.listing(conn, clearance="GREEN", route_id=route, limit=500)
            assert len(got["rows"]) == 2
            seen[k] = _as_seen(got)
    assert seen[1] == seen[40]


def test_the_listing_and_the_chain_check_ask_one_question(conn):
    """The listing's flag and what decides whether Verify the chain gives its row count are one rule."""
    with conn.transaction(force_rollback=True):
        es.empty_ledger(conn)
        _world(conn)
        for clearance, withheld in (("GREEN", True), ("AMBER", True), ("RED", False)):
            assert egress_ledger.withholds_any(conn, clearance=clearance) is withheld
            assert egress_ledger.listing(
                conn, clearance=clearance, limit=1)["some_withheld"] is withheld


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
        assert red["some_withheld"] == egress_ledger.listing(
            conn, clearance="RED", limit=500)["some_withheld"]
