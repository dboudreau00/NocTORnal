"""collect.egress_connection: append-only, hash-chained, labelled at read
time (S2, 2026-09-24).

The tamper case runs inside a transaction that is rolled back, so no
developer database and no CI run keeps a broken chain in a table nothing
can clean. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import threading
from uuid import uuid4

import psycopg
import pytest

import egress_support as es
from noctornal_api import egress_ledger
from noctornal_api.egress_ledger import Row

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egl-"


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.collection_standin(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


def _open(connection_id=None, **kw) -> Row:
    values = dict(event="OPEN", route_id="integration:webhook", reason="allowed",
                  connection_id=connection_id or uuid4(), protocol="HTTP_CONNECT",
                  route_kind="integration", dest_host="hooks.example", dest_port=443,
                  exit_kind="DIRECT")
    values.update(kw)
    return Row(**values)


def _close(connection_id, **kw) -> Row:
    values = dict(event="CLOSE", route_id="integration:webhook", reason="client_closed",
                  connection_id=connection_id, protocol="HTTP_CONNECT",
                  route_kind="integration", exit_kind="DIRECT", bytes_up=10,
                  bytes_down=20, duration_ms=5)
    values.update(kw)
    return Row(**values)



def _registered(conn, keys):
    """Register each key before a raw write carries it (test_fixture_invariants)."""
    for key in keys:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))

def test_update_delete_and_truncate_are_refused(conn):
    seq = egress_ledger.write(conn, _open())
    for statement in ("UPDATE collect.egress_connection SET reason = 'x' WHERE seq = %s",
                      "DELETE FROM collect.egress_connection WHERE seq = %s"):
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute(statement, (seq,))
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        conn.execute("TRUNCATE collect.egress_connection")


@pytest.mark.parametrize("row", [
    _open(dest_host=None),
    _open(reason="refused"),
    _open(bytes_up=3),
    Row(event="REFUSED", route_id="integration:webhook", reason="allowed",
        connection_id=uuid4(), protocol="SOCKS5", route_kind="integration"),
    _close(uuid4(), dest_host="hooks.example"),
    _close(uuid4(), dest_digest=b"x"),
    _close(uuid4(), bytes_up=-1),
    Row(event="PREAUTH", route_id="proxy", reason="preauth_refused", item_count=1),
    Row(event="PREAUTH", route_id="proxy", reason="preauth_refused", item_count=2,
        peer_address="10.0.0.1", route_kind="integration"),
    Row(event="REWRAP", route_id="proxy", reason="exits_rewrapped", item_count=1,
        dest_host="hooks.example"),
    _open(peer_address="10.0.0.1"),
    _open(egress_profile_id=uuid4()),
    Row(event="OPEN", route_id="persona:passive", reason="allowed", connection_id=uuid4(),
        protocol="HTTP_CONNECT", route_kind="persona", dest_host="feed.example",
        dest_port=443, exit_kind="DIRECT", integration_route_id=uuid4()),
])
def test_every_event_shape_refuses_its_malformed_row(conn, row):
    with pytest.raises(psycopg.errors.CheckViolation):
        egress_ledger.write(conn, row)


def test_a_close_reason_outside_the_list_is_refused_before_the_database():
    with pytest.raises(ValueError):
        egress_ledger.write(None, _close(uuid4(), reason="because"))


def test_the_chain_verifies_over_a_mixed_run_of_events(conn):
    cid = uuid4()
    egress_ledger.write(conn, _open(cid))
    egress_ledger.write(conn, Row(event="REFUSED", route_id="integration:webhook",
                                  reason="port_not_allowed", connection_id=uuid4(),
                                  protocol="SOCKS5", route_kind="integration",
                                  dest_digest=b"\x01" * 32, dest_port=22))
    egress_ledger.write(conn, _close(cid))
    egress_ledger.write(conn, Row(event="PREAUTH", route_id="proxy",
                                  reason="preauth_refused", peer_address="172.31.243.10",
                                  item_count=7))
    egress_ledger.write(conn, Row(event="REWRAP", route_id="proxy",
                                  reason="exits_rewrapped", item_count=0))
    result = egress_ledger.verify(conn)
    assert result["first_break_seq"] is None and result["rows"] >= 5


def test_eight_writers_at_once_leave_one_unforked_chain_in_seq_order(conn):
    from noctornal_api.db import connect
    errors = []

    def writer():
        try:
            with connect() as c:
                for _ in range(25):
                    egress_ledger.write(c, _open())
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors
    assert egress_ledger.verify(conn)["first_break_seq"] is None
    # seq order IS chain order: each row's prev_hash is the row before's.
    forks = conn.execute(
        """SELECT count(*) FROM (
             SELECT prev_hash, lag(row_hash) OVER (ORDER BY seq) AS before
               FROM collect.egress_connection) x
            WHERE x.before IS NOT NULL AND x.prev_hash IS DISTINCT FROM x.before"""
    ).fetchone()[0]
    assert forks == 0


def test_a_row_the_owner_rewrote_breaks_the_chain_at_its_seq(conn):
    seq = egress_ledger.write(conn, _open())
    egress_ledger.write(conn, _open())

    class Rollback(Exception):
        pass

    with pytest.raises(Rollback):
        with conn.transaction():
            conn.execute("ALTER TABLE collect.egress_connection DISABLE TRIGGER USER")
            conn.execute("UPDATE collect.egress_connection SET dest_host = 'forged.example' "
                         "WHERE seq = %s", (seq,))
            assert egress_ledger.verify(conn)["first_break_seq"] == seq
            raise Rollback
    assert egress_ledger.verify(conn)["first_break_seq"] is None


def test_the_verifier_and_the_trigger_share_one_expression_and_one_grant_list():
    migration = es.migration("0086")
    assert migration.ROW_HASH_SQL == egress_ledger.ROW_HASH_SQL
    assert migration.EGRESS_GRANTS == egress_ledger.EGRESS_GRANTS


def _labelled_world(conn, classification="AMBER"):
    sid = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url="http://forum.example/", classification=classification)
    rows = []
    cid = uuid4()
    rows.append(egress_ledger.write(conn, Row(
        event="OPEN", route_id="persona:" + str(uuid4()), reason="allowed",
        connection_id=cid, protocol="SOCKS5", route_kind="persona",
        dest_host="forum.example", dest_port=443, exit_kind="SOCKS5",
        source_id=sid, classification=classification, context_kind="run",
        context_id=uuid4())))
    return sid, cid, rows[0]


def _seqs(listing):
    return {r["seq"] for r in listing["rows"]}


def test_listing_withholds_rows_above_clearance_and_counts_them(conn):
    _sid, _cid, seq = _labelled_world(conn, "RED")
    amber = egress_ledger.listing(conn, clearance="AMBER", limit=500)
    assert seq not in _seqs(amber) and amber["withheld"] >= 1
    assert seq in _seqs(egress_ledger.listing(conn, clearance="RED", limit=500))


def test_a_source_raised_later_raises_its_earlier_rows(conn):
    sid, _cid, seq = _labelled_world(conn, "GREEN")
    assert seq in _seqs(egress_ledger.listing(conn, clearance="AMBER", limit=500))
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s", (sid,))
    assert seq not in _seqs(egress_ledger.listing(conn, clearance="AMBER", limit=500))


def test_a_deleted_sources_rows_stand_and_stay_shown_on_their_stored_label(conn):
    sid, _cid, seq = _labelled_world(conn, "GREEN")
    conn.execute("DELETE FROM collect.source WHERE id = %s", (sid,))
    shown = egress_ledger.listing(conn, clearance="GREEN", limit=500)
    assert seq in _seqs(shown)
    flagged = egress_ledger.write(conn, Row(
        event="REFUSED", route_id="persona:" + str(uuid4()), reason="authority_missing",
        connection_id=uuid4(), protocol="SOCKS5", route_kind="persona",
        source_id=uuid4(), source_compartmented=True, dest_digest=b"\x02" * 32))
    assert flagged not in _seqs(egress_ledger.listing(conn, clearance="RED", limit=500))


def test_a_compartmented_sources_rows_need_its_compartments(conn):
    _registered(conn, ["HUMINT-X"])
    added = not conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'compartments')""").fetchone()[0]
    if added:
        conn.execute("ALTER TABLE collect.source ADD COLUMN compartments text[] "
                     "NOT NULL DEFAULT '{}'")
    try:
        sid, _cid, seq = _labelled_world(conn, "GREEN")
        conn.execute("UPDATE collect.source SET compartments = '{HUMINT-X}' WHERE id = %s",
                     (sid,))
        assert seq not in _seqs(egress_ledger.listing(conn, clearance="RED", limit=500))
        assert seq in _seqs(egress_ledger.listing(conn, clearance="RED",
                                                  compartments={"HUMINT-X"}, limit=500))
    finally:
        if added:
            conn.execute("ALTER TABLE collect.source DROP COLUMN compartments")


def test_listing_pairs_open_with_close_and_marks_an_open_left_unclosed(conn):
    closed, unclosed = uuid4(), uuid4()
    first = egress_ledger.write(conn, _open(closed))
    egress_ledger.write(conn, _close(closed, reason="upstream_closed"))
    second = egress_ledger.write(conn, _open(unclosed))
    rows = {r["seq"]: r for r in egress_ledger.listing(conn, clearance="GREEN",
                                                        event="OPEN", limit=500)["rows"]}
    assert rows[first]["closed"]["reason"] == "upstream_closed"
    assert rows[first]["closed"]["bytes_down"] == 20
    assert rows[second]["closed"] is None
    assert rows[second]["close_text"] == egress_ledger.NO_CLOSE
    assert all(r["event"] != "CLOSE" for r in rows.values())


def test_deleting_what_a_row_names_leaves_the_row(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    persona = es.persona(conn, PREFIX, profile=pid)
    sid = es.source(conn, PREFIX)
    run = es.run(conn, sid)
    seq = egress_ledger.write(conn, Row(
        event="REFUSED", route_id=f"persona:{pid}", reason="run_not_running",
        connection_id=uuid4(), protocol="SOCKS5", route_kind="persona",
        egress_profile_id=pid, collection_account_id=persona, source_id=sid,
        collection_run_id=run, dest_digest=b"\x03" * 32))
    conn.execute("DELETE FROM collect.collection_run WHERE id = %s", (run,))
    conn.execute("DELETE FROM collect.source WHERE id = %s", (sid,))
    conn.execute("DELETE FROM collect.collection_account WHERE id = %s", (persona,))
    conn.execute("DELETE FROM collect.egress_profile WHERE id = %s", (pid,))
    assert conn.execute("SELECT route_id FROM collect.egress_connection WHERE seq = %s",
                        (seq,)).fetchone()[0] == f"persona:{pid}"


def test_the_downgrade_refuses_while_the_ledger_holds_rows(conn):
    egress_ledger.write(conn, _open())
    migration = es.migration("0086")
    migration.run = lambda sql: conn.execute(sql)

    refusal = (r"refusing to downgrade 0086: collect.egress_connection holds "
               r"(one row|\d+ rows),")
    with pytest.raises(psycopg.errors.RaiseException, match=refusal):
        with conn.transaction():
            migration.downgrade()
    assert conn.execute("SELECT to_regclass('collect.egress_connection')").fetchone()[0]


def test_the_application_role_keeps_select_only(conn):
    migration = es.migration("0086")
    assert migration.GUARDED_TABLES == {"collect.egress_connection": ("SELECT",)}
    assert es.migration("0085").GUARDED_TABLES == {"collect.egress_binding": ("SELECT",)}
