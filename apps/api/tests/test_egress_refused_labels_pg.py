"""Refused persona rows carry what the reader labels them by (S2,
2026-09-25).

A refusal raised after the proxy had tied the destination to a source
(above_route_ceiling, port_not_allowed, onion_not_allowed, a passive feed's
port) once wrote the host in clear with no source, run or profile, so the
connection log kept showing it at its insert-time label after the source was
raised, and to people without the source's compartments. Every persona
refusal now carries the decision so far, the reader takes a row's source
from its run when the row names none, and a persona row with nothing to be
labelled by never shows a host.

A real proxy on an ephemeral loopback port. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import egress_support as es
from test_egress_proxy_pg import PREFIX, _expect, _persona_user, _world
from noctornal_api import egress_ledger, egress_policy
from noctornal_api.egress_ledger import Row

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

_REAL_IS_BLOCKED = egress_policy.is_blocked


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c), es.collection_standin(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


@pytest.fixture(scope="module")
def people(conn):
    return (es.user(conn, "CASE_OWNER", prefix=PREFIX, clearance="RED"),
            es.user(conn, "CASE_OWNER", prefix=PREFIX, clearance="RED"))


@pytest.fixture
def loopback_public(monkeypatch):
    def fake(address):
        address = getattr(address, "ipv4_mapped", None) or address
        if address.version == 4 and str(address).startswith("127."):
            return False
        return _REAL_IS_BLOCKED(address)
    monkeypatch.setattr(egress_policy, "is_blocked", fake)


@pytest.fixture
def resolver(monkeypatch):
    import socket
    fake = es.FakeResolver()
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


@pytest.fixture
def proxy():
    runner = es.ProxyRunner()
    yield runner
    runner.stop()


def _refused(conn, run_or_persona):
    return conn.execute(
        """SELECT seq, reason, dest_host, source_id, collection_run_id, egress_profile_id,
                  classification::text
             FROM collect.egress_connection
            WHERE event = 'REFUSED' AND context_id = %s ORDER BY seq DESC LIMIT 1""",
        (run_or_persona,)).fetchone()


def _seqs(listing):
    return {r["seq"] for r in listing["rows"]}


@pytest.fixture
def compartments_column(conn):
    """collect.source.compartments, which the egress readers use once the
    column exists, for the duration of one test where it is not there
    yet."""
    added = not conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'compartments')""").fetchone()[0]
    if added:
        conn.execute("ALTER TABLE collect.source ADD COLUMN compartments text[] "
                     "NOT NULL DEFAULT '{}'")
    yield
    if added:
        conn.execute("ALTER TABLE collect.source DROP COLUMN compartments")



def _registered(conn, keys):
    """Register each key before a raw write carries it (test_fixture_invariants)."""
    for key in keys:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))

def test_a_passive_feed_refused_on_its_port_names_its_run_and_follows_its_source(
        conn, people, loopback_public, resolver, proxy):
    passive = es.profile(conn, PREFIX, ports=(443,), passive=True)
    sid = es.source(conn, PREFIX, base_url="http://feed.rebind.test:8080/rss",
                    classification="AMBER")
    run = es.run(conn, sid)
    _expect(proxy, f"persona.passive~run.{run}", "feed.rebind.test:8080",
            "port_not_allowed")
    seq, reason, host, source, row_run, profile, label = _refused(conn, run)
    assert (reason, host, source, row_run, profile, label) == (
        "port_not_allowed", "feed.rebind.test", sid, run, passive, "AMBER")
    assert seq in _seqs(egress_ledger.listing(conn, clearance="AMBER", limit=500))
    # Raised after the fact: an AMBER reader no longer sees the host.
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s", (sid,))
    after = egress_ledger.listing(conn, clearance="AMBER", limit=500)
    assert seq not in _seqs(after) and after["withheld"] >= 1
    red = {r["seq"]: r for r in egress_ledger.listing(conn, clearance="RED",
                                                       limit=500)["rows"]}
    assert red[seq]["classification"] == "RED"


def test_a_run_above_its_ceiling_is_hidden_without_its_sources_compartments(
        conn, people, loopback_public, resolver, proxy, compartments_column):
    _registered(conn, ["HUMINT-EGRESS"])
    pid, persona, sid, aid = _world(conn, people, 443, classification="RED",
                                    host="secretforum.rebind.test")
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "secretforum.rebind.test:443",
            "above_route_ceiling")
    seq, _reason, host, source, row_run, profile, _label = _refused(conn, run)
    assert (host, source, row_run, profile) == ("secretforum.rebind.test", sid, run, pid)
    conn.execute("UPDATE collect.source SET compartments = '{HUMINT-EGRESS}' WHERE id = %s",
                 (sid,))
    assert seq not in _seqs(egress_ledger.listing(conn, clearance="RED", limit=500))
    assert seq in _seqs(egress_ledger.listing(conn, clearance="RED",
                                              compartments={"HUMINT-EGRESS"}, limit=500))


def test_an_act_refused_after_its_source_tie_names_the_source_and_persona(
        conn, people, loopback_public, resolver, proxy):
    pid, persona, sid, _aid = _world(conn, people, 443)
    # Port 8443 is not on the profile: the destination matched the source
    # first, so the row may name it, and names what labels it.
    _expect(proxy, _persona_user(pid, f"act.{persona}"), "forum.rebind.test:8443",
            "port_not_allowed")
    row = conn.execute(
        """SELECT dest_host, source_id, collection_account_id, egress_profile_id
             FROM collect.egress_connection
            WHERE event = 'REFUSED' AND context_id = %s ORDER BY seq DESC LIMIT 1""",
        (persona,)).fetchone()
    assert row == ("forum.rebind.test", sid, persona, pid)


def test_a_route_level_refusal_writes_no_host(conn, people, loopback_public, resolver,
                                              proxy):
    pid, persona, sid, aid = _world(conn, people, 443)
    conn.execute("UPDATE collect.egress_profile SET is_active = false WHERE id = %s", (pid,))
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "route_inactive")
    row = conn.execute(
        """SELECT dest_host, dest_digest IS NOT NULL FROM collect.egress_connection
            WHERE event = 'REFUSED' AND context_id = %s""", (run,)).fetchone()
    assert row == (None, True)


def test_the_reader_labels_a_run_row_without_a_source_by_its_run(conn):
    """A row written before the proxy carried its decision on refusals, or by
    any writer that named only the run, still follows the run's source."""
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    sid = es.source(conn, PREFIX, classification="GREEN")
    run = es.run(conn, sid)
    seq = egress_ledger.write(conn, Row(
        event="REFUSED", route_id=f"persona:{pid}", reason="port_not_allowed",
        connection_id=uuid4(), protocol="HTTP_CONNECT", route_kind="persona",
        egress_profile_id=pid, collection_run_id=run, context_kind="run", context_id=run,
        dest_host="older.rebind.test", dest_port=8080, classification="GREEN"))
    assert seq in _seqs(egress_ledger.listing(conn, clearance="GREEN", limit=500))
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s", (sid,))
    assert seq not in _seqs(egress_ledger.listing(conn, clearance="AMBER", limit=500))


def test_a_persona_row_with_nothing_to_label_it_by_shows_no_host(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    seq = egress_ledger.write(conn, Row(
        event="REFUSED", route_id=f"persona:{pid}", reason="port_not_allowed",
        connection_id=uuid4(), protocol="SOCKS5", route_kind="persona",
        egress_profile_id=pid, context_kind="run", context_id=uuid4(),
        dest_host="orphan.rebind.test", dest_port=8080, classification="GREEN"))
    rows = {r["seq"]: r for r in egress_ledger.listing(conn, clearance="RED",
                                                        limit=500)["rows"]}
    assert rows[seq]["dest_host"] is None and rows[seq]["destination_withheld"] is True
