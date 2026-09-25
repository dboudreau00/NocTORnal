"""The egress proxy's decisions against the database (S2, 2026-09-24;
docs/20 section 8.5).

A real proxy on an ephemeral loopback port, the collection framework's
schema (or the stand-in egress_support creates where it is missing), and
loopback origins admitted by patching the classifier the way
test_collection_ssrf_rebinding.py patches collection._is_blocked:
127.0.0.1 stands in for a public forum. Names resolve through a fake
resolver that counts the lookups.

Runs are inserted as run_once writes them (a feed run's
egress_profile_id is NULL).

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time
from uuid import uuid4

import pytest

import egress_support as es
from noctornal_api import egress_authz, egress_ledger, egress_policy

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egp-"
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
    """127.0.0.1 is a public forum for this test; 127.0.0.1:9 stays refused
    by the probe only when the test restores the classifier."""
    def fake(address):
        address = getattr(address, "ipv4_mapped", None) or address
        if address.version == 4 and str(address).startswith("127."):
            return False
        return _REAL_IS_BLOCKED(address)
    monkeypatch.setattr(egress_policy, "is_blocked", fake)


@pytest.fixture
def resolver(monkeypatch):
    fake = es.FakeResolver()
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


@pytest.fixture
def proxy():
    runner = es.ProxyRunner()
    yield runner
    runner.stop()


class Origin:
    """A loopback echo server that reads the ledger when it accepts, so a
    test can prove the OPEN row was committed before the dial arrived."""

    def __init__(self, check_ledger=None):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.accepted = 0
        self.saw_open: list[bool] = []
        self.check_ledger = check_ledger
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            self.accepted += 1
            if self.check_ledger is not None:
                self.saw_open.append(self.check_ledger())
            threading.Thread(target=self._echo, args=(sock,), daemon=True).start()

    @staticmethod
    def _echo(sock):
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                sock.sendall(data)
        except OSError:
            pass
        finally:
            sock.close()

    def close(self):
        self.listener.close()


@pytest.fixture
def origin():
    o = Origin()
    yield o
    o.close()


def _persona_user(pid, context):
    return f"persona.{pid}~{context}"


def _connect(proxy, username, target):
    route_part = username.split("~", 1)[0]
    return es.raw_connect(proxy.port, username, es.token_for(route_part), target)


def _status(head: bytes):
    parts = head.split(b"\r\n", 1)[0].split(b" ", 2)
    return int(parts[1]), parts[2].decode()


def _rows(conn, context_id):
    return conn.execute(
        """SELECT event, reason, dest_host, dest_digest IS NOT NULL, classification::text,
                  source_id, egress_profile_id, collection_run_id, bytes_up, bytes_down
             FROM collect.egress_connection WHERE context_id = %s ORDER BY seq""",
        (context_id,)).fetchall()


def _expect(proxy, username, target, code):
    head, sock = _connect(proxy, username, target)
    sock.close()
    got = _status(head)
    assert got[1] == code, (got, code)
    return got


def _world(conn, people, origin_port, *, kind="RESIDENTIAL", ceiling="AMBER",
           classification="AMBER", host="forum.rebind.test", source_kind="XENFORO",
           cidrs=(), exit_kind="SOCKS5", upstream=None, persona_status="HEALTHY",
           upstream_host="127.0.0.1"):
    """A persona on a sealed exit, its forum source, a live authority."""
    pid = es.profile(conn, PREFIX, kind=kind, ceiling=ceiling, ports=(origin_port, 443),
                     any_public_host=False, suffixes=(host,) if host else (),
                     cidrs=cidrs, exit_kind=None)
    if exit_kind == "DIRECT":
        conn.execute("UPDATE collect.egress_profile SET exit_kind = 'DIRECT' WHERE id = %s",
                     (pid,))
    else:
        blob, kid, fp = es.seal_for(pid, exit_kind, upstream_host, upstream or 9)
        conn.execute("""UPDATE collect.egress_profile SET exit_kind = %s, exit_sealed = %s,
                          exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                     (exit_kind, blob, kid, fp, pid))
    persona = es.persona(conn, PREFIX, profile=pid, status=persona_status)
    sid = es.source(conn, PREFIX, kind=source_kind, parser="xenforo",
                    base_url=f"http://{host}:{origin_port}/" if host else None,
                    classification=classification, persona=persona)
    aid = es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                       sources=(sid,), classification="RED")
    return pid, persona, sid, aid


# ---------------------------------------------------------------------------
# The passive route
# ---------------------------------------------------------------------------

def test_a_passive_feed_run_tunnels_and_its_open_row_precedes_the_dial(
        conn, people, loopback_public, resolver, proxy):
    run_id_holder = {}

    def committed():
        from noctornal_api.db import connect
        with connect() as c:
            return c.execute("SELECT count(*) FROM collect.egress_connection "
                             "WHERE context_id = %s AND event = 'OPEN'",
                             (run_id_holder["id"],)).fetchone()[0] == 1

    origin = Origin(check_ledger=committed)
    try:
        passive = es.profile(conn, PREFIX, ports=(origin.port, 80, 443), passive=True)
        resolver.names["feed.rebind.test"] = ["127.0.0.1"]
        sid = es.source(conn, PREFIX, base_url=f"http://feed.rebind.test:{origin.port}/")
        run = es.run(conn, sid)
        run_id_holder["id"] = run
        head, sock = _connect(proxy, f"persona.passive~run.{run}",
                              f"feed.rebind.test:{origin.port}")
        assert _status(head) == (200, "Connection established")
        sock.sendall(b"ping")
        assert sock.recv(4) == b"ping"
        sock.close()
        assert origin.saw_open == [True]
        time.sleep(0.5)
        rows = _rows(conn, run)
        assert [r[0] for r in rows] == ["OPEN", "CLOSE"]
        assert rows[0][6] == passive and rows[0][2] == "feed.rebind.test"
    finally:
        origin.close()


def test_a_run_naming_another_profile_on_the_passive_route_is_context_refused(
        conn, people, loopback_public, resolver, proxy, origin):
    es.profile(conn, PREFIX, ports=(origin.port,), passive=True)
    other = es.profile(conn, PREFIX, ports=(origin.port,))
    resolver.names["feed.rebind.test"] = ["127.0.0.1"]
    sid = es.source(conn, PREFIX, base_url=f"http://feed.rebind.test:{origin.port}/")
    run = es.run(conn, sid, profile=other)
    _expect(proxy, f"persona.passive~run.{run}", f"feed.rebind.test:{origin.port}",
            "context_refused")
    assert origin.accepted == 0


def test_a_forum_source_on_the_passive_route_is_passive_route_misused(
        conn, people, loopback_public, resolver, proxy, origin):
    es.profile(conn, PREFIX, ports=(origin.port,), passive=True)
    sid = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url=f"http://feed.rebind.test:{origin.port}/")
    run = es.run(conn, sid)
    _expect(proxy, f"persona.passive~run.{run}", f"feed.rebind.test:{origin.port}",
            "passive_route_misused")


def test_an_unwritable_ledger_refuses_and_dials_nothing(
        conn, people, loopback_public, resolver, proxy, origin, monkeypatch):
    es.profile(conn, PREFIX, ports=(origin.port,), passive=True)
    resolver.names["feed.rebind.test"] = ["127.0.0.1"]
    sid = es.source(conn, PREFIX, base_url=f"http://feed.rebind.test:{origin.port}/")
    run = es.run(conn, sid)
    real = egress_ledger.write

    def failing(c, row):
        if row.event == "OPEN":
            raise RuntimeError("ledger down")
        return real(c, row)

    monkeypatch.setattr(egress_ledger, "write", failing)
    _expect(proxy, f"persona.passive~run.{run}", f"feed.rebind.test:{origin.port}",
            "ledger_unavailable")
    assert origin.accepted == 0


# ---------------------------------------------------------------------------
# Persona runs
# ---------------------------------------------------------------------------

@pytest.fixture
def upstream():
    """A fake chained exit: HTTP CONNECT and SOCKS5 on one port, recording
    what it was asked to reach, then echoing."""
    up = FakeUpstream()
    yield up
    up.close()


class FakeUpstream:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.seen: list[tuple] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(sock,), daemon=True).start()

    def _one(self, sock):
        try:
            sock.settimeout(10)
            first = sock.recv(1, socket.MSG_PEEK)
            if first == b"\x05":
                sock.recv(2 + sock.recv(2, socket.MSG_PEEK)[1])
                sock.sendall(b"\x05\x00")
                ver, cmd, _r, atyp = sock.recv(4)
                if atyp == 3:
                    length = sock.recv(1)[0]
                    addr = sock.recv(length).decode()
                elif atyp == 1:
                    addr = str(ipaddress.IPv4Address(sock.recv(4)))
                else:
                    addr = str(ipaddress.IPv6Address(sock.recv(16)))
                port = int.from_bytes(sock.recv(2), "big")
                self.seen.append(("SOCKS5", atyp, addr, port))
                sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            else:
                head = b""
                while b"\r\n\r\n" not in head:
                    head += sock.recv(1)
                line = head.split(b"\r\n", 1)[0].decode()
                self.seen.append(("HTTP", line))
                sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                sock.sendall(data)
        except OSError:
            pass
        finally:
            sock.close()

    def close(self):
        self.listener.close()


def test_a_persona_run_with_a_live_authority_tunnels_through_its_exit_by_name(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443")
    assert _status(head) == (200, "Connection established")
    sock.sendall(b"hi")
    assert sock.recv(2) == b"hi"
    sock.close()
    # The exit got the NAME, and nothing here looked it up.
    assert upstream.seen[-1] == ("SOCKS5", 3, "forum.rebind.test", 443)
    assert "forum.rebind.test" not in resolver.asked
    time.sleep(0.3)
    rows = _rows(conn, run)
    assert rows[0][0] == "OPEN" and rows[0][4] == "AMBER" and rows[0][5] == sid


def test_an_http_exit_receives_connect_name_and_resolve_at_proxy_sends_the_literal(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, exit_kind="HTTP",
                                    upstream=upstream.port)
    conn.execute("UPDATE collect.egress_profile SET cleartext_upstream_ack = true "
                 "WHERE id = %s", (pid,))
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443")
    sock.close()
    assert _status(head)[0] == 200
    assert upstream.seen[-1] == ("HTTP", "CONNECT forum.rebind.test:443 HTTP/1.1")
    assert "forum.rebind.test" not in resolver.asked
    conn.execute("UPDATE collect.egress_profile SET resolve_at_proxy = true WHERE id = %s",
                 (pid,))
    resolver.names["forum.rebind.test"] = ["127.0.0.1"]
    run2 = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run2}"), "forum.rebind.test:443")
    sock.close()
    assert upstream.seen[-1] == ("HTTP", "CONNECT 127.0.0.1:443 HTTP/1.1")


def test_a_run_without_an_authority_is_authority_missing(
        conn, people, loopback_public, resolver, proxy):
    pid, persona, sid, _aid = _world(conn, people, 443)
    run = es.run(conn, sid, profile=pid, persona=persona, authority=None)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "authority_missing")


def test_an_authority_recorded_before_a_widening_no_longer_passes(
        conn, people, loopback_public, resolver, proxy):
    pid, persona, sid, _aid = _world(conn, people, 443)
    # Recorded before the widening below, confirmed after it: refused.
    stale = es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                         sources=(sid,), classification="RED",
                         recorded="now() - interval '10 minutes'",
                         confirmed="now() + interval '1 second'",
                         added="now() - interval '10 minutes'",
                         target_confirmed="now() + interval '1 second'")
    conn.execute("UPDATE collect.egress_profile SET allowed_ports = allowed_ports || 8443 "
                 "WHERE id = %s", (pid,))
    run = es.run(conn, sid, profile=pid, persona=persona, authority=stale)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "authority_predates_route_change")


def test_an_authority_confirmed_before_the_persona_was_rebound_no_longer_passes(
        conn, people, loopback_public, resolver, proxy):
    pid, persona, sid, aid = _world(conn, people, 443)
    other = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    conn.execute("UPDATE collect.collection_account SET egress_profile_id = %s WHERE id = %s",
                 (other, persona))
    conn.execute("UPDATE collect.collection_account SET egress_profile_id = %s WHERE id = %s",
                 (pid, persona))
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "authority_predates_route_change")


def test_a_personaless_source_rebound_voids_its_older_authority(
        conn, people, loopback_public, resolver, proxy):
    pid = es.profile(conn, PREFIX, ports=(443,), any_public_host=False,
                     suffixes=("board.rebind.test",))
    sid = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url="http://board.rebind.test/", profile=pid)
    aid = es.authority(conn, recorder=people[0], confirmer=people[1], sources=(sid,))
    resolver.names["board.rebind.test"] = ["127.0.0.1"]
    run = es.run(conn, sid, profile=pid, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "board.rebind.test:443")
    sock.close()
    # A persona-less source may leave from a DATACENTRE DIRECT profile.
    assert _status(head)[1] in ("Connection established", "connect_failed")
    other = es.profile(conn, PREFIX, ports=(443,))
    conn.execute("UPDATE collect.source SET egress_profile_id = %s WHERE id = %s",
                 (other, sid))
    conn.execute("UPDATE collect.source SET egress_profile_id = %s WHERE id = %s", (pid, sid))
    run2 = es.run(conn, sid, profile=pid, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run2}"), "board.rebind.test:443",
            "authority_predates_route_change")


def test_a_finished_run_and_a_stale_run_are_refused(conn, people, loopback_public,
                                                   resolver, proxy):
    pid, persona, sid, aid = _world(conn, people, 443)
    done = es.run(conn, sid, status="OK", profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{done}"), "forum.rebind.test:443",
            "run_not_running")
    stale = es.run(conn, sid, profile=pid, persona=persona, authority=aid, age_s=901)
    _expect(proxy, _persona_user(pid, f"run.{stale}"), "forum.rebind.test:443",
            "run_expired")


def test_a_run_reaches_only_its_own_source(conn, people, loopback_public, resolver, proxy):
    pid, persona, sid, _stale = _world(conn, people, 443)
    conn.execute("UPDATE collect.egress_profile SET allowed_host_suffixes = "
                 "allowed_host_suffixes || '{other.rebind.test}'::text[] WHERE id = %s", (pid,))
    # The widening above voided the first authority; this one follows it.
    aid = es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                       sources=(sid,), classification="RED")
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "other.rebind.test:443",
            "destination_not_in_source")
    # The refused destination was not tied to the run's source, so the row
    # carries a digest, never the name.
    refused = [r for r in _rows(conn, run) if r[0] == "REFUSED"][-1]
    assert refused[2] is None and refused[3] is True


def test_a_telegram_run_reaches_only_addresses_in_its_networks_on_listed_ports(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, source_kind="TELEGRAM", host=None,
                                    cidrs=("127.0.0.0/24",), upstream=upstream.port)
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "127.0.0.5:443")
    sock.close()
    assert _status(head)[0] == 200
    _expect(proxy, _persona_user(pid, f"run.{run}"), "127.0.1.5:443",
            "destination_not_in_source")
    # A listed network on an unlisted port: no port hole.
    _expect(proxy, _persona_user(pid, f"run.{run}"), "127.0.0.5:22", "port_not_allowed")


def test_a_persona_on_a_direct_exit_is_persona_needs_exit(conn, people, loopback_public,
                                                         resolver, proxy):
    pid, persona, sid, aid = _world(conn, people, 443, kind="DATACENTRE",
                                    exit_kind="DIRECT")
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "persona_needs_exit")


def test_a_second_persona_on_the_profile_is_profile_shared(conn, people, loopback_public,
                                                          resolver, proxy):
    pid, persona, sid, aid = _world(conn, people, 443)
    es.persona(conn, PREFIX, profile=pid)
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "profile_shared")


@pytest.mark.parametrize("status, hold, lock, run_code, act_code", [
    ("BURNED", None, None, "persona_unavailable", "persona_unavailable"),
    ("LOCKED", None, None, "persona_unavailable", "persona_unavailable"),
    ("RETIRED", None, None, "persona_unavailable", "persona_unavailable"),
    ("HEALTHY", "now() + interval '1 hour'", None, "persona_unavailable",
     "persona_unavailable"),
    # A machine lock refuses a run and lets an act (the enrolment that
    # clears it) through (2026-09-24).
    ("HEALTHY", None, "CREDENTIAL_DUPLICATED", "persona_unavailable", None),
])
def test_an_unusable_persona_is_refused(conn, people, loopback_public, resolver, proxy,
                                        upstream, status, hold, lock, run_code, act_code):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    conn.execute(
        f"""UPDATE collect.collection_account SET status = %s,
              machine_hold_until = {hold or 'NULL'},
              machine_hold_reason = {"'RATE_LIMITED'" if hold else 'NULL'},
              machine_lock_code = %s, machine_lock_at = {"now()" if lock else 'NULL'}
            WHERE id = %s""", (status, lock, persona))
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443", run_code)
    head, sock = _connect(proxy, _persona_user(pid, f"act.{persona}"),
                          "forum.rebind.test:443")
    sock.close()
    if act_code is None:
        assert _status(head)[0] == 200
    else:
        assert _status(head)[1] == act_code


def test_cooldown_with_no_end_is_usable(conn, people, loopback_public, resolver, proxy,
                                        upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port,
                                    persona_status="COOLDOWN")
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443")
    sock.close()
    assert _status(head)[0] == 200


def test_a_red_source_on_an_amber_profile_is_above_route_ceiling(
        conn, people, loopback_public, resolver, proxy):
    pid, persona, sid, aid = _world(conn, people, 443, classification="RED")
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "above_route_ceiling")


# ---------------------------------------------------------------------------
# Acts and stops
# ---------------------------------------------------------------------------

def test_stop_needs_no_authority_and_eight_concurrent_stops_yield_four(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    # Room on the route for all eight, so the stop limit is what answers.
    conn.execute("UPDATE collect.egress_profile SET max_concurrent = 16 WHERE id = %s",
                 (pid,))
    conn.execute("ALTER TABLE collect.collection_authority DISABLE TRIGGER USER")
    conn.execute("UPDATE collect.collection_authority SET revoked_at = now(), "
                 "revoked_by = %s, revoke_reason = 'revoked for the stop test' "
                 "WHERE id = %s", (people[0], aid))
    conn.execute("ALTER TABLE collect.collection_authority ENABLE TRIGGER USER")
    results = []

    def one():
        head, sock = _connect(proxy, _persona_user(pid, f"stop.{persona}"),
                              "forum.rebind.test:443")
        results.append(_status(head)[1])
        time.sleep(0.5)
        sock.close()

    threads = [threading.Thread(target=one) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(results) == ["Connection established"] * 4 + ["stop_limit"] * 4
    opens = conn.execute("SELECT count(*) FROM collect.egress_connection WHERE "
                         "collection_account_id = %s AND context_kind = 'stop' "
                         "AND event = 'OPEN'", (persona,)).fetchone()[0]
    assert opens == 4


def test_act_needs_a_live_authority_and_ends_at_its_session_limit(
        conn, people, loopback_public, resolver, proxy, upstream, monkeypatch):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    monkeypatch.setattr(egress_authz, "ACT_MAX_SESSION_S", 1)
    head, sock = _connect(proxy, _persona_user(pid, f"act.{persona}"), "forum.rebind.test:443")
    assert _status(head)[0] == 200
    sock.settimeout(10)
    assert sock.recv(10) == b""   # closed by the proxy at the act limit
    sock.close()
    time.sleep(0.3)
    close = conn.execute(
        "SELECT reason FROM collect.egress_connection WHERE collection_account_id = %s "
        "AND context_kind = 'act' AND event = 'CLOSE' ORDER BY seq DESC LIMIT 1",
        (persona,)).fetchone()
    assert close[0] == "session_limit"
    bare = es.persona(conn, PREFIX, profile=es.profile(conn, PREFIX, kind="VPN",
                                                       exit_kind=None))
    _expect(proxy, _persona_user(pid, f"act.{bare}"), "forum.rebind.test:443",
            "persona_not_bound")


def test_revoking_the_authority_or_finishing_the_run_closes_an_open_tunnel(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443")
    assert _status(head)[0] == 200
    conn.execute("UPDATE collect.collection_run SET status = 'OK', finished_at = now() "
                 "WHERE id = %s", (run,))
    proxy.call(proxy.proxy.recheck_now())
    sock.settimeout(10)
    assert sock.recv(10) == b""
    sock.close()
    time.sleep(0.3)
    assert _rows(conn, run)[-1][:2] == ("CLOSE", "run_finished")

    run2 = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run2}"), "forum.rebind.test:443")
    assert _status(head)[0] == 200
    conn.execute("ALTER TABLE collect.collection_authority DISABLE TRIGGER USER")
    conn.execute("UPDATE collect.collection_authority SET revoked_at = now(), "
                 "revoked_by = %s, revoke_reason = 'revoked mid tunnel' WHERE id = %s",
                 (people[0], aid))
    conn.execute("ALTER TABLE collect.collection_authority ENABLE TRIGGER USER")
    proxy.call(proxy.proxy.recheck_now())
    assert sock.recv(10) == b""
    sock.close()
    time.sleep(0.3)
    assert _rows(conn, run2)[-1][:2] == ("CLOSE", "authority_revoked")


# ---------------------------------------------------------------------------
# Destinations: egress_policy and nothing else
# ---------------------------------------------------------------------------

def test_a_name_answering_public_then_private_is_refused_after_one_lookup(
        conn, people, proxy, monkeypatch):
    fake = es.FakeResolver({"mixed.rebind.test": ["93.184.216.34", "10.0.0.5"]})
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    es.profile(conn, PREFIX, ports=(443,), passive=True)
    sid = es.source(conn, PREFIX, base_url="http://mixed.rebind.test/")
    run = es.run(conn, sid)
    _expect(proxy, f"persona.passive~run.{run}", "mixed.rebind.test:443", "blocked_address")
    assert fake.asked.count("mixed.rebind.test") == 1


def test_onion_is_refused_on_a_vpn_profile_and_forwarded_unresolved_on_tor(
        conn, people, loopback_public, resolver, proxy, upstream):
    onion = "abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefgh.onion"
    vpn, persona, sid, aid = _world(conn, people, 443, host=onion, kind="VPN",
                                    upstream=upstream.port)
    run = es.run(conn, sid, profile=vpn, persona=persona, authority=aid)
    _expect(proxy, _persona_user(vpn, f"run.{run}"), f"{onion}:443", "onion_not_allowed")
    tor, tpersona, tsid, _stale = _world(conn, people, 443, host=onion, kind="TOR",
                                         upstream=upstream.port)
    conn.execute("UPDATE collect.egress_profile SET allow_onion = true WHERE id = %s", (tor,))
    # Turning onion on widened the profile: a new authority follows it.
    taid = es.authority(conn, recorder=people[0], confirmer=people[1], persona=tpersona,
                        sources=(tsid,), classification="RED")
    run = es.run(conn, tsid, profile=tor, persona=tpersona, authority=taid)
    head, sock = _connect(proxy, _persona_user(tor, f"run.{run}"), f"{onion}:443")
    sock.close()
    assert _status(head)[0] == 200
    assert upstream.seen[-1] == ("SOCKS5", 3, onion, 443)
    assert onion not in resolver.asked


def test_an_upstream_on_the_internal_networks_is_upstream_blocked(conn, people, resolver,
                                                                 upstream, monkeypatch,
                                                                 loopback_public):
    runner = es.ProxyRunner(es.proxy_config(
        internal=(ipaddress.ip_network("127.0.0.0/8"),),
        upstream_allow=(ipaddress.ip_network("127.0.0.0/24"),)))
    try:
        pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
        run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
        _expect(runner, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
                "upstream_blocked")
    finally:
        runner.stop()


def test_a_sidecar_exit_is_handed_a_checked_address_unless_it_is_tor(
        conn, people, resolver, upstream, monkeypatch):
    # A sidecar resolves and connects inside this host, so the proxy
    # resolves and admits the name itself.
    runner = es.ProxyRunner(es.proxy_config(
        upstream_allow=(ipaddress.ip_network("127.0.0.0/24"),)))
    try:
        resolver.names["forum.rebind.test"] = ["93.184.216.34"]
        pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
        run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
        head, sock = _connect(runner, _persona_user(pid, f"run.{run}"),
                              "forum.rebind.test:443")
        sock.close()
        assert _status(head)[0] == 200
        assert upstream.seen[-1] == ("SOCKS5", 1, "93.184.216.34", 443)
        resolver.names["forum.rebind.test"] = ["10.0.0.9"]
        run2 = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
        _expect(runner, _persona_user(pid, f"run.{run2}"), "forum.rebind.test:443",
                "blocked_address")
    finally:
        runner.stop()


def _integration(conn, name, entries):
    rid = conn.execute(
        "INSERT INTO collect.egress_integration_route (name, description) "
        "VALUES (%s, %s) RETURNING id", (name, f"{PREFIX}route")).fetchone()[0]
    for entry in entries:
        conn.execute("INSERT INTO collect.egress_destination (route_id, entry, note) "
                     "VALUES (%s, %s, 'test entry')", (rid, entry))
    return rid


def _retire_routes(conn, name):
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = (SELECT id FROM iam.app_user LIMIT 1),
                      retire_reason = 'test finished' WHERE name = %s AND retired_at IS NULL""",
                 (name,))


def test_an_integration_reaches_a_named_host_only_through_its_exact_entry(
        conn, people, resolver, proxy, origin):
    _retire_routes(conn, "webhook")
    resolver.names["hooks.corp.test"] = ["127.0.0.1"]
    _integration(conn, "webhook", [f"hooks.corp.test@127.0.0.0/8:{origin.port}"])
    try:
        head, sock = _connect(proxy, "integration.webhook~delivery." + str(uuid4()),
                              f"hooks.corp.test:{origin.port}")
        sock.close()
        assert _status(head)[0] == 200
        # The same host by address is not the named entry.
        _expect(proxy, "integration.webhook", f"127.0.0.1:{origin.port}",
                "destination_not_allowed")
        _expect(proxy, "integration.webhook", "hooks.corp.test:22", "port_not_allowed")
    finally:
        _retire_routes(conn, "webhook")


def test_a_metadata_answer_inside_a_declared_network_is_refused(conn, people, resolver,
                                                                proxy):
    _retire_routes(conn, "webhook")
    resolver.names["relay.corp.test"] = ["100.100.100.200"]
    # Written past the validator on purpose: the proxy refuses it anyway.
    _integration(conn, "webhook", ["relay.corp.test@100.100.0.0/16:443"])
    try:
        _expect(proxy, "integration.webhook", "relay.corp.test:443", "metadata_address")
    finally:
        _retire_routes(conn, "webhook")


def test_retiring_an_integration_route_closes_its_open_tunnel(conn, people, resolver,
                                                              proxy, origin):
    _retire_routes(conn, "webhook")
    _integration(conn, "webhook", [f"localhost:{origin.port}"])
    try:
        head, sock = _connect(proxy, "integration.webhook", f"localhost:{origin.port}")
        assert _status(head)[0] == 200
        _retire_routes(conn, "webhook")
        proxy.call(proxy.proxy.recheck_now())
        sock.settimeout(10)
        assert sock.recv(10) == b""
        sock.close()
    finally:
        _retire_routes(conn, "webhook")


def test_socks5_and_connect_write_the_same_rows(conn, people, resolver, proxy, origin):
    from python_socks import ProxyType
    from python_socks.sync import Proxy
    _retire_routes(conn, "webhook")
    _integration(conn, "webhook", [f"localhost:{origin.port}"])
    try:
        context = uuid4()
        username = f"integration.webhook~delivery.{context}"
        head, sock = _connect(proxy, username, f"localhost:{origin.port}")
        sock.close()
        socks = Proxy.create(ProxyType.SOCKS5, "127.0.0.1", proxy.port, username=username,
                             password=es.token_for("integration.webhook"), rdns=True)
        s2 = socks.connect("localhost", origin.port, timeout=10)
        s2.close()
        time.sleep(0.5)
        rows = conn.execute(
            """SELECT protocol, event, route_id, dest_host, dest_port, exit_kind, reason,
                      classification::text
                 FROM collect.egress_connection WHERE context_id = %s AND event = 'OPEN'
                ORDER BY seq""", (context,)).fetchall()
        assert [r[0] for r in rows] == ["HTTP_CONNECT", "SOCKS5"]
        assert rows[0][1:] == rows[1][1:]
    finally:
        _retire_routes(conn, "webhook")


def test_the_probe_is_never_logged_and_refuses_loopback_with_its_headers(conn, proxy):
    before = conn.execute("SELECT count(*) FROM collect.egress_connection").fetchone()[0]
    head, sock = es.raw_connect(proxy.port, "probe.readiness",
                                es.token_for("probe.readiness"), "127.0.0.1:9")
    sock.close()
    assert _status(head) == (403, "blocked_address")
    assert b"X-Egress-Keys: " in head and b"X-Egress-Unopenable: " in head
    head, sock = es.raw_connect(proxy.port, "probe.readiness",
                                es.token_for("probe.readiness"), "93.184.216.34:443")
    sock.close()
    assert _status(head) == (403, "probe_only")
    after = conn.execute("SELECT count(*) FROM collect.egress_connection").fetchone()[0]
    assert after == before


# ---------------------------------------------------------------------------
# The process's commands
# ---------------------------------------------------------------------------

def test_the_healthcheck_passes_only_against_a_proxy_that_refuses_loopback(proxy):
    from noctornal_api import egress_proxy
    env = dict(es.keys(), NOCTORNAL_EGRESS_LISTEN=f"127.0.0.1:{proxy.port}")
    assert egress_proxy.check(env) == 0
    env["NOCTORNAL_EGRESS_CLIENT_KEY"] = es.b64(b"q" * 32)
    assert egress_proxy.check(env) == 1


def test_rewrap_reseals_under_the_active_key_and_records_it(conn, monkeypatch):
    from noctornal_api import egress_proxy
    from noctornal_api.security import egress_seal
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    endpoint = egress_seal.ExitEndpoint("gw.example", 1080, "user-a", "pw-a")
    old = egress_seal.load_public(es.old_seal_public())
    blob, kid = egress_seal.seal(old, profile_id=pid, exit_kind="SOCKS5", endpoint=endpoint)
    fp = egress_seal.fingerprint(es.FINGERPRINT_KEY, "SOCKS5", endpoint)
    conn.execute("""UPDATE collect.egress_profile SET exit_kind = 'SOCKS5', exit_sealed = %s,
                      exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                 (blob, kid, fp, pid))
    reach = conn.execute("SELECT reach_changed_at FROM collect.egress_profile WHERE id = %s",
                         (pid,)).fetchone()[0]
    env = dict(es.keys(retired=True), DATABASE_URL=os.environ["DATABASE_URL"])
    opened, resealed = egress_proxy.rewrap(env, apply=False)
    assert resealed == 0 and opened >= 1
    before = conn.execute("SELECT coalesce(max(seq), 0) FROM collect.egress_connection").fetchone()[0]
    opened, resealed = egress_proxy.rewrap(env, apply=True)
    assert resealed >= 1
    row = conn.execute("SELECT exit_seal_key_id, reach_changed_at FROM collect.egress_profile "
                       "WHERE id = %s", (pid,)).fetchone()
    ring = egress_seal.ExitRing.from_env(env)
    assert row[0] == ring.active_id and row[1] == reach   # a rewrap is not a widening
    rewraps = conn.execute("SELECT item_count FROM collect.egress_connection WHERE seq > %s "
                           "AND event = 'REWRAP'", (before,)).fetchall()
    assert rewraps == [(resealed,)]


# ---------------------------------------------------------------------------
# An https exit: TLS to the upstream, its certificate checked against its name
# ---------------------------------------------------------------------------

def _certificate(tmp_path, name):
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


class TlsUpstream(FakeUpstream):
    """FakeUpstream behind TLS with a certificate for `name`."""

    def __init__(self, cert, key):
        import ssl
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        super().__init__()

    def _one(self, sock):
        # HTTP CONNECT only: a TLS socket takes no MSG_PEEK, so the protocol
        # is not sniffed here.
        try:
            wrapped = self.context.wrap_socket(sock, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = wrapped.recv(1)
                if not chunk:
                    return
                head += chunk
            self.seen.append(("HTTP", head.split(b"\r\n", 1)[0].decode()))
            wrapped.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            while True:
                data = wrapped.recv(65536)
                if not data:
                    break
                wrapped.sendall(data)
        except OSError:
            pass
        finally:
            sock.close()


def test_an_https_exit_is_reached_over_tls_verified_against_its_name(
        conn, people, loopback_public, resolver, tmp_path):
    import ssl
    cert, key = _certificate(tmp_path, "gw.tls.test")
    up = TlsUpstream(cert, key)
    trust = ssl.create_default_context(cafile=str(cert))
    runner = es.ProxyRunner(upstream_tls=trust)
    try:
        resolver.names["gw.tls.test"] = ["127.0.0.1"]
        resolver.names["gw-other.tls.test"] = ["127.0.0.1"]
        pid, persona, sid, aid = _world(conn, people, 443, exit_kind="HTTPS",
                                        upstream=up.port, upstream_host="gw.tls.test")
        run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
        head, sock = _connect(runner, _persona_user(pid, f"run.{run}"),
                              "forum.rebind.test:443")
        sock.close()
        assert _status(head)[0] == 200
        assert up.seen[-1] == ("HTTP", "CONNECT forum.rebind.test:443 HTTP/1.1")
        # The same upstream reached under a name its certificate does not
        # carry: the handshake fails and nothing is tunnelled.
        pid2, persona2, sid2, aid2 = _world(conn, people, 443, exit_kind="HTTPS",
                                            upstream=up.port,
                                            upstream_host="gw-other.tls.test")
        run2 = es.run(conn, sid2, profile=pid2, persona=persona2, authority=aid2)
        _expect(runner, _persona_user(pid2, f"run.{run2}"), "forum.rebind.test:443",
                "upstream_failed")
    finally:
        runner.stop()
        up.close()


def test_a_profile_and_binding_from_before_0085_read_as_never_widened(
        conn, people, loopback_public, resolver, proxy, upstream):
    """0085 backfills reach_changed_at and bound_at with '-infinity', which
    psycopg cannot load: they read as no floor, so the authorities of an
    upgraded deployment keep working."""
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    conn.execute("ALTER TABLE collect.egress_profile DISABLE TRIGGER egress_profile_reach")
    conn.execute("UPDATE collect.egress_profile SET reach_changed_at = '-infinity' "
                 "WHERE id = %s", (pid,))
    conn.execute("ALTER TABLE collect.egress_profile ENABLE TRIGGER egress_profile_reach")
    conn.execute("ALTER TABLE collect.egress_binding DISABLE TRIGGER USER")
    conn.execute("UPDATE collect.egress_binding SET bound_at = '-infinity' "
                 "WHERE collection_account_id = %s", (persona,))
    conn.execute("ALTER TABLE collect.egress_binding ENABLE TRIGGER USER")
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    head, sock = _connect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443")
    sock.close()
    assert _status(head)[0] == 200
    from noctornal_api.egress_admin import EgressAdminService
    body = EgressAdminService(conn).overview(clearance="RED")
    row = next(p for p in body["profiles"] if p["id"] == str(pid))
    assert row["reach_changed_at"] is None
