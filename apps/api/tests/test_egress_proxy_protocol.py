"""The egress proxy's wire handling, with the decision and the ledger stubbed
(S2, 2026-09-24; docs/20 sections 8.1 to 8.4).

Pure asyncio on loopback: no database. `authorise` is replaced by a
function answering one decision (an integration route to a loopback
origin), and ledger writes are captured, so these cases hold the listener's
parsing, its caps and its splice to the contract without the persona
machinery. The decisions themselves are test_egress_proxy_pg.py's.
"""
from __future__ import annotations

import asyncio
import base64
import socket
import threading
import time
from uuid import uuid4

import pytest

from egress_support import CLIENT_KEY, ProxyRunner, proxy_config, token_for
from noctornal_api import egress_authz, egress_ledger, egress_proxy
from noctornal_api.egress_policy import PUBLIC_POLICY, RoutePolicy

ROUTE = "integration.webhook"


class Origin:
    """A loopback TCP server: echoes, or with `speak` writes that many
    bytes then waits, or stays silent."""

    def __init__(self, mode="echo", speak=0):
        self.mode, self.speak = mode, speak
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.port = self.listener.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        try:
            if self.mode == "echo":
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
            elif self.mode == "flood":
                chunk = b"x" * 65536
                sent = 0
                conn.settimeout(10)
                while sent < self.speak:
                    conn.sendall(chunk)
                    sent += len(chunk)
                time.sleep(5)
            else:
                time.sleep(10)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.listener.close()


@pytest.fixture
def rows(monkeypatch):
    captured: list[egress_ledger.Row] = []

    def write(_conn, row):
        captured.append(row)
        return len(captured)

    monkeypatch.setattr(egress_ledger, "write", write)
    return captured


@pytest.fixture
def origin():
    o = Origin()
    yield o
    o.close()


def _decision(port, **kw) -> egress_authz.Decision:
    values = dict(route_kind="integration", route_id="integration:webhook",
                  host="127.0.0.1", port=port, literal=True,
                  policy=RoutePolicy("integration", any_public=False),
                  tied=True, exit_kind="DIRECT", resolve_locally=True,
                  idle_s=30, session_s=60, max_concurrent=8,
                  route_key="integration:webhook")
    values.update(kw)
    return egress_authz.Decision(**values)


@pytest.fixture
def decide(monkeypatch):
    """Answer every authorisation with the decision set on `.decision`."""
    holder = {"decision": None, "calls": 0}

    def authorise(_conn, claim, host, port, **_kw):
        holder["calls"] += 1
        if holder["decision"] is None:
            raise egress_authz.Refused("route_unknown")
        return holder["decision"]

    monkeypatch.setattr(egress_authz, "authorise", authorise)
    return holder


def _runner(**config):
    runner = ProxyRunner(proxy_config(dsn="postgresql://nobody@127.0.0.1:1/none", **config))

    async def db(fn, *args, **kwargs):
        return fn(None, *args, **kwargs)

    runner.proxy.db = db
    return runner


@pytest.fixture
def proxy():
    runner = _runner()
    yield runner
    runner.stop()


def _send(port, data: bytes, *, source=None, read=True, timeout=10) -> bytes:
    sock = socket.socket()
    if source:
        sock.bind((source, 0))
    sock.settimeout(timeout)
    sock.connect(("127.0.0.1", port))
    sock.sendall(data)
    if not read:
        return sock
    out = b""
    try:
        while b"\r\n\r\n" not in out:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
    finally:
        sock.close()
    return out


def _connect(target: str, username=ROUTE, token=None, extra="") -> bytes:
    token = token or token_for(username.split("~", 1)[0])
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    return (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{extra}"
            f"Proxy-Authorization: Basic {creds}\r\n\r\n").encode()


def _status(head: bytes) -> tuple[int, str]:
    parts = head.split(b"\r\n", 1)[0].split(b" ", 2)
    return int(parts[1]), parts[2].decode()


# ---------------------------------------------------------------------------
# HTTP CONNECT head
# ---------------------------------------------------------------------------

def test_a_head_of_33_lines_is_bad_request(proxy, rows):
    extra = "".join(f"X-Pad-{i}: y\r\n" for i in range(31))
    head = _send(proxy.port, _connect("hooks.example:443", extra=extra))
    assert _status(head) == (400, "bad_request")


def test_a_head_over_8_kib_is_bad_request(proxy, rows):
    extra = "X-Pad: " + "y" * 8200 + "\r\n"
    head = _send(proxy.port, _connect("hooks.example:443", extra=extra))
    assert _status(head) == (400, "bad_request")


def test_a_refusal_is_exactly_the_status_line_and_two_headers(proxy, rows):
    head = _send(proxy.port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert head == (b"HTTP/1.1 405 method_not_allowed\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n")


def test_missing_credentials_are_407_route_auth_required_with_the_challenge(proxy, rows):
    head = _send(proxy.port, b"CONNECT hooks.example:443 HTTP/1.1\r\n"
                             b"Host: hooks.example:443\r\n\r\n")
    assert _status(head) == (407, "route_auth_required")
    assert b'Proxy-Authenticate: Basic realm="noctornal-egress"\r\n' in head


@pytest.mark.parametrize("username, token", [
    (ROUTE, "x" * 43),                          # wrong token
    ("integration:webhook", "x" * 43),          # the logical id, colon and all
    ("integration.webhook~run." + str(uuid4()), None),  # a persona context on an integration
    ("persona.not-a-uuid~run." + str(uuid4()), None),
])
def test_wrong_or_malformed_credentials_are_407_route_auth_failed(proxy, rows,
                                                                    username, token):
    token = token or token_for(username.split("~", 1)[0].replace(":", "."))
    head = _send(proxy.port, _connect("hooks.example:443", username=username, token=token))
    assert _status(head) == (407, "route_auth_failed")
    assert b"Proxy-Authenticate" in head


@pytest.mark.parametrize("authority", [
    "hooks.example:+443", "hooks.example: 443", "hooks.example:4_43",
    "hooks.example:" + chr(0x0664) + "43", "hooks.example:0", "hooks.example:65536",
    "hooks.example", "::1:443", "[hooks.example]:443", "hooks.example:443:1",
])
def test_the_authority_grammar_refuses_what_int_would_take(proxy, rows, authority):
    request = (f"CONNECT {authority} HTTP/1.1\r\nHost: x\r\n\r\n").encode("utf-8")
    head = _send(proxy.port, request)
    assert _status(head)[0] == 400, (authority, head)


def test_a_second_proxy_authorization_is_bad_request_and_unknown_headers_are_ignored(
        proxy, rows, decide, origin):
    doubled = _connect("hooks.example:443",
                       extra="Proxy-Authorization: Basic eDp5\r\n")
    assert _status(_send(proxy.port, doubled)) == (400, "bad_request")
    decide["decision"] = _decision(origin.port)
    head = _send(proxy.port, _connect(f"127.0.0.1:{origin.port}",
                                      extra="User-Agent: python-socks/3.1.1\r\n"))
    assert _status(head) == (200, "Connection established")


def test_a_head_not_complete_within_the_handshake_timeout_is_closed_unanswered(rows):
    runner = _runner(handshake_s=1.0)
    try:
        sock = _send(runner.port, b"CONNECT hooks.example:443 HTTP/1.1\r\n", read=False)
        sock.settimeout(5)
        began = time.monotonic()
        assert sock.recv(100) == b""
        assert time.monotonic() - began < 4
        sock.close()
    finally:
        runner.stop()


# ---------------------------------------------------------------------------
# SOCKS5
# ---------------------------------------------------------------------------

def _socks(port, username=ROUTE, token=None, *, methods=b"\x02", cmd=1, atyp=3,
           addr=b"\x0dhooks.example", dport=443):
    token = token or token_for(username.split("~", 1)[0])
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    choice = sock.recv(2)
    if choice != b"\x05\x02":
        return sock, choice, None, None
    u, t = username.encode(), token.encode()
    sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(t)]) + t)
    status = sock.recv(2)
    if status != b"\x01\x00":
        return sock, choice, status, None
    sock.sendall(bytes([5, cmd, 0, atyp]) + addr + dport.to_bytes(2, "big"))
    return sock, choice, status, sock.recv(10)


def test_socks5_offering_only_no_auth_gets_0xff(proxy, rows):
    sock, choice, _s, _r = _socks(proxy.port, methods=b"\x00")
    assert choice == b"\x05\xff"
    sock.close()


def test_socks5_with_bad_credentials_gets_status_1_and_is_closed(proxy, rows):
    sock, _c, status, _r = _socks(proxy.port, token="y" * 43)
    assert status == b"\x01\x01"
    assert sock.recv(10) == b""
    sock.close()


@pytest.mark.parametrize("cmd", [2, 3])
def test_bind_and_udp_associate_get_rep_7(proxy, rows, cmd):
    sock, _c, _s, reply = _socks(proxy.port, cmd=cmd)
    assert reply[:2] == b"\x05\x07"
    sock.close()


def test_an_unknown_address_type_gets_rep_8(proxy, rows):
    sock, _c, _s, reply = _socks(proxy.port, atyp=5, addr=b"")
    assert reply[:2] == b"\x05\x08"
    sock.close()


def test_a_socks5_success_discloses_no_bound_address(proxy, rows, decide, origin):
    decide["decision"] = _decision(origin.port)
    sock, _c, _s, reply = _socks(proxy.port, atyp=1, addr=bytes([127, 0, 0, 1]),
                                 dport=origin.port)
    assert reply == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    sock.sendall(b"ping")
    assert sock.recv(4) == b"ping"
    sock.close()


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------

def test_the_global_cap_answers_proxy_busy(rows, decide, origin):
    runner = _runner(max_connections=1)
    try:
        decide["decision"] = _decision(origin.port)
        first = socket.create_connection(("127.0.0.1", runner.port), timeout=10)
        first.sendall(_connect(f"127.0.0.1:{origin.port}"))
        assert first.recv(4096).startswith(b"HTTP/1.1 200")
        head = _send(runner.port, _connect(f"127.0.0.1:{origin.port}"))
        assert _status(head) == (503, "proxy_busy")
        first.close()
    finally:
        runner.stop()


def test_one_peer_with_unfinished_handshakes_is_capped_and_another_peer_is_not(
        rows, decide, origin):
    runner = _runner(peer_handshakes=16, handshake_s=10.0)
    held = []
    try:
        decide["decision"] = _decision(origin.port)
        for _ in range(16):
            held.append(_send(runner.port, b"CONNECT hooks.example", read=False))
        time.sleep(0.5)
        head = _send(runner.port, _connect(f"127.0.0.1:{origin.port}"))
        assert _status(head) == (503, "proxy_busy")
        other = _send(runner.port, _connect(f"127.0.0.1:{origin.port}"), source="127.0.0.2")
        assert _status(other) == (200, "Connection established")
    finally:
        for sock in held:
            sock.close()
        runner.stop()


def test_the_per_route_cap_answers_route_busy(proxy, rows, decide, origin):
    decide["decision"] = _decision(origin.port, max_concurrent=1)
    first = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    first.sendall(_connect(f"127.0.0.1:{origin.port}"))
    assert first.recv(4096).startswith(b"HTTP/1.1 200")
    head = _send(proxy.port, _connect(f"127.0.0.1:{origin.port}"))
    assert _status(head) == (503, "route_busy")
    first.close()


# ---------------------------------------------------------------------------
# The splice
# ---------------------------------------------------------------------------

def _wait_for(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_an_idle_tunnel_is_closed_with_idle_timeout_and_its_byte_counts(
        proxy, rows, decide, origin):
    decide["decision"] = _decision(origin.port, idle_s=1, session_s=60)
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    sock.sendall(_connect(f"127.0.0.1:{origin.port}"))
    assert sock.recv(4096).startswith(b"HTTP/1.1 200")
    sock.sendall(b"hello")
    assert sock.recv(5) == b"hello"
    assert _wait_for(lambda: any(r.event == "CLOSE" for r in rows))
    close = next(r for r in rows if r.event == "CLOSE")
    assert close.reason == "idle_timeout"
    assert (close.bytes_up, close.bytes_down) == (5, 5)
    sock.close()


def test_a_tunnel_is_closed_at_its_session_limit(proxy, rows, decide, origin):
    decide["decision"] = _decision(origin.port, idle_s=30, session_s=1)
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    sock.sendall(_connect(f"127.0.0.1:{origin.port}"))
    assert sock.recv(4096).startswith(b"HTTP/1.1 200")
    try:
        for _ in range(8):
            sock.sendall(b"k")
            time.sleep(0.3)
    except OSError:
        pass   # the proxy closed it, which is the point
    assert _wait_for(lambda: any(r.event == "CLOSE" for r in rows))
    assert next(r for r in rows if r.event == "CLOSE").reason == "session_limit"
    sock.close()


def test_the_byte_cap_of_an_act_or_stop_closes_at_session_limit(proxy, rows, decide):
    flood = Origin("flood", speak=512 * 1024)
    try:
        decide["decision"] = _decision(flood.port, max_bytes=64 * 1024)
        sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
        sock.sendall(_connect(f"127.0.0.1:{flood.port}"))
        got = b""
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                got += chunk
        except OSError:
            pass
        assert _wait_for(lambda: any(r.event == "CLOSE" for r in rows))
        close = next(r for r in rows if r.event == "CLOSE")
        assert close.reason == "session_limit"
        assert close.bytes_down <= 64 * 1024 + 65536
        sock.close()
    finally:
        flood.close()


def test_a_slow_reader_stalls_the_splice_instead_of_growing_a_buffer(proxy, rows, decide):
    flood = Origin("flood", speak=16 * 1024 * 1024)
    try:
        decide["decision"] = _decision(flood.port)
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", proxy.port))
        sock.sendall(_connect(f"127.0.0.1:{flood.port}"))
        head = b""
        while b"\r\n\r\n" not in head:
            head += sock.recv(1)
        time.sleep(2)   # read nothing: the origin keeps writing
        tunnel = next(iter(proxy.proxy.tunnels.values()))
        # Far less than the 16 MiB the origin offered reached the proxy.
        assert tunnel.bytes_down < 8 * 1024 * 1024, tunnel.bytes_down
        sock.close()
    finally:
        flood.close()


def test_a_drip_fed_upstream_connect_reply_is_cut_at_the_upstream_timeout(
        monkeypatch, rows, decide):
    from noctornal_api.security.egress_seal import ExitEndpoint
    monkeypatch.setattr(egress_proxy, "UPSTREAM_TIMEOUT_S", 1.0)
    drip = socket.socket()
    drip.bind(("127.0.0.1", 0))
    drip.listen(4)

    def serve():
        conn, _ = drip.accept()
        conn.recv(4096)
        try:
            for byte in b"HTTP/1.1 200 OK":
                conn.sendall(bytes([byte]))
                time.sleep(0.4)
        except OSError:
            pass
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    runner = _runner(upstream_allow=())
    try:
        profile_row = type("P", (), {"id": uuid4(), "kind": "RESIDENTIAL"})()
        decide["decision"] = _decision(443, route_kind="persona", host="forum.example",
                                       literal=False, exit_kind="HTTP",
                                       resolve_locally=False, profile=profile_row,
                                       route_id="persona:x", route_key="persona:x")
        runner.proxy._open_exit = lambda _p: ExitEndpoint("127.0.0.1",
                                                          drip.getsockname()[1])

        async def address(_endpoint):
            return "127.0.0.1", False

        runner.proxy._upstream_address = address
        began = time.monotonic()
        head = _send(runner.port, _connect("forum.example:443",
                                           username="persona." + str(uuid4()) + "~act."
                                           + str(uuid4()),
                                           token=None))
        assert _status(head) == (504, "upstream_timeout")
        assert time.monotonic() - began < 4
    finally:
        runner.stop()
        drip.close()


# ---------------------------------------------------------------------------
# The probe route and the pre-authentication count
# ---------------------------------------------------------------------------

def test_the_probe_route_resolves_no_name_and_refuses_loopback_as_private(
        proxy, rows, monkeypatch):
    asked = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: asked.append(a) or [])
    head = _send(proxy.port, _connect("metadata.example:80", username="probe.readiness"))
    assert _status(head) == (403, "probe_only")
    head = _send(proxy.port, _connect("127.0.0.1:9", username="probe.readiness"))
    assert _status(head) == (403, "blocked_address")
    assert b"X-Egress-Keys: " in head
    assert asked == [] and rows == []


def test_a_probe_with_a_wrong_token_is_407_without_the_probe_headers(proxy, rows):
    head = _send(proxy.port, _connect("127.0.0.1:9", username="probe.readiness",
                                      token="z" * 43))
    assert _status(head) == (407, "route_auth_failed")
    assert b"X-Egress" not in head


def test_a_flood_of_bad_credentials_is_one_preauth_row_per_peer(proxy, rows):
    for _ in range(50):
        _send(proxy.port, _connect("hooks.example:443", token="w" * 43))
    proxy.call(proxy.proxy._flush_preauth())
    preauth = [r for r in rows if r.event == "PREAUTH"]
    assert len(preauth) == 1
    assert preauth[0].item_count == 50 and preauth[0].peer_address == "127.0.0.1"
    assert not any(r.event == "REFUSED" for r in rows)


def test_every_refusal_the_proxy_writes_is_a_wire_code():
    from noctornal_api.egress_policy import WIRE_CODES
    source = (egress_proxy.__file__, egress_authz.__file__)
    import re
    for path in source:
        text = open(path, encoding="utf-8").read()
        for code in re.findall(r'(?:Refused|_Refuse|refuse)\("([a-z_]+)"', text):
            assert code in WIRE_CODES, (path, code)


def test_client_key_is_never_in_a_reply(proxy, rows):
    head = _send(proxy.port, _connect("hooks.example:443", token="w" * 43))
    assert base64.b64encode(CLIENT_KEY) not in head


def test_the_http_refusal_builder_matches_the_contract_for_every_code():
    from noctornal_api.egress_policy import PROXY_STATUS, WIRE_CODES
    for code in WIRE_CODES:
        head = egress_proxy.http_refusal(code)
        assert head.startswith(f"HTTP/1.1 {PROXY_STATUS[code]} {code}\r\n".encode())
        assert head.endswith(b"\r\n\r\n")
        assert (b"Proxy-Authenticate" in head) == (PROXY_STATUS[code] == 407)


def test_policy_objects_are_used_not_rebuilt():
    # The decision's policy is egress_policy's own RoutePolicy, never a
    # second matcher: the proxy module defines none.
    assert not hasattr(egress_proxy, "RoutePolicy")
    assert PUBLIC_POLICY.kind == "persona"


def test_asyncio_is_used_for_the_listener():
    assert asyncio.iscoroutinefunction(egress_proxy.EgressProxy.start)


def test_connections_arriving_together_cannot_all_pass_the_route_cap(proxy, rows, decide,
                                                                     origin, monkeypatch):
    decide["decision"] = _decision(origin.port, max_concurrent=2)
    real = proxy.proxy._open_row

    async def slow_open_row(*args, **kwargs):
        # Every connection is past the cap check and waiting here at once.
        await asyncio.sleep(0.3)
        return await real(*args, **kwargs)

    proxy.proxy._open_row = slow_open_row
    results, socks_ = [], []

    def one():
        sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
        sock.sendall(_connect(f"127.0.0.1:{origin.port}"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(1)
            if not chunk:
                break
            head += chunk
        results.append(_status(head)[1])
        socks_.append(sock)

    threads = [threading.Thread(target=one) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert sorted(results) == ["Connection established"] * 2 + ["route_busy"] * 3
    for sock in socks_:
        sock.close()


def test_two_failed_rechecks_close_the_tunnels_they_could_not_verify(proxy, rows, decide,
                                                                    origin, monkeypatch):
    decide["decision"] = _decision(origin.port)

    def broken(*_a, **_k):
        raise RuntimeError("database down")

    monkeypatch.setattr(egress_authz, "recheck", broken)
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    sock.sendall(_connect(f"127.0.0.1:{origin.port}"))
    assert sock.recv(4096).startswith(b"HTTP/1.1 200")
    proxy.call(proxy.proxy.recheck_now())
    assert proxy.proxy.tunnels, "one failed re-check must not close anything yet"
    proxy.call(proxy.proxy.recheck_now())
    assert _wait_for(lambda: any(r.event == "CLOSE" for r in rows))
    assert next(r for r in rows if r.event == "CLOSE").reason == "error"
    sock.close()


def test_a_socks5_name_that_is_not_ascii_never_reaches_the_name_rules():
    from uuid import UUID

    from noctornal_api.egress_policy import WireClaim
    claim = WireClaim("integration", "webhook", None, None)
    with pytest.raises(egress_authz.Refused) as caught:
        egress_authz.authorise(None, claim, "\x00", 443, production=False, internal=())
    assert caught.value.code == "bad_host"
    assert UUID(int=0)
