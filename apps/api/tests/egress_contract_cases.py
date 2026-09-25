"""The egress proxy's wire contract, as cases both sides run (2026-09-24;
docs/20 section 8).

Importable, with no test functions of its own. `test_egress_contract.py`
runs every `case_*` below against `StubProxy`, a loopback proxy written to
docs/20 section 8 to the letter; the egress proxy's own suite runs the same cases
against its real listener through a harness of the same shape, and the
Telegram suite runs python-socks through the stub. So the client and the
server are held to one text rather than to two readings of it.

A harness has:

- `proxy_host`, `proxy_port`: where the one listener is;
- `route(kind="integration", name="webhook", context=None, rules=())`: an
  EgressRoute in PROXY mode carrying a token the proxy accepts;
- `origin(name, port)`: make `name` reach a local server on `port` through
  the proxy, without this process ever resolving it;
- `refusing(code)`: a context manager in which the proxy refuses every
  CONNECT with that code (the stub scripts it; a real listener arranges
  the condition, or the case is skipped by its runner);
- `records`: one dict per accepted handshake, with "protocol", "username"
  and "target".

The stub is lenient where the contract says a server must be: extra
header lines within the 8 KiB and 32 line caps are accepted and ignored,
because python-socks 3.1.1 sends a User-Agent line between Host and
Proxy-Authorization.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import ipaddress
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from unittest import mock

from noctornal_api import egress_policy, pinned_http
from noctornal_api.egress_policy import (
    PROXY_STATUS,
    SOCKS5_REPLY,
    WIRE_CODES,
    EgressRoute,
    Refusal,
    RoutePolicy,
    parse_wire_username,
)

#: The MAC domain of a route token (docs/20 section 7).
TOKEN_DOMAIN = b"noctornal-egress-route-v1"
STUB_KEY = b"k" * 32

_REAL_GETADDRINFO = socket.getaddrinfo


def contract_token(key: bytes, route_part: str) -> str:
    """The route token: base64url without padding of HMAC-SHA256(K,
    domain NUL route part). The context is not in the MAC, so one token
    serves every run of a route."""
    mac = hmac.new(key, TOKEN_DOMAIN + b"\x00" + route_part.encode("ascii"),
                   hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def _refusal_head(code: str, extra: str = "") -> bytes:
    status = PROXY_STATUS[code]
    head = (f"HTTP/1.1 {status} {code}\r\nContent-Length: 0\r\n"
            f"Connection: close\r\n{extra}")
    if status == 407:
        head += 'Proxy-Authenticate: Basic realm="noctornal-egress"\r\n'
    return (head + "\r\n").encode("ascii")


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def copy(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    threads = [threading.Thread(target=copy, args=(a, b), daemon=True),
               threading.Thread(target=copy, args=(b, a), daemon=True)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    a.close()
    b.close()


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("short read")
        data += chunk
    return data


class StubProxy:
    """One loopback listener speaking CONNECT and SOCKS5, told apart by the
    first byte (docs/20 section 8.1). It authenticates with contract_token,
    tunnels to names it has been told about (`names`), answers 502
    name_not_found for any other name, and never resolves anything itself,
    so a test can prove the client resolved nothing but the proxy."""

    def __init__(self, key: bytes = STUB_KEY):
        self.key = key
        #: name -> the address that name reaches through this proxy.
        self.names: dict[str, str] = {}
        #: A code every CONNECT is refused with, when set.
        self.refuse_code: str | None = None
        #: Replaces the reply to an authenticated CONNECT: fn(conn, target).
        self.handler = None
        self.records: list[dict] = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # --- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.listener.close()

    def __enter__(self) -> StubProxy:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _peer = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._answer, args=(conn,), daemon=True).start()

    def _answer(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            first = conn.recv(1, socket.MSG_PEEK)
            if not first:
                conn.close()
                return
            if first == b"\x05":
                self._socks5(conn)
            else:
                self._connect(conn)
        except OSError:
            conn.close()

    # --- shared decisions ----------------------------------------------------

    def _authenticate(self, username: str | None, token: str | None) -> str | None:
        """None when the credentials hold, else the refusal code."""
        if username is None or token is None:
            return "route_auth_required"
        try:
            parse_wire_username(username)
        except Refusal:
            return "route_auth_failed"
        route_part = username.split("~", 1)[0]
        if not hmac.compare_digest(token, contract_token(self.key, route_part)):
            return "route_auth_failed"
        return None

    def _decide(self, username: str, host: str, port: int) -> tuple[str | None, str | None]:
        """(refusal code or None, the address to dial)."""
        if username == "probe.readiness":
            literal = _literal(host)
            if literal is not None and egress_policy.is_blocked(literal):
                return "blocked_address", None
            return "probe_only", None
        if self.refuse_code is not None:
            return self.refuse_code, None
        literal = _literal(host)
        if literal is not None:
            return None, str(literal)
        address = self.names.get(host)
        if address is None:
            return "name_not_found", None
        return None, address

    def _dial(self, address: str, port: int) -> socket.socket | None:
        # By number, with no lookup: the stub shares the test's process, and
        # a case counts every name handed to getaddrinfo.
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((address, port))
        except OSError:
            sock.close()
            return None
        return sock

    # --- HTTP CONNECT (6.2) --------------------------------------------------

    def _connect(self, conn: socket.socket) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                conn.close()
                return
            head += chunk
            if len(head) > 8192:
                conn.sendall(_refusal_head("bad_request"))
                conn.close()
                return
        head = head.split(b"\r\n\r\n", 1)[0]
        lines = head.decode("latin-1").split("\r\n")
        if len(lines) > 32:
            conn.sendall(_refusal_head("bad_request"))
            conn.close()
            return
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            conn.sendall(_refusal_head("bad_request"))
            conn.close()
            return
        if parts[0] != "CONNECT":
            conn.sendall(_refusal_head("method_not_allowed"))
            conn.close()
            return
        host, _, port_text = parts[1].rpartition(":")
        host = host[1:-1] if host.startswith("[") else host
        username = token = None
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if name.strip().lower() == "proxy-authorization":
                scheme, _, encoded = value.strip().partition(" ")
                if scheme == "Basic":
                    try:
                        decoded = base64.b64decode(encoded, validate=True).decode("ascii")
                    except (ValueError, UnicodeDecodeError):
                        decoded = ""
                    username, _, token = decoded.partition(":")
        refusal = self._authenticate(username, token)
        if refusal is not None:
            conn.sendall(_refusal_head(refusal))
            conn.close()
            return
        port = int(port_text)
        self.records.append({"protocol": "CONNECT", "username": username,
                             "target": f"{host}:{port}", "head": head})
        if self.handler is not None:
            self.handler(conn, host, port)
            return
        code, address = self._decide(username, host, port)
        if code is not None:
            extra = ("X-Egress-Keys: k1\r\nX-Egress-Unopenable: 0\r\n"
                     if username == "probe.readiness" else "")
            conn.sendall(_refusal_head(code, extra))
            conn.close()
            return
        upstream = self._dial(address, port)
        if upstream is None:
            conn.sendall(_refusal_head("connect_failed"))
            conn.close()
            return
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        conn.settimeout(None)
        _pipe(conn, upstream)

    # --- SOCKS5 (6.4) --------------------------------------------------------

    def _socks5(self, conn: socket.socket) -> None:
        _ver, count = _recv_exact(conn, 2)
        methods = _recv_exact(conn, count)
        if 0x02 not in methods:
            conn.sendall(b"\x05\xff")
            conn.close()
            return
        conn.sendall(b"\x05\x02")
        _sub, ulen = _recv_exact(conn, 2)
        username = _recv_exact(conn, ulen).decode("ascii", "replace")
        plen = _recv_exact(conn, 1)[0]
        token = _recv_exact(conn, plen).decode("ascii", "replace")
        if self._authenticate(username, token) is not None:
            conn.sendall(b"\x01\x01")
            conn.close()
            return
        conn.sendall(b"\x01\x00")
        _ver, cmd, _rsv, atyp = _recv_exact(conn, 4)

        def reply(code: str | None) -> None:
            rep = 0 if code is None else SOCKS5_REPLY[code]
            conn.sendall(bytes([5, rep, 0, 1, 0, 0, 0, 0, 0, 0]))

        if atyp == 1:
            host = str(ipaddress.IPv4Address(_recv_exact(conn, 4)))
        elif atyp == 3:
            host = _recv_exact(conn, _recv_exact(conn, 1)[0]).decode("ascii", "replace")
        elif atyp == 4:
            host = str(ipaddress.IPv6Address(_recv_exact(conn, 16)))
        else:
            reply("address_type_refused")
            conn.close()
            return
        port = int.from_bytes(_recv_exact(conn, 2), "big")
        if cmd != 1:
            reply("method_not_allowed")
            conn.close()
            return
        self.records.append({"protocol": "SOCKS5", "username": username,
                             "target": f"{host}:{port}"})
        code, address = self._decide(username, host, port)
        if code is not None:
            reply(code)
            conn.close()
            return
        upstream = self._dial(address, port)
        if upstream is None:
            reply("connect_failed")
            conn.close()
            return
        reply(None)
        conn.settimeout(None)
        _pipe(conn, upstream)


def _literal(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


class StubHarness:
    """The harness of the module docstring, over a StubProxy."""

    proxy_host = "127.0.0.1"

    def __init__(self, stub: StubProxy):
        self.stub = stub
        self.proxy_port = stub.port

    @property
    def records(self) -> list[dict]:
        return self.stub.records

    def route(self, kind: str = "integration", name: str = "webhook",
              context: str | None = None, rules=(), *, any_public=None,
              proxy_host: str | None = None) -> EgressRoute:
        if any_public is None:
            any_public = kind == "persona" or not rules
        policy = RoutePolicy(kind, tuple(rules), any_public=any_public,
                             admission="proxy")
        route_part = egress_policy.wire_username(kind, name)
        return EgressRoute(kind, name, "PROXY", policy, context,
                           proxy_host or self.proxy_host, self.proxy_port,
                           contract_token(self.stub.key, route_part))

    def origin(self, name: str, port: int) -> None:
        self.stub.names[name] = "127.0.0.1"

    @contextmanager
    def refusing(self, code: str):
        self.stub.refuse_code = code
        try:
            yield
        finally:
            self.stub.refuse_code = None


# ---------------------------------------------------------------------------
# Origins the cases reach through the proxy
# ---------------------------------------------------------------------------

class _OriginHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - the stdlib's naming
        server = self.server
        server.seen.append((self.path, self.headers.get("Host"),
                            self.headers.get("User-Agent")))
        target = server.redirects.get(self.path)
        if target is not None:
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(server.body)))
        self.end_headers()
        self.wfile.write(server.body)

    def log_message(self, *_args):
        pass


class Origin(http.server.HTTPServer):
    """A loopback HTTP server recording (path, Host, User-Agent)."""

    def __init__(self, body: bytes = b"through the tunnel"):
        self.body = body
        self.seen: list[tuple] = []
        self.redirects: dict[str, str] = {}
        self.connections: list[tuple] = []
        super().__init__(("127.0.0.1", 0), _OriginHandler)
        self.thread = threading.Thread(target=self.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def verify_request(self, request, client_address):
        self.connections.append(client_address)
        return True

    def close(self) -> None:
        self.shutdown()
        self.server_close()


class _CountingResolver:
    """socket.getaddrinfo, counting the names it is asked for."""

    def __init__(self):
        self.names: list[str] = []

    def __call__(self, host, port, *args, **kwargs):
        self.names.append(host)
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)


# ---------------------------------------------------------------------------
# The client-side cases
# ---------------------------------------------------------------------------

def case_connect_carries_the_route_credentials_and_the_name(h) -> None:
    origin = Origin()
    try:
        h.origin("feed.rebind.test", origin.server_port)
        route = h.route("persona", "passive", f"run:{_uuid()}")
        url = f"http://feed.rebind.test:{origin.server_port}/feed"
        fetched = pinned_http.fetch_response(url, route=route, timeout=5)
        assert fetched.body == origin.body and fetched.via == "PROXY"
        assert fetched.peer is None
        record = h.records[-1]
        assert record["target"] == f"feed.rebind.test:{origin.server_port}"
        assert record["username"] == route.wire_username
        assert ":" not in record["username"]
        assert origin.seen[-1][1] == f"feed.rebind.test:{origin.server_port}"
    finally:
        origin.close()


def case_the_target_is_never_resolved_or_dialled_locally(h) -> None:
    origin = Origin()
    resolver = _CountingResolver()
    try:
        h.origin("feed.rebind.test", origin.server_port)
        route = h.route(proxy_host="localhost")
        with mock.patch.object(socket, "getaddrinfo", resolver):
            pinned_http.fetch_response(
                f"http://feed.rebind.test:{origin.server_port}/", route=route, timeout=5)
        assert resolver.names == ["localhost"], resolver.names
    finally:
        origin.close()


def case_a_server_first_banner_in_the_same_segment_as_the_200_is_kept(h) -> None:
    def banner(conn, _host, _port):
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n220 relay ready\r\n")
        time.sleep(1)
        conn.close()

    h.stub.handler = banner
    try:
        route = h.route("integration", "smtp")
        with pinned_http.Deadline(10) as deadline:
            sock = pinned_http.open_connection(route, "relay.example", 587,
                                               timeout=5, deadline=deadline)
            try:
                assert sock.recv(64) == b"220 relay ready\r\n"
            finally:
                sock.close()
    finally:
        h.stub.handler = None


def case_a_one_or_two_token_reason_on_200_opens_the_tunnel(h) -> None:
    for head in (b"HTTP/1.0 200 OK\r\n\r\n",
                 b"HTTP/1.1 200 Tunnel open for you\r\n\r\n"):
        def answer(conn, _host, _port, head=head):
            conn.sendall(head + b"hello")
            time.sleep(0.5)
            conn.close()

        h.stub.handler = answer
        try:
            with pinned_http.Deadline(10) as deadline:
                sock = pinned_http.open_connection(h.route(), "hooks.example", 443,
                                                   timeout=5, deadline=deadline)
                try:
                    assert sock.recv(16) == b"hello"
                finally:
                    sock.close()
        finally:
            h.stub.handler = None


def case_every_wire_code_maps_through_its_code(h) -> None:
    for code in sorted(WIRE_CODES):
        with h.refusing(code):
            try:
                pinned_http.fetch_response("http://hooks.example/", route=h.route(),
                                           timeout=5, max_redirects=0)
            except pinned_http.OutboundError as exc:
                expected = pinned_http.EXCEPTION_FOR_CODE[code]
                assert type(exc) is expected, (code, type(exc))
                assert exc.code == code, (code, exc.code)
                assert exc.request_sent is False, code
                assert str(exc) != code
            else:
                raise AssertionError(f"{code} opened a tunnel")
    with h.refusing("route_retired"):
        try:
            pinned_http.fetch_response("http://hooks.example/", route=h.route(),
                                       timeout=5, max_redirects=0)
        except pinned_http.RouteUnavailable:
            pass


def case_502_name_not_found_is_permanent_and_resolve_failed_is_not(h) -> None:
    try:
        pinned_http.fetch_response("http://nowhere.example/", route=h.route(), timeout=5)
    except pinned_http.UnresolvableHost as exc:
        assert exc.permanent and exc.code == "name_not_found"
        assert str(exc) == "cannot resolve nowhere.example"
    else:
        raise AssertionError("an unknown name was reached")
    with h.refusing("resolve_failed"):
        try:
            pinned_http.fetch_response("http://slow.example/", route=h.route(), timeout=5)
        except pinned_http.UnresolvableHost as exc:
            assert not exc.permanent
        else:
            raise AssertionError("resolve_failed opened a tunnel")


def case_407_is_route_auth_failed_and_never_names_the_proxy(h) -> None:
    good = h.route()
    bad = EgressRoute(good.kind, good.name, "PROXY", good.policy, None, good.proxy_host,
                      good.proxy_port, "x" * 43)
    try:
        pinned_http.fetch_response("http://hooks.example/", route=bad, timeout=5)
    except pinned_http.RouteUnavailable as exc:
        assert exc.code == "route_auth_failed"
        assert str(h.proxy_port) not in str(exc) and h.proxy_host not in str(exc)
    else:
        raise AssertionError("a bad token opened a tunnel")


def case_redirects_through_the_proxy_are_checked_by_name_and_tunnelled_again(h) -> None:
    origin = Origin()
    try:
        h.origin("feed.rebind.test", origin.server_port)
        h.origin("next.rebind.test", origin.server_port)
        origin.redirects["/feed"] = f"http://next.rebind.test:{origin.server_port}/next"
        before = len(h.records)
        fetched = pinned_http.fetch_response(
            f"http://feed.rebind.test:{origin.server_port}/feed", route=h.route(), timeout=5)
        assert fetched.url.endswith("/next") and fetched.redirects == 1
        targets = [r["target"] for r in h.records[before:]]
        assert targets == [f"feed.rebind.test:{origin.server_port}",
                           f"next.rebind.test:{origin.server_port}"]
        origin.redirects["/feed"] = "http://metadata.google.internal/"
        try:
            pinned_http.fetch_response(
                f"http://feed.rebind.test:{origin.server_port}/feed", route=h.route(),
                timeout=5)
        except pinned_http.DestinationRefused as exc:
            assert exc.code == "metadata_host"
        else:
            raise AssertionError("a redirect to a metadata name was followed")
    finally:
        origin.close()


def case_python_socks_authenticates_to_the_contract_on_both_protocols(h) -> None:
    from python_socks import ProxyType
    from python_socks.sync import Proxy

    origin = Origin()
    try:
        h.origin("dc.telegram.test", origin.server_port)
        route = h.route("persona", "passive", f"act:{_uuid()}")
        seen = []
        for kind in (ProxyType.HTTP, ProxyType.SOCKS5):
            before = len(h.records)
            proxy = Proxy.create(kind, h.proxy_host, h.proxy_port,
                                 username=route.wire_username, password=route.token,
                                 rdns=True)
            sock = proxy.connect("dc.telegram.test", origin.server_port, timeout=5)
            try:
                sock.sendall(b"GET /p HTTP/1.1\r\nHost: dc.telegram.test\r\n"
                             b"Connection: close\r\n\r\n")
                assert b"200" in sock.recv(64)
            finally:
                sock.close()
            seen.append(h.records[before]["username"])
        assert seen == [route.wire_username, route.wire_username]
        assert {r["protocol"] for r in h.records[-2:]} == {"CONNECT", "SOCKS5"}
    finally:
        origin.close()


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())


CASES = [value for name, value in sorted(globals().items()) if name.startswith("case_")]
