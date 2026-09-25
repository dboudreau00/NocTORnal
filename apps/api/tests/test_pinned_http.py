"""pinned_http.py, the one outbound HTTP client (2026-09-24;
docs/00 decision 72, docs/20 section 5).

What is held here is the client's shape rather than the collector's
behaviour (test_collection_fetch_response.py and the collector's own suites
hold that): nothing hands a name to the socket layer, the classifier seam
is private, no call is retried, a pre-resolved hop is accepted only as
resolve() issued it, and a DIRECT integration route reaches what its rules
name and nothing else.

Pure: no database, and no network beyond loopback.
"""
from __future__ import annotations

import ast
import dataclasses
import http.server
import inspect
import pathlib
import socket
import socketserver
import threading
import time
from uuid import uuid4

import pytest

from noctornal_api import egress, egress_policy, pinned_http
from noctornal_api.egress_policy import (
    PUBLIC_POLICY,
    EgressRoute,
    RoutePolicy,
    Rule,
    parse_rule,
)

SRC = pathlib.Path(pinned_http.__file__).parent
ROOT = SRC.parents[3]
_REAL_GETADDRINFO = socket.getaddrinfo


def _calls(module) -> dict[str, list[str]]:
    """Every call name in a module, with the functions it appears in."""
    tree = ast.parse(inspect.getsource(module))
    found: dict[str, list[str]] = {}

    def walk(node, where):
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.ClassDef)) else where
            if isinstance(child, ast.Call):
                name = (child.func.attr if isinstance(child.func, ast.Attribute)
                        else getattr(child.func, "id", None))
                found.setdefault(name, []).append(where)
            walk(child, inner)

    walk(tree, "<module>")
    return found


def test_nothing_here_hands_a_name_to_the_socket_layer():
    """The rebinding suite's guard, over the three modules the collector's
    work moved into, with set_tunnel added: it dials the proxy and shakes
    hands outside the watchdog."""
    resolving = {"urlopen", "build_opener", "create_connection", "HTTPSConnection",
                 "HTTPConnection", "OpenerDirector", "set_tunnel"}
    for module in (pinned_http, egress_policy, egress):
        called = set(_calls(module))
        assert not called & resolving, (module.__name__, sorted(called & resolving))


def test_getaddrinfo_is_called_only_in_the_two_places():
    assert _calls(egress_policy).get("getaddrinfo") == ["resolve_and_pin"]
    assert _calls(pinned_http).get("getaddrinfo") == ["_proxy_hop"]
    assert "getaddrinfo" not in _calls(egress)


def test_the_seam_is_private():
    for fn in (pinned_http.fetch_response, pinned_http.resolve,
               pinned_http.open_connection):
        params = inspect.signature(fn).parameters
        assert not any("block" in p or "classif" in p for p in params), fn
    allowed = {"collection.py", "pinned_http.py", "egress_policy.py"}
    holders = set()
    for base in (SRC, ROOT / "scripts"):
        for path in base.rglob("*.py"):
            if "_blocked_override" in path.read_text(encoding="utf-8"):
                holders.add(path.name)
    assert holders == allowed, holders


def test_every_code_maps_to_a_class_here():
    for code in egress_policy.CODES:
        cls = pinned_http.EXCEPTION_FOR_CODE[code]
        assert issubclass(cls, pinned_http.OutboundError)
        assert issubclass(cls, pinned_http.CollectionError)


# ---------------------------------------------------------------------------
# A loopback server for the behaviour below
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        server.requests.append((self.command, self.path, dict(self.headers), body))
        self.send_response(server.status)
        self.send_header("Content-Length", str(len(server.body)))
        self.end_headers()
        self.wfile.write(server.body)

    do_GET = do_POST = _answer  # noqa: N815 - the stdlib's naming

    def log_message(self, *_args):
        pass


class _Server(http.server.HTTPServer):
    def __init__(self, host="127.0.0.1"):
        self.requests: list[tuple] = []
        self.status = 200
        self.body = b"ok"
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        super().__init__((host, 0), _Handler)
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.shutdown()
    s.server_close()


def _dev_integration(*rules: Rule, name="webhook") -> EgressRoute:
    return EgressRoute.direct("integration", name, RoutePolicy(
        "integration", rules, any_public=False, allow_loopback=True))


def test_no_call_is_retried(server):
    server.status = 503
    route = _dev_integration(Rule.for_host("localhost", {server.server_port}))
    for method, body in (("GET", None), ("POST", b"{}")):
        server.requests.clear()
        with pytest.raises(pinned_http.HttpStatusError) as caught:
            pinned_http.fetch_response(f"http://localhost:{server.server_port}/x",
                                       route=route, method=method, body=body,
                                       max_redirects=0, timeout=5)
        assert caught.value.status == 503 and str(caught.value) == "HTTP 503"
        assert len(server.requests) == 1, (method, server.requests)


def test_an_integration_route_admits_a_declared_private_host_only_inside_its_network(server):
    """Loopback stands in for the private network through the development
    localhost rule: inside the rule it connects, a name outside the rule
    is refused, and a metadata address is refused even when the rule's
    network contains it."""
    port = server.server_port
    route = _dev_integration(Rule.for_host("localhost", {port}),
                             Rule.for_host("127.0.0.1", {port}))
    assert pinned_http.fetch_response(f"http://localhost:{port}/", route=route,
                                      max_redirects=0, timeout=5).body == b"ok"
    assert pinned_http.fetch_response(f"http://127.0.0.1:{port}/", route=route,
                                      max_redirects=0, timeout=5).body == b"ok"
    with pytest.raises(pinned_http.DestinationRefused) as caught:
        pinned_http.fetch_response(f"http://127.0.0.2:{port}/", route=route,
                                   max_redirects=0, timeout=5)
    assert caught.value.code == "destination_not_allowed"
    with pytest.raises(pinned_http.DestinationRefused):
        pinned_http.fetch_response(f"http://localhost:{port + 1 if port < 65535 else 1}/",
                                   route=route, max_redirects=0, timeout=5)
    metadata = _dev_integration(parse_rule("169.254.169.254/32:80"))
    with pytest.raises(pinned_http.DestinationRefused) as caught:
        pinned_http.fetch_response("http://169.254.169.254/latest", route=metadata,
                                   max_redirects=0, timeout=5)
    assert caught.value.code == "metadata_address"


def test_a_persona_route_refuses_private_space_even_when_declared():
    rule = Rule.for_host("localhost", {80})
    route = EgressRoute.direct("persona", "passive",
                               dataclasses.replace(PUBLIC_POLICY, rules=(rule,)),
                               context=f"run:{uuid4()}")
    with pytest.raises(pinned_http.DestinationRefused) as caught:
        pinned_http.fetch_response("http://localhost/", route=route, timeout=5)
    assert caught.value.code in ("blocked_address", "loopback_refused")
    assert egress_policy.validate_rule(rule, kind="persona", production=False)


def test_an_onion_name_is_never_resolved_on_a_direct_route(monkeypatch):
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: calls.append(a) or _REAL_GETADDRINFO(*a, **k))
    tor = EgressRoute.direct("persona", "passive",
                             dataclasses.replace(PUBLIC_POLICY, onion=True),
                             context=f"run:{uuid4()}")
    for route in (tor, EgressRoute.direct("persona", "passive", PUBLIC_POLICY)):
        with pytest.raises(pinned_http.DestinationRefused) as caught:
            pinned_http.fetch_response("http://" + "a" * 56 + ".onion/", route=route,
                                       timeout=5)
        assert caught.value.code == "onion_not_allowed"
    assert calls == []


# ---------------------------------------------------------------------------
# A pre-resolved hop is accepted only as resolve() issued it
# ---------------------------------------------------------------------------

def test_a_hand_built_or_borrowed_hop_is_refused(server):
    port = server.server_port
    route = _dev_integration(Rule.for_host("localhost", {port}))
    url = f"http://localhost:{port}/x"
    real = pinned_http.resolve(url, route=route)
    assert real.via == "DIRECT" and real.locality == "loopback"
    assert pinned_http.fetch_response(url, route=route, hop=real, max_redirects=0,
                                      timeout=5).body == b"ok"
    forged = pinned_http.Hop("http", "localhost", port, "/x",
                             ((socket.AF_INET, socket.SOCK_STREAM, 6, ("10.0.0.5", port)),),
                             "private", "DIRECT")
    with pytest.raises(ValueError, match="resolve"):
        pinned_http.fetch_response(url, route=route, hop=forged, max_redirects=0)
    swapped = dataclasses.replace(real, addresses=(
        (socket.AF_INET, socket.SOCK_STREAM, 6, ("169.254.169.254", port)),))
    with pytest.raises(ValueError):
        pinned_http.fetch_response(url, route=route, hop=swapped, max_redirects=0)
    other = _dev_integration(Rule.for_host("localhost", {port}), name="smtp")
    with pytest.raises(ValueError):
        pinned_http.fetch_response(url, route=other, hop=real, max_redirects=0)
    proxied = EgressRoute("integration", "webhook", "PROXY",
                          RoutePolicy("integration", admission="proxy"), None,
                          "127.0.0.1", 9, "t" * 43)
    with pytest.raises(ValueError, match="mode"):
        pinned_http.fetch_response(url, route=proxied, hop=real, max_redirects=0)
    with pytest.raises(ValueError):
        pinned_http.fetch_response(url, route=route, hop=real, max_redirects=1)
    with pytest.raises(ValueError):
        pinned_http.fetch_response(f"http://localhost:{port}/y", route=route, hop=real,
                                   max_redirects=0)


def test_resolve_then_send_makes_one_lookup(server, monkeypatch):
    port = server.server_port
    lookups = []
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: lookups.append(a[0]) or _REAL_GETADDRINFO(*a, **k))
    route = _dev_integration(Rule.for_host("localhost", {port}), name="embeddings")
    url = f"http://localhost:{port}/embed"
    hop = pinned_http.resolve(url, route=route)
    pinned_http.fetch_response(url, route=route, hop=hop, method="POST", body=b"[]",
                               max_redirects=0, error_excerpt=False, deadline=5.0)
    assert lookups == ["localhost"]


# ---------------------------------------------------------------------------
# The deadline argument
# ---------------------------------------------------------------------------

def test_a_numeric_deadline_is_its_own_allowance_up_to_the_ceiling(monkeypatch):
    """A number is never cut to max_seconds' 60 second default: the
    CAPEv2 row passes up to 900 seconds."""
    made = []
    real = pinned_http.Deadline

    class Spy(real):
        def __init__(self, seconds):
            made.append(seconds)
            super().__init__(seconds)

    monkeypatch.setattr(pinned_http, "Deadline", Spy)
    route = _dev_integration(Rule.for_host("localhost", {9}))
    for value in (120, 900.0):
        with pytest.raises(pinned_http.OutboundError):
            pinned_http.fetch_response("http://localhost:9/", route=route, timeout=1,
                                       max_redirects=0, deadline=value)
    assert made == [120.0, 900.0]
    with pytest.raises(ValueError):
        pinned_http.fetch_response("http://localhost:9/", route=route, deadline=901)
    with pytest.raises(ValueError):
        pinned_http.fetch_response("http://localhost:9/", route=route, deadline=0)


def test_a_numeric_deadline_outlives_the_default_allowance(monkeypatch):
    """A drip longer than max_seconds' default and shorter than the
    numeric deadline completes: the scaled form of "deadline=120 survives
    a 90 second drip"."""
    monkeypatch.setattr(pinned_http, "MAX_FETCH_SECONDS", 0.5)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
        for byte in b"slowx":
            time.sleep(0.3)
            conn.sendall(bytes([byte]))
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    route = _dev_integration(Rule.for_host("127.0.0.1", {port}))
    fetched = pinned_http._fetch_response(f"http://127.0.0.1:{port}/", route=route,
                                          max_redirects=0, timeout=5, deadline=4.0,
                                          max_seconds=0.5)
    listener.close()
    assert fetched.body == b"slowx"


# ---------------------------------------------------------------------------
# open_connection (the SMTP relay)
# ---------------------------------------------------------------------------

def _banner_server(host):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.bind((host, 0))
    listener.listen(4)

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            conn.sendall(b"220 relay ready\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return listener


def test_open_connection_reaches_the_development_relay_by_either_spelling(monkeypatch):
    """The installers write SMTP_HOST=127.0.0.1 and CI writes localhost,
    which a Windows resolver answers with ::1 AND 127.0.0.1: both reach the
    relay through the development loopback exception."""
    listener = _banner_server("127.0.0.1")
    port = listener.getsockname()[1]
    try:
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, p, *a, **k: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", p, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p)),
        ] if host == "localhost" else _REAL_GETADDRINFO(host, p, *a, **k))
        for host in ("localhost", "127.0.0.1"):
            route = _dev_integration(Rule.for_host(host, {port}), name="smtp")
            with pinned_http.Deadline(10) as deadline:
                sock = pinned_http.open_connection(route, host, port, timeout=5,
                                                   deadline=deadline)
                try:
                    assert sock.recv(32).startswith(b"220")
                finally:
                    sock.close()
    finally:
        listener.close()


def test_open_connection_takes_only_an_entered_deadline():
    route = _dev_integration(Rule.for_host("localhost", {25}), name="smtp")
    with pytest.raises(ValueError):
        pinned_http.open_connection(route, "localhost", 25, timeout=5,
                                    deadline=pinned_http.Deadline(5))


def test_open_connection_refuses_what_the_route_does_not_name():
    route = _dev_integration(Rule.for_host("localhost", {1025}), name="smtp")
    with pinned_http.Deadline(5) as deadline:
        with pytest.raises(pinned_http.DestinationRefused) as caught:
            pinned_http.open_connection(route, "relay.example", 587, timeout=5,
                                        deadline=deadline)
    assert caught.value.code == "destination_not_allowed"
    assert caught.value.request_sent is False and caught.value.connected is False
