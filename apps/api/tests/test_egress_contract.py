"""The pinned client against the egress proxy's wire contract (2026-09-24;
docs/20 section 8).

Every case of egress_contract_cases runs here against its loopback stub;
the egress proxy's own suite runs the same cases against the real
listener. The tests below them are the client-side cases only a scripted
proxy can stage: a head dripped a byte at a time, a head too big to be one,
a reason phrase carrying markup, a TLS handshake dripped through the
tunnel.

Pure: no database, and no network beyond loopback.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from uuid import uuid4

import pytest
from egress_contract_cases import (
    CASES,
    Origin,
    StubHarness,
    StubProxy,
    contract_token,
)
from test_collection_ssrf_rebinding import _certificates

from noctornal_api import egress_policy, pinned_http
from noctornal_api.egress_policy import (
    INTEGRATION_CONTEXTS,
    PERSONA_CONTEXTS,
    wire_username,
)


@pytest.fixture
def harness():
    with StubProxy() as stub:
        yield StubHarness(stub)


@pytest.mark.parametrize("case", CASES, ids=[c.__name__[5:] for c in CASES])
def test_the_contract_case(harness, case):
    case(harness)


def test_the_cases_cover_what_the_contract_names():
    names = {c.__name__ for c in CASES}
    for needed in ("case_connect_carries_the_route_credentials_and_the_name",
                   "case_a_server_first_banner_in_the_same_segment_as_the_200_is_kept",
                   "case_every_wire_code_maps_through_its_code",
                   "case_502_name_not_found_is_permanent_and_resolve_failed_is_not",
                   "case_python_socks_authenticates_to_the_contract_on_both_protocols"):
        assert needed in names


# ---------------------------------------------------------------------------
# What only a scripted proxy can stage
# ---------------------------------------------------------------------------

def test_https_through_the_tunnel_checks_the_certificate_against_the_name(
        harness, tmp_path):
    ca, cert, key = _certificates(tmp_path, ["feed.rebind.test"], [])
    origin = Origin(b"secure")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    origin.socket = server_ctx.wrap_socket(origin.socket, server_side=True)
    try:
        harness.origin("feed.rebind.test", origin.server_port)
        client = ssl.create_default_context(cadata=ca)
        fetched = pinned_http.fetch_response(
            f"https://feed.rebind.test:{origin.server_port}/", route=harness.route(),
            timeout=5, tls_context=client)
        assert fetched.body == b"secure"
        harness.origin("other.rebind.test", origin.server_port)
        with pytest.raises(pinned_http.CertificateRefused):
            pinned_http.fetch_response(
                f"https://other.rebind.test:{origin.server_port}/",
                route=harness.route(), timeout=5, tls_context=client)
    finally:
        origin.close()


def test_http_goes_through_the_tunnel_too(harness):
    origin = Origin(b"plain")
    try:
        harness.origin("plain.rebind.test", origin.server_port)
        fetched = pinned_http.fetch_response(
            f"http://plain.rebind.test:{origin.server_port}/x", route=harness.route(),
            timeout=5)
        assert fetched.body == b"plain" and fetched.via == "PROXY"
        assert harness.records[-1]["protocol"] == "CONNECT"
    finally:
        origin.close()


def _timed(route, url, allowance=1.5):
    began = time.monotonic()
    with pytest.raises(pinned_http.OutboundError) as caught:
        pinned_http.fetch_response(url, route=route, timeout=3.0, deadline=allowance)
    return time.monotonic() - began, caught.value


def test_a_connect_reply_dripped_a_byte_at_a_time_ends_inside_the_allowance(harness):
    stop = threading.Event()

    def drip(conn, _host, _port):
        try:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\nX-Drip: ")
            while not stop.wait(0.2):
                conn.sendall(b"a")
        except OSError:
            pass
        finally:
            conn.close()

    harness.stub.handler = drip
    try:
        elapsed, error = _timed(harness.route(), "http://hooks.example/")
    finally:
        stop.set()
    assert isinstance(error, pinned_http.DeadlineExceeded), error
    assert elapsed < 1.5 + 2.5


def test_a_handshake_dripped_through_the_tunnel_ends_inside_the_allowance(harness):
    """The target's first TLS record header, then its body a byte at a
    time, arriving through the tunnel: the allowance governs the handshake
    inside the tunnel as it does on a direct hop."""
    stop = threading.Event()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve():
        conn, _ = listener.accept()
        try:
            conn.sendall(b"\x16\x03\x03\x40\x00")
            while not stop.wait(0.2):
                conn.sendall(b"\x00")
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    harness.origin("slow.rebind.test", port)
    try:
        elapsed, error = _timed(harness.route(), f"https://slow.rebind.test:{port}/")
    finally:
        stop.set()
        listener.close()
    assert isinstance(error, pinned_http.DeadlineExceeded), error
    assert elapsed < 1.5 + 2.5


@pytest.mark.parametrize("head", [
    b"HTTP/1.1 200 Connection established\r\nX-Pad: " + b"a" * 9216 + b"\r\n\r\n",
    b"HTTP/1.1 200 Connection established\r\n" + b"X-Line: 1\r\n" * 32 + b"\r\n",
])
def test_an_oversized_or_chatty_connect_head_is_refused(harness, head):
    harness.stub.handler = lambda conn, _h, _p: (conn.sendall(head), time.sleep(0.5))
    with pytest.raises(pinned_http.Unreachable) as caught:
        pinned_http.fetch_response("http://hooks.example/", route=harness.route(), timeout=5)
    assert caught.value.code == "proxy_protocol"


def test_a_head_of_exactly_thirty_two_lines_is_read():
    """The cap is 32 lines, the status line included."""
    with StubProxy() as stub:
        h = StubHarness(stub)
        head = (b"HTTP/1.1 200 Connection established\r\n" + b"X-Line: 1\r\n" * 31
                + b"\r\n")

        def answer(conn, _h, _p):
            conn.sendall(head + b"ok")
            time.sleep(0.5)
            conn.close()

        stub.handler = answer
        with pinned_http.Deadline(5) as deadline:
            sock = pinned_http.open_connection(h.route(), "hooks.example", 443,
                                               timeout=5, deadline=deadline)
            assert sock.recv(2) == b"ok"
            sock.close()


def test_an_unknown_reason_phrase_is_never_reflected(harness):
    hostile = b"<script>alert(1)</script>"
    harness.stub.handler = lambda conn, _h, _p: (
        conn.sendall(b"HTTP/1.1 403 " + hostile + b"\r\n\r\n"), conn.close())
    with pytest.raises(pinned_http.DestinationRefused) as caught:
        pinned_http.fetch_response("http://hooks.example/", route=harness.route(), timeout=5)
    assert caught.value.code == "destination_not_allowed"
    assert "script" not in str(caught.value) and "alert" not in repr(caught.value.args)
    # A known code on the wrong status is not believed either.
    harness.stub.handler = lambda conn, _h, _p: (
        conn.sendall(b"HTTP/1.1 503 name_not_found\r\n\r\n"), conn.close())
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        pinned_http.fetch_response("http://hooks.example/", route=harness.route(), timeout=5)
    assert caught.value.code == "proxy_busy"


def test_a_reply_that_is_not_http_is_proxy_protocol(harness):
    harness.stub.handler = lambda conn, _h, _p: (
        conn.sendall(b"SSH-2.0-OpenSSH\r\n\r\n"), conn.close())
    with pytest.raises(pinned_http.Unreachable) as caught:
        pinned_http.fetch_response("http://hooks.example/", route=harness.route(), timeout=5)
    assert caught.value.code == "proxy_protocol"


def test_the_proxy_address_is_resolved_once_and_metadata_is_refused(monkeypatch, harness):
    calls = []

    def metadata(host, port, *args, **kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", metadata)
    route = harness.route(proxy_host="egress-proxy.internal")
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        pinned_http.fetch_response("http://hooks.example/", route=route, timeout=5)
    assert caught.value.code == "proxy_unreachable"
    assert "169.254" not in str(caught.value) and "egress-proxy" not in str(caught.value)
    assert calls == ["egress-proxy.internal"]


def test_an_unreachable_proxy_is_route_unavailable_without_its_address():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    with StubProxy() as stub:
        route = StubHarness(stub).route()
    route = egress_policy.EgressRoute(route.kind, route.name, "PROXY", route.policy, None,
                                      "127.0.0.1", port, route.token)
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        pinned_http.fetch_response("http://hooks.example/", route=route, timeout=2)
    assert caught.value.code == "proxy_unreachable"
    assert str(port) not in str(caught.value)
    assert caught.value.request_sent is False


def test_no_username_the_grammar_emits_is_refused_by_python_socks():
    from python_socks._protocols.http import BasicAuth

    uid = str(uuid4())
    for kind, name, contexts in (("persona", uid, PERSONA_CONTEXTS),
                                 ("persona", "passive", PERSONA_CONTEXTS),
                                 ("integration", "lookup-" + "a" * 33, INTEGRATION_CONTEXTS)):
        for context in (None,) + tuple(f"{c}:{uid}" for c in contexts):
            username = wire_username(kind, name, context)
            BasicAuth(username, "t" * 43)
            assert ":" not in username


def test_the_readiness_probe_reads_its_headers_through_the_one_client(harness):
    token = contract_token(harness.stub.key, "probe.readiness")
    with pinned_http.Deadline(5) as deadline:
        reply = pinned_http.probe_proxy(harness.proxy_host, harness.proxy_port,
                                        token=token, target_host="127.0.0.1",
                                        target_port=9, deadline=deadline)
    assert (reply.status, reply.code) == (403, "blocked_address")
    assert reply.headers == {"x-egress-keys": "k1", "x-egress-unopenable": "0"}
    with pinned_http.Deadline(5) as deadline:
        other = pinned_http.probe_proxy(harness.proxy_host, harness.proxy_port,
                                        token=token, target_host="example.com",
                                        target_port=443, deadline=deadline)
    assert other.code == "probe_only"
    with pinned_http.Deadline(5) as deadline:
        wrong = pinned_http.probe_proxy(harness.proxy_host, harness.proxy_port,
                                        token="x" * 43, target_host="127.0.0.1",
                                        target_port=9, deadline=deadline)
    assert (wrong.status, wrong.code) == (407, "route_auth_failed")
    with pytest.raises(ValueError):
        pinned_http.probe_proxy(harness.proxy_host, harness.proxy_port, token=token,
                                target_host="127.0.0.1", target_port=9,
                                deadline=pinned_http.Deadline(5))


def test_a_socks5_client_offering_no_credentials_is_turned_away(harness):
    with socket.create_connection((harness.proxy_host, harness.proxy_port), timeout=5) as s:
        s.sendall(b"\x05\x01\x00")
        assert s.recv(2) == b"\x05\xff"
