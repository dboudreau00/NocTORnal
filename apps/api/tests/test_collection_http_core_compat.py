"""collection.py after its HTTP core moved to egress_policy.py and
pinned_http.py (docs/00 decision 72, 2026-09-24): the old names are the moved
objects, fetch keeps its signature and messages, the collector's test seam
still reaches the connect, and a call that names no route is refused once
a proxy is configured.

Pure: no database, and no network beyond loopback.
"""
from __future__ import annotations

import http.server
import inspect
import socket
import threading

import pytest
from test_collection_ssrf_rebinding import NAME, PUBLIC, _Rebinder, _Server, _start, _stop

from noctornal_api import collection, egress, egress_policy, pinned_http
from noctornal_api.collection import CollectionError, fetch


def test_the_old_names_are_the_moved_objects():
    same = {
        "_BLOCKED_NETWORKS": egress_policy.BLOCKED_NETWORKS,
        "_METADATA_HOSTS": egress_policy.METADATA_HOSTS,
        "_is_blocked": egress_policy.is_blocked,
        "MAX_REDIRECTS": pinned_http.MAX_REDIRECTS,
        "MAX_RESPONSE_BYTES": pinned_http.MAX_RESPONSE_BYTES,
        "MAX_FETCH_SECONDS": pinned_http.MAX_FETCH_SECONDS,
        "_Hop": pinned_http.Hop,
        "_cut": pinned_http._cut,
        "_Deadline": pinned_http.Deadline,
        "_dial": pinned_http._dial,
        "_PinnedConnection": pinned_http._PinnedConnection,
        "_refuse_unverifying": pinned_http._refuse_unverifying,
        "_REDIRECT_CODES": pinned_http.REDIRECT_CODES,
        "REDIRECT_CODES": pinned_http.REDIRECT_CODES,
        "CollectionError": pinned_http.CollectionError,
        "_SECRET_PATTERNS": pinned_http._SECRET_PATTERNS,
        "MIN_REDACTABLE_LENGTH": pinned_http.MIN_REDACTABLE_LENGTH,
        "_LIVE_SECRETS": pinned_http._LIVE_SECRETS,
        "_secret_forms": pinned_http._secret_forms,
        "secret_in_scope": pinned_http.secret_in_scope,
        "redact": pinned_http.redact,
        "HttpStatusError": pinned_http.HttpStatusError,
        "UnresolvableHost": pinned_http.UnresolvableHost,
        "DestinationRefused": pinned_http.DestinationRefused,
        "RequestUncertain": pinned_http.RequestUncertain,
        "RouteUnavailable": pinned_http.RouteUnavailable,
        "Unreachable": pinned_http.Unreachable,
        "DeadlineExceeded": pinned_http.DeadlineExceeded,
        "RedirectRefused": pinned_http.RedirectRefused,
        "Fetched": pinned_http.Fetched,
        "COLLECTOR_USER_AGENT": pinned_http.COLLECTOR_USER_AGENT,
        "LOOKUP_USER_AGENT": pinned_http.LOOKUP_USER_AGENT,
        "LOOKUP_MAX_SECONDS": pinned_http.LOOKUP_MAX_SECONDS,
    }
    for name, obj in same.items():
        assert getattr(collection, name) is obj, name
    # The domain's own errors still hang off the one root.
    for name in ("PersonaUnavailable", "CollectionNotFound", "CollectionBusy"):
        assert issubclass(getattr(collection, name), pinned_http.CollectionError)


def test_fetch_keeps_its_signature_and_defaults():
    params = list(inspect.signature(fetch).parameters.values())
    assert [p.name for p in params] == ["url", "etag", "timeout", "max_redirects",
                                        "max_bytes", "tls_context", "max_seconds",
                                        "route"]
    defaults = {p.name: p.default for p in params[1:]}
    assert defaults == {"etag": None, "timeout": 15.0, "max_redirects": 5,
                        "max_bytes": 16 * 1024 * 1024, "tls_context": None,
                        "max_seconds": 60.0, "route": None}


@pytest.fixture
def public(monkeypatch):
    server = _Server((PUBLIC, 0), b"<rss/>")
    _start(server)
    resolver = _Rebinder(first=[PUBLIC], later=[PUBLIC])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    yield server, server.server_address[1], resolver
    _stop(server)


def test_the_collector_seam_still_reaches_the_connect(public, monkeypatch):
    server, port, _resolver = public
    # 127.0.0.1 played as public: fetch connects.
    monkeypatch.setattr(collection, "_is_blocked",
                        lambda address: str(address) != PUBLIC)
    assert fetch(f"http://{NAME}:{port}/feed", timeout=5)[:2] == (b"<rss/>", 200)
    # And told that everything is internal, fetch refuses the same URL.
    monkeypatch.setattr(collection, "_is_blocked", lambda address: True)
    with pytest.raises(CollectionError, match="private address space"):
        fetch(f"http://{NAME}:{port}/feed", timeout=5)
    assert len(server.connections) == 1


class _Redirector(http.server.BaseHTTPRequestHandler):
    target = "http://127.0.0.1/"

    def do_GET(self):  # noqa: N802 - the stdlib's naming
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *_args):
        pass


def test_the_hardening_redirect_chain_shape_passes_through_the_seam(monkeypatch):
    """An IP-literal first hop with the seam patched to False reaches the
    redirect logic (the IP-literal seam)."""
    server = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        _Redirector.target = f"http://localhost:{port}/next"
        monkeypatch.setattr("noctornal_api.collection._is_blocked", lambda _a: False)
        with pytest.raises(pinned_http.RedirectRefused, match="redirect"):
            fetch(f"http://127.0.0.1:{port}/start")
    finally:
        server.shutdown()
        server.server_close()


def test_every_asserted_message_is_unchanged(public, monkeypatch):
    """Each message the collector's suites read, through fetch, against
    the literal taken from the source before the move."""
    server, port, _resolver = public
    cases = [
        ("file:///etc/passwd", "refusing scheme 'file': only http and https are "
         "fetched, and file:// or gopher:// in a watch target is an attempt rather "
         "than a mistake"),
        ("http:///nohost", "no host in URL"),
        (f"http://u:p@{NAME}/", "a watch target URL may not carry a user name or "
         "password: credentials belong in the persona vault, and a URL is stored, "
         "logged and shown"),
        ("http://metadata.google.internal/x", "metadata.google.internal is a cloud "
         "metadata endpoint. Reaching it from a collector steals our own credentials, "
         "which is worse than the SSRF this check is usually about"),
        (f"http://{NAME}:99999/", "the port in the URL is not a port"),
        ("http://127.0.0.1:8000/healthz", "127.0.0.1 resolves into private address "
         "space, which a watch target must not: fetching it would reach this "
         "deployment's own internal network"),
    ]
    for url, message in cases:
        with pytest.raises(CollectionError) as caught:
            fetch(url, timeout=5)
        assert str(caught.value) == message, url
    real = collection._is_blocked
    monkeypatch.setattr(collection, "_is_blocked",
                        lambda a: False if str(a) == PUBLIC else real(a))
    server.status = 503
    with pytest.raises(CollectionError) as caught:
        fetch(f"http://{NAME}:{port}/feed", timeout=5)
    assert str(caught.value) == "HTTP 503"
    server.status = 200
    server.redirects["/feed"] = ""
    with pytest.raises(CollectionError) as caught:
        fetch(f"http://{NAME}:{port}/feed", timeout=5)
    assert str(caught.value) == "HTTP 302 with no Location header"
    server.redirects["/feed"] = "/feed"
    with pytest.raises(CollectionError) as caught:
        fetch(f"http://{NAME}:{port}/feed", timeout=5)
    assert str(caught.value) == "redirect loop at 1 hop"
    server.redirects["/feed"] = "/a"
    server.redirects["/a"] = "/b"
    with pytest.raises(CollectionError) as caught:
        fetch(f"http://{NAME}:{port}/feed", timeout=5, max_redirects=1)
    assert str(caught.value) == (
        "more than 1 redirects. A chain this long is a loop or an attempt to "
        "exhaust the validator, and neither is a feed")


def test_a_forgotten_route_is_refused_once_a_proxy_is_configured(monkeypatch):
    lookups = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: lookups.append(a) or [])
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        fetch(f"http://{NAME}/feed")
    assert caught.value.code == "no_route"
    with pytest.raises(pinned_http.RouteUnavailable):
        collection.fetch_response(f"http://{NAME}/feed")
    monkeypatch.setenv(egress.PROXY_URL_ENV, "socks5://egress-proxy:1080")
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        fetch(f"http://{NAME}/feed")
    assert caught.value.code == "proxy_misconfigured"
    assert lookups == []


def test_error_class_names_the_subclass(public, monkeypatch):
    """run_once stores type(exc).__name__ as collection_run.error_class."""
    server, port, _resolver = public
    real = collection._is_blocked
    monkeypatch.setattr(collection, "_is_blocked",
                        lambda a: False if str(a) == PUBLIC else real(a))
    server.status = 503
    try:
        fetch(f"http://{NAME}:{port}/feed", timeout=5)
    except CollectionError as exc:
        recorded = type(exc).__name__
    assert recorded == "HttpStatusError"
