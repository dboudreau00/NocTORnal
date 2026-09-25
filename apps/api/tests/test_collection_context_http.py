"""RunContext through the REAL collection.fetch_response (2026-09-24),
because the context tests must not all run on a stub fetcher.

A loopback stand-in server answers a reserved name, the resolver is told
that name is the loopback address, and the classifier is told that
address is public, the seam test_collection_ssrf_rebinding.py uses. So
the pinned client really resolves, dials, reads under the one Deadline,
and hands back its Fetched, and RunContext's rules are held against it.
Pure: no database, no network beyond loopback.
"""
from __future__ import annotations

import http.server
import socket
import socketserver
import threading
import time
from uuid import uuid4

import pytest

NAME = "board.example.test"
_REAL_GETADDRINFO = socket.getaddrinfo


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - the stdlib's naming
        server = self.server
        server.seen.append(self.path)
        route = server.routes.get(self.path.split("#", 1)[0])
        if route is None:
            body = b"<p>page</p>"
            status, headers = 200, {}
        else:
            status, headers, body = route
        if server.delay:
            time.sleep(server.delay)
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class _Server(http.server.HTTPServer):
    def __init__(self):
        self.seen: list[str] = []
        self.routes: dict[str, tuple] = {}
        self.delay = 0.0
        super().__init__(("127.0.0.1", 0), _Handler)

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@pytest.fixture
def server(monkeypatch):
    from noctornal_api import collection

    real = collection._is_blocked
    monkeypatch.setattr(collection, "_is_blocked",
                        lambda a: False if str(a) == "127.0.0.1" else real(a))

    def resolver(host, port, *args, **kwargs):
        if host == NAME:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     ("127.0.0.1", int(port) if port else 0))]
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    srv = _Server()
    thread = threading.Thread(target=srv.serve_forever,
                              kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


class Adapter:
    key = "stubforum"
    requires_authority = True
    run_seconds = 30.0
    max_pages = 10
    max_page_bytes = 100_000
    max_run_bytes = 1_000_000


class Limiter:
    def __init__(self):
        self.calls = 0

    def wait(self, *_a):
        self.calls += 1

    def wait_persona(self, *_a):
        self.calls += 1


def _context(server, *, adapter=None, policy=None, limiter=None):
    from noctornal_api.collection import SourceRow
    from noctornal_api.collection_context import RunContext
    from noctornal_api.egress_policy import PUBLIC_POLICY, EgressRoute

    base = f"http://{NAME}:{server.server_port}/forums/7/"
    source = SourceRow(uuid4(), "XENFORO", "ctx", base, "stubforum", "AMBER", "C",
                       100.0, True, None, None, {}, None, None)
    route = EgressRoute.direct("persona", str(uuid4()), policy or PUBLIC_POLICY,
                               context=f"run:{uuid4()}")
    return RunContext(source=source, run_id=uuid4(), adapter=adapter or Adapter(),
                      route=route, limiter=limiter or Limiter())


def test_a_same_origin_302_is_followed_and_paced_through_the_real_client(server):
    server.routes["/forums/7/"] = (302, {"Location": "/showthread.php?tid=42"}, b"")
    limiter = Limiter()
    ctx = _context(server, limiter=limiter)
    with ctx:
        fetched = ctx.fetch("/forums/7/")
    assert fetched.status == 200 and fetched.body == b"<p>page</p>"
    assert server.seen == ["/forums/7/", "/showthread.php?tid=42"], (
        "the followed request carries the query the server named")
    assert limiter.calls == 2, "every request is paced, hops included"
    assert [e["status"] for e in ctx.logged()] == [302, 200]


def test_an_off_origin_302_comes_back_unfollowed_as_a_fetched_with_its_location(server):
    server.routes["/forums/7/"] = (302, {"Location": "https://sso.example.test/login?next=/"}, b"")
    ctx = _context(server)
    with ctx:
        fetched = ctx.fetch("/forums/7/")
    assert fetched.status == 302
    assert fetched.location == "https://sso.example.test/login?next=/"
    assert server.seen == ["/forums/7/"]


def test_a_302_to_a_login_page_is_classified_as_a_login_wall(server):
    from noctornal_api.collection import LoginWall

    server.routes["/threads/9/"] = (302, {"Location": "/login/?redirect=/threads/9/"}, b"")
    server.routes["/login/?redirect=/threads/9/"] = (200, {}, b"<form>sign in</form>")

    def adapter_read(ctx):
        page = ctx.fetch("/threads/9/", accept_status={401, 403})
        if "/login/" in page.url:
            raise LoginWall("The board asked for a sign-in.")
        return page

    ctx = _context(server)
    with ctx, pytest.raises(LoginWall):
        adapter_read(ctx)


def test_one_deadline_bounds_the_whole_poll(server):
    from noctornal_api.collection import BudgetSpent

    server.delay = 0.9
    adapter = Adapter()
    adapter.run_seconds = 2.0
    ctx = _context(server, adapter=adapter)
    read = 0
    started = time.monotonic()
    with ctx, pytest.raises(BudgetSpent):
        for n in range(3):
            ctx.fetch(f"/threads/{n}/")
            read += 1
    assert time.monotonic() - started < 3.5, "the poll ended inside its allowance"
    assert 1 <= read < 3
    assert any("stopped at its budget" in n for n in ctx.notes())


def test_a_page_cut_by_the_run_budget_is_budget_spent_through_the_real_client(server):
    from noctornal_api.collection import BudgetSpent

    server.routes["/big/"] = (200, {}, b"x" * 5000)
    adapter = Adapter()
    adapter.max_run_bytes = 3000
    ctx = _context(server, adapter=adapter)
    with ctx:
        ctx.fetch("/small/")
        with pytest.raises(BudgetSpent):
            ctx.fetch("/big/")


def test_a_route_refusal_is_egress_unavailable_and_nothing_is_sent(server):
    from noctornal_api.collection import EgressUnavailable
    from noctornal_api.egress_policy import RoutePolicy

    closed = RoutePolicy("persona", any_public=False)
    ctx = _context(server, policy=closed)
    with ctx, pytest.raises(EgressUnavailable):
        ctx.fetch("/forums/7/")
    assert server.seen == []
