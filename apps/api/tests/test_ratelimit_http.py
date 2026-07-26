"""The HTTP half of rate limiting: subject derivation from a request, the
status a refusal gets, and the middleware ordering that decides whether a
refusal is served with security headers.

Deliberately database-free. The blanket middleware limit runs before
session validation and needs no connection, which is what makes it able to
brake an unauthenticated flood -- and what makes it testable here. The
per-endpoint, per-user limits are exercised over a real login in
`test_http_e2e.py`.
"""
from __future__ import annotations

import os

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

import pytest
from fastapi import Depends, FastAPI, Response
from fastapi.testclient import TestClient
from starlette.requests import Request

from noctornal_api.http.errors import install_error_handlers
from noctornal_api.http.limits import (
    build_limiter,
    client_ip,
    credential_subject,
    install_rate_limit_middleware,
    rate_limit,
    refuse,
)
from noctornal_api.ratelimit import (
    LIMITS,
    Decision,
    InProcessBackend,
    Limit,
    RateLimiter,
    Scope,
)


def _request(*, client_host: str | None = "203.0.113.9", headers=None,
             cookies=None) -> Request:
    """A Starlette Request with no server behind it."""
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        jar = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw.append((b"cookie", jar.encode()))
    return Request({
        "type": "http", "http_version": "1.1", "method": "GET", "path": "/",
        "headers": raw, "query_string": b"", "scheme": "http",
        "client": (client_host, 12345) if client_host else None,
        "server": ("testserver", 80),
    })


def _tiny_limiter(**overrides: Limit) -> RateLimiter:
    """The real catalogue with a few entries shrunk, so a test can trip a
    limit in three requests instead of six hundred."""
    catalogue = dict(LIMITS)
    catalogue.update(overrides)
    return RateLimiter(InProcessBackend(), limits=catalogue)


# ---------------------------------------------------------------------------
# Subject derivation
# ---------------------------------------------------------------------------

def test_x_forwarded_for_is_ignored_by_default():
    """The header is client-authored. Trusting it lets an attacker both
    escape their own limit (rotate the value) and exhaust someone else's
    (send the victim's address) -- the second is a remotely triggerable
    lockout of a named analyst, delivered through the control meant to
    prevent one."""
    os.environ.pop("NOCTORNAL_TRUSTED_PROXY_HOPS", None)
    request = _request(headers={"x-forwarded-for": "198.51.100.1, 198.51.100.2"})
    assert client_ip(request) == "203.0.113.9"


def test_x_forwarded_for_is_read_from_the_right_when_a_proxy_is_declared():
    """Counting from the LEFT is the classic mistake: the leftmost entry is
    whatever the client put there. The rightmost entries were appended by
    infrastructure the operator runs, so a deployment behind one proxy
    trusts exactly one entry from the right."""
    os.environ["NOCTORNAL_TRUSTED_PROXY_HOPS"] = "1"
    try:
        request = _request(headers={"x-forwarded-for": "1.2.3.4, 198.51.100.2"})
        assert client_ip(request) == "198.51.100.2"
    finally:
        os.environ.pop("NOCTORNAL_TRUSTED_PROXY_HOPS", None)


def test_a_short_forwarded_chain_falls_back_to_the_peer():
    """Fewer entries than declared proxies means the chain is not what the
    operator described -- so it is not a chain we can trust the left of."""
    os.environ["NOCTORNAL_TRUSTED_PROXY_HOPS"] = "2"
    try:
        request = _request(headers={"x-forwarded-for": "1.2.3.4"})
        assert client_ip(request) == "203.0.113.9"
    finally:
        os.environ.pop("NOCTORNAL_TRUSTED_PROXY_HOPS", None)


def test_a_nonsense_hop_count_is_treated_as_no_proxy():
    os.environ["NOCTORNAL_TRUSTED_PROXY_HOPS"] = "banana"
    try:
        request = _request(headers={"x-forwarded-for": "1.2.3.4"})
        assert client_ip(request) == "203.0.113.9"
    finally:
        os.environ.pop("NOCTORNAL_TRUSTED_PROXY_HOPS", None)


def test_the_bearer_token_and_the_cookie_reach_the_same_subject():
    """One caller must not get two buckets by switching credential
    transport mid-flood."""
    bearer = _request(headers={"authorization": "Bearer abc123"})
    cookie = _request(cookies={"__Host-session": "abc123"})
    assert credential_subject(bearer) == credential_subject(cookie)


def test_the_token_itself_is_never_the_key():
    assert "abc123" not in credential_subject(
        _request(headers={"authorization": "Bearer abc123"}))


def test_anonymous_callers_are_bucketed_by_address_not_lumped_together():
    """One shared anonymous bucket would let a single attacker deny service
    to every other unauthenticated caller -- including everyone trying to
    log in."""
    a = credential_subject(_request(client_host="198.51.100.1"))
    b = credential_subject(_request(client_host="198.51.100.2"))
    assert a != b


# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------

def test_a_measured_refusal_is_429_with_retry_after():
    limit = LIMITS["search"]
    problem = refuse(Decision(False, limit, 0, 7, 30))
    assert problem.status == 429
    assert problem.headers["Retry-After"] == "7"


def test_a_degraded_refusal_is_503_not_429():
    """429 says the caller asked for too much; 503 says we could not
    measure and this endpoint refuses rather than run unmetered. Telling a
    caller they exceeded a limit they did not exceed sends them looking in
    the wrong place -- and hides a backend outage behind a client error."""
    limit = LIMITS["analytics.suite"]
    problem = refuse(Decision(False, limit, 0, 5, 0, degraded=True))
    assert problem.status == 503
    assert "Retry-After" in problem.headers


def test_retry_after_is_never_zero():
    """Retry-After: 0 is an instruction to retry immediately, which is the
    one thing a limited client must not do."""
    problem = refuse(Decision(False, LIMITS["search"], 0, 0, 0))
    assert int(problem.headers["Retry-After"]) >= 1


# ---------------------------------------------------------------------------
# The blanket middleware, over a real app
# ---------------------------------------------------------------------------

@pytest.fixture
def app_with_tiny_blanket_limit():
    from noctornal_api.http.app import create_app
    app = create_app()
    app.state.limiter = _tiny_limiter(request=Limit(
        "request", quota=3, per_seconds=60, scope=Scope.CREDENTIAL, burst=3))
    return app


def test_the_blanket_limit_refuses_after_the_burst(app_with_tiny_blanket_limit):
    client = TestClient(app_with_tiny_blanket_limit)
    codes = [client.get("/api/v1/no-such-route").status_code for _ in range(5)]
    assert codes[:3] == [404, 404, 404]
    assert codes[3:] == [429, 429]


def test_the_429_is_problem_json(app_with_tiny_blanket_limit):
    client = TestClient(app_with_tiny_blanket_limit)
    for _ in range(4):
        response = client.get("/api/v1/no-such-route")
    assert response.status_code == 429
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["status"] == 429
    assert int(response.headers["Retry-After"]) >= 1


def test_the_429_still_carries_the_security_headers(app_with_tiny_blanket_limit):
    """Middleware order, asserted rather than assumed. The last middleware
    registered runs FIRST, so registering the limiter last would let every
    refusal -- the response an attacker sees most of -- return without
    nosniff, without a CSP and without no-store."""
    client = TestClient(app_with_tiny_blanket_limit)
    for _ in range(4):
        response = client.get("/api/v1/no-such-route")
    assert response.status_code == 429
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_healthz_is_never_limited(app_with_tiny_blanket_limit):
    """A load balancer polls /healthz. Limiting it means a burst of user
    traffic makes the instance look dead and gets it pulled from rotation --
    a rate limit that causes the outage."""
    client = TestClient(app_with_tiny_blanket_limit)
    for _ in range(50):
        assert client.get("/healthz").status_code == 200


def test_successful_responses_advertise_the_limit(app_with_tiny_blanket_limit):
    client = TestClient(app_with_tiny_blanket_limit)
    response = client.get("/healthz")  # exempt, so the middleware adds nothing
    assert "RateLimit-Limit" not in response.headers
    response = client.get("/api/v1/no-such-route")
    assert response.headers["RateLimit-Limit"] == "3"
    assert response.headers["RateLimit-Remaining"] == "2"


def test_different_credentials_get_different_buckets(app_with_tiny_blanket_limit):
    client = TestClient(app_with_tiny_blanket_limit)
    for _ in range(4):
        client.get("/api/v1/no-such-route", headers={"authorization": "Bearer one"})
    # A second caller is unaffected by the first's flood.
    assert client.get("/api/v1/no-such-route",
                      headers={"authorization": "Bearer two"}).status_code == 404


# ---------------------------------------------------------------------------
# The dependency path
# ---------------------------------------------------------------------------

def test_the_dependency_puts_its_headers_on_the_response():
    """A limit applied in a dependency has to reach the response object, or
    the headers exist only on the refusal and a client cannot pace itself."""
    app = FastAPI()
    install_error_handlers(app)
    app.state.limiter = _tiny_limiter(request=Limit(
        "request", quota=2, per_seconds=60, scope=Scope.CREDENTIAL, burst=2))

    @app.get("/thing", dependencies=[Depends(rate_limit("request"))])
    def thing() -> dict:
        return {"ok": True}

    client = TestClient(app)
    first = client.get("/thing")
    assert first.status_code == 200
    assert first.headers["RateLimit-Remaining"] == "1"
    client.get("/thing")
    third = client.get("/thing")
    assert third.status_code == 429


def test_a_typo_in_a_limit_name_fails_at_import_not_at_request():
    """`rate_limit("analytics.suit")` must not mean "unlimited". Resolving
    the name when the decorator runs turns a silent hole into a boot
    failure."""
    with pytest.raises(KeyError):
        rate_limit("analytics.suit")


def test_build_limiter_honours_the_off_switch():
    previous = os.environ.get("NOCTORNAL_RATELIMIT")
    os.environ["NOCTORNAL_RATELIMIT"] = "off"
    try:
        assert build_limiter().enabled is False
    finally:
        if previous is None:
            os.environ.pop("NOCTORNAL_RATELIMIT", None)
        else:
            os.environ["NOCTORNAL_RATELIMIT"] = previous


def test_two_apps_do_not_share_meters():
    """The limiter lives on app.state, not in a module global. A shared
    global would make one test's burst fail the next test's first request,
    and a flaky security test is a deleted security test."""
    from noctornal_api.http.app import create_app
    a, b = create_app(), create_app()
    assert a.state.limiter is not b.state.limiter


def test_the_middleware_is_installed_on_a_default_app():
    """Belt and braces: a refactor that drops the install call would leave
    every test above passing against a hand-built app while the real one
    ships unlimited."""
    app = FastAPI()
    install_rate_limit_middleware(app)
    app.state.limiter = _tiny_limiter(request=Limit(
        "request", quota=1, per_seconds=60, scope=Scope.CREDENTIAL, burst=1))

    @app.get("/x")
    def x() -> dict:
        return {}

    client = TestClient(app)
    assert client.get("/x").status_code == 200
    assert client.get("/x").status_code == 429


# ---------------------------------------------------------------------------
# Regressions from the adversarial review pass (2026-07-25)
#
# Each is a defect that shipped, was found by a reviewer trying to break the
# limiter rather than to confirm it, and was reproduced against the running
# app before being fixed.
# ---------------------------------------------------------------------------

@pytest.fixture
def app_with_tiny_blanket_limits():
    """Both blanket meters shrunk. The credential one alone was what shipped,
    and what the review broke."""
    from noctornal_api.http.app import create_app
    app = create_app()
    app.state.limiter = _tiny_limiter(
        request=Limit("request", quota=3, per_seconds=60,
                      scope=Scope.CREDENTIAL, burst=3),
        **{"request.source": Limit("request.source", quota=6, per_seconds=60,
                                   scope=Scope.IP, burst=6)})
    return app


def test_rotating_the_bearer_token_does_not_escape_the_blanket_limit(
        app_with_tiny_blanket_limits):
    """THE critical regression.

    The blanket ceiling was keyed only on the presented credential, and
    nothing validates that a bearer token is a live session, so a fresh
    random token per request minted a fresh empty bucket per request. The
    reviewer reproduced it against the real app: with the limit at 3, a
    fixed token gave 27 refusals in 30 requests and a rotating one gave
    zero. Worse, because the bearer branch returned early it suppressed the
    address fallback, so sending one garbage header made a caller strictly
    LESS limited than sending no credential at all. The control inverted.

    `request.source` is keyed on the peer address, which a caller cannot
    mint, so a rotating token now only subdivides a budget it cannot leave.
    """
    import secrets

    client = TestClient(app_with_tiny_blanket_limits)
    codes = []
    for _ in range(30):
        codes.append(client.get(
            "/api/v1/no-such-route",
            headers={"authorization": "Bearer " + secrets.token_hex(16)},
        ).status_code)
    assert 429 in codes, "a rotating token must not escape the ceiling"
    assert codes.count(429) >= 20


def test_rotating_the_session_cookie_does_not_escape_it_either(
        app_with_tiny_blanket_limits):
    """The cookie branch has the same shape and had the same hole. The
    review found the bearer path; this one was a line below it."""
    client = TestClient(app_with_tiny_blanket_limits)
    codes = []
    for i in range(30):
        client.cookies.set("__Host-session", "rotating-" + str(i))
        codes.append(client.get("/api/v1/no-such-route").status_code)
    assert 429 in codes


def test_x_forwarded_for_is_read_across_repeated_header_lines():
    """RFC 9110 makes repeated field lines equivalent to one comma-joined
    value, and HAProxy's `option forwardfor` emits a SEPARATE line by
    default. Reading only the first line meant `parts[-hops]` indexed a list
    the client authored in full, with the proxy's own entry sitting unread
    in the second line -- the whole count-from-the-right defence reading the
    attacker's value."""
    os.environ["NOCTORNAL_TRUSTED_PROXY_HOPS"] = "1"
    try:
        request = Request({
            "type": "http", "http_version": "1.1", "method": "GET", "path": "/",
            # Two separate header lines, as a real proxy emits them.
            "headers": [(b"x-forwarded-for", b"1.2.3.4"),
                        (b"x-forwarded-for", b"198.51.100.2")],
            "query_string": b"", "scheme": "http",
            "client": ("203.0.113.9", 1234), "server": ("testserver", 80),
        })
        assert client_ip(request) == "198.51.100.2", (
            "the proxy's entry is in the SECOND line; reading only the first "
            "reads the client's own value")
    finally:
        os.environ.pop("NOCTORNAL_TRUSTED_PROXY_HOPS", None)


def test_the_middleware_does_not_block_the_event_loop():
    """`RedisBackend` drives the SYNCHRONOUS redis-py client. Called from an
    `async def` middleware it would do blocking socket I/O on the loop
    thread, serialising every request in the process behind one Redis round
    trip -- and the 250ms socket timeout would cost 250ms of loop time per
    request before it even raised. That defeats the fail-OPEN policy this
    limit exists to have: a sick Redis must not become a sick API.

    Asserted by having the backend record which thread it ran on.
    """
    import threading

    from noctornal_api.http.app import create_app

    ran_on: list = []

    class ThreadRecordingBackend(InProcessBackend):
        def measure(self, key, emission_us, tolerance_us):
            ran_on.append(threading.current_thread().name)
            return super().measure(key, emission_us, tolerance_us)

    app = create_app()
    app.state.limiter = RateLimiter(ThreadRecordingBackend(), limits=dict(LIMITS))

    main = threading.current_thread().name
    TestClient(app).get("/api/v1/no-such-route")
    assert ran_on, "the blanket limiter did not run at all"
    assert all(name != main for name in ran_on), (
        "the blanket limit ran on the event-loop thread; a slow Redis would "
        "stall every request in the process")


def test_a_response_returning_handler_still_advertises_its_own_limit():
    """FastAPI discards `sub_response` entirely when a handler returns a
    Response object directly -- which evidence export and download both do.
    The endpoint's headers vanished, and the blanket middleware then filled
    the gap with its own ceiling, so the client was not merely told nothing,
    it was told the wrong number.

    `enforce` now also stashes the decision on `request.state`, and the
    middleware writes that onto the outgoing response. Reproduced here by
    calling `enforce` from inside a Response-returning handler, which is
    exactly the shape FastAPI throws the headers away for.
    """
    from fastapi.responses import PlainTextResponse

    from noctornal_api.http.limits import enforce

    app = FastAPI()
    install_error_handlers(app)
    install_rate_limit_middleware(app)
    app.state.limiter = _tiny_limiter(
        request=Limit("request", quota=500, per_seconds=60,
                      scope=Scope.CREDENTIAL, burst=500),
        search=Limit("search", quota=7, per_seconds=60, scope=Scope.CREDENTIAL,
                     burst=7))

    @app.get("/raw")
    def raw(request: Request, response: Response) -> PlainTextResponse:
        enforce(request, response, "search", "u:test")
        # Returning a Response object: `response` above is now discarded.
        return PlainTextResponse("bytes")

    result = TestClient(app).get("/raw")
    assert result.status_code == 200
    assert result.headers["RateLimit-Limit"] == "7", (
        "the endpoint's own limit, not the blanket ceiling's 500")


def test_a_peek_guard_does_not_advertise_a_meter_the_caller_did_not_spend():
    """Both login dependencies wrote the same header names, so the peek
    guard overwrote the attempt limit's numbers and a 200 described a meter
    the caller never touched."""
    app = FastAPI()
    install_error_handlers(app)
    app.state.limiter = _tiny_limiter(
        request=Limit("request", quota=11, per_seconds=60,
                      scope=Scope.CREDENTIAL, burst=11))

    @app.get("/thing", dependencies=[Depends(rate_limit("request"))])
    def thing() -> dict:
        return {}

    response = TestClient(app).get("/thing")
    assert response.headers["RateLimit-Limit"] == "11"
