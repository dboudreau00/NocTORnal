"""Wiring the rate limiter into HTTP: subject derivation, the dependency that guards a named
endpoint, and the blanket middleware behind it.

The middleware applies one ceiling to every request, keyed on the presented credential; it
needs no database, so it also limits an unauthenticated flood, and it fails open when the
backend is down (`ratelimit.py`) so a Redis restart cannot take the tool offline. The
dependency applies a much smaller limit to a named endpoint, keyed on the authenticated user,
after the session and before the access gate; it fails closed, because on those endpoints
being unlimited is the danger. X-Forwarded-For is read only when
`NOCTORNAL_TRUSTED_PROXY_HOPS` names the proxies the operator runs, and then counted from the
right: a client-controlled header would let an attacker rotate past the limit or exhaust a
named analyst's login bucket.
"""
from __future__ import annotations

import logging
import os
import re
from collections.abc import Awaitable, Callable

import psycopg
from fastapi import Depends, Request, Response
from fastapi.routing import APIRoute
from psycopg.types.json import Json
from starlette.exceptions import HTTPException

from noctornal_api.http.errors import Problem
from noctornal_api.ratelimit import (
    LIMITS,
    Decision,
    InProcessBackend,
    RateLimiter,
    Scope,
    hashed,
    ip_subject,
)

log = logging.getLogger("noctornal.ratelimit")

_OFF = {"0", "off", "false", "no", "disabled"}

#: The words the eviction warning opens with. A constant rather than a
#: string in the call, so the test that pins the warning and the code that
#: emits it cannot drift apart silently.
EVICTION_WARNING = "RATE-LIMIT REDIS EVICTS KEYS"


def rate_limiting_disabled() -> bool:
    """Is the NOCTORNAL_RATELIMIT off-switch thrown?

    One reader for the off-set: `build_limiter` and the readiness register (`readiness.py`)
    both ask it, so a deployment cannot be reported ready with a limiter that never built.
    """
    setting = os.environ.get("NOCTORNAL_RATELIMIT", "").strip().lower()
    return setting in _OFF


#: The proxies the operator runs in front of the API (see the module note on
#: X-Forwarded-For above).
HOPS_ENV = "NOCTORNAL_TRUSTED_PROXY_HOPS"


def trusted_proxy_hops() -> int:
    """How many proxies sit in front of this process, as the operator said.

    One reader for the count: `client_ip` takes the address from it and the readiness register
    (`proxy_hops_declared`) reports on it, so the two cannot read the variable differently.
    Unset, negative or not a number is 0."""
    raw = os.environ.get(HOPS_ENV, "0")
    try:
        return max(0, int(raw))
    except ValueError:
        log.warning("%s=%r is not a number; treating as 0", HOPS_ENV, raw)
        return 0


def client_ip(request: Request) -> str | None:
    """The peer address, or the address the outermost trusted proxy saw.

    Every `X-Forwarded-For` field line is joined before splitting: RFC 9110 makes repeated lines
    one comma-joined value, and HAProxy's `option forwardfor` appends a separate line, so reading
    only the first would index a list the client wrote in full and defeat counting from the
    right.
    """
    hops = trusted_proxy_hops()
    if hops:
        lines = request.headers.getlist("x-forwarded-for")
        forwarded = ", ".join(line for line in lines if line)
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if len(parts) >= hops:
                return parts[-hops]
            # Fewer entries than proxies means the chain is not what the
            # operator described. Fall through to the peer address rather
            # than trusting a short, client-authored list.
            log.warning("X-Forwarded-For has %d entries, expected at least %d",
                        len(parts), hops)
    return request.client.host if request.client else None


def credential_subject(request: Request) -> str:
    """A stable per-caller key with no database lookup.

    The token is hashed, never used as a key: a Redis key is not a secret store, and `KEYS *` on
    a shared instance would hand over live session tokens. This key subdivides; it does not
    bound. Nothing here verifies the token, so a caller rotating tokens mints a fresh meter each
    time; the middleware's address-scoped ceiling (`request.source`) is what bounds them. An
    anonymous caller falls back to their address, so one attacker cannot share, and exhaust,
    every other anonymous caller's bucket.
    """
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        if token:
            return "tok:" + hashed(token)
    cookie = request.cookies.get("__Host-session")
    if cookie:
        return "tok:" + hashed(cookie)
    return ip_subject(client_ip(request))


def build_limiter() -> RateLimiter:
    """Construct the limiter for one application instance.

    Held on `app.state` rather than in a module global so two apps in one
    test process do not share meters -- a limit leaking between tests is a
    flaky suite, and a flaky security test gets deleted.
    """
    if rate_limiting_disabled():
        log.warning(
            "RATE LIMITING IS DISABLED (NOCTORNAL_RATELIMIT=%s). Login guessing "
            "is braked only by the account lockout, and the analytics endpoints "
            "are an unmetered CPU-bound path for any authenticated analyst.",
            os.environ.get("NOCTORNAL_RATELIMIT", "").strip().lower(),
        )
        return RateLimiter(InProcessBackend(), enabled=False)

    url = os.environ.get("REDIS_URL", "").strip()
    if not url:
        log.warning(
            "REDIS_URL is not set; rate limiting is PER PROCESS. N uvicorn "
            "workers will enforce N times the configured rate. Correct for a "
            "single-process development instance, wrong for a deployment.",
        )
        return RateLimiter(InProcessBackend())

    from noctornal_api.ratelimit_redis import RedisBackend

    backend = RedisBackend(url)
    if backend.ping():
        log.info("rate limiting via Redis at %s", redacted_url(url))
        _warn_if_evicting(backend, url)
    else:
        # Not fatal: the per-limit policy says what an unreachable backend means, and refusing to
        # boot would make a cache outage an application outage; but it is logged loudly. No
        # eviction probe either: it would only add a second timeout.
        log.error(
            "rate-limit Redis at %s did not answer PING. Limits with "
            "on_backend_failure=DENY will refuse until it does.", redacted_url(url),
        )
    return RateLimiter(backend)


def _warn_if_evicting(backend, url: str) -> None:
    """Shout at startup if the limiter's Redis may delete its own meters.

    Under an evicting policy, memory pressure deletes rate-limit keys, and an evicted meter is a
    reset meter (docs/16), so this is reported in the same voice as RATE LIMITING IS DISABLED.
    The bundled compose file runs `noeviction`; this matters for an operator's own Redis and for
    a dev stack created from an older compose file, which keeps `allkeys-lru` until the
    container is recreated (the warning says how). A Redis that refuses CONFIG (managed
    offerings usually rename it) is reported as UNKNOWN below WARNING, because nagging every
    boot trains people to ignore the line that matters.
    """
    from noctornal_api.ratelimit_redis import is_evicting_policy

    policy = backend.maxmemory_policy()
    if policy is None:
        log.info(
            "rate-limit Redis at %s: maxmemory-policy is unknown (CONFIG GET was "
            "refused, which managed Redis usually does). Confirm out of band that "
            "it runs with maxmemory-policy=noeviction (docs/16 C8).",
            redacted_url(url),
        )
    elif is_evicting_policy(policy):
        log.warning(
            "%s (maxmemory-policy=%s at %s). Under memory pressure Redis will "
            "delete live rate-limit meters, and a deleted meter admits the "
            "subject it was refusing with a full burst: the limiter stops "
            "limiting whoever the cache evicts, silently. Run the limiter's "
            "Redis with maxmemory-policy=noeviction, or give it its own "
            "instance (docs/16 C8). The bundled infra/docker-compose.yml runs "
            "noeviction; a dev stack started from an older copy of that file "
            "keeps its old policy until `docker compose -f "
            "infra/docker-compose.yml up -d` recreates it.",
            EVICTION_WARNING, policy, redacted_url(url),
        )


#: `password=` as a query argument, up to the next argument or fragment.
_QUERY_PASSWORD = re.compile(r"(?i)([?&]password=)[^&#]*")


def redacted_url(url: str) -> str:
    """A Redis URL with its password masked, for a log line or readiness evidence.

    The password can sit in the userinfo or in a `password=` query argument, which redis-py
    honours just the same; both are masked, the argument matched without regard to case,
    because masking a value redis-py would not have read costs nothing."""
    if "@" in url:
        scheme, _, rest = url.partition("://")
        url = f"{scheme}://***@{rest.rpartition('@')[2]}"
    return _QUERY_PASSWORD.sub(r"\1***", url)


def limiter_of(request: Request) -> RateLimiter:
    return request.app.state.limiter


def _audit(conn, *, action: str, actor_id, detail: dict, ip_hash: bytes | None) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail,
                outcome, ip_hash)
           VALUES (%s, %s, %s, 'ratelimit', NULL, %s, 'DENIED', %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, Json(detail), ip_hash),
    )


def _ip_hash(request: Request) -> bytes | None:
    import hashlib
    address = client_ip(request)
    return hashlib.sha256(address.encode()).digest() if address else None


def refuse(decision: Decision) -> Problem:
    """Turn a refusal into the right status.

    429 and 503 are not interchangeable here. 429 means *you* asked for too
    much and the headers say when to come back. 503 means the limiter could
    not measure anything and this endpoint's policy is to refuse rather than
    guess -- the caller did nothing wrong, and telling them they exceeded a
    limit they did not exceed sends them looking in the wrong place.
    """
    if decision.degraded:
        return Problem(
            503, "Service unavailable",
            "rate limiting is unavailable, so this endpoint is refusing "
            "requests rather than running unmetered; retry shortly",
            headers={"Retry-After": str(max(1, decision.retry_after_seconds))},
        )
    return Problem(
        429, "Too many requests",
        f"rate limit '{decision.limit.name}' exceeded; retry in "
        f"{max(1, decision.retry_after_seconds)}s",
        headers=decision.headers,
    )


def enforce(request: Request, response: Response, name: str, subject: str, *,
            conn=None, actor_id=None, consume: bool = True) -> Decision:
    """Check one limit and apply the outcome. Returns on success.

    `consume=False` reads the meter without spending from it -- used where
    the metered event is not the request (see `consume_on_failure`).
    """
    limiter = limiter_of(request)
    decision = limiter.check(name, subject) if consume \
        else limiter.peek(name, subject)

    # Headers describe the meter the caller SPENT. A peek guard reports on a
    # meter the caller did not touch, and since both write the same header
    # names the peek would overwrite the real one -- a successful login
    # would advertise the failure meter's numbers.
    if consume:
        for key, value in decision.headers.items():
            response.headers[key] = value
        # ...and stash it, because FastAPI discards `sub_response` when a handler returns a
        # Response directly (evidence export and download do). The blanket middleware writes
        # the endpoint's headers onto the real response, or the client is told the blanket
        # ceiling, which is the wrong number.
        request.state.rate_limit_decision = decision

    if decision.allowed:
        return decision

    # Audited, but at most once per window per subject: see
    # RateLimiter.should_audit for why unbounded auditing of a flood is a
    # worse denial of service than the flood.
    if conn is not None and limiter.should_audit(name, subject):
        try:
            _audit(
                conn,
                action="RATE_LIMIT_DEGRADED" if decision.degraded
                else "RATE_LIMIT_EXCEEDED",
                actor_id=actor_id,
                detail={"limit": name, "scope": decision.limit.scope.value,
                        "quota": decision.limit.quota,
                        "per_seconds": decision.limit.per_seconds},
                ip_hash=_ip_hash(request),
            )
        except psycopg.Error:
            log.warning("could not audit rate-limit denial for %s", name, exc_info=True)
    log.warning("rate limit %s hit (degraded=%s)", name, decision.degraded)
    raise refuse(decision)


def consume_on_failure(request: Request, name: str) -> None:
    """Spend one slot on an IP-scoped meter because something failed.

    A limit on login attempts tight enough to stop spraying would take a NAT'd organisation
    offline (`ratelimit.py`); a meter of failures never moves for analysts signing on
    successfully. Never raises: this runs on a path already returning 401, where a metering
    hiccup must not become a 500.
    """
    try:
        limiter_of(request).check(name, ip_subject(client_ip(request)))
    except Exception:  # noqa: BLE001
        log.warning("could not record a failure against %s", name, exc_info=True)


def rate_limit_peek(name: str):
    """Guard an endpoint on a meter it does not itself consume.

    Declared as a dependency so the refusal happens BEFORE the handler --
    on login that means before the Argon2id verify, which is the expensive
    part and therefore the part an attacker wants to keep triggering.
    """
    limit = LIMITS[name]
    if limit.scope is not Scope.IP:
        raise ValueError(f"{name}: peek guards are IP-scoped only")
    from noctornal_api.http.deps import get_conn

    def _dep(
        request: Request,
        response: Response,
        conn: psycopg.Connection = Depends(get_conn),
    ) -> None:
        enforce(request, response, name, ip_subject(client_ip(request)),
                conn=conn, consume=False)

    return _dep


def rate_limit(name: str):
    """Dependency factory guarding one endpoint with one named limit.

    The subject follows the limit's own scope, so an endpoint cannot key a
    per-user limit on the peer address by mistake -- behind a corporate NAT
    that would rate-limit a whole police force as one caller.
    """
    limit = LIMITS[name]  # fail at import time on a typo, not at request time

    if limit.scope is Scope.USER:
        # Imported here: deps imports errors, and a module-level import of
        # deps from limits would close a cycle once deps starts using
        # limits for its own gating.
        from noctornal_api.http.deps import CurrentUser, current_user, get_conn

        def _user_dep(
            request: Request,
            response: Response,
            user: CurrentUser = Depends(current_user),
            conn: psycopg.Connection = Depends(get_conn),
        ) -> None:
            enforce(request, response, name, f"u:{user.user_id}",
                    conn=conn, actor_id=user.user_id)

        return _user_dep

    if limit.scope is Scope.IP:
        from noctornal_api.http.deps import get_conn

        def _ip_dep(
            request: Request,
            response: Response,
            conn: psycopg.Connection = Depends(get_conn),
        ) -> None:
            enforce(request, response, name, ip_subject(client_ip(request)), conn=conn)

        return _ip_dep

    def _credential_dep(request: Request, response: Response) -> None:
        enforce(request, response, name, credential_subject(request))

    return _credential_dep


def _blanket_check(limiter: RateLimiter, credential: str, source: str):
    """Both blanket meters, in one call so the middleware crosses the
    thread boundary once.

    Returns the first refusal, else the credential decision -- whose headers
    are the more useful of the two, because the source ceiling is a flood
    guard rather than a number an honest client should pace itself against.
    """
    by_credential = limiter.check("request", credential)
    if not by_credential.allowed:
        return by_credential
    by_source = limiter.check("request.source", source)
    if not by_source.allowed:
        return by_source
    return by_credential


def install_rate_limit_middleware(app) -> None:
    """The blanket ceiling: two meters, and it takes both.

    Middleware rather than a global dependency, so it covers every path, the static UI mount and
    any route added later included. The credential-scoped meter subdivides fairly between the
    analysts behind one address; the address-scoped one is the ceiling, since a client-supplied
    token can be rotated for a fresh bucket. Run off the event loop (`run_in_threadpool`)
    because `RedisBackend` drives the synchronous redis-py client: blocking the loop, a slow
    Redis would stall every request and make failing open meaningless.
    """
    from starlette.concurrency import run_in_threadpool

    @app.middleware("http")
    async def _blanket(request: Request, call_next):
        limiter: RateLimiter = request.app.state.limiter
        # /healthz is what a load balancer polls. Limiting it means a burst
        # of user traffic can make the instance look dead and get it pulled
        # out of rotation, turning a rate limit into an outage.
        if request.url.path == "/healthz":
            return await call_next(request)

        decision = await run_in_threadpool(
            _blanket_check, limiter, credential_subject(request),
            ip_subject(client_ip(request)))
        if not decision.allowed:
            log.warning("blanket %s limit hit for %s", decision.limit.name,
                        request.url.path)
            problem = refuse(decision)
            from noctornal_api.http.errors import problem_response
            return problem_response(problem.status, problem.title, problem.detail,
                                    problem.type, problem.headers)

        response = await call_next(request)
        # A specific endpoint limit's numbers beat the blanket ceiling's, or a caller who hit a
        # small endpoint limit is shown the wrong number. The endpoint's decision arrives via
        # request.state because FastAPI drops `sub_response` when a handler returns a Response.
        endpoint = getattr(request.state, "rate_limit_decision", None)
        source = endpoint or decision
        for key, value in source.headers.items():
            response.headers[key] = value
        return response


# ---------------------------------------------------------------------------
# Body caps: refusing an oversized body BEFORE it is buffered
# ---------------------------------------------------------------------------
#
# Evidence matters most: it lands under a COMPLIANCE object lock that no credential can shorten.
# Two mechanisms, because routes read their bodies differently. `read_body_capped` is for a
# handler that reads the raw body itself. `BodyCappedRoute` with `body_cap` is for a multipart
# upload, which FastAPI parses before it resolves any dependency, so only the route class can
# stand in front of the parser: it wraps the ASGI `receive` and refuses on the chunk that
# crosses the cap. In both, `Content-Length` is a reason to refuse early, never to accept: a
# declared length over the cap is refused before a byte is read, and anything else is still
# measured chunk by chunk.


def body_too_large(cap: int, what: str, *, declared: int | None = None) -> Problem:
    """The one 413 for every over-cap body, with the cap in the message so the caller can act.

    `Connection: close` is set because the rest of the body is never read and the server closes
    the socket after this response; saying so lets a well-behaved client stop sending.
    """
    detail = (f"{what} is capped at {cap} bytes; the request was refused at "
              f"the cap rather than buffered whole")
    if declared is not None:
        detail += f" (the request declared {declared} bytes)"
    return Problem(413, "Payload too large", detail,
                   headers={"Connection": "close"})


def declared_length(request: Request) -> int | None:
    """Content-Length as an integer, or None when absent or unparseable.

    Never trusted as a BOUND -- a chunked body has no length and a lying
    client can declare any -- only as an early exit. That is why every
    caller below still measures the stream.
    """
    raw = request.headers.get("content-length")
    if raw is None:
        return None
    try:
        length = int(raw)
    except ValueError:
        return None
    return length if length >= 0 else None


async def read_body_capped(request: Request, cap: int, *, what: str) -> bytes:
    """Read the request body, refusing on the chunk that crosses `cap`.

    Use it instead of `await request.body()`, which buffers everything before a length check can
    run. The process never holds more than the cap plus one chunk, and a declared length over
    the cap is refused before the first chunk is read.
    """
    declared = declared_length(request)
    if declared is not None and declared > cap:
        raise body_too_large(cap, what, declared=declared)
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > cap:
            raise body_too_large(cap, what)
        chunks.append(chunk)
    return b"".join(chunks)


def capped_receive(receive: Callable[[], Awaitable[dict]], cap: int, *,
                   what: str) -> Callable[[], Awaitable[dict]]:
    """An ASGI `receive` that raises the 413 on the chunk crossing `cap`.

    Whatever reads through this -- Starlette's multipart parser, a JSON
    body read, anything -- gets the chunks below the cap and an exception
    instead of the one that crosses it. The exception is a `Problem`, which
    the route's exception wrapper turns into the problem+json response, so
    the refusal is the same shape as every other refusal in the API.
    """
    total = 0

    async def _receive() -> dict:
        nonlocal total
        message = await receive()
        if message["type"] == "http.request":
            total += len(message.get("body", b""))
            if total > cap:
                raise body_too_large(cap, what)
        return message

    return _receive


#: The attribute `body_cap` leaves on an endpoint and `BodyCappedRoute`
#: reads. One name in one place, so the marker and its reader cannot spell
#: it differently.
_BODY_CAP_ATTR = "__body_cap__"


def body_cap(cap: int | Callable[[], int], *, what: str):
    """Mark an endpoint's body cap for `BodyCappedRoute` to enforce.

    `cap` may be a callable, read at request time, so a test can lower it instead of sending
    256 MB. The marker does nothing unless the router is built with
    `route_class=BodyCappedRoute`; `test_body_caps_http_pg.py` proves the two are connected.
    """
    def mark(endpoint):
        setattr(endpoint, _BODY_CAP_ATTR, (cap, what))
        return endpoint
    return mark


class BodyCappedRoute(APIRoute):
    """An `APIRoute` that enforces a `body_cap` marker on its endpoint.

    Only endpoints carrying the marker are wrapped, so declaring the class on a router caps
    nothing by accident. A route class, not a dependency, because FastAPI spools a multipart
    upload before any dependency runs; the route handler is the one seam between the ASGI
    `receive` and the parser. FastAPI 0.141 calls `get_route_handler()` on the original route
    object at request time, so the override survives `include_router`.
    """

    def get_route_handler(self):
        original = super().get_route_handler()
        marker = getattr(self.endpoint, _BODY_CAP_ATTR, None)
        if marker is None:
            return original
        cap_of, what = marker

        async def handler(request: Request) -> Response:
            cap = cap_of() if callable(cap_of) else cap_of
            declared = declared_length(request)
            if declared is not None and declared > cap:
                raise body_too_large(cap, what, declared=declared)
            # A second Request over the same scope, with the capped receive underneath it.
            # `request.state` is shared, because `HTTPConnection.state` wraps `scope["state"]`;
            # the send half is omitted, since Starlette uses it only for HTTP/2 push promises.
            capped = Request(request.scope,
                             capped_receive(request.receive, cap, what=what))
            try:
                return await original(capped)
            except HTTPException as exc:
                # FastAPI wraps any exception raised while it reads the body into
                # `HTTPException(400, "There was an error parsing the body")`, chaining the
                # original, so the 413 with the cap in it is unwrapped here. Only a Problem is
                # unwrapped: nothing else raises one from under the parser.
                if isinstance(exc.__cause__, Problem):
                    raise exc.__cause__ from None
                raise

        return handler
