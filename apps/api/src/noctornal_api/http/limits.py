"""Wiring the rate limiter into HTTP: subject derivation, the dependency
that guards a named endpoint, and the blanket middleware behind it.

Two layers, because they fail differently:

**The middleware** applies one ceiling to every request, keyed on the
presented credential. It needs no database, so it runs before session
validation and therefore limits an unauthenticated flood too. It fails
OPEN when the backend is down -- see `ratelimit.py` -- because a Redis
restart must not take an investigation tool offline.

**The dependency** applies a specific, much smaller limit to a named
endpoint, keyed on the authenticated user. It runs after the session is
resolved and before the access gate, so a limited caller does not get to
spend the gate's queries either. It fails CLOSED, because these are the
endpoints where being unlimited is the actual danger.

## X-Forwarded-For is not read unless a deployment says so

An IP-scoped limit derived from a header the client controls is worse than
no limit at all. The attacker rotates the header and is never limited; and
because the header names the SUBJECT, they can also send a victim's
address and exhaust the victim's login bucket instead of their own -- a
remotely triggerable lockout of a named analyst, which is the same defect
class the DB lockout decay fixed.

So the peer address is used, full stop, unless `NOCTORNAL_TRUSTED_PROXY_HOPS`
is set to the number of proxies the operator actually runs. Then the
(hops)-th entry from the RIGHT of the header is taken: the rightmost
entries were appended by infrastructure the operator controls, everything
to the left of them is client-supplied and still untrusted. Counting from
the left -- the common mistake -- reads whatever the client put there
first.
"""
from __future__ import annotations

import logging
import os

import psycopg
from fastapi import Depends, Request, Response
from psycopg.types.json import Json

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


def _trusted_proxy_hops() -> int:
    raw = os.environ.get("NOCTORNAL_TRUSTED_PROXY_HOPS", "0")
    try:
        return max(0, int(raw))
    except ValueError:
        log.warning("NOCTORNAL_TRUSTED_PROXY_HOPS=%r is not a number; treating as 0", raw)
        return 0


def client_ip(request: Request) -> str | None:
    """The peer address, or the address the outermost trusted proxy saw.

    EVERY `X-Forwarded-For` field line is joined before splitting, not just
    the first. RFC 9110 makes repeated field lines semantically identical to
    one comma-joined value, and real proxies differ about which they emit --
    HAProxy's `option forwardfor` appends a SEPARATE header line by default.
    Reading only the first line would mean `parts[-hops]` indexes a list the
    client authored in full, with the proxy's own entry sitting unread in a
    second line: the entire "count from the right" defence this module is
    built around, silently reading the attacker's value. Found by
    adversarial review.
    """
    hops = _trusted_proxy_hops()
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

    The token itself is never used as a key -- a Redis key is not a secret
    store, and `KEYS *` on a shared instance would hand over live session
    tokens. The hash is enough to be stable and useless to a reader.

    **This key SUBDIVIDES; it does not bound.** It is derived from a value
    the caller sends and nothing here verifies that the token is a live
    session, so a caller rotating a random token per request mints a fresh
    meter every time. Adversarial review demonstrated exactly that: with the
    blanket limit shrunk to 3, a fixed token gave 27 refusals out of 30 and
    a rotating one gave zero. Worse, the early return meant a garbage token
    also suppressed the address fallback, so sending one extra header made a
    caller strictly LESS limited than sending no credential at all.

    The fix is not here -- a subject derived from client input cannot be
    made trustworthy. It is in the middleware, which checks an
    address-scoped ceiling (`request.source`) as well, so a rotating token
    can only carve up a source's budget and never escape it.

    An anonymous caller still falls back to their address, so one attacker
    cannot deny service to every other anonymous caller by sharing a bucket
    with them.
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
    setting = os.environ.get("NOCTORNAL_RATELIMIT", "").strip().lower()
    if setting in _OFF:
        log.warning(
            "RATE LIMITING IS DISABLED (NOCTORNAL_RATELIMIT=%s). Login guessing "
            "is braked only by the account lockout, and the analytics endpoints "
            "are an unmetered CPU-bound path for any authenticated analyst.",
            setting,
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
        log.info("rate limiting via Redis at %s", _redacted(url))
    else:
        # Not fatal: the per-limit policy already says what an unreachable
        # backend means, and refusing to boot would make a cache outage an
        # application outage. But it must not be discovered from a graph.
        log.error(
            "rate-limit Redis at %s did not answer PING. Limits with "
            "on_backend_failure=DENY will refuse until it does.", _redacted(url),
        )
    return RateLimiter(backend)


def _redacted(url: str) -> str:
    """A Redis URL may carry a password. It is going into a log line."""
    if "@" in url:
        scheme, _, rest = url.partition("://")
        return f"{scheme}://***@{rest.rpartition('@')[2]}"
    return url


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
        # ...and stash it, because FastAPI discards `sub_response` entirely
        # when a handler returns a Response object directly (evidence export
        # and download both do). The blanket middleware reads this back and
        # writes the endpoint's headers onto the real response. Without it a
        # client is not merely told nothing, it is told the 600/min blanket
        # ceiling, which is actively the wrong number.
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
    """Spend one slot on an IP-scoped meter because something FAILED.

    The login failure meter exists because an IP-scoped limit on login
    *attempts* cannot be tight enough to stop spraying without also taking
    a NAT'd organisation offline -- see the catalogue in `ratelimit.py`.
    Metering failures instead makes the control asymmetric: a building full
    of analysts signing on successfully never moves it, and a sprayer moves
    nothing else.

    Never raises. This runs on a path that is already returning 401, and
    turning a metering hiccup into a 500 there would replace a clear
    refusal with a confusing one.
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

    Registered as middleware rather than a global dependency because it must
    cover every path -- including the static UI mount and any route added
    later without remembering to opt in. A limit you have to remember to
    apply is a limit that is missing from the endpoint added in a hurry.

    **Why two.** The credential-scoped meter subdivides fairly between the
    analysts behind one address; the address-scoped one is the actual
    ceiling. On its own the credential meter is no ceiling at all, because
    its subject is client-supplied: rotate the Bearer token and every
    request gets a fresh, empty bucket. Adversarial review reproduced that
    against the real app.

    **Why off the event loop.** `RedisBackend` drives the SYNCHRONOUS
    redis-py client. Calling it from an `async def` middleware would do
    blocking socket I/O on the loop thread, so one slow Redis would
    serialise every request in the process -- and the whole point of this
    limit failing OPEN is that a sick Redis must not become a sick API. The
    250ms socket timeout would then cost 250ms of loop time per request
    before it even raised. `run_in_threadpool` is what keeps the fail-open
    policy meaningful rather than nominal.
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
        # A specific endpoint limit's numbers beat the blanket ceiling's:
        # telling a caller about 600/min when they just hit the 10-per-5-min
        # analytics limit points them at the wrong number. The endpoint's
        # decision arrives via request.state because FastAPI throws away
        # `sub_response` for any handler that returns a Response directly.
        endpoint = getattr(request.state, "rate_limit_decision", None)
        source = endpoint or decision
        for key, value in source.headers.items():
            response.headers[key] = value
        return response
