"""Rate limiting: the GCRA decision, the limit catalogue, and one explicit
answer to the question a rate limiter usually gets wrong.

Pure by construction. Nothing in this module opens a socket, reads a
database or looks at the wall clock -- the decision is a function of
(now, theoretical arrival time, limit), so it can be tested against
hand-computed values the same way `analytics.py` is. The Redis half lives
in `ratelimit_redis.py`; the HTTP half in `http/limits.py`.

## Why GCRA and not a counter

A fixed-window counter ("100 per minute") lets 200 requests through across
a window boundary, which on the analytics path means 200 igraph runs in two
seconds. A sliding-window log is exact but stores one entry per request,
so the memory cost of limiting an attacker scales with the attack. GCRA
(the leaky bucket as a meter) stores ONE number per subject -- the
theoretical arrival time -- and yields both a smooth sustained rate and an
exact `Retry-After` from it. It also has the property that matters under
attack: **a denied request does not advance the meter**, so hammering a
limit does not extend your own penalty, and an attacker cannot lock a
subject out for longer than the limit itself allows.

## The fail-open question, answered per class

"What happens when Redis is down" is the real design question and it does
not have one answer, so this module makes it a per-limit field rather than
a global constant.

- `OnBackendFailure.DENY` -- the cost-bearing and security-sensitive
  limits (login, analytics, export, capture, merge). A limiter that fails
  open is an availability-triggered bypass: knock the backend over, or
  simply wait for a restart, and you get unlimited password guessing and
  unlimited CPU burn. Everything else in this codebase fails closed --
  access resolution, the evidence hash re-verify, the ingest key scope
  check -- and a limiter that does not is the odd one out.
- `OnBackendFailure.ALLOW` -- the blanket per-credential ceiling that the
  middleware applies to every request. Denying that one would turn a Redis
  restart into a total outage of an investigation tool, which is a worse
  failure than the one it prevents.

So a backend outage degrades the expensive features and leaves the case
file readable. Both branches log; a fail-open degradation is announced,
never silent (invariant 12's spirit: nothing is dropped quietly).

## Keys are hashed, and that is obfuscation, not anonymisation

A subject key carries an IP or a session token. Neither should sit in
plaintext in a cache that is not the system of record, so both are
SHA-256'd -- the same treatment `audit.event.ip_hash` gives an address.
Be honest about what that buys: the IPv4 space is 2^32, so a hash of an
address is reversible by anyone motivated. It stops casual disclosure
(a `KEYS *` dump, a memory snapshot), not a determined analyst.

## A note on the Redis eviction policy

Every key written here carries a TTL. `infra/docker-compose.yml` runs
Redis with `allkeys-lru`, so under memory pressure rate-limit state is
evictable -- and an evicted meter is a reset meter. That is acceptable for
a cache and not acceptable for a security control sharing an instance with
one, which is why a real deployment should give the limiter its own Redis
database (or its own instance) rather than sharing the projection cache's.
Documented rather than solved, because solving it is a deployment
decision, not a code change.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

log = logging.getLogger("noctornal.ratelimit")

MICROS = 1_000_000

# The in-process backend holds one meter per subject in a dict, so an
# attacker who can vary the subject (a random Bearer token per request)
# can grow it without bound. Capped, with the eviction order chosen below.
IN_PROCESS_MAX_KEYS = 50_000


class OnBackendFailure(Enum):
    """What an unreachable backend means for this particular limit."""

    DENY = "deny"
    ALLOW = "allow"


class Scope(Enum):
    """What the limit counts. The HTTP layer derives the subject from this
    so an endpoint cannot accidentally key a per-user limit on the IP."""

    USER = "user"            # the authenticated user id
    IP = "ip"                # the peer address (or its /64 for IPv6)
    CREDENTIAL = "credential"  # the presented token, hashed; no DB lookup


@dataclass(frozen=True)
class Limit:
    """`quota` requests per `per_seconds`, with `burst` allowed at once.

    Sustained rate and burst are separate on purpose. An analyst opening a
    case does six reads in one second and then nothing for a minute; a
    limit with no burst allowance punishes exactly that shape of use while
    barely inconveniencing a steady attacker.
    """

    name: str
    quota: int
    per_seconds: float
    scope: Scope
    burst: int | None = None
    on_backend_failure: OnBackendFailure = OnBackendFailure.DENY
    #: Seconds between audit rows for one (limit, subject). See
    #: `RateLimiter.should_audit`.
    audit_every_seconds: int = 300

    def __post_init__(self) -> None:
        if self.quota <= 0 or self.per_seconds <= 0:
            raise ValueError(f"{self.name}: quota and period must be positive")
        if self.burst is not None and self.burst < 1:
            raise ValueError(f"{self.name}: burst must be at least 1")

    @property
    def effective_burst(self) -> int:
        return self.burst if self.burst is not None else self.quota

    @property
    def emission_us(self) -> int:
        """Microseconds of credit one request costs. Integer microseconds
        rather than float seconds because the same arithmetic runs in Lua,
        where every number is a double -- keeping both sides on integers
        below 2^53 means the Python decision and the Redis decision cannot
        drift apart at the boundary."""
        return max(1, int(self.per_seconds * MICROS / self.quota))

    @property
    def tolerance_us(self) -> int:
        return self.emission_us * self.effective_burst


@dataclass(frozen=True)
class RawDecision:
    """The backend's answer, in microseconds and without policy applied."""

    allowed: bool
    retry_after_us: int
    remaining: int
    reset_us: int


@dataclass(frozen=True)
class Decision:
    """What the HTTP layer needs: the verdict, the headers, and whether the
    verdict was reached by measurement or by policy."""

    allowed: bool
    limit: Limit
    remaining: int
    retry_after_seconds: int
    reset_seconds: int
    #: True when the backend was unreachable and `on_backend_failure`
    #: decided this. A degraded ALLOW is not evidence the caller is within
    #: their limit, and a degraded DENY is a 503, not a 429.
    degraded: bool = False

    @property
    def headers(self) -> dict[str, str]:
        """RFC 9331-style advisory headers. Sent on success as well as
        failure so a well-behaved client can pace itself instead of
        discovering the limit by hitting it."""
        h = {
            "RateLimit-Limit": str(self.limit.quota),
            "RateLimit-Remaining": str(max(0, self.remaining)),
            "RateLimit-Reset": str(max(0, self.reset_seconds)),
            "RateLimit-Policy": (
                f"{self.limit.quota};w={int(self.limit.per_seconds)};"
                f"burst={self.limit.effective_burst}"
            ),
        }
        if not self.allowed:
            h["Retry-After"] = str(max(1, self.retry_after_seconds))
        return h


class BackendUnavailable(Exception):
    """The store could not be reached or answered nonsense. Raised by a
    backend, caught by `RateLimiter`, never seen by a caller."""


def gcra(*, now_us: int, tat_us: int | None, emission_us: int,
         tolerance_us: int) -> tuple[RawDecision, int | None]:
    """The whole algorithm, as a pure function.

    Returns the decision and the new theoretical arrival time to store --
    or None when nothing should be written, which is the case on every
    denial. That "no write on denial" is not an optimisation: it is what
    stops a caller who ignores `Retry-After` from pushing their own
    recovery time out indefinitely, and what stops a third party who can
    forge the subject from doing it to someone else.

    `tat_us` is None for a subject with no meter yet, which is treated as
    a meter that emptied at `now_us`.
    """
    tat = now_us if tat_us is None or tat_us < now_us else tat_us
    new_tat = tat + emission_us
    allow_at = new_tat - tolerance_us

    if allow_at > now_us:
        # Denied. `reset` reports the CURRENT meter draining, not the
        # would-be one, so a client polling a 429 sees the number fall.
        return (
            RawDecision(
                allowed=False,
                retry_after_us=allow_at - now_us,
                remaining=0,
                reset_us=max(0, tat - now_us),
            ),
            None,
        )

    used_us = new_tat - now_us
    remaining = int((tolerance_us - used_us) // emission_us)
    return (
        RawDecision(
            allowed=True,
            retry_after_us=0,
            remaining=max(0, remaining),
            reset_us=used_us,
        ),
        new_tat,
    )


class Backend(Protocol):
    """The operations a limiter needs. `measure` must be atomic.

    Non-atomic read-modify-write would let two concurrent requests both
    read the same meter and both be allowed, which is the entire bug a
    rate limiter exists to prevent.
    """

    def measure(self, key: str, emission_us: int, tolerance_us: int) -> RawDecision:
        """Apply GCRA to `key` and CONSUME a slot. Raises BackendUnavailable."""
        ...

    def peek(self, key: str, emission_us: int, tolerance_us: int) -> RawDecision:
        """What `measure` would return, without consuming anything.

        Used where the thing being metered is not the request itself --
        the login failure meter is consumed by a failed authentication, but
        has to be READ before one, so that a source which has exhausted it
        is refused before the deliberately expensive password hash runs.
        Peeking does not need to be atomic: it is advisory, and the
        authoritative consume is still a single atomic operation.
        """
        ...

    def claim_once(self, key: str, window_seconds: int) -> bool:
        """True for the FIRST caller in the window, False afterwards.
        Used to throttle audit writes. Never raises: an audit-throttle
        failure must not turn into a request failure."""
        ...


class InProcessBackend:
    """A backend with no Redis, for single-process development and for the
    unit tests.

    It is genuinely correct for one process and genuinely wrong for many:
    N uvicorn workers enforce N times the configured rate. `http/limits.py`
    logs that loudly at startup rather than letting a deployment discover
    it from an incident.

    The clock is `time.monotonic`, not `time.time`. The development host
    this was built on has an unsynchronised clock (docs/15), and a wall
    clock that steps backwards would hand out free capacity while it
    caught up.
    """

    def __init__(self, *, now=None, max_keys: int = IN_PROCESS_MAX_KEYS):
        self._now = now or (lambda: time.monotonic())
        self._max_keys = max_keys
        self._lock = threading.Lock()
        # Insertion order is not useful here (see _evict), but OrderedDict
        # gives cheap removal of an arbitrary key while iterating cheaply.
        self._meters: OrderedDict[str, int] = OrderedDict()
        self._claims: dict[str, int] = {}

    def _now_us(self) -> int:
        return int(self._now() * MICROS)

    def _evict(self, now_us: int) -> None:
        """Drop expired meters first -- an expired meter is indistinguishable
        from an absent one, so removing it loses no enforcement at all. Only
        if that is not enough, drop the meters with the EARLIEST arrival
        time: those are the subjects closest to empty, so evicting them
        forgives the least. Evicting by insertion order (a plain LRU) would
        let an attacker cycling random tokens flush the meter of the caller
        who is actually being throttled."""
        for key in [k for k, tat in self._meters.items() if tat <= now_us]:
            del self._meters[key]
        if len(self._meters) < self._max_keys:
            return
        overflow = len(self._meters) - self._max_keys + 1
        for key, _ in sorted(self._meters.items(), key=lambda kv: kv[1])[:overflow]:
            del self._meters[key]
        log.warning(
            "rate-limit meter table full (%d keys); evicted %d least-throttled "
            "subjects. This is a memory-pressure signal, not normal operation.",
            self._max_keys, overflow,
        )

    def measure(self, key: str, emission_us: int, tolerance_us: int) -> RawDecision:
        with self._lock:
            now_us = self._now_us()
            if key not in self._meters and len(self._meters) >= self._max_keys:
                self._evict(now_us)
            decision, new_tat = gcra(
                now_us=now_us, tat_us=self._meters.get(key),
                emission_us=emission_us, tolerance_us=tolerance_us,
            )
            if new_tat is not None:
                self._meters[key] = new_tat
            return decision

    def peek(self, key: str, emission_us: int, tolerance_us: int) -> RawDecision:
        with self._lock:
            decision, _ = gcra(
                now_us=self._now_us(), tat_us=self._meters.get(key),
                emission_us=emission_us, tolerance_us=tolerance_us,
            )
            return decision

    def claim_once(self, key: str, window_seconds: int) -> bool:
        with self._lock:
            now_us = self._now_us()
            expires = self._claims.get(key)
            if expires is not None and expires > now_us:
                return False
            self._claims = {k: v for k, v in self._claims.items() if v > now_us}
            self._claims[key] = now_us + window_seconds * MICROS
            return True


def hashed(value: str) -> str:
    """A short, stable, non-plaintext key component. Truncated to 128 bits
    -- a collision means two subjects share a meter, and 2^-64 by birthday
    across the key space this holds is not a risk worth 32 more bytes per
    key."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def ip_subject(address: str | None) -> str:
    """The subject for an IP-scoped limit.

    IPv6 is collapsed to its /64. A residential IPv6 allocation is a /64 at
    minimum and frequently a /56, so limiting a single /128 limits one
    address out of eighteen quintillion the same host already owns -- an
    IP-scoped limit on IPv6 addresses is not a limit at all.

    An address that will not parse is bucketed under a single fixed key
    rather than trusted as distinct, so a malformed value cannot mint
    unlimited subjects.

    **IPv4-mapped addresses are unmapped FIRST**, and getting this wrong is
    not theoretical: a dual-stack listener reports every IPv4 peer as
    `::ffff:a.b.c.d`, every one of which has the same /64 (`::/64`). Without
    the unmapping below, every IPv4 client on such a deployment -- which is
    the default for uvicorn bound to `::` -- would share ONE login bucket,
    and the first person to mistype their password would lock out the
    internet. Found by adversarial review, not by a test.
    """
    if not address:
        return "ip:unknown"
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return "ip:unparseable"
    if parsed.version == 6:
        mapped = parsed.ipv4_mapped
        if mapped is not None:
            parsed = mapped
    if parsed.version == 6:
        network = ipaddress.ip_network(f"{parsed}/64", strict=False)
        return "ip6:" + hashed(str(network))
    return "ip4:" + hashed(str(parsed))


# ---------------------------------------------------------------------------
# The catalogue. One table, so "what are the limits" is answerable by
# reading a file rather than grepping decorators.
#
# The numbers are set for an analyst working hard, not for an analyst
# working normally: a limit that a busy hour trips is a limit that gets
# raised in an incident, and a limit raised in an incident is never
# lowered again. Each is roughly an order of magnitude above observed
# legitimate use and roughly two below what the endpoint costs to serve.
# ---------------------------------------------------------------------------

LIMITS: dict[str, Limit] = {
    # Login is metered twice, and the split is the whole point.
    #
    # An IP-scoped limit on login ATTEMPTS cannot be tight, because the
    # customer for this product is an organisation behind one egress
    # address. A police unit of two hundred people signing on at 09:00 is
    # two hundred logins from a single IP inside ten minutes; a limit tuned
    # to stop password spraying would take that unit offline every Monday,
    # and a limit that does that gets raised in an incident and never
    # lowered again. So the attempt limit is generous -- it exists to cap
    # one source's CPU draw on a deliberately expensive Argon2id verify,
    # not to stop guessing.
    #
    # What stops guessing is the SECOND meter, which counts FAILURES.
    # Successful sign-ons never touch it, so a whole building can log in
    # behind one address without moving it at all, while a sprayer -- whose
    # traffic is nothing but failures -- exhausts it in seconds. That
    # asymmetry is what makes an IP-scoped login control compatible with
    # NAT.
    #
    # Neither is email-scoped. An email-keyed limit is a remotely
    # triggerable lockout of a named analyst, since anyone can send that
    # address -- the same defect class a previous review found in the DB
    # lockout and fixed by making it decay. Targeted guessing against one
    # account is that lockout's job.
    #
    # Honest about the gap: both are per-source, so a botnet spreading one
    # guess per address per hour moves neither meter. Nothing here fixes
    # that; the account lockout and password strength do.
    # The burst is deliberately much smaller than the quota, and that is
    # the mitigation for a race adversarial review found: the failure meter
    # is PEEKED before the Argon2id verify and consumed after it, so a
    # simultaneous burst all read an un-advanced meter and all proceed. The
    # number of guesses one burst buys is therefore bounded by THIS burst,
    # not by the failure meter's. 20 concurrent verifies is comfortable for
    # a shift starting at 09:00 and is not a useful guessing window.
    "auth.login": Limit(
        "auth.login", quota=120, per_seconds=60, scope=Scope.IP, burst=20,
        on_backend_failure=OnBackendFailure.DENY, audit_every_seconds=60,
    ),
    "auth.login_failed": Limit(
        "auth.login_failed", quota=30, per_seconds=300, scope=Scope.IP, burst=15,
        on_backend_failure=OnBackendFailure.DENY, audit_every_seconds=60,
    ),
    # Minting a fresh set of recovery codes invalidates the old set. A
    # loop here is a denial of service against the account's own owner.
    "auth.recovery_codes": Limit(
        "auth.recovery_codes", quota=5, per_seconds=3600, scope=Scope.USER,
        burst=3, on_backend_failure=OnBackendFailure.DENY,
    ),
    # decision 30 names this as the DoS surface: a CPU-bound igraph run
    # behind a non-step-up permission. 2k nodes is ~1.15s of one core.
    "analytics.suite": Limit(
        "analytics.suite", quota=30, per_seconds=300, scope=Scope.USER, burst=10,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # KPP-Neg is combinatorial in the removal-set size and is the most
    # expensive thing the API will do, so it gets its own smaller bucket
    # rather than sharing the suite's.
    "analytics.key_player": Limit(
        "analytics.key_player", quota=10, per_seconds=300, scope=Scope.USER,
        burst=4, on_backend_failure=OnBackendFailure.DENY,
    ),
    # docs/05: "hard limits on export and search". Search is full-text
    # over a case file and is also the shape an exfiltration attempt takes.
    "search": Limit(
        "search", quota=120, per_seconds=60, scope=Scope.USER, burst=40,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # Export leaves the boundary. It is the one action where a limit is
    # about the data getting out, not about the server staying up.
    "evidence.export": Limit(
        "evidence.export", quota=30, per_seconds=3600, scope=Scope.USER, burst=10,
        on_backend_failure=OnBackendFailure.DENY, audit_every_seconds=60,
    ),
    # Every ingest writes to WORM storage under object lock. Bytes written
    # there cannot be deleted before the retention period expires, so an
    # ingest loop is a permanent, unbillable storage commitment.
    "evidence.ingest": Limit(
        "evidence.ingest", quota=120, per_seconds=3600, scope=Scope.USER, burst=30,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # Capture runs extraction over pasted text and raises a proposal per
    # new value; a loop floods the triage queue, which is an attack on the
    # analyst's attention rather than on the server.
    "capture": Limit(
        "capture", quota=120, per_seconds=3600, scope=Scope.USER, burst=30,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # A merge rewrites endpoints across a case and writes a ledger row per
    # re-pointed edge. Small, deliberate, and already step-up gated.
    "merge": Limit(
        "merge", quota=30, per_seconds=3600, scope=Scope.USER, burst=10,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # The blanket ceiling is TWO limits, and it has to be.
    #
    # `request` is keyed on the presented credential, which needs no
    # database lookup and fairly subdivides a shared address between the
    # analysts behind it. On its own it is not a ceiling at all: adversarial
    # review demonstrated that a caller sending a fresh random
    # `Authorization: Bearer <hex>` on every request mints a fresh meter
    # every time and is never limited -- and, worse, that presenting a
    # garbage token was CHEAPER than presenting none, because the bearer
    # branch suppressed the address fallback. Sending one extra header made
    # a caller strictly less limited. The control inverted.
    #
    # `request.source` is the fix. It is keyed on the peer address, which a
    # caller cannot mint, so a rotating token can only SUBDIVIDE a source's
    # budget and never escape it. Both are checked; the tighter one binds.
    # Its quota is generous because the customer is a whole unit behind one
    # egress address -- it exists to bound an unauthenticated flood, not to
    # ration normal work.
    #
    # Both ALLOW on backend failure: see the module docstring. Denying the
    # blanket ceiling would turn a Redis restart into a total outage.
    "request": Limit(
        "request", quota=600, per_seconds=60, scope=Scope.CREDENTIAL, burst=200,
        on_backend_failure=OnBackendFailure.ALLOW, audit_every_seconds=600,
    ),
    "request.source": Limit(
        "request.source", quota=3000, per_seconds=60, scope=Scope.IP, burst=600,
        on_backend_failure=OnBackendFailure.ALLOW, audit_every_seconds=600,
    ),
    # The sociogram's read paths. `/graph/metrics` computes degree,
    # clustering and k-core over a materialised projection behind the SAME
    # `analytics.run` permission the metered suite uses, with no result
    # cache -- so leaving it unmetered left the analytics door locked and
    # the window open. It shares `analytics.suite`'s budget deliberately:
    # two doors onto the same cost with two separate budgets is one budget
    # that means nothing.
    "graph.view": Limit(
        "graph.view", quota=240, per_seconds=60, scope=Scope.USER, burst=80,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # Destruction. The tightest quota here, and deliberately so.
    #
    # A purge is irreversible and a legal hold is what stands between an
    # exhibit and one, so both meter together: the attack is not volume,
    # it is a script looping over cases. Ten an hour is more than any real
    # retention run needs and far fewer than a loop wants. Fails CLOSED --
    # if the meter is unavailable, not destroying things is the safe
    # direction.
    "retention.destroy": Limit(
        "retention.destroy", quota=10, per_seconds=3600, scope=Scope.USER,
        burst=3, on_backend_failure=OnBackendFailure.DENY,
        audit_every_seconds=60,
    ),
    # The ingest 202 endpoint, and the ONE limit in this catalogue that
    # cannot be USER-scoped.
    #
    # Its caller presents an ingest API key, not a session, so a
    # `Scope.USER` limit would resolve `current_user` and reject every
    # legitimate submission with "invalid or expired session" -- which is
    # exactly what happened when it was first wired to `evidence.ingest`.
    #
    # CREDENTIAL scope is safe HERE, unlike for the blanket ceiling that
    # adversarial review broke. There the subject was client-chosen and a
    # rotating token minted a fresh bucket per request. An ingest key
    # cannot be rotated by its holder: they have the one key they were
    # issued, and an unauthenticated caller sending fresh garbage keys is
    # refused at 401 before doing work and is bounded by the
    # address-scoped `request.source` ceiling regardless.
    "ingest.submit": Limit(
        "ingest.submit", quota=600, per_seconds=3600, scope=Scope.CREDENTIAL,
        burst=120, on_backend_failure=OnBackendFailure.DENY,
    ),
    # PGP verification SPAWNS A SUBPROCESS, twice, with a 20-second timeout
    # each. It is the only route in this system that forks, which makes an
    # unmetered loop of it a trivial way to exhaust process slots and file
    # handles -- far cheaper for the caller than for the server, which is
    # the definition of the thing a limit is for. The quota is deliberately
    # low: verifying a signature is a deliberate analyst action on a
    # specific claim, not something anything iterates over.
    "comms.verify": Limit(
        "comms.verify", quota=60, per_seconds=3600, scope=Scope.USER, burst=10,
        on_backend_failure=OnBackendFailure.DENY,
    ),
}


class RateLimiter:
    """Applies the catalogue against a backend and turns the raw meter
    reading into a decision plus its policy consequences."""

    def __init__(self, backend: Backend, *, limits: dict[str, Limit] | None = None,
                 enabled: bool = True, key_prefix: str = "rl"):
        self._backend = backend
        self._limits = limits if limits is not None else LIMITS
        self._enabled = enabled
        self._prefix = key_prefix

    @property
    def enabled(self) -> bool:
        return self._enabled

    def limit(self, name: str) -> Limit:
        try:
            return self._limits[name]
        except KeyError:
            # A typo in a decorator must not silently mean "unlimited".
            raise KeyError(f"unknown rate limit {name!r}") from None

    def check(self, name: str, subject: str) -> Decision:
        """Measure and consume."""
        return self._decide(name, subject, consume=True)

    def peek(self, name: str, subject: str) -> Decision:
        """Read the meter without consuming. See `Backend.peek`."""
        return self._decide(name, subject, consume=False)

    def _decide(self, name: str, subject: str, *, consume: bool) -> Decision:
        limit = self.limit(name)
        if not self._enabled:
            return Decision(True, limit, limit.effective_burst, 0, 0)
        key = f"{self._prefix}:{name}:{subject}"
        operation = self._backend.measure if consume else self._backend.peek
        try:
            raw = operation(key, limit.emission_us, limit.tolerance_us)
        except BackendUnavailable as exc:
            allow = limit.on_backend_failure is OnBackendFailure.ALLOW
            log.error(
                "rate-limit backend unavailable for %s; failing %s per policy: %s",
                name, "OPEN" if allow else "CLOSED", exc,
            )
            return Decision(
                allowed=allow, limit=limit, remaining=0,
                retry_after_seconds=0 if allow else 5,
                reset_seconds=0, degraded=True,
            )
        return Decision(
            allowed=raw.allowed,
            limit=limit,
            remaining=raw.remaining,
            # Ceiling, not round: a Retry-After that rounds DOWN tells a
            # compliant client to retry into a second denial.
            retry_after_seconds=-(-raw.retry_after_us // MICROS),
            reset_seconds=-(-raw.reset_us // MICROS),
        )

    def should_audit(self, name: str, subject: str) -> bool:
        """True at most once per `audit_every_seconds` for this subject.

        `audit.event` is append-only and hash-chained, and the chain
        trigger takes an advisory lock so rows serialise. Auditing every
        denial would therefore let a caller who is ALREADY being throttled
        convert their rejected requests into unbounded, serialised,
        undeletable writes -- a rate limiter that hands an attacker a
        better denial of service than the one it blocks. One row per
        window records the campaign; the count is in the access log.

        An unreachable backend means DO NOT audit, not "audit everything".

        That looks backwards for a moment and is not. The backend being
        unreachable is the SAME condition that makes every DENY-policy limit
        refuse every request -- so a throttle that failed open would, during
        an outage, turn each of those refusals into a serialised,
        undeletable append-only write. The outage would author the exact
        flood the throttle exists to prevent. The outage itself is already
        logged loudly by `check()`, so nothing goes unrecorded; what is lost
        is one audit row per subject, during a window in which the audit log
        is the thing under threat.
        """
        limit = self.limit(name)
        try:
            return self._backend.claim_once(
                f"{self._prefix}:audit:{name}:{subject}", limit.audit_every_seconds
            )
        except Exception:  # noqa: BLE001 - never fail a request over an audit throttle
            log.error(
                "audit throttle unavailable for %s; NOT auditing this denial, "
                "because an unthrottled audit during a backend outage is a "
                "worse denial of service than the one being refused",
                name, exc_info=True)
            return False
