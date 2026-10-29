"""Rate limiting: the GCRA decision, the limit catalogue, and the fail-open policy per limit class.

Pure by construction: nothing here opens a socket, reads a database or looks at the wall clock, so
the decision is a function of (now, theoretical arrival time, limit) and can be tested against
hand-computed values. The Redis half lives in `ratelimit_redis.py`; the HTTP half in
`http/limits.py`.

GCRA stores ONE number per subject (a fixed-window counter lets 200 requests through across a window
boundary; a sliding-window log's memory scales with the attack) and yields a smooth rate and an
exact `Retry-After`. A denied request does not advance the meter, so hammering a limit does not
extend your own penalty and an attacker cannot lock a subject out for longer than the limit allows.

What happens when Redis is down is a per-limit field, `OnBackendFailure`. DENY covers the
cost-bearing and security-sensitive limits (login, analytics, export, capture, merge): a limiter
that fails open is an availability-triggered bypass, unlimited password guessing and CPU burn for
anyone who can knock the backend over. ALLOW covers the blanket per-credential ceiling on every
request: denying it would turn a Redis restart into a total outage. Both branches log; a fail-open
degradation is announced, never silent.

Subject keys carry an IP or a session token, so both are SHA-256'd before they reach Redis. That is
obfuscation, not anonymisation: the IPv4 space is 2^32, so a hashed address is reversible by anyone
motivated. It stops casual disclosure (a `KEYS *` dump, a memory snapshot), not a determined
analyst.

Every key carries a TTL, and under an evicting `maxmemory-policy` an evicted meter is a reset meter.
The limiter needs a Redis instance of its own running `noeviction`: the bundled
`infra/docker-compose.yml` runs `noeviction`. The code cannot make that deployment decision, so
`http/limits.py` warns at startup and the readiness register's `redis_limiter_store` row fails
whenever the limiter's Redis evicts.
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

    Returns the decision and the new theoretical arrival time to store, or None when nothing should
    be written, which is every denial. "No write on denial" is what stops a caller who ignores
    `Retry-After` from pushing their own recovery time out indefinitely, and a third party who can
    forge the subject from doing it to someone else.

    `tat_us` is None for a subject with no meter yet, treated as a meter that emptied at `now_us`.
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
    """A backend with no Redis, for single-process development and the unit tests.

    Correct for one process and wrong for many: N uvicorn workers enforce N times the configured
    rate, which `http/limits.py` logs at startup. The clock is `time.monotonic`, not `time.time`: a
    wall clock that steps backwards would hand out free capacity while it caught up (the development
    host's clock is unsynchronised, docs/15).
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

    IPv6 is collapsed to its /64: a residential allocation is a /64 at minimum and often a /56, so
    limiting a single /128 limits one address out of eighteen quintillion the same host already
    owns. An address that will not parse is bucketed under a single fixed key rather than trusted as
    distinct, so a malformed value cannot mint unlimited subjects.

    **IPv4-mapped addresses are unmapped FIRST.** A dual-stack listener (the default for uvicorn
    bound to `::`) reports every IPv4 peer as `::ffff:a.b.c.d`, all in the same /64 (`::/64`), so
    without the unmapping every IPv4 client would share ONE login bucket and the first person to
    mistype a password would lock out the internet.
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


# The catalogue. One table, so "what are the limits" is answerable by reading a file rather than
# grepping decorators.
#
# The numbers are set for an analyst working hard, not for an analyst working normally: a limit that
# a busy hour trips is a limit that gets raised in an incident, and a limit raised in an incident is
# never lowered again. Each is roughly an order of magnitude above observed legitimate use and
# roughly two below what the endpoint costs to serve.

LIMITS: dict[str, Limit] = {
    # Login is metered twice, and the split is the whole point.
    #
    # The ATTEMPT meter is generous: the customer is an organisation behind one egress address (two
    # hundred people signing on at 09:00 is two hundred logins from one IP), so it only caps one
    # source's CPU draw on the deliberately expensive Argon2id verify. Its burst is small because
    # the failure meter is PEEKED before the verify and consumed after it, so a simultaneous burst
    # all reads an un-advanced meter: one burst buys at most 20 guesses.
    #
    # What stops guessing is the FAILURE meter. Successful sign-ons never touch it, so a whole
    # building can log in behind one address, while a sprayer, whose traffic is all failures,
    # exhausts it in seconds. Neither meter is email-scoped, which would be a remotely triggerable
    # lockout of a named analyst; both are per-source, so a botnet spreading one guess per address
    # per hour moves neither, and the account lockout and password strength cover that.
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
    # An administrator minting somebody ELSE's credentials: provisioning an account, or re-enrolling
    # a colleague's authenticator. Both answer with a one-time password or secret, so a loop is
    # worth braking (both are step-up gated behind `user.manage` already).
    #
    # Its own meter, not `auth.recovery_codes`, which is sized for one person reissuing their OWN
    # codes and is partly spent by the first administrator's codes at first sign-in. A refused
    # request still spends from a meter (the limit runs before the gate's step-up check, on purpose,
    # see http/limits.py). Set for standing up a unit in one sitting: twenty at once, then one a
    # minute.
    "admin.credentials": Limit(
        "admin.credentials", quota=60, per_seconds=3600, scope=Scope.USER,
        burst=20, on_backend_failure=OnBackendFailure.DENY,
        audit_every_seconds=60,
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
    # `request` is keyed on the presented credential, which needs no database lookup and fairly
    # subdivides a shared address between the analysts behind it. Alone it is not a ceiling: a fresh
    # random bearer token on every request mints a fresh meter every time, and a garbage token would
    # be cheaper than none. `request.source` is keyed on the peer address, which a caller cannot
    # mint, so a rotating token can only SUBDIVIDE a source's budget and never escape it. Both are
    # checked; the tighter one binds. Its quota is generous because the customer is a whole unit
    # behind one egress address.
    #
    # Both ALLOW on backend failure (see the module docstring).
    "request": Limit(
        "request", quota=600, per_seconds=60, scope=Scope.CREDENTIAL, burst=200,
        on_backend_failure=OnBackendFailure.ALLOW, audit_every_seconds=600,
    ),
    "request.source": Limit(
        "request.source", quota=3000, per_seconds=60, scope=Scope.IP, burst=600,
        on_backend_failure=OnBackendFailure.ALLOW, audit_every_seconds=600,
    ),
    # The sociogram's read paths: the projection, ego networks, paths and
    # the saved layout.
    "graph.view": Limit(
        "graph.view", quota=240, per_seconds=60, scope=Scope.USER, burst=80,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # `/graph/metrics`: degree, weighted degree, clustering and k-core over one projection, which
    # the console fetches with every projection it draws. Its own budget, not `analytics.suite`'s:
    # these four local counts cost about what drawing the projection costs, whereas the suite runs
    # igraph centralities, so navigation must not spend the suite's budget. Still per analyst and
    # failing closed. The console caches each answer per projection and graph state and fetches on
    # scrubber release, not at every pause of a drag.
    "graph.metrics": Limit(
        "graph.metrics", quota=120, per_seconds=60, scope=Scope.USER, burst=40,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # Destruction. The tightest quota here, and deliberately so: a purge is irreversible, so the
    # attack is a script looping over cases, not volume. Ten an hour is more than any real retention
    # run needs. Fails CLOSED: if the meter is unavailable, not destroying things is the safe
    # direction.
    #
    # One meter per act, so a lead who previewed a case twice and lifted a hold is not made to wait
    # before the purge they came to run. The routes spend only after the gate has let the request
    # in.
    "retention.destroy": Limit(
        "retention.destroy", quota=10, per_seconds=3600, scope=Scope.USER,
        burst=3, on_backend_failure=OnBackendFailure.DENY,
        audit_every_seconds=60,
    ),
    # Releasing a hold is what makes a later destruction lawful, so it keeps
    # the tight meter and fails closed. Placing one is never metered here:
    # preservation is the act that must not be slowed (decision 192).
    "retention.lift": Limit(
        "retention.lift", quota=10, per_seconds=3600, scope=Scope.USER,
        burst=3, on_backend_failure=OnBackendFailure.DENY,
        audit_every_seconds=60,
    ),
    # A dry run destroys nothing and is the first step of every real run, and
    # the Records pane opens on one, so it is metered as a read that scans a
    # case's clocks (the analytics suite's shape) and not as a destruction.
    "retention.dry_run": Limit(
        "retention.dry_run", quota=30, per_seconds=300, scope=Scope.USER,
        burst=10, on_backend_failure=OnBackendFailure.DENY,
    ),
    # The ingest 202 endpoint, and the ONE limit in this catalogue that cannot be USER-scoped: its
    # caller presents an ingest API key, not a session, so a `Scope.USER` limit would reject every
    # legitimate submission with "invalid or expired session".
    #
    # CREDENTIAL scope is safe HERE, unlike for the blanket ceiling: an ingest key cannot be rotated
    # by its holder, and an unauthenticated caller sending fresh garbage keys is refused at 401
    # before doing work and bounded by the address-scoped `request.source` ceiling regardless.
    "ingest.submit": Limit(
        "ingest.submit", quota=600, per_seconds=3600, scope=Scope.CREDENTIAL,
        burst=120, on_backend_failure=OnBackendFailure.DENY,
    ),
    # PGP verification SPAWNS A SUBPROCESS, twice, with a 20-second timeout each. It is the only
    # route that forks, so an unmetered loop would exhaust process slots and file handles far more
    # cheaply for the caller than for the server. The quota is low: verifying a signature is a
    # deliberate analyst action on a specific claim, not something anything iterates over.
    "comms.verify": Limit(
        "comms.verify", quota=60, per_seconds=3600, scope=Scope.USER, burst=10,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # The sample-origin download, the only limit here that meters a route reachable with NO
    # credential at all once it is deployed.
    #
    # The credential may be a one-shot ticket in the request BODY, so the sample process cannot tell
    # an authorised caller from a stranger until it has looked one up. A ticket matching no row is a
    # sampled warning rather than an `audit.event` row (`samples.py`), since that table is
    # append-only, hash-chained and serialised by an advisory lock. This limit is the other half:
    # the refusals that DO still audit each name a real minted ticket, so replaying one spent ticket
    # in a loop would write an undeletable row per attempt.
    #
    # Keyed on the peer address, the only subject that exists before a ticket is validated (a
    # body-borne credential cannot be the key, for `credential_subject`'s reason). 120 per five
    # minutes, 30 at once: an analyst pulling the samples for one intrusion clicks through a handful
    # in a few seconds, and the sustained rate from a WHOLE egress address is far above any lab's
    # real rate and far below what the route costs to serve (`SampleService.download` reads the
    # object whole, XORs it in Python, re-hashes it and ZIPs it). DENY on backend failure.
    # `audit_every_seconds` is inert here: the dependency in `routers/samples.py` passes no
    # connection, so a denial on this route is logged and never written.
    "sample.download": Limit(
        "sample.download", quota=120, per_seconds=300, scope=Scope.IP,
        burst=30, on_backend_failure=OnBackendFailure.DENY,
    ),
    # A read with venues projected to entities re-projects AND transforms: up to about 0.6 s of CPU
    # and 52 MB at affiliation.MAX_DERIVED_TIES, where a plain read costs what GET /graph costs.
    # Every one-mode analysis route spends this BESIDE its own meter, and it fails closed with the
    # other cost-bearing limits. Opening the pane with venues projected spends up to three; the pane
    # checks currency with one batched call and at most once in 30 seconds, so background checks
    # cannot empty the budget an explicit Run needs.
    "analytics.one_mode": Limit(
        "analytics.one_mode", quota=60, per_seconds=300, scope=Scope.USER,
        burst=20, on_backend_failure=OnBackendFailure.DENY,
    ),
    # CONCOR positions: 0.6 to 0.7 s typical at 1,000 entities with ties, 1.7 s worst with every
    # split at the 50-round cap, 120 MB (1.1 to 1.2 s and a 154 MB peak with memory tracing on).
    # BLAS is capped to one thread per process (blockmodel.py). Its own bucket, like key player, so
    # the Roles card cannot spend the suite's.
    "analytics.concor": Limit(
        "analytics.concor", quota=10, per_seconds=300, scope=Scope.USER,
        burst=4, on_backend_failure=OnBackendFailure.DENY,
    ),
    # REGE (regular roles): about 2 s of CPU for the dearest view its caps admit (1,000 entities,
    # 2,500 tied pairs, 5,000 tie directions), 0.3 to 1.5 s for a view counted as present (rege.py's
    # REGE_MAX_PAIRS has the measurements). At this quota one user can queue about 21 s of CPU on
    # the one API process in five minutes. CONCOR's numbers and its own bucket, closed when the
    # backend cannot count.
    "analytics.rege": Limit(
        "analytics.rege", quota=10, per_seconds=300, scope=Scope.USER,
        burst=4, on_backend_failure=OnBackendFailure.DENY,
    ),
    # Running static triage on demand decrypts a live sample and starts child processes, so it is a
    # deliberate act on one sample, not something to loop. Similarity scores candidates in Python
    # and a value search is a probe of what the lab holds, so it is tighter than search. Rule set
    # writes are rare governance acts; the file view decompresses stored rule source.
    "sample.triage": Limit(
        "sample.triage", quota=12, per_seconds=300, scope=Scope.USER,
        burst=4, on_backend_failure=OnBackendFailure.DENY,
    ),
    "sample.similar": Limit(
        "sample.similar", quota=30, per_seconds=60, scope=Scope.USER,
        burst=10, on_backend_failure=OnBackendFailure.DENY,
    ),
    "yara.ruleset": Limit(
        "yara.ruleset", quota=20, per_seconds=3600, scope=Scope.USER,
        burst=5, on_backend_failure=OnBackendFailure.DENY,
    ),
    "yara.source": Limit(
        "yara.source", quota=60, per_seconds=300, scope=Scope.USER,
        burst=10, on_backend_failure=OnBackendFailure.DENY,
    ),
    # The collection foundation. Creating a source, a persona or a binding: configuration of what
    # the collector reads and as whom, set for standing a unit's collection up in one sitting, and
    # closed when the backend cannot count.
    "collection.config": Limit(
        "collection.config", quota=60, per_seconds=3600, scope=Scope.USER,
        burst=20, on_backend_failure=OnBackendFailure.DENY,
    ),
    # Collection authorities (docs/00 decision 69). Recording, extending, confirming and stopping a
    # collection authority: each is a two-person act an officer reads.
    "collection.authority": Limit(
        "collection.authority", quota=30, per_seconds=3600, scope=Scope.USER,
        burst=10, on_backend_failure=OnBackendFailure.DENY,
    ),
    # The egress proxy. Every write to the egress configuration and the dry-run check. Configuration
    # is where a boundary is quietly widened, and each write is step-up and audited; an
    # administrator setting up routes makes tens of changes, never hundreds. DENY on backend failure
    # with the other security-sensitive limits.
    "admin.egress": Limit(
        "admin.egress", quota=60, per_seconds=3600, scope=Scope.USER,
        burst=20, on_backend_failure=OnBackendFailure.DENY,
    ),
    # A Web Key Directory lookup request and its approval: each approval sends a request outside
    # this deployment, so the meter fails closed, and twenty an hour is far above any
    # investigation's need.
    "comms.key.lookup": Limit(
        "comms.key.lookup", quota=20, per_seconds=3600, scope=Scope.USER,
        burst=5, on_backend_failure=OnBackendFailure.DENY,
    ),
    # Every MEANING send the API makes (a free-text query in any column, and embedding a stored item
    # on demand for a /similar call) spends one, BESIDE the 'search' meter every similarity route
    # spends: a similarity crawl walking the corpus outward from one seed is a search exfiltration
    # that also discloses to the model endpoint. Fails closed.
    "search.meaning": Limit(
        "search.meaning", quota=60, per_seconds=60, scope=Scope.USER, burst=20,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # The console's "run a pass now" (Administration, Embeddings). A
    # pass of up to 2,000 items, bounded to 20 seconds.
    "embedding.pass": Limit(
        "embedding.pass", quota=30, per_seconds=3600, scope=Scope.USER, burst=5,
        on_backend_failure=OnBackendFailure.DENY,
    ),
    # Requeue, Drain now and every Jira or provider configuration write: each can send real mail or
    # real case material out, so they fail closed.
    "integration.write": Limit(
        "integration.write", quota=60, per_seconds=3600, scope=Scope.USER,
        burst=20, on_backend_failure=OnBackendFailure.DENY,
    ),
    # The integration test and the provider test reach a live third party.
    "integration.test": Limit(
        "integration.test", quota=20, per_seconds=3600, scope=Scope.USER,
        burst=5, on_backend_failure=OnBackendFailure.DENY,
        audit_every_seconds=60,
    ),
    # A lookup, a sign-off and a batch commit each may send a case selector to a provider.
    "lookup.request": Limit(
        "lookup.request", quota=120, per_seconds=3600, scope=Scope.USER,
        burst=20, on_backend_failure=OnBackendFailure.DENY,
    ),
    # A plan resolves up to 501 subjects and runs every gate on each without sending, so it is
    # metered as the read it is.
    "lookup.plan": Limit(
        "lookup.plan", quota=30, per_seconds=3600, scope=Scope.USER,
        burst=10, on_backend_failure=OnBackendFailure.DENY,
    ),
    # A list import parses, copies and indexes a file and then screens every held sample; a pass
    # started from the console runs up to 20 seconds of database work. Both are rare governance
    # acts. A detonation request, sign-off or cancel decides whether a live sample leaves for a
    # sandbox, so it is never looped.
    "screening.import": Limit(
        "screening.import", quota=10, per_seconds=3600, scope=Scope.USER,
        burst=3, on_backend_failure=OnBackendFailure.DENY,
    ),
    "screening.rescan": Limit(
        "screening.rescan", quota=6, per_seconds=3600, scope=Scope.USER,
        burst=2, on_backend_failure=OnBackendFailure.DENY,
    ),
    "sample.detonate": Limit(
        "sample.detonate", quota=20, per_seconds=3600, scope=Scope.USER,
        burst=5, on_backend_failure=OnBackendFailure.DENY,
    ),
    # Every attended act a persona performs on Telegram (looking a chat up, joining, checking
    # membership, rebinding): each is seen by Telegram as that account, and a burst of them is what
    # its anti-abuse systems ban. Stopping a chat carries none of this: stopping is always allowed.
    "collection.persona_act": Limit(
        "collection.persona_act", quota=20, per_seconds=3600, scope=Scope.USER,
        burst=5, on_backend_failure=OnBackendFailure.DENY,
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

        `audit.event` is append-only and hash-chained, and the chain trigger takes an advisory lock
        so rows serialise. Auditing every denial would let a caller who is ALREADY being throttled
        convert their rejected requests into unbounded, serialised, undeletable writes: a rate
        limiter that hands an attacker a better denial of service than the one it blocks. One row
        per window records the campaign; the count is in the access log.

        An unreachable backend means DO NOT audit, not "audit everything". The backend being
        unreachable is the SAME condition that makes every DENY-policy limit refuse every request,
        so a throttle that failed open would turn each of those refusals into a serialised,
        undeletable write: the outage would author the exact flood the throttle exists to prevent.
        The outage is already logged loudly by `check()`, so what is lost is one audit row per
        subject, during a window in which the audit log is the thing under threat.
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
