"""Rate limiter: the GCRA maths against hand-computed values, the policy
that decides what a dead backend means, and the two properties that make
the limiter itself safe to attack.

No Redis, no database, no real clock -- `ratelimit.py` is pure for exactly
this reason. The Redis leg is `test_ratelimit_redis.py`, which asserts the
Lua and this module agree request for request.
"""
from __future__ import annotations

import pytest

from noctornal_api.ratelimit import (
    LIMITS,
    BackendUnavailable,
    InProcessBackend,
    Limit,
    OnBackendFailure,
    RateLimiter,
    Scope,
    gcra,
    hashed,
    ip_subject,
)

SEC = 1_000_000  # microseconds, the unit the limiter works in


class FakeClock:
    """Seconds as a float, movable. Mirrors conftest's Clock, which deals in
    datetimes -- the limiter deliberately uses monotonic seconds instead."""

    def __init__(self, start: float = 0.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# ---------------------------------------------------------------------------
# The algorithm
# ---------------------------------------------------------------------------

def test_gcra_allows_the_full_burst_then_meters_at_the_sustained_rate():
    """3 at once, then one per second. Values are hand-computed, not
    read off the implementation."""
    emission, tolerance = 1 * SEC, 3 * SEC

    tat = None
    for expected_remaining in (2, 1, 0):
        decision, tat = gcra(now_us=0, tat_us=tat, emission_us=emission,
                             tolerance_us=tolerance)
        assert decision.allowed
        assert decision.remaining == expected_remaining

    # Fourth request in the same instant: the meter is full.
    decision, new_tat = gcra(now_us=0, tat_us=tat, emission_us=emission,
                             tolerance_us=tolerance)
    assert not decision.allowed
    assert decision.retry_after_us == 1 * SEC
    assert decision.reset_us == 3 * SEC  # the whole burst drains in 3s

    # One second later exactly one slot has reopened.
    decision, tat = gcra(now_us=1 * SEC, tat_us=tat, emission_us=emission,
                         tolerance_us=tolerance)
    assert decision.allowed
    assert decision.remaining == 0


def test_a_denied_request_does_not_advance_the_meter():
    """The property that stops the limiter being a weapon.

    If a denial pushed the arrival time out, a client ignoring Retry-After
    would extend its own lockout without bound -- and anyone able to forge
    the subject (a spoofed X-Forwarded-For, a guessed user id) could hold a
    third party out indefinitely with a trickle of requests. GCRA does not
    write on denial, so the penalty is capped at the limit itself.
    """
    emission, tolerance = 1 * SEC, 2 * SEC
    tat = None
    for _ in range(2):
        _, tat = gcra(now_us=0, tat_us=tat, emission_us=emission,
                      tolerance_us=tolerance)
    saturated = tat

    for _ in range(1000):
        decision, new_tat = gcra(now_us=0, tat_us=saturated, emission_us=emission,
                                 tolerance_us=tolerance)
        assert not decision.allowed
        assert new_tat is None, "a denial must write nothing"
        # And the wait never grows past one emission interval.
        assert decision.retry_after_us == 1 * SEC


def test_an_idle_subject_does_not_bank_unlimited_credit():
    """A leaky bucket that kept filling would let a subject idle for a day
    and then fire a day's worth of requests at once."""
    emission, tolerance = 1 * SEC, 3 * SEC
    _, tat = gcra(now_us=0, tat_us=None, emission_us=emission, tolerance_us=tolerance)

    # An hour passes. Credit is capped at the burst, not at the idle time.
    now = 3600 * SEC
    allowed = 0
    for _ in range(50):
        decision, new_tat = gcra(now_us=now, tat_us=tat, emission_us=emission,
                                 tolerance_us=tolerance)
        if not decision.allowed:
            break
        allowed += 1
        tat = new_tat
    assert allowed == 3


def test_first_ever_request_is_allowed():
    decision, tat = gcra(now_us=12345, tat_us=None, emission_us=SEC,
                         tolerance_us=SEC)
    assert decision.allowed
    assert tat == 12345 + SEC


# ---------------------------------------------------------------------------
# The in-process backend
# ---------------------------------------------------------------------------

def test_in_process_backend_meters_over_time():
    clock = FakeClock()
    backend = InProcessBackend(now=clock)
    limit = Limit("t", quota=3, per_seconds=3, scope=Scope.USER)

    for _ in range(3):
        assert backend.measure("k", limit.emission_us, limit.tolerance_us).allowed
    assert not backend.measure("k", limit.emission_us, limit.tolerance_us).allowed

    clock.advance(1.0)
    assert backend.measure("k", limit.emission_us, limit.tolerance_us).allowed
    assert not backend.measure("k", limit.emission_us, limit.tolerance_us).allowed


def test_subjects_do_not_share_a_meter():
    clock = FakeClock()
    backend = InProcessBackend(now=clock)
    limit = Limit("t", quota=1, per_seconds=10, scope=Scope.USER)

    assert backend.measure("a", limit.emission_us, limit.tolerance_us).allowed
    assert not backend.measure("a", limit.emission_us, limit.tolerance_us).allowed
    assert backend.measure("b", limit.emission_us, limit.tolerance_us).allowed


def test_eviction_drops_expired_meters_before_live_ones():
    """The meter table is bounded, because an attacker varying the subject
    (a fresh random Bearer token per request) would otherwise grow it until
    the process dies -- a memory exhaustion delivered through the component
    installed to prevent exhaustion."""
    clock = FakeClock()
    backend = InProcessBackend(now=clock, max_keys=4)
    limit = Limit("t", quota=1, per_seconds=1, scope=Scope.USER)

    # Four subjects, each one emission (1s) deep.
    for name in "abcd":
        backend.measure(name, limit.emission_us, limit.tolerance_us)
    clock.advance(2.0)  # all four meters have now drained

    backend.measure("e", limit.emission_us, limit.tolerance_us)
    # The expired four were free to drop, so the live one is all that is left.
    assert set(backend._meters) == {"e"}


def test_eviction_forgives_the_least_throttled_subject_first():
    """When nothing has expired, eviction has to lose SOME enforcement.
    Losing it from the subject closest to empty forgives the least. A plain
    insertion-order LRU would do the opposite: an attacker cycling subjects
    would flush the meter of whoever is actually being throttled."""
    clock = FakeClock()
    backend = InProcessBackend(now=clock, max_keys=3)
    deep = Limit("deep", quota=1, per_seconds=100, scope=Scope.USER)
    shallow = Limit("shallow", quota=1, per_seconds=1, scope=Scope.USER)

    backend.measure("heavily-throttled", deep.emission_us, deep.tolerance_us)
    backend.measure("barely-used", shallow.emission_us, shallow.tolerance_us)
    backend.measure("also-deep", deep.emission_us, deep.tolerance_us)

    backend.measure("new", deep.emission_us, deep.tolerance_us)
    assert "heavily-throttled" in backend._meters
    assert "barely-used" not in backend._meters


def test_claim_once_is_true_exactly_once_per_window():
    clock = FakeClock()
    backend = InProcessBackend(now=clock)
    assert backend.claim_once("k", 60) is True
    for _ in range(100):
        assert backend.claim_once("k", 60) is False
    clock.advance(61)
    assert backend.claim_once("k", 60) is True


# ---------------------------------------------------------------------------
# Policy: what an unreachable backend means
# ---------------------------------------------------------------------------

class DeadBackend:
    def measure(self, key, emission_us, tolerance_us):
        raise BackendUnavailable("simulated outage")

    def peek(self, key, emission_us, tolerance_us):
        raise BackendUnavailable("simulated outage")

    def claim_once(self, key, window_seconds):
        raise BackendUnavailable("simulated outage")


def test_a_dead_backend_fails_closed_for_a_deny_limit():
    limiter = RateLimiter(DeadBackend(), limits={
        "x": Limit("x", quota=1, per_seconds=1, scope=Scope.USER,
                   on_backend_failure=OnBackendFailure.DENY)})
    decision = limiter.check("x", "u:1")
    assert not decision.allowed
    assert decision.degraded, "a policy refusal must be distinguishable from a 429"


def test_a_dead_backend_fails_open_for_an_allow_limit():
    limiter = RateLimiter(DeadBackend(), limits={
        "x": Limit("x", quota=1, per_seconds=1, scope=Scope.USER,
                   on_backend_failure=OnBackendFailure.ALLOW)})
    decision = limiter.check("x", "u:1")
    assert decision.allowed
    assert decision.degraded, "a fail-open must announce itself, never be silent"


def test_the_audit_throttle_never_fails_a_request():
    """An audit throttle that raised would turn a Redis blip into a 500 on
    a path that was already refusing the request."""
    limiter = RateLimiter(DeadBackend(), limits={
        "x": Limit("x", quota=1, per_seconds=1, scope=Scope.USER)})
    limiter.should_audit("x", "u:1")  # must not raise


def test_the_audit_throttle_fails_CLOSED_not_open():
    """Found by adversarial review, and it reads backwards until you see it.

    An unreachable backend is the SAME condition that makes every
    DENY-policy limit refuse every request. A throttle that failed open
    would therefore, during an outage, turn each of those refusals into a
    serialised, undeletable, append-only audit write -- the outage authoring
    the exact flood the throttle exists to prevent. The outage is already
    logged loudly by check(); what is given up is one audit row per subject,
    during the window in which the audit log is the thing under threat.
    """
    limiter = RateLimiter(DeadBackend(), limits={
        "x": Limit("x", quota=1, per_seconds=1, scope=Scope.USER)})
    assert limiter.should_audit("x", "u:1") is False


def test_an_unknown_limit_raises_rather_than_meaning_unlimited():
    limiter = RateLimiter(InProcessBackend())
    with pytest.raises(KeyError):
        limiter.check("analytics.suit", "u:1")  # a plausible typo


def test_disabled_limiter_allows_everything():
    limiter = RateLimiter(InProcessBackend(), enabled=False)
    for _ in range(10_000):
        assert limiter.check("auth.login", "ip4:x").allowed


# ---------------------------------------------------------------------------
# Subjects
# ---------------------------------------------------------------------------

def test_ipv6_is_limited_by_its_64_not_its_128():
    """A residential IPv6 allocation is a /64 at minimum. Limiting a single
    address limits one out of 2^64 the same host already holds, which is
    not a limit."""
    a = ip_subject("2001:db8:1234:5678::1")
    b = ip_subject("2001:db8:1234:5678:ffff:ffff:ffff:ffff")
    c = ip_subject("2001:db8:1234:9999::1")
    assert a == b
    assert a != c


def test_ipv4_addresses_are_distinct_subjects():
    assert ip_subject("198.51.100.7") != ip_subject("198.51.100.8")


def test_an_unparseable_address_cannot_mint_unlimited_subjects():
    assert ip_subject("not-an-ip") == ip_subject("also-not-an-ip")
    assert ip_subject(None) == ip_subject("")


def test_subject_keys_do_not_carry_the_plaintext():
    """Keys land in Redis, which is not the system of record and not a
    secret store. Obfuscation, not anonymisation -- see the module
    docstring -- but a KEYS dump must not hand over live session tokens."""
    token = "a-live-session-token"
    assert token not in hashed(token)
    assert "198.51.100.7" not in ip_subject("198.51.100.7")


# ---------------------------------------------------------------------------
# The catalogue itself
# ---------------------------------------------------------------------------

def test_every_catalogue_entry_is_keyed_by_its_own_name():
    """A mismatch would make `rate_limit("x")` apply limit "y" -- silently,
    and only visibly wrong under load."""
    for key, limit in LIMITS.items():
        assert limit.name == key


def test_every_cost_bearing_limit_fails_closed():
    """The blanket per-request ceiling is the ONLY limit allowed to fail
    open; see the module docstring. This test is what stops a later edit
    quietly adding a second one."""
    fail_open = {name for name, limit in LIMITS.items()
                 if limit.on_backend_failure is OnBackendFailure.ALLOW}
    # Both blanket meters, and only the blanket meters. `request.source` is
    # the address-scoped half added after review found the credential half
    # was not a ceiling at all; denying either would turn a Redis restart
    # into a total outage.
    assert fail_open == {"request", "request.source"}


def test_the_login_limit_is_ip_scoped_not_user_scoped():
    """An email- or user-scoped login limit is a remotely triggerable
    lockout of a named analyst: anyone can send that email address. The
    decaying account lockout covers targeted guessing; this covers spraying."""
    assert LIMITS["auth.login"].scope is Scope.IP


def test_the_blanket_limit_needs_no_database_lookup():
    """It runs in middleware, before session validation, so it can only be
    keyed on something present in the request itself."""
    assert LIMITS["request"].scope is Scope.CREDENTIAL


def test_burst_never_exceeds_quota():
    """burst > quota would let a subject exceed the sustained rate over the
    window the quota is stated in, which makes the documented number a lie."""
    for limit in LIMITS.values():
        assert limit.effective_burst <= limit.quota


def test_limit_construction_rejects_nonsense():
    with pytest.raises(ValueError):
        Limit("x", quota=0, per_seconds=1, scope=Scope.USER)
    with pytest.raises(ValueError):
        Limit("x", quota=1, per_seconds=0, scope=Scope.USER)
    with pytest.raises(ValueError):
        Limit("x", quota=1, per_seconds=1, scope=Scope.USER, burst=0)


def test_retry_after_rounds_up_never_down():
    """A Retry-After that rounds down tells a compliant client to come back
    into a second denial, which makes well-behaved clients look like
    attackers."""
    limiter = RateLimiter(InProcessBackend(now=FakeClock()), limits={
        "x": Limit("x", quota=2, per_seconds=3, scope=Scope.USER, burst=1)})
    assert limiter.check("x", "u").allowed
    denied = limiter.check("x", "u")
    assert not denied.allowed
    # emission is 1.5s, so the true wait is 1.5s and the header must say 2.
    assert denied.retry_after_seconds == 2
    assert denied.headers["Retry-After"] == "2"


def test_headers_are_present_on_success_too():
    """A client that only learns the limit by hitting it will hit it."""
    limiter = RateLimiter(InProcessBackend(now=FakeClock()))
    headers = limiter.check("search", "u:1").headers
    assert headers["RateLimit-Limit"] == str(LIMITS["search"].quota)
    assert "Retry-After" not in headers
    assert "burst=" in headers["RateLimit-Policy"]


# ---------------------------------------------------------------------------
# Peek: reading a meter you are not the one filling
# ---------------------------------------------------------------------------

def test_peek_reports_without_consuming():
    """The login failure meter is consumed by a failed authentication but
    has to be READ before one, so that a source which has exhausted it is
    refused before the deliberately expensive password hash runs."""
    clock = FakeClock()
    backend = InProcessBackend(now=clock)
    limit = Limit("t", quota=2, per_seconds=10, scope=Scope.IP, burst=2)

    for _ in range(100):
        assert backend.peek("k", limit.emission_us, limit.tolerance_us).allowed
    # A hundred peeks spent nothing, so both slots are still there.
    assert backend.measure("k", limit.emission_us, limit.tolerance_us).allowed
    assert backend.measure("k", limit.emission_us, limit.tolerance_us).allowed
    assert not backend.peek("k", limit.emission_us, limit.tolerance_us).allowed


def test_peek_and_measure_agree_about_the_verdict():
    """A peek that disagrees with the consume it guards either refuses
    requests that would have been allowed, or admits ones that would not."""
    clock = FakeClock()
    backend = InProcessBackend(now=clock)
    limit = Limit("t", quota=5, per_seconds=5, scope=Scope.IP, burst=5)

    for _ in range(12):
        predicted = backend.peek("k", limit.emission_us, limit.tolerance_us)
        actual = backend.measure("k", limit.emission_us, limit.tolerance_us)
        assert predicted.allowed == actual.allowed
        clock.advance(0.3)


def test_the_limiter_exposes_peek_as_well_as_check():
    limiter = RateLimiter(InProcessBackend(now=FakeClock()), limits={
        "t": Limit("t", quota=1, per_seconds=60, scope=Scope.IP, burst=1)})
    assert limiter.peek("t", "ip4:x").allowed
    assert limiter.peek("t", "ip4:x").allowed
    assert limiter.check("t", "ip4:x").allowed
    assert not limiter.peek("t", "ip4:x").allowed


def test_a_dead_backend_fails_closed_on_peek_too():
    """A peek that silently succeeded when the backend is down would let
    the guard it implements evaporate during an outage."""
    limiter = RateLimiter(DeadBackend(), limits={
        "t": Limit("t", quota=1, per_seconds=1, scope=Scope.IP,
                   on_backend_failure=OnBackendFailure.DENY)})
    decision = limiter.peek("t", "ip4:x")
    assert not decision.allowed and decision.degraded


def test_login_is_metered_by_failures_not_only_by_attempts():
    """The catalogue must carry BOTH login meters. Dropping the failure one
    would leave only the generous attempt limit, which is tuned for a
    NAT'd organisation and is not an anti-guessing control at all."""
    assert LIMITS["auth.login_failed"].scope is Scope.IP
    assert LIMITS["auth.login_failed"].quota < LIMITS["auth.login"].quota


def test_the_attempt_limit_is_generous_enough_for_a_natted_organisation():
    """Two hundred analysts behind one egress address signing on within ten
    minutes of 09:00 must not look like an attack. Stated as a test because
    it is the number most likely to be "tightened" by someone who has not
    met the customer."""
    limit = LIMITS["auth.login"]
    per_minute = limit.quota * 60 / limit.per_seconds
    assert per_minute >= 60, "a whole unit signs on through one address"


# ---------------------------------------------------------------------------
# Regressions from the adversarial review pass (2026-07-25)
#
# Each of these is a defect that shipped, was found by a reviewer trying to
# break the limiter rather than to confirm it, and was reproduced against
# the running app before being fixed. They are named for the defect.
# ---------------------------------------------------------------------------

def test_ipv4_mapped_addresses_are_not_all_the_same_subject():
    """`::ffff:a.b.c.d` addresses ALL share the /64 `::/64`.

    A dual-stack listener -- uvicorn bound to `::`, which is the default on
    many deployments -- reports every IPv4 peer in that form. Before the
    unmapping, every IPv4 client in the world therefore shared ONE login
    bucket, and the first person to mistype a password locked out everyone
    else. The limiter would have looked like it was working.
    """
    assert ip_subject("::ffff:198.51.100.7") == ip_subject("198.51.100.7")
    assert ip_subject("::ffff:198.51.100.7") != ip_subject("::ffff:203.0.113.99")
    assert ip_subject("::ffff:198.51.100.7") != ip_subject("::1")


def test_real_ipv6_addresses_still_collapse_to_their_64():
    """The unmapping must not undo the /64 rule for actual IPv6."""
    assert ip_subject("2001:db8:1:2::1") == ip_subject("2001:db8:1:2:ffff::9")
    assert ip_subject("2001:db8:1:2::1") != ip_subject("2001:db8:1:3::1")


def test_the_blanket_ceiling_has_a_meter_the_caller_cannot_mint():
    """The critical one.

    `request` is keyed on the presented credential, which the caller
    supplies and nothing validates -- so rotating a random Bearer token per
    request mints a fresh meter every time. Reproduced against the real app:
    with the limit shrunk to 3, a fixed token gave 27 refusals in 30
    requests and a rotating one gave zero. The credential meter subdivides;
    it cannot bound. `request.source` is the meter that bounds, because a
    caller cannot choose their own peer address.
    """
    assert LIMITS["request"].scope is Scope.CREDENTIAL
    assert LIMITS["request.source"].scope is Scope.IP
    # And the ceiling has to be the more generous of the two, or the
    # subdivision is meaningless.
    assert LIMITS["request.source"].quota >= LIMITS["request"].quota


def test_the_login_burst_bounds_the_peek_consume_race():
    """The failure meter is PEEKED before the Argon2id verify and consumed
    after it, so a simultaneous burst all read an un-advanced meter and all
    proceed. The number of guesses one burst buys is therefore bounded by
    the ATTEMPT limit's burst, not by the failure limit's -- which is why
    the attempt burst is small even though its quota is not."""
    attempts, failures = LIMITS["auth.login"], LIMITS["auth.login_failed"]
    assert attempts.effective_burst <= failures.quota, (
        "a single burst must not be able to spend more guesses than the "
        "failure meter allows in its whole window")
