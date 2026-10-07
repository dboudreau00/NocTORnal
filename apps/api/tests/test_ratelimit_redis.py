"""The Redis leg: prove the Lua script and the pure Python decide the same
way, request for request.

Two implementations of one algorithm is two chances to be wrong, and the
failure mode is quiet -- a limiter that is 20% too generous looks exactly
like a limiter that works. So the central test here does not assert
hand-computed values a second time; it runs the SAME request sequence
through `InProcessBackend` and `RedisBackend` and asserts the allow/deny
sequences are identical. If the two ever disagree, that is the bug.

Env-gated on REDIS_URL, like the Postgres legs are on DATABASE_URL. Note
that CI fails the run if anything skips, so this gate means "the Redis
service is missing", not "these tests are optional".
"""
from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest

REDIS_URL = os.environ.get("REDIS_URL", "")
pytestmark = pytest.mark.skipif(
    not REDIS_URL, reason="REDIS_URL not set; the Redis leg is gated"
)


@pytest.fixture
def backend():
    from noctornal_api.ratelimit_redis import RedisBackend
    return RedisBackend(REDIS_URL)


def _forget(*patterns: str) -> None:
    """Delete what a test wrote. `test:` keys are not the limiter's, and
    since 2026-09-23 the readiness row `redis_limiter_isolated` reports a
    Redis holding them as SHARED (sec-redis-isolation), so a suite that
    left them for their TTL (a minute, for `claim_once`) would flip the
    register it tests in whichever readiness test ran next. Best effort:
    a Redis that went away mid-test is that test's failure, not this one's."""
    import redis

    try:
        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1,
                                      socket_timeout=1)
        for pattern in patterns:
            for name in client.scan_iter(match=pattern, count=1000):
                client.delete(name)
        client.close()
    except Exception:  # noqa: BLE001 - cleanup never decides a verdict
        pass


@pytest.fixture
def key():
    # A fresh key per test: these run against a shared dev Redis and a
    # leftover meter from a previous run would make the first assertion
    # fail for reasons that have nothing to do with the code.
    name = f"test:rl:{uuid4().hex}"
    yield name
    _forget(name)


def test_the_script_allows_the_burst_then_refuses(backend, key):
    emission, tolerance = 100_000, 300_000  # 0.1s each, burst 3
    for expected in (2, 1, 0):
        decision = backend.measure(key, emission, tolerance)
        assert decision.allowed
        assert decision.remaining == expected
    denied = backend.measure(key, emission, tolerance)
    assert not denied.allowed
    assert 0 < denied.retry_after_us <= emission


def test_a_denial_writes_nothing(backend, key):
    """Same property as the pure implementation, asserted against the real
    script: hammering must not extend your own lockout."""
    emission, tolerance = 1_000_000, 1_000_000
    assert backend.measure(key, emission, tolerance).allowed
    waits = [backend.measure(key, emission, tolerance).retry_after_us
             for _ in range(20)]
    # Each successive denial asks for LESS time (the meter is draining),
    # never more. A meter advanced by denials would show waits growing.
    assert waits == sorted(waits, reverse=True)
    assert waits[0] <= emission


def test_the_meter_expires_on_its_own(backend, key):
    """The TTL is what stops an abandoned subject occupying memory forever.
    A limiter whose keys never expire is a slow memory leak with a security
    story attached."""
    emission, tolerance = 200_000, 200_000  # 0.2s
    assert backend.measure(key, emission, tolerance).allowed
    assert not backend.measure(key, emission, tolerance).allowed
    time.sleep(0.3)
    assert backend.measure(key, emission, tolerance).allowed


#: The production script's one clock read, which the agreement test below
#: replaces with an argument.
_CLOCK_READ = ("local now = redis.call('TIME')\n"
               "local now_us = tonumber(now[1]) * 1000000 + tonumber(now[2])\n")


def test_redis_and_python_agree_request_for_request(key):
    """The test that matters. One algorithm, two implementations, one
    decision sequence, asserted at the boundaries.

    Both sides run on ONE injected clock (beta gate, 2026-10-07). Until then
    each read its own wall clock, every Redis round trip added elapsed time
    to the Redis side only, and on a loaded machine the two drifted across
    a boundary the other had not reached: the test failed with nothing
    wrong (known since 2026-07-30). The production script reads Redis's
    TIME and `measure` takes no clock, by design (the next test asserts
    both), so the Redis side here runs the production script's own text
    with that one read replaced by an argument, called through
    `RedisBackend`'s own parsing; every other line is what production runs.
    Time being exact, requests land ON the boundary (allow_at == now),
    which wall time could never place, and whole decisions are compared,
    not just the verdict.

    The clock is whole seconds at a realistic epoch, so the in-process
    side's float clock converts exactly and the Redis side carries numbers
    the size production does; an emission of a minute keeps every meter's
    real TTL far longer than the test.
    """
    import random

    from noctornal_api.ratelimit import InProcessBackend
    from noctornal_api.ratelimit_redis import _GCRA_LUA, RedisBackend

    assert _GCRA_LUA.count(_CLOCK_READ) == 1
    clock_s = [1_790_000_000]
    backend = RedisBackend(REDIS_URL)
    timed = backend._redis.register_script(
        _GCRA_LUA.replace(_CLOCK_READ, "local now_us = tonumber(ARGV[4])\n"))
    backend._script = lambda keys, args: timed(
        keys=keys, args=[*args, clock_s[0] * 1_000_000])
    local = InProcessBackend(now=lambda: float(clock_s[0]))

    emission, tolerance = 60_000_000, 300_000_000  # a minute each, burst 5
    # (seconds to advance, operation): a burst to refusal, the far side of
    # the boundary, the boundary itself, peeks that must consume nothing, a
    # partial drain and an emptied meter; then a seeded random tail.
    script = ([(0, "measure")] * 6 + [(59, "measure"), (1, "peek"),
              (0, "measure"), (0, "measure"), (59, "measure"),
              (1, "measure"), (150, "measure"), (0, "peek"), (0, "measure"),
              (0, "measure"), (1000, "measure")])
    rng = random.Random(20261007)
    script += [(rng.choice((0, 0, 1, 59, 60, 61, 150)),
                rng.choice(("measure", "measure", "peek"))) for _ in range(60)]

    redis_side, local_side, at_boundary = [], [], 0
    for advance, op in script:
        clock_s[0] += advance
        before = local.peek("mirror", emission, tolerance)
        redis_side.append(getattr(backend, op)(key, emission, tolerance))
        local_side.append(getattr(local, op)("mirror", emission, tolerance))
        # Allowed with the meter then exactly full: allow_at == now.
        at_boundary += before.allowed and before.reset_us == tolerance
    assert redis_side == local_side
    # The sequence has to exercise both branches and the boundary itself,
    # or it passes vacuously on a limit nobody reached.
    verdicts = [d.allowed for d in redis_side]
    assert True in verdicts and False in verdicts
    assert at_boundary


def test_time_comes_from_redis_not_from_the_caller(backend, key):
    """There is no `now` parameter to pass, by design. Several API
    processes with disagreeing clocks would otherwise each enforce their
    own idea of the rate, and one whose clock stepped backwards would hand
    out free capacity while it caught up -- the development host for this
    project has an unsynchronised clock, so this is not hypothetical.

    Asserted structurally: the script reads TIME itself, and `measure`
    exposes no clock argument to get wrong.
    """
    import inspect

    from noctornal_api.ratelimit_redis import _GCRA_LUA, RedisBackend

    assert "redis.call('TIME')" in _GCRA_LUA
    params = inspect.signature(RedisBackend.measure).parameters
    assert set(params) == {"self", "key", "emission_us", "tolerance_us"}


def test_claim_once_is_atomic_across_calls(backend, key):
    assert backend.claim_once(key, 60) is True
    assert backend.claim_once(key, 60) is False


def test_a_malformed_script_result_is_treated_as_no_backend(backend, key):
    """A nonsense answer must not be read as an allow. Treating an
    unparseable result as success is how a limiter silently stops
    limiting."""
    from noctornal_api.ratelimit import BackendUnavailable

    backend._script = lambda keys, args: ["not", "numbers"]
    with pytest.raises(BackendUnavailable):
        backend.measure(key, 1000, 1000)


def test_an_unreachable_redis_raises_backend_unavailable_not_a_redis_error():
    """The policy decision (fail open or fail closed) is taken in exactly
    one place. That only works if every Redis-level failure arrives there
    as the same exception."""
    from noctornal_api.ratelimit import BackendUnavailable
    from noctornal_api.ratelimit_redis import RedisBackend

    # A port nothing listens on inside the test host.
    dead = RedisBackend("redis://127.0.0.1:6399/0")
    with pytest.raises(BackendUnavailable):
        dead.measure("k", 1000, 1000)
    assert dead.ping() is False


def test_a_dead_backend_does_not_hang_the_request():
    """redis-py's default socket timeout is None. A Redis that accepts
    connections and stops answering would then hang every limited request
    for as long as the TCP stack allows -- the limiter causing the outage
    it was installed to prevent."""
    from noctornal_api.ratelimit_redis import (
        CONNECT_TIMEOUT_S,
        SOCKET_TIMEOUT_S,
        RedisBackend,
    )

    assert 0 < CONNECT_TIMEOUT_S <= 1.0
    assert 0 < SOCKET_TIMEOUT_S <= 1.0

    dead = RedisBackend("redis://127.0.0.1:6399/0")
    started = time.monotonic()
    try:
        dead.measure("k", 1000, 1000)
    except Exception:  # noqa: BLE001 - the point is the elapsed time
        pass
    assert time.monotonic() - started < 3.0


def test_the_limiter_end_to_end_over_redis(key):
    """The full stack as the API uses it: catalogue -> limiter -> Lua."""
    from noctornal_api.ratelimit import Limit, RateLimiter, Scope
    from noctornal_api.ratelimit_redis import RedisBackend

    prefix = f"test:{uuid4().hex[:8]}"
    limiter = RateLimiter(
        RedisBackend(REDIS_URL),
        limits={"t": Limit("t", quota=4, per_seconds=4, scope=Scope.USER, burst=2)},
        key_prefix=prefix,
    )
    try:
        assert limiter.check("t", "u:1").allowed
        assert limiter.check("t", "u:1").allowed
        denied = limiter.check("t", "u:1")
        assert not denied.allowed
        assert not denied.degraded, "a measured refusal is not a degraded one"
        assert denied.headers["Retry-After"] == "1"
        # A different subject is unaffected.
        assert limiter.check("t", "u:2").allowed
    finally:
        _forget(f"{prefix}:*")


def test_peek_does_not_consume_over_redis(backend, key):
    emission, tolerance = 500_000, 1_000_000  # 0.5s each, burst 2
    for _ in range(20):
        assert backend.peek(key, emission, tolerance).allowed
    assert backend.measure(key, emission, tolerance).allowed
    assert backend.measure(key, emission, tolerance).allowed
    assert not backend.peek(key, emission, tolerance).allowed


def test_one_script_serves_both_so_they_cannot_drift(backend, key):
    """Peek and measure share a script, switched by an argument. Two
    scripts would be two chances to change one and not the other, and the
    resulting disagreement is silent."""
    from noctornal_api.ratelimit_redis import _GCRA_LUA

    assert _GCRA_LUA.count("local allow_at") == 1, "one decision, not two"
    assert "if commit == 1 then" in _GCRA_LUA

    emission, tolerance = 200_000, 600_000
    for _ in range(10):
        predicted = backend.peek(key, emission, tolerance)
        actual = backend.measure(key, emission, tolerance)
        assert predicted.allowed == actual.allowed
