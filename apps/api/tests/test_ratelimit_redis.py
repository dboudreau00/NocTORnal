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


@pytest.fixture
def key():
    # A fresh key per test: these run against a shared dev Redis and a
    # leftover meter from a previous run would make the first assertion
    # fail for reasons that have nothing to do with the code.
    return f"test:rl:{uuid4().hex}"


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


def test_redis_and_python_agree_request_for_request(backend, key):
    """The test that matters. One algorithm, two implementations, one
    verdict sequence.

    Timing is kept away from the boundaries deliberately: this asserts the
    two implementations agree, not that either can resolve a microsecond.
    """
    from noctornal_api.ratelimit import InProcessBackend

    emission, tolerance = 50_000, 250_000  # 0.05s each, burst 5
    local = InProcessBackend()
    local_key = "mirror"

    redis_verdicts, local_verdicts = [], []
    for i in range(30):
        redis_verdicts.append(backend.measure(key, emission, tolerance).allowed)
        local_verdicts.append(local.measure(local_key, emission, tolerance).allowed)
        if i % 7 == 6:
            time.sleep(0.12)  # two and a bit emissions of recovery

    assert redis_verdicts == local_verdicts
    # And the sequence has to actually exercise both branches, or the test
    # passes vacuously on a limit nobody reached.
    assert True in redis_verdicts and False in redis_verdicts


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

    limiter = RateLimiter(
        RedisBackend(REDIS_URL),
        limits={"t": Limit("t", quota=4, per_seconds=4, scope=Scope.USER, burst=2)},
        key_prefix=f"test:{uuid4().hex[:8]}",
    )
    assert limiter.check("t", "u:1").allowed
    assert limiter.check("t", "u:1").allowed
    denied = limiter.check("t", "u:1")
    assert not denied.allowed
    assert not denied.degraded, "a measured refusal is not a degraded one"
    assert denied.headers["Retry-After"] == "1"
    # A different subject is unaffected.
    assert limiter.check("t", "u:2").allowed


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
