"""The Redis half of the rate limiter: one atomic Lua script, and the
connection settings that stop a sick Redis from becoming a sick API.

`ratelimit.py` holds the decision; this holds the only thing that has to be
shared between processes -- the meter. The split is the same one
`analytics.py` / `analytics_runs.py` uses, and for the same reason: the
part with the reasoning in it should be testable without infrastructure.

## Three things this file exists to get right

**1. The script is atomic, and it has to be.**
Read-then-write across two round trips lets two concurrent requests read
the same meter and both be allowed, which is the entire failure a rate
limiter exists to prevent. Redis runs a Lua script to completion with
nothing interleaved, so the compare, the decide and the store are one
operation.

**2. Time comes from Redis, not from the caller.**
Passing `now` in from Python would make the limit a function of the API
process's clock: several processes disagreeing by seconds hand out extra
capacity, and one process whose clock steps backwards hands out a lot of
it. The development host for this project has an unsynchronised clock
(docs/15 records the TOTP consequences of that), which makes the point
concrete rather than theoretical. `redis.call('TIME')` gives every process
the same monotonic-enough reference: the meter's server.

**3. A hung backend must fail fast.**
The default socket timeout in redis-py is None -- no timeout. A Redis that
accepts connections and stops answering would then hang every request that
touches a limited endpoint, for as long as the TCP stack allows. That is a
rate limiter causing the outage it was installed to prevent. Timeouts here
are deliberately shorter than any user-visible latency budget: a limiter
that cannot answer in a quarter of a second should be treated as absent
and the per-limit `on_backend_failure` policy applied.
"""
from __future__ import annotations

import logging

from noctornal_api.ratelimit import BackendUnavailable, RawDecision

log = logging.getLogger("noctornal.ratelimit")

# A dead-but-listening Redis must not become the API's latency. See (3).
CONNECT_TIMEOUT_S = 0.25
SOCKET_TIMEOUT_S = 0.25

# GCRA, atomically. Microseconds throughout: Lua numbers are doubles, and
# integer microseconds of Unix time (~1.8e15) sit comfortably below 2^53,
# so this arithmetic is exact and matches ratelimit.gcra() exactly.
#
# ONE script serves both measure and peek, switched by ARGV[3], rather than
# two scripts that would slowly drift apart. A peek whose arithmetic no
# longer matches the consume it guards is a limit that refuses requests it
# would have allowed, or worse, admits ones it would not.
#
# KEYS[1]  the meter
# ARGV[1]  emission interval, microseconds per request
# ARGV[2]  delay tolerance, microseconds (emission * burst)
# ARGV[3]  1 to consume a slot, 0 to read only
# returns  {allowed, retry_after_us, remaining, reset_us}
_GCRA_LUA = """
local now = redis.call('TIME')
local now_us = tonumber(now[1]) * 1000000 + tonumber(now[2])
local emission = tonumber(ARGV[1])
local tolerance = tonumber(ARGV[2])
local commit = tonumber(ARGV[3])

local tat = tonumber(redis.call('GET', KEYS[1]))
if tat == nil or tat < now_us then
  tat = now_us
end

local new_tat = tat + emission
local allow_at = new_tat - tolerance

if allow_at > now_us then
  -- Denied. Deliberately NO write: a denied request must not advance the
  -- meter, or a client ignoring Retry-After extends its own lockout without
  -- limit and anyone able to forge the subject can do it to a third party.
  return {0, allow_at - now_us, 0, tat - now_us}
end

if commit == 1 then
  local ttl_ms = math.ceil((new_tat - now_us) / 1000)
  if ttl_ms < 1 then ttl_ms = 1 end
  redis.call('SET', KEYS[1], new_tat, 'PX', ttl_ms)
end

local remaining = math.floor((tolerance - (new_tat - now_us)) / emission)
if remaining < 0 then remaining = 0 end
return {1, 0, remaining, new_tat - now_us}
"""


class RedisBackend:
    """A `ratelimit.Backend` over Redis.

    Every Redis-level failure becomes `BackendUnavailable`, so the policy
    decision (fail open or fail closed) is taken in exactly one place --
    `RateLimiter.check` -- and not scattered across exception handlers that
    each guess differently.
    """

    def __init__(self, url: str, *, client=None):
        if client is not None:
            self._redis = client
        else:
            import redis  # imported here so the package is optional at import time

            self._redis = redis.Redis.from_url(
                url,
                socket_connect_timeout=CONNECT_TIMEOUT_S,
                socket_timeout=SOCKET_TIMEOUT_S,
                # A pooled connection that died while idle would otherwise
                # surface as a failed request rather than a reconnect.
                health_check_interval=30,
                # Fail fast and let the policy decide. Retrying inside the
                # client multiplies the timeout by the retry count, which
                # is the hang this file exists to avoid.
                retry_on_timeout=False,
                decode_responses=False,
            )
        self._script = self._redis.register_script(_GCRA_LUA)

    def measure(self, key: str, emission_us: int, tolerance_us: int) -> RawDecision:
        return self._run(key, emission_us, tolerance_us, commit=1)

    def peek(self, key: str, emission_us: int, tolerance_us: int) -> RawDecision:
        return self._run(key, emission_us, tolerance_us, commit=0)

    def _run(self, key: str, emission_us: int, tolerance_us: int,
             *, commit: int) -> RawDecision:
        try:
            result = self._script(keys=[key],
                                  args=[emission_us, tolerance_us, commit])
        except Exception as exc:  # redis.RedisError, OSError, and anything a
            # broken client library raises -- all of them mean "no meter".
            raise BackendUnavailable(f"{type(exc).__name__}: {exc}") from exc
        try:
            allowed, retry_after_us, remaining, reset_us = (int(v) for v in result)
        except (TypeError, ValueError) as exc:
            # A shape we did not write. Treating a nonsense answer as a
            # valid one is how a limiter silently stops limiting.
            raise BackendUnavailable(f"malformed script result: {result!r}") from exc
        return RawDecision(
            allowed=bool(allowed),
            retry_after_us=max(0, retry_after_us),
            remaining=max(0, remaining),
            reset_us=max(0, reset_us),
        )

    def claim_once(self, key: str, window_seconds: int) -> bool:
        """First caller in the window wins. SET NX EX is atomic, so two
        concurrent denials cannot both decide they are the first.

        Returns False when Redis is unreachable -- deliberately, and see
        `RateLimiter.should_audit` for the reasoning. Returning True there
        would mean that during a Redis outage, when every DENY-policy limit
        is refusing every request, each refusal writes a row to a
        hash-chained append-only table whose trigger serialises writes. The
        outage would author the flood.
        """
        try:
            return bool(self._redis.set(key, b"1", nx=True, ex=max(1, window_seconds)))
        except Exception:  # noqa: BLE001 - an audit throttle must never fail a request
            log.error("audit-throttle claim failed; not auditing", exc_info=True)
            return False

    def ping(self) -> bool:
        try:
            return bool(self._redis.ping())
        except Exception:  # noqa: BLE001 - a startup probe reports, it does not raise
            return False

    def close(self) -> None:
        try:
            self._redis.close()
        except Exception:  # noqa: BLE001
            pass
