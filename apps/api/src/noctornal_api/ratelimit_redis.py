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

# Every maxmemory-policy Redis documents, other than `noeviction`, starts
# with one of these two prefixes: the allkeys-* family evicts any key and
# the volatile-* family evicts keys that carry a TTL -- which is EVERY
# meter this backend writes (`SET ... PX`). Under either, memory pressure
# deletes live meters, and a deleted meter reads as an empty one: the
# next request from a subject that was being refused is admitted with a
# full burst. Nothing errors and nothing logs; the limiter just stops
# limiting whoever the cache happened to evict.
_EVICTING_PREFIXES = ("allkeys-", "volatile-")


# ---------------------------------------------------------------------------
# The limiter's own Redis user (the limiter's Redis ACL, 2026-10-02)
# ---------------------------------------------------------------------------
#
# Until 2026-10-02 the production Redis had one user, `default`, behind a
# password, so whatever held that password could run every command on every
# key: FLUSHALL, CONFIG SET, a co-tenant's cache. `redis_limiter_isolated`
# could only REPORT keys somebody else had written. Isolation is now a
# property of the server: infra/production/compose.yml starts Redis with an
# ACL file in which `default` is disabled and this user is the only one, and
# the user may read and write keys under the limiter's prefix alone and run
# exactly the commands below. The compose file writes the rule out as text;
# a test holds that text equal to `limiter_acl_rules()`, so the two cannot
# drift.
#
# What that does NOT confine, stated because "confined to rl:" was read as
# more than it is (review of 2026-10-02): three of the commands below reach
# past the limiter's own keys without reading or writing one. SCAN lists
# every key NAME in the database, INFO reports the server's statistics, and
# ACL GETUSER reads any user's rules and password hashes. The census and
# the readiness row need all three, and on the compose file's Redis the
# only other user is the disabled `default`, which has no hash to read.
#
# Each command is here because something in this process sends it, and the
# readiness row fails a production user granted anything more:
#
#   evalsha, script|load   the GCRA script: redis-py's Script sends EVALSHA,
#                          and SCRIPT LOAD once when the server answers
#                          NOSCRIPT (a restarted Redis). EVAL is never sent.
#   get, set, time         what the script calls (ACL binds a script's own
#                          calls too), and `claim_once`'s SET NX EX.
#   ping                   `ping`, and redis-py's idle health check.
#   info                   `maxmemory_policy`, and the census of the other
#                          databases (INFO keyspace). CONFIG is NOT granted:
#                          CONFIG GET reads every setting the server has.
#   dbsize, scan           the census of the limiter's own database, which
#                          counts key names and reads no value.
#   acl|whoami,            the readiness row reading this very ACL. GETUSER
#   acl|getuser            shows any user's rules and password HASHES; the
#                          only other user here is the disabled `default`,
#                          which has none.
#
# No pub/sub channel and no selector: the limiter publishes nothing. And
# no CLIENT SETINFO (granted until the review of 2026-10-02): redis-py
# names its library on every connection unless told not to, and swallows
# a refusal, so the grant served only to keep two denials per connection
# out of ACL LOG. `RedisBackend` now tells it not to (`_no_client_setinfo`),
# which takes a grant away and with it the ACL file's need for Redis 7.2.
LIMITER_ACL_USER = "noctornal_limiter"
LIMITER_ACL_COMMANDS: tuple[str, ...] = (
    "evalsha", "script|load",
    "get", "set", "time",
    "ping",
    "info",
    "dbsize", "scan",
    "acl|whoami", "acl|getuser",
)


def _no_client_setinfo() -> dict:
    """The redis-py keyword that stops CLIENT SETINFO on connect, in the
    spelling the installed version reads: `driver_info=None` where the
    client takes it (8.1.0, the pinned version, does), else
    `lib_name=None, lib_version=None`, the spelling of the 5.0 line that
    began sending it and that pyproject still admits. Either way no CLIENT
    command is sent, so the limiter's ACL user needs no grant for one
    (2026-10-02)."""
    import inspect

    import redis

    if "driver_info" in inspect.signature(redis.Redis.__init__).parameters:
        return {"driver_info": None}
    return {"lib_name": None, "lib_version": None}


def limiter_key_prefix() -> str:
    """`rl:`, the prefix every key the limiter writes starts with, read from
    `RateLimiter`'s own constructor default (what `build_limiter` builds
    with), so the ACL cannot confine the limiter to a prefix it no longer
    writes under."""
    import inspect

    from noctornal_api.ratelimit import RateLimiter

    prefix = inspect.signature(RateLimiter).parameters["key_prefix"].default
    return f"{prefix}:"


def limiter_acl_rules() -> str:
    """The ACL rules of `LIMITER_ACL_USER`, after its password: its keys,
    no channel, and the commands above with everything else taken away."""
    granted = " ".join(f"+{command}" for command in LIMITER_ACL_COMMANDS)
    return (f"resetkeys ~{limiter_key_prefix()}* resetchannels "
            f"-@all {granted}")


def is_evicting_policy(policy: str | None) -> bool:
    """True when `policy` is a maxmemory-policy under which Redis may
    delete a rate-limit meter of its own accord.

    Prefix-matched rather than listed, so a policy Redis adds later
    (allkeys-lfu arrived in 4.0; volatile-lfu with it) is classified by
    the family it belongs to instead of slipping through an enumeration
    written against one version. Case-insensitive because CONFIG GET
    echoes whatever case the operator typed.
    """
    if not policy:
        return False
    return policy.strip().lower().startswith(_EVICTING_PREFIXES)

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
                # No CLIENT SETINFO on connect: the production ACL does not
                # grant it (the limiter's Redis ACL, review of 2026-10-02).
                **_no_client_setinfo(),
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

    def maxmemory_policy(self) -> str | None:
        """The server's maxmemory-policy, as text: from `INFO memory` when
        the server reports it there, else `CONFIG GET maxmemory-policy`.

        Returns the policy name (`"allkeys-lru"`, `"noeviction"`, ...), an
        empty string when the server answered but named no policy, and
        None when the server would not answer at all. None is a distinct
        value on purpose: most managed Redis offerings rename or disable
        CONFIG, and "the server refused to say" is not the same fact as
        "the server does not evict". `build_limiter` reports the first as
        unknown and the second as fine, and collapsing them would report
        an unverifiable deployment as a verified one.

        INFO first since the limiter's Redis ACL (2026-10-02): the
        production user may run INFO and not CONFIG, which reads every
        setting the server holds, and asking CONFIG first would write a
        denial into the server's ACL LOG on every boot and every readiness
        call, where a real probe of the ACL should stand out.

        Never raises. This is a startup probe, and a probe that can turn
        a boot into an outage is worse than no probe -- the same rule
        `ping` follows.

        Added 2026-09-02: until then nothing in the process read the
        policy, and docs/16 C8 was the only place the eviction risk was
        recorded.
        """
        try:
            memory = self._redis.info("memory")
        except Exception as exc:  # noqa: BLE001 - see docstring: reports, never raises
            log.debug("INFO memory was refused: %s: %s", type(exc).__name__, exc)
            memory = None
        if isinstance(memory, dict):
            for key, value in memory.items():
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="replace")
                if key == "maxmemory_policy":
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="replace")
                    return str(value)
        try:
            answer = self._redis.config_get("maxmemory-policy")
        except Exception as exc:  # noqa: BLE001 - see docstring: reports, never raises
            log.debug("CONFIG GET maxmemory-policy was refused: %s: %s",
                      type(exc).__name__, exc)
            return None
        # `decode_responses` is off (the Lua path wants bytes), so the
        # keys and values may come back as bytes; older client versions
        # decode CONFIG replies regardless. Accept both.
        for key, value in (answer or {}).items():
            if isinstance(key, bytes):
                key = key.decode("utf-8", errors="replace")
            if key == "maxmemory-policy":
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                return str(value)
        return ""

    def close(self) -> None:
        try:
            self._redis.close()
        except Exception:  # noqa: BLE001
            pass
