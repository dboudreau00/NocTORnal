"""The rate limiter's Redis must not evict its own meters.

A GCRA meter is one key with a TTL. Under `allkeys-*` or `volatile-*`
eviction, memory pressure removes keys the limiter still needs, and a
removed meter is a meter that reads as empty: the next request from a
subject that was being refused is admitted with a full burst. Nothing
errors, nothing logs, the limiter just stops limiting whoever the cache
happened to evict. docs/16 C8 records that `infra/docker-compose.yml`
runs Redis with `allkeys-lru` for exactly this reason, and until
2026-09-02 nothing in the process checked -- the operator had to know to
look.

`build_limiter` now reads `CONFIG GET maxmemory-policy` once at startup
and warns in the same voice as the existing "RATE LIMITING IS DISABLED"
line. A Redis that refuses CONFIG (most managed offerings disable it) is
tolerated: the probe reports "unknown", never crashes, and never turns a
startup into an outage.

Pure: every test drives `RedisBackend` and `build_limiter` with a fake
client, so the verdict is about the code and not about whichever Redis
happens to be running.
"""
from __future__ import annotations

import logging

import pytest

from noctornal_api.http.limits import EVICTION_WARNING
from noctornal_api.ratelimit_redis import RedisBackend, is_evicting_policy

LOGGER = "noctornal.ratelimit"

# EVICTION_WARNING is IMPORTED from the module that emits it, not restated
# here. Until 2026-09-02 this file kept its own copy of the literal. The
# positive assertion below would still have caught a reworded warning, but
# the three `EVICTION_WARNING not in text` assertions would not have: once
# the copy and the emitter drifted, "the warning was not emitted" would be
# satisfied by a warning that WAS emitted under its new wording. A negative
# assertion against a stale literal is an assertion about nothing, which is
# the quieter half of this codebase's "two internally consistent halves"
# defect -- consistent with itself, and no longer about the product.


class FakeRedis:
    """Just enough of redis-py for the startup path: PING, CONFIG GET and
    script registration. `policy` is what CONFIG GET answers; a
    `config_error` is raised instead when set, which is how a managed
    Redis with CONFIG disabled behaves."""

    def __init__(self, policy, *, config_error: Exception | None = None,
                 ping_ok: bool = True, as_bytes: bool = False):
        self._policy = policy
        self._config_error = config_error
        self._ping_ok = ping_ok
        self._as_bytes = as_bytes
        self.config_calls: list[str] = []

    def ping(self) -> bool:
        if not self._ping_ok:
            raise ConnectionError("refused")
        return True

    def config_get(self, name: str) -> dict:
        self.config_calls.append(name)
        if self._config_error is not None:
            raise self._config_error
        if self._policy is None:
            return {}
        if self._as_bytes:
            return {name.encode(): self._policy.encode()}
        return {name: self._policy}

    def register_script(self, lua: str):
        return lambda keys, args: [1, 0, 0, 0]

    def close(self) -> None:
        pass


# --- the classifier --------------------------------------------------------

@pytest.mark.parametrize("policy, evicting", [
    ("noeviction", False),
    ("", False),
    (None, False),
    ("allkeys-lru", True),
    ("allkeys-lfu", True),
    ("allkeys-random", True),
    ("volatile-lru", True),
    ("volatile-lfu", True),
    ("volatile-random", True),
    ("volatile-ttl", True),
    ("ALLKEYS-LRU", True),
])
def test_every_documented_evictor_is_recognised(policy, evicting):
    assert is_evicting_policy(policy) is evicting


# --- the probe on the backend --------------------------------------------

def test_the_probe_returns_the_policy_as_text():
    backend = RedisBackend("redis://unused", client=FakeRedis("allkeys-lru"))
    assert backend.maxmemory_policy() == "allkeys-lru"


def test_the_probe_decodes_a_bytes_answer():
    """redis-py hands back bytes unless decode_responses is on, and the
    backend deliberately leaves it off for the Lua path."""
    backend = RedisBackend("redis://unused",
                           client=FakeRedis("volatile-ttl", as_bytes=True))
    assert backend.maxmemory_policy() == "volatile-ttl"


def test_an_unset_policy_reads_as_empty_not_unknown():
    backend = RedisBackend("redis://unused", client=FakeRedis(None))
    assert backend.maxmemory_policy() == ""


def test_a_redis_that_refuses_config_reports_unknown_and_does_not_raise():
    refused = RuntimeError("ERR unknown command 'CONFIG'")
    backend = RedisBackend("redis://unused",
                           client=FakeRedis("allkeys-lru", config_error=refused))
    assert backend.maxmemory_policy() is None


# --- the startup warning ---------------------------------------------------

@pytest.fixture
def redis_env(monkeypatch):
    monkeypatch.delenv("NOCTORNAL_RATELIMIT", raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://limiter.test:6379/0")


def _build_with(monkeypatch, fake):
    import redis

    from noctornal_api.http.limits import build_limiter
    monkeypatch.setattr(redis.Redis, "from_url",
                        classmethod(lambda cls, url, **kw: fake))
    return build_limiter()


@pytest.mark.parametrize("policy", ["allkeys-lru", "volatile-ttl", "allkeys-random"])
def test_build_limiter_warns_loudly_about_an_evicting_redis(
        monkeypatch, caplog, redis_env, policy):
    caplog.set_level(logging.INFO, logger=LOGGER)
    fake = FakeRedis(policy)
    limiter = _build_with(monkeypatch, fake)
    assert limiter.enabled is True
    assert fake.config_calls == ["maxmemory-policy"]
    warnings = [r for r in caplog.records
                if r.name == LOGGER and r.levelno >= logging.WARNING]
    assert warnings, "an evicting Redis must be shouted about at startup"
    text = "\n".join(r.getMessage() for r in warnings)
    assert EVICTION_WARNING in text
    assert policy in text
    assert "noeviction" in text, "the warning has to say what to set instead"


@pytest.mark.parametrize("policy", ["noeviction", "", None])
def test_build_limiter_is_quiet_about_a_non_evicting_redis(
        monkeypatch, caplog, redis_env, policy):
    caplog.set_level(logging.INFO, logger=LOGGER)
    _build_with(monkeypatch, FakeRedis(policy))
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == LOGGER)
    assert EVICTION_WARNING not in text
    assert "rate limiting via Redis" in text


def test_build_limiter_tolerates_a_redis_that_refuses_config(
        monkeypatch, caplog, redis_env):
    """Managed Redis usually has CONFIG renamed away. That must neither
    crash startup nor be reported as an evictor -- it is reported as
    UNKNOWN, which is the true statement, at a level below WARNING so a
    deployment that cannot answer is not nagged on every boot."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    refused = RuntimeError("ERR unknown command 'CONFIG'")
    limiter = _build_with(monkeypatch, FakeRedis("allkeys-lru", config_error=refused))
    assert limiter.enabled is True
    warnings = [r.getMessage() for r in caplog.records
                if r.name == LOGGER and r.levelno >= logging.WARNING]
    assert not any(EVICTION_WARNING in w for w in warnings)
    infos = [r.getMessage() for r in caplog.records if r.name == LOGGER]
    assert any("maxmemory-policy" in m and "unknown" in m.lower() for m in infos)


def test_build_limiter_does_not_probe_a_redis_that_did_not_answer_ping(
        monkeypatch, caplog, redis_env):
    """The existing PING failure path is left exactly as it was: one error
    line, no second probe against a backend already known to be down."""
    caplog.set_level(logging.INFO, logger=LOGGER)
    fake = FakeRedis("allkeys-lru", ping_ok=False)
    _build_with(monkeypatch, fake)
    assert fake.config_calls == []
    text = "\n".join(r.getMessage() for r in caplog.records if r.name == LOGGER)
    assert "did not answer PING" in text
    assert EVICTION_WARNING not in text
