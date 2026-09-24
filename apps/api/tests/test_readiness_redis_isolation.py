"""`redis_limiter_isolated`: the limiter's Redis, to itself (docs/16 C8,
sec-redis-isolation, 2026-09-23).

`noeviction` was half of C8 and the register checked it. The other half,
that nothing else lives in that Redis, the register called "a deployment
fact the runtime cannot see". A co-tenant leaves keys, and its harm comes
through the memory they hold: `maxmemory` is per instance, so under
noeviction it fills the instance until every meter write fails and every
limit that fails closed refuses everyone.

Held here, against a fake that fails the test on any command that returns
a value:

* keys outside the limiter's prefix in its own database fail the row, and
  so do keys in any other database on the instance;
* the evidence carries counts, never a key name and never a value;
* a Redis that will not answer SCAN or INFO, or a walk that cannot finish,
  is NOT a pass: the register lists things confirmed;
* the prefix is the one the limiter writes with, read from `RateLimiter`.

The last two tests run against a real Redis when REDIS_URL is set, in
database 15, with keys that expire on their own if the test dies.
"""
from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import pytest

from noctornal_api import readiness

LIMITER_KEYS = [b"rl:login.ip:ip:203.0.113.9", b"rl:audit:login.ip:ip:203.0.113.9",
                b"rl:api.blanket:tok:9f2c"]
#: A co-tenant's key names: an email and a session id, exactly what must
#: never reach a screenshot of the register.
FOREIGN_KEYS = [b"session:analyst@agency.example", b"cache:case:OP-NIGHTJAR-26"]


class CensusRedis:
    """Enough of redis-py for `RedisBackend` and the census, and nothing
    that reads a value: any other attribute fails the test, so a check that
    started calling GET, MGET, TYPE, DUMP or HGETALL would be caught here
    rather than in an operator's screenshot."""

    def __init__(self, keys, *, db=0, others=None, page=2,
                 scan_error=None, info_error=None):
        self._keys = list(keys)
        self._db = db
        self._others = others or {}
        self._page = page
        self._scan_error = scan_error
        self._info_error = info_error
        self.calls: list[str] = []
        self.connection_pool = type("Pool", (), {"connection_kwargs": {"db": db}})()

    def __getattr__(self, name):
        raise AssertionError(f"the census sent {name!r}, which is not a counting command")

    def ping(self):
        return True

    def config_get(self, name):
        return {name: "noeviction"}

    def register_script(self, lua):
        return lambda keys, args: [1, 0, 0, 0]

    def close(self):
        pass

    def dbsize(self):
        self.calls.append("dbsize")
        return len(self._keys)

    def scan(self, cursor=0, count=None, **kwargs):
        self.calls.append("scan")
        if self._scan_error:
            raise self._scan_error
        cursor = int(cursor)
        chunk = self._keys[cursor:cursor + self._page]
        after = cursor + self._page
        return (0 if after >= len(self._keys) else after), chunk

    def info(self, section=None):
        self.calls.append(f"info {section}")
        if self._info_error:
            raise self._info_error
        answer = {f"db{self._db}": {"keys": len(self._keys), "expires": 0}} \
            if self._keys else {}
        for db, n in self._others.items():
            answer[f"db{db}"] = {"keys": n, "expires": 0, "avg_ttl": 0}
        return answer


@pytest.fixture
def served(monkeypatch):
    """Point REDIS_URL at a fake and hand back a function that installs one."""
    import redis

    monkeypatch.setenv("REDIS_URL", "redis://:Zm4tR@limiter.test:6379/0")

    def serve(fake):
        monkeypatch.setattr(redis.Redis, "from_url",
                            classmethod(lambda cls, url, **kw: fake))
        return fake
    return serve


def _check():
    return readiness._redis_limiter_isolated(None)


def _no_names_or_values(check):
    text = check.evidence + check.action
    for key in FOREIGN_KEYS + LIMITER_KEYS:
        assert key.decode() not in text, key
    assert "Zm4tR" not in text, "the Redis password reached the evidence"
    for fragment in ("analyst@", "OP-NIGHTJAR", "203.0.113.9"):
        assert fragment not in text, fragment


# --- the verdicts ----------------------------------------------------------

def test_a_redis_holding_only_meters_passes_and_says_what_it_cannot_see(served):
    served(CensusRedis(LIMITER_KEYS))
    check = _check()
    assert check.ok is True, check
    assert check.action == ""
    assert "3 keys, all of them under the limiter's prefix rl:" in check.evidence
    assert "not visible from here" in check.evidence
    _no_names_or_values(check)


def test_one_meter_is_counted_in_agreement(served):
    served(CensusRedis(LIMITER_KEYS[:1]))
    assert "holds 1 key, and it is under" in _check().evidence


def test_an_empty_redis_passes(served):
    served(CensusRedis([]))
    check = _check()
    assert check.ok is True, check
    assert "holds no keys" in check.evidence


def test_a_co_tenants_keys_fail_the_row_by_count_alone(served):
    served(CensusRedis(LIMITER_KEYS + FOREIGN_KEYS))
    check = _check()
    assert check.ok is False
    assert check.evidence.startswith("SHARED: the limiter uses database 0 at "), check.evidence
    assert "; 2 keys in it are not the limiter's" in check.evidence
    assert "are not the limiter's" in check.evidence
    assert "of 5 in all" in check.evidence
    assert "own" in check.action and "noeviction" in check.action
    _no_names_or_values(check)


def test_one_foreign_key_is_counted_in_agreement(served):
    served(CensusRedis(LIMITER_KEYS + FOREIGN_KEYS[:1]))
    assert "; 1 key in it is not the limiter's" in _check().evidence


#: AWS documents that ElastiCache writes this into database 0 of every
#: Valkey or Redis OSS cluster to measure replication lag.
ELASTICACHE_KEY = b"ElastiCacheMasterReplicationTimestamp"


def test_a_dedicated_elasticache_redis_is_not_reported_shared(served):
    """c24 (2026-09-24): the service's own bookkeeping key made a limiter
    alone on ElastiCache SHARED on every call, with an action nobody could
    carry out. It is counted, said, and not held against the row."""
    served(CensusRedis(LIMITER_KEYS + [ELASTICACHE_KEY]))
    check = _check()
    assert check.ok is True, check
    assert "SHARED" not in check.evidence
    assert ("holds 4 keys: 3 under the limiter's prefix rl: and 1 key the "
            "hosting service writes for its own replication bookkeeping") \
        in check.evidence, check.evidence
    assert ELASTICACHE_KEY.decode() not in check.evidence, (
        "the evidence names keys by count only, the service's included")
    _no_names_or_values(check)


def test_an_elasticache_redis_with_nothing_metered_yet_passes(served):
    served(CensusRedis([ELASTICACHE_KEY]))
    check = _check()
    assert check.ok is True, check
    assert "holds nothing metered yet, only 1 key the hosting service" \
        in check.evidence, check.evidence


def test_the_bookkeeping_exemption_is_one_exact_name_in_database_0(
        served, monkeypatch):
    """Not a pattern, and not in any other database: the same name where
    the service does not write it was put there by somebody else, and a
    near miss is a co-tenant's key."""
    served(CensusRedis(LIMITER_KEYS + [ELASTICACHE_KEY + b"x"]))
    assert _check().ok is False

    monkeypatch.setenv("REDIS_URL", "redis://:Zm4tR@limiter.test:6379/2")
    served(CensusRedis(LIMITER_KEYS + [ELASTICACHE_KEY], db=2))
    assert _check().ok is False


def test_a_limiter_off_database_0_on_elasticache_is_told_where_to_go(
        served, monkeypatch):
    """INFO keyspace carries counts, so the service's key in db0 cannot be
    recognised while the limiter sits in another database. The row stays
    red, since the key could as well be a co-tenant's, and the action
    names the move that lets it be recognised."""
    monkeypatch.setenv("REDIS_URL", "redis://:Zm4tR@limiter.test:6379/1")
    served(CensusRedis(LIMITER_KEYS, db=1, others={0: 1}))
    check = _check()
    assert check.ok is False
    assert "point REDIS_URL at database 0 there" in check.action, check.action

    # A db0 holding more than the service writes is a tenant, not a hint.
    served(CensusRedis(LIMITER_KEYS, db=1, others={0: 7}))
    assert "ElastiCache" not in _check().action


@pytest.mark.parametrize("name", [b"test:rl:abc", b"rlx:login", b"RL:login.ip:x",
                                  b"rl", b"limiter:rl:x"])
def test_only_the_limiters_own_prefix_counts_as_the_limiters(served, name):
    """`rl:` exactly, as `RateLimiter` writes it. A test meter under
    `test:rl:` or a key that merely starts with the letters is somebody
    else's."""
    served(CensusRedis(LIMITER_KEYS + [name]))
    assert _check().ok is False


def test_the_prefix_is_the_limiters_own_default():
    import inspect

    from noctornal_api.ratelimit import RateLimiter
    default = inspect.signature(RateLimiter).parameters["key_prefix"].default
    assert readiness._limiter_prefix() == f"{default}:".encode()
    assert readiness._limiter_prefix() == b"rl:"


def test_keys_in_another_database_fail_the_row(served):
    """maxmemory is per instance, so a co-tenant one database over fills
    the same memory the meters need."""
    served(CensusRedis(LIMITER_KEYS, others={3: 12, 1: 1}))
    check = _check()
    assert check.ok is False
    assert "other databases on the instance hold keys: db1 1 key, db3 12 keys" \
        in check.evidence, check.evidence
    _no_names_or_values(check)


def test_the_limiters_own_database_is_the_one_in_the_url(served, monkeypatch):
    """Database 4 is the limiter's here, so its keys are not "another
    database's", and database 0 holding keys is."""
    monkeypatch.setenv("REDIS_URL", "redis://:Zm4tR@limiter.test:6379/4")
    served(CensusRedis(LIMITER_KEYS, db=4, others={0: 7}))
    check = _check()
    assert "database 4 at" in check.evidence
    assert "db0 7 keys" in check.evidence
    assert "db4" not in check.evidence


def test_a_refused_scan_is_unknown_not_a_pass(served):
    served(CensusRedis(LIMITER_KEYS, scan_error=RuntimeError("NOPERM scan")))
    check = _check()
    assert check.ok is False
    assert "UNKNOWN" in check.evidence
    assert "out of band" in check.action


def test_a_refused_info_is_unknown_not_a_pass(served):
    served(CensusRedis(LIMITER_KEYS, info_error=RuntimeError("NOPERM info")))
    check = _check()
    assert check.ok is False
    assert "INFO keyspace was refused" in check.evidence
    assert "UNKNOWN" in check.evidence


def test_a_walk_that_cannot_finish_is_unknown_not_a_pass(served, monkeypatch):
    monkeypatch.setattr(readiness, "_CENSUS_LIMIT", 2)
    served(CensusRedis(LIMITER_KEYS * 4, page=2))
    check = _check()
    assert check.ok is False
    assert "the walk stopped there" in check.evidence
    assert "UNKNOWN" in check.evidence


def test_a_foreign_key_found_before_the_walk_stops_is_reported_as_at_least(
        served, monkeypatch):
    monkeypatch.setattr(readiness, "_CENSUS_LIMIT", 2)
    served(CensusRedis(FOREIGN_KEYS + LIMITER_KEYS * 4, page=2))
    check = _check()
    assert check.ok is False
    assert "at least 2 keys" in check.evidence


def test_the_census_sends_only_counting_commands(served):
    fake = served(CensusRedis(LIMITER_KEYS + FOREIGN_KEYS))
    _check()
    assert set(fake.calls) <= {"dbsize", "scan", "info keyspace"}, fake.calls
    assert "scan" in fake.calls


def test_unset_redis_url_fails_and_names_the_variable(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    check = _check()
    assert check.ok is False
    assert "REDIS_URL" in check.evidence and check.action


def test_a_redis_that_does_not_answer_fails_fast(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    check = _check()
    assert check.ok is False
    assert "did not answer PING" in check.evidence


def test_the_row_is_registered_after_the_store_row_and_does_not_block():
    names = readiness.CHECK_NAMES
    assert names.index("redis_limiter_isolated") == names.index("redis_limiter_store") + 1
    assert "redis_limiter_isolated" not in readiness.BLOCKING_CHECKS


def test_the_store_row_no_longer_calls_isolation_invisible():
    """Its passing evidence said whether the limiter had the instance to
    itself was a fact the runtime cannot see. Part of it now can be."""
    import inspect
    source = inspect.getsource(readiness._redis_limiter_store)
    assert "runtime cannot see" not in source
    assert "redis_limiter_isolated" in source


# --- against a real Redis ----------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL", "")
needs_redis = pytest.mark.skipif(
    not REDIS_URL, reason="REDIS_URL not set; the Redis leg is gated")


def _database_15() -> str:
    """The same server in database 15, so these keys never share a
    database with the meters of an API or another test."""
    parts = urlsplit(REDIS_URL)
    return urlunsplit((parts.scheme, parts.netloc, "/15", "", ""))


@needs_redis
def test_a_real_foreign_key_fails_the_row_without_its_name(monkeypatch):
    import redis

    url = _database_15()
    client = redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
    name = f"isolation-probe:{uuid4().hex}"
    value = f"never-read-{uuid4().hex}"
    client.set(name, value, px=30_000)
    try:
        monkeypatch.setenv("REDIS_URL", url)
        check = _check()
    finally:
        client.delete(name)
        client.close()
    assert check.ok is False, check
    assert "database 15 at" in check.evidence
    assert "not the limiter's" in check.evidence
    assert name not in check.evidence and value not in check.evidence


@needs_redis
def test_a_real_meter_is_the_limiters(monkeypatch):
    """Only the own-database half is asserted: another database on a
    shared development Redis may hold keys, which this row would rightly
    report, and that is not what this test is about."""
    import redis

    url = _database_15()
    client = redis.Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
    name = f"rl:isolation-probe:{uuid4().hex}"
    client.set(name, b"1", px=30_000)
    try:
        monkeypatch.setenv("REDIS_URL", url)
        check = _check()
    finally:
        client.delete(name)
        client.close()
    assert "not the limiter's" not in check.evidence, check.evidence
    assert name not in check.evidence
