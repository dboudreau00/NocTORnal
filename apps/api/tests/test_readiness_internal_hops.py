"""The readiness row `internal_hops_encrypted`: how this process reaches Postgres and the limiter's Redis.

Stubs, no services: a connection that answers `pg_stat_ssl` as told, and `RedisBackend.transport` answering
as a TLS or a plain socket would. In production a hop that is not TLS 1.3, or a setting that does not
check the server, fails the row and names the hop; outside production the row passes and says what it
read; it is not blocking; and its evidence names protocols, ciphers and a date, never a host or a user.
"""
from __future__ import annotations

import pytest

from noctornal_api import readiness
from noctornal_api.ratelimit_redis import RedisBackend

HOST, USER, PASSWORD = "db-internal-7.example.gov", "noctornal_app", "Xk9pQ-hops"
REDIS_HOST, REDIS_PASSWORD = "cache-internal-3.example.gov", "Zm4tR-hops"
TLS = "?sslmode=verify-full&sslrootcert=/certs/ca.crt"
NOT_AFTER = "Nov 14 15:41:00 2029 GMT"


class _Session:
    def __init__(self, row):
        self.row, self.sql = row, []

    def execute(self, sql, *_args):
        self.sql.append(sql)
        return self

    def fetchone(self):
        return self.row


TLS13 = (True, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
PLAIN = (False, None, None)
REDIS_TLS = {"answered": True, "tls": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
             "not_after": NOT_AFTER, "read_from": "socket"}
REDIS_PLAIN = {"answered": True, "tls": False, "version": None, "cipher": None, "not_after": None,
               "read_from": "socket"}


@pytest.fixture
def hops(monkeypatch):
    """Run the row with a session answering `row` and a Redis answering `redis`, in `mode`."""
    def run(row=TLS13, redis=REDIS_TLS, *, production=True, dsn_query=TLS, dsn=None,
            redis_url=f"rediss://noctornal_limiter:{REDIS_PASSWORD}@{REDIS_HOST}:6379/0"
                      f"?ssl_ca_certs=/certs/ca.crt"):
        if production:
            monkeypatch.setenv("NOCTORNAL_ENV", "production")
        else:
            monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
        monkeypatch.setenv("DATABASE_URL",
                           f"postgresql+psycopg://{USER}:{PASSWORD}@{HOST}:5432/noctornal{dsn_query}")
        monkeypatch.setenv("NOCTORNAL_WORKER_DATABASE_URL",
                           f"postgresql+psycopg://noctornal_worker:{PASSWORD}@{HOST}:5432/n{dsn_query}")
        if dsn is not None:
            monkeypatch.setenv("DATABASE_URL", dsn)
            monkeypatch.setenv("NOCTORNAL_WORKER_DATABASE_URL", dsn)
        if redis_url is None:
            monkeypatch.delenv("REDIS_URL", raising=False)
        else:
            monkeypatch.setenv("REDIS_URL", redis_url)
        monkeypatch.setattr(RedisBackend, "transport", lambda self: dict(redis))
        session = _Session(row)
        check = readiness._internal_hops_encrypted(session)
        assert session.sql == ["SELECT ssl, version, cipher FROM pg_stat_ssl "
                               "WHERE pid = pg_backend_pid()"]
        return check
    return run


def _clean(check):
    text = check.evidence + check.action
    for secret in (HOST, USER, PASSWORD, REDIS_HOST, REDIS_PASSWORD):
        assert secret not in text, secret


def test_the_row_fails_in_production_when_postgres_is_plaintext(hops):
    check = hops(row=PLAIN)
    assert check.ok is False
    assert "the database session is not TLS 1.3" in check.evidence
    assert "Redis hop" not in check.evidence.split(". So ")[1]
    assert "scripts/internal_tls.py" in check.action and "--production-secrets" in check.action
    _clean(check)


@pytest.mark.parametrize("query", ["", "?sslmode=require", "?sslmode=verify-ca"])
def test_the_row_fails_in_production_on_a_dsn_that_does_not_check_the_database(hops, query):
    """A session that is TLS now under `prefer` or `require` could be plain text or someone else's on
    the next connection."""
    check = hops(dsn_query=query)
    assert check.ok is False
    assert "DATABASE_URL does not ask for TLS that checks the database" in check.evidence
    _clean(check)


def test_the_row_fails_in_production_when_redis_is_plaintext(hops):
    check = hops(redis=REDIS_PLAIN)
    assert check.ok is False
    assert "the Redis hop is not TLS 1.3" in check.evidence
    assert "the limiter's Redis connection is not encrypted" in check.evidence
    _clean(check)
    check = hops(redis={**REDIS_PLAIN, "read_from": "scheme", "tls": None},
                 redis_url=f"redis://noctornal_limiter:{REDIS_PASSWORD}@{REDIS_HOST}:6379/0")
    assert check.ok is False and "REDIS_URL is not rediss://" in check.evidence
    _clean(check)


def test_the_row_fails_in_production_when_redis_cannot_be_asked(hops):
    check = hops(redis={**REDIS_TLS, "answered": False})
    assert check.ok is False and "the Redis hop could not be read" in check.evidence


def test_the_row_fails_in_production_on_a_rediss_url_that_does_not_check_the_server(hops):
    check = hops(redis_url=f"rediss://noctornal_limiter:{REDIS_PASSWORD}@{REDIS_HOST}:6379/0"
                           f"?ssl_cert_reqs=none")
    assert check.ok is False and "REDIS_URL switches off the check of the server" in check.evidence
    _clean(check)


def test_the_row_passes_and_reports_protocol_when_both_are_tls_1_3(hops):
    check = hops()
    assert check.ok is True and check.action == ""
    assert "this register's database session is TLSv1.3 (TLS_AES_256_GCM_SHA384)" in check.evidence
    assert "DATABASE_URL asks for sslmode=verify-full" in check.evidence
    assert "NOCTORNAL_WORKER_DATABASE_URL asks for sslmode=verify-full" in check.evidence
    assert (f"the limiter's Redis connection is TLSv1.3 (TLS_AES_256_GCM_SHA384), its certificate "
            f"valid until {NOT_AFTER}") in check.evidence
    _clean(check)


def test_a_client_that_keeps_no_readable_socket_falls_back_to_the_scheme_and_says_so(hops):
    check = hops(redis={**REDIS_TLS, "read_from": "scheme", "tls": None, "version": None})
    assert check.ok is True
    assert "keeps no socket this can read, so its transport is taken from the URL's scheme (TLS)" \
        in check.evidence


def test_unix_sockets_stay_on_the_host_and_pass(hops):
    """A socket never leaves the host, so a plain session over one passes; a DSN naming a host
    beside it would not."""
    socket = "postgresql://noctornal_app@/noctornal?host=/run/postgresql"
    check = hops(row=PLAIN, dsn=socket, redis=REDIS_PLAIN, redis_url="unix:///run/redis.sock")
    assert check.ok is True, check
    assert "DATABASE_URL asks for a unix socket" in check.evidence
    assert "REDIS_URL is a unix socket" in check.evidence
    check = hops(row=PLAIN, dsn_query="", redis=REDIS_PLAIN, redis_url="unix:///run/redis.sock")
    assert check.ok is False and "the database session is not TLS 1.3" in check.evidence


def test_the_row_passes_in_development_and_says_plaintext_is_expected(hops):
    check = hops(row=PLAIN, redis=REDIS_PLAIN, production=False, dsn_query="",
                 redis_url=f"redis://{REDIS_HOST}:6379/0")
    assert check.ok is True
    assert "this register's database session is not encrypted" in check.evidence
    assert "the limiter's Redis connection is not encrypted" in check.evidence
    assert "the development stack's database and Redis are plain text on purpose" in check.evidence
    _clean(check)


def test_an_unset_redis_url_is_no_redis_hop(hops):
    check = hops(redis_url=None)
    assert check.ok is True and "there is no Redis hop" in check.evidence


def test_the_row_is_not_blocking_and_sits_after_the_limiters_rows():
    names = list(readiness.CHECK_NAMES)
    assert "internal_hops_encrypted" in names
    assert names.index("internal_hops_encrypted") == names.index("redis_limiter_isolated") + 1
    assert "internal_hops_encrypted" not in readiness.BLOCKING_CHECKS
    assert "internal_hops_encrypted" not in readiness.CONSEQUENCES
    assert "internal_hops_encrypted" not in readiness.UI_TARGETS


def test_the_row_never_prints_a_host_or_user(hops):
    for args in ({"row": PLAIN}, {"redis": REDIS_PLAIN}, {"dsn_query": ""}, {}):
        _clean(hops(**args))
