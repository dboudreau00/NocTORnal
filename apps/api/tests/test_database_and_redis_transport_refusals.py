"""Production refuses a database hop that is not TLS checking the server (config.database_hop_problems).

The compose database admits the network over `hostssl` alone (infra/production/pg_hba.conf), so a DSN
without sslmode is refused by the server anyway; these refusals name the variable at boot, before the
first query fails, and they hold every other deployment to the same rule: `require` encrypts but takes
any certificate, `verify-ca` any certificate the CA signed, and only `verify-full` checks that the server
answering is the database. A unix socket stays on the host and passes. The limiter's Redis is held to the
same (config.redis_hop_problems): rediss:// with redis-py's defaults, which require a certificate the CA
vouches for and check the host's name, or a unix socket. Pure: dictionaries, no database, no Redis.
"""
from __future__ import annotations

import pytest
from test_config_boot import _production

from noctornal_api import config, egress_proxy
from noctornal_api.db import WORKER_DSN_ENV

PASSWORD = "Xk9pQ-hop-secret"
TLS = "?sslmode=verify-full&sslrootcert=/certs/ca.crt"


def _dsn(query: str = TLS, host: str = "db") -> str:
    return f"postgresql+psycopg://noctornal_app:{PASSWORD}@{host}:5432/noctornal{query}"


def _hop_refusals(problems: list[str]) -> list[str]:
    return [p for p in problems if "sslmode=verify-full" in p or "driver can read" in p]


@pytest.mark.parametrize("query", ["", "?sslmode=disable", "?sslmode=allow", "?sslmode=prefer",
                                   "?sslmode=require", "?sslmode=verify-ca",
                                   "?sslmode=verify-ca&sslrootcert=/certs/ca.crt",
                                   "?sslmode=VERIFY-FULL", "?sslrootcert=/certs/ca.crt"])
def test_production_refuses_a_database_url_without_verify_full(query):
    env = {**_production(), "DATABASE_URL": _dsn(query)}
    refused = _hop_refusals(config.verify_environment(env))
    assert len(refused) == 1, refused
    assert refused[0].startswith("DATABASE_URL reaches its database over the network without "
                                 "sslmode=verify-full")


@pytest.mark.parametrize("dsn", [
    _dsn(),
    _dsn("?sslmode=verify-full"),
    "postgresql+psycopg://noctornal_app:pw@/noctornal?host=/var/run/postgresql",
    "postgresql://noctornal_app@/noctornal",
    "host=/run/postgresql dbname=noctornal user=noctornal_app",
])
def test_verify_full_and_a_unix_socket_pass(dsn):
    env = {**_production(), "DATABASE_URL": dsn}
    assert _hop_refusals(config.verify_environment(env)) == []
    assert config.database_hop(dsn, {}) in ("verified", "socket")


def test_a_dsn_naming_no_host_is_held_to_where_pghost_sends_it():
    """libpq connects where PGHOST says when the DSN names no host: an address is the network."""
    dsn = "postgresql://noctornal_app@/noctornal"
    assert config.database_hop(dsn, {"PGHOST": "/var/run/postgresql"}) == "socket"
    assert config.database_hop(dsn, {"PGHOST": "db.example.gov"}) == "unverified"
    assert config.database_hop(dsn + "?sslmode=verify-full", {"PGHOST": "db"}) == "verified"
    assert config.database_hop("host=/tmp hostaddr=10.0.0.5 dbname=x", {}) == "unverified"


@pytest.mark.parametrize("dsn, env", [
    ("service=agency dbname=noctornal user=noctornal_app", {}),
    ("dbname=noctornal user=noctornal_app", {"PGSERVICE": "agency"}),
    ("postgresql://noctornal_app@/noctornal?service=agency", {}),
    ("postgresql://noctornal_app@/noctornal", {"PGSERVICE": "agency", "PGHOST": "/run/pg"}),
    # A socket the DSN names is not enough: the service's file may set hostaddr, which wins.
    ("host=/run/postgresql dbname=noctornal", {"PGSERVICE": "agency"}),
])
def test_a_target_a_connection_service_may_supply_is_the_network(dsn, env):
    """libpq fills what the DSN leaves out from the service's pg_service.conf, which nothing here reads,
    before PGHOST and the default socket: the independent review TRANSPORT-02 read such a DSN as a socket, so production
    started on a hop to whatever host the file named, without TLS. Only the DSN's own
    sslmode=verify-full, which a service file cannot change, makes it a verified hop."""
    assert config.database_hop(dsn, env) == "unverified"
    sep = ("&" if "?" in dsn else "?") if "://" in dsn else " "
    assert config.database_hop(dsn + sep + "sslmode=verify-full", env) == "verified"


def test_a_socket_the_dsn_pins_whole_stays_a_socket_beside_a_service():
    """With host a socket path and hostaddr named empty, nothing a service file says can move it."""
    dsn = "host=/run/postgresql hostaddr='' dbname=noctornal"
    assert config.database_hop(dsn, {"PGSERVICE": "agency"}) == "socket"


def test_pghostaddr_is_the_network_whatever_host_says():
    """hostaddr decides TCP in libpq whatever host names, and PGHOSTADDR fills it when the DSN does
    not."""
    assert config.database_hop("host=/run/postgresql dbname=x", {"PGHOSTADDR": "10.1.2.3"}) == \
        "unverified"
    assert config.database_hop("host=/run/postgresql dbname=x", {}) == "socket"


@pytest.mark.parametrize("variable", ["DATABASE_URL", WORKER_DSN_ENV])
def test_production_refuses_a_service_dsn_without_verify_full(variable):
    service_dsn = f"service=agency dbname=noctornal user=noctornal_app password={PASSWORD}"
    env = {**_production(), variable: service_dsn}
    refused = _hop_refusals(config.verify_environment(env))
    assert len(refused) == 1, refused
    assert refused[0].startswith(f"{variable} may reach its database over the network, since a "
                                 f"connection service")
    assert PASSWORD not in refused[0] and "agency" not in refused[0]
    env = {**_production(), "PGSERVICE": "agency",
           variable: "postgresql://noctornal_app@/noctornal"}
    assert len(_hop_refusals(config.verify_environment(env))) == 1
    env[variable] += "?sslmode=verify-full&sslrootcert=/certs/ca.crt"
    assert _hop_refusals(config.verify_environment(env)) == []


def test_pgsslmode_does_not_stand_in_for_the_dsn():
    """The sslmode is read from the DSN alone, the one place an operator and readiness look."""
    env = {**_production(), "DATABASE_URL": _dsn(""), "PGSSLMODE": "verify-full"}
    assert len(_hop_refusals(config.verify_environment(env))) == 1


def test_an_unreadable_dsn_is_refused_without_quoting_it():
    env = {**_production(), "DATABASE_URL": "postgresql://noctornal_app:Xk9pQ-hop-secret@db/x?sslmode"}
    refused = _hop_refusals(config.verify_environment(env))
    assert len(refused) == 1 and refused[0].startswith("DATABASE_URL is not a connection string")
    assert PASSWORD not in refused[0]


def test_the_same_refusal_covers_the_worker_migration_and_egress_dsns():
    env = {**_production(), WORKER_DSN_ENV: _dsn("?sslmode=require").replace("app", "worker")}
    refused = _hop_refusals(config.verify_environment(env))
    assert len(refused) == 1 and refused[0].startswith(f"{WORKER_DSN_ENV} reaches")

    migrate = {"NOCTORNAL_ENV": "production",
               config.MIGRATION_DSN_ENV: _dsn("").replace("noctornal_app", "noctornal")}
    refused = _hop_refusals(config.migration_job_problems(migrate))
    assert len(refused) == 1, refused
    assert refused[0].startswith(f"migrate: refusing to run: {config.MIGRATION_DSN_ENV} reaches")
    migrate[config.MIGRATION_DSN_ENV] = _dsn().replace("noctornal_app", "noctornal")
    assert config.migration_job_problems(migrate) == []

    proxy = {"NOCTORNAL_ENV": "production",
             egress_proxy.DATABASE_URL_ENV: _dsn("?sslmode=prefer").replace("noctornal_app",
                                                                            "noctornal_egress")}
    refused = _hop_refusals(egress_proxy.verify_proxy_environment(proxy))
    assert len(refused) == 1 and refused[0].startswith(f"{egress_proxy.DATABASE_URL_ENV} reaches")
    proxy[egress_proxy.DATABASE_URL_ENV] = _dsn().replace("noctornal_app", "noctornal_egress")
    assert _hop_refusals(egress_proxy.verify_proxy_environment(proxy)) == []


def test_the_refusal_names_the_variable_and_never_a_value():
    env = {**_production(), "DATABASE_URL": _dsn("?sslmode=disable"),
           WORKER_DSN_ENV: _dsn("").replace("app", "worker")}
    refused = _hop_refusals(config.verify_environment(env))
    assert [r.split(" ", 1)[0] for r in refused] == ["DATABASE_URL", WORKER_DSN_ENV]
    for sentence in refused:
        assert PASSWORD not in sentence and "@db" not in sentence and "noctornal_app" not in sentence
        assert config.DATABASE_TLS_QUERY in sentence, "it says what to add"


def test_a_development_environment_is_untouched():
    env = {**_production(), "DATABASE_URL": _dsn(""), WORKER_DSN_ENV: _dsn("")}
    env.pop("NOCTORNAL_ENV")
    assert config.verify_environment(env) == []
    assert config.refuse_unsafe_job_environment("notify_drain", env) == []
    assert config.migration_job_problems({config.MIGRATION_DSN_ENV: _dsn("")}) == []
    proxy = {egress_proxy.DATABASE_URL_ENV: _dsn("")}
    assert _hop_refusals(egress_proxy.verify_proxy_environment(proxy)) == []


@pytest.mark.parametrize("job, kwargs", [
    ("collection_poll", {"holds_persona_key": True}),
    ("notify_drain", {}),
    ("lookup_drain", {}),
    ("embed_pass", {}),
    ("collector", {"holds_persona_key": True}),
])
def test_every_job_refuses_a_plaintext_database_hop(job, kwargs):
    env = {**_production(), "DATABASE_URL": _dsn("?sslmode=prefer")}
    refused = _hop_refusals(config.refuse_unsafe_job_environment(job, env, **kwargs))
    assert refused == [f"{job}: refusing to run: " + config.database_hop_problems(
        env, names=("DATABASE_URL",))[0]], refused
    env["DATABASE_URL"] = _dsn()
    assert _hop_refusals(config.refuse_unsafe_job_environment(job, env, **kwargs)) == []


# ---------------------------------------------------------------------------
# The limiter's Redis
# ---------------------------------------------------------------------------

REDIS_PASSWORD = "Zm4tR-hop-secret"


def _redis(scheme: str = "rediss", query: str = "?ssl_ca_certs=/certs/ca.crt") -> str:
    return f"{scheme}://noctornal_limiter:{REDIS_PASSWORD}@redis:6379/0{query}"


def _redis_refusals(problems: list[str]) -> list[str]:
    return [p for p in problems if p.startswith("REDIS_URL") and "rediss" in p
            or "switches off the check" in p]


@pytest.mark.parametrize("url", [_redis("redis"), _redis("redis", ""), _redis("REDIS", ""),
                                 _redis("http", "")])
def test_production_refuses_a_plaintext_redis_url(url):
    refused = _redis_refusals(config.verify_environment({**_production(), "REDIS_URL": url}))
    assert len(refused) == 1, refused
    assert refused[0].startswith("REDIS_URL is not a rediss:// (or unix://) URL")
    assert REDIS_PASSWORD not in refused[0] and config.REDIS_TLS_QUERY in refused[0]


@pytest.mark.parametrize("query", ["?ssl_cert_reqs=none", "?ssl_cert_reqs=optional",
                                   "?ssl_cert_reqs=NONE&ssl_ca_certs=/certs/ca.crt",
                                   "?ssl_check_hostname=false", "?ssl_check_hostname=0",
                                   "?ssl_check_hostname=no",
                                   "?ssl_cert_reqs=required&ssl_cert_reqs=none"])
def test_production_refuses_a_rediss_url_that_switches_verification_off(query):
    refused = _redis_refusals(config.verify_environment(
        {**_production(), "REDIS_URL": _redis(query=query)}))
    assert len(refused) == 1, refused
    assert refused[0].startswith("REDIS_URL asks for TLS but switches off the check")
    assert REDIS_PASSWORD not in refused[0]


@pytest.mark.parametrize("url", [_redis(), _redis(query=""), _redis(query="?ssl_cert_reqs=required"),
                                 _redis(query="?ssl_check_hostname=true"), "unix:///run/redis.sock",
                                 "rediss://cache.agency.example:6380/0"])
def test_a_verified_rediss_url_or_a_socket_passes(url):
    assert _redis_refusals(config.verify_environment({**_production(), "REDIS_URL": url})) == []
    assert config.redis_hop(url) in ("verified", "socket")


def test_a_development_redis_is_untouched():
    env = {**_production(), "REDIS_URL": _redis("redis", "")}
    env.pop("NOCTORNAL_ENV")
    assert config.verify_environment(env) == []
