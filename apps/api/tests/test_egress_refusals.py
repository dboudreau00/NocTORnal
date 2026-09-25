"""The production refusals of the egress proxy (S2,
2026-09-24): the API's key checks, the start refusal on outbound uses with
no proxy, and the egress proxy's own environment check. Pure: the
environments are dictionaries and the database is a stand-in."""
from __future__ import annotations

import pytest

import egress_support as es
from noctornal_api import config, egress, egress_proxy, egress_routes

PRODUCTION = {"NOCTORNAL_ENV": "production"}
PROXY = {"NOCTORNAL_EGRESS_PROXY_URL": "http://172.31.243.11:3128"}


def _egress_problems(env):
    return [p for p in config.verify_environment(env) if "EGRESS" in p and
            "PROXY_URL" not in p and "INTERNAL_CIDRS" not in p]


def test_the_key_checks_fire_only_in_production_with_a_proxy():
    assert _egress_problems(PROXY) == []
    assert _egress_problems(PRODUCTION) == []
    problems = _egress_problems({**PRODUCTION, **PROXY})
    assert any("NOCTORNAL_EGRESS_CLIENT_KEY is not a usable key" in p for p in problems)
    assert any("NOCTORNAL_EGRESS_FINGERPRINT_KEY is not base64 of 32 bytes" in p
               for p in problems)


def test_good_keys_pass_and_a_bad_public_key_is_named_without_its_value():
    keys = es.keys()
    good = {**PRODUCTION, **PROXY, **keys}
    assert _egress_problems(good) == []
    bad = dict(good, NOCTORNAL_EGRESS_SEAL_PUBLIC="bm90LWEta2V5")
    problems = _egress_problems(bad)
    assert problems == ["NOCTORNAL_EGRESS_SEAL_PUBLIC is not a 32 byte X25519 public key, "
                        "so no egress exit can be sealed for the proxy."]
    for p in config.verify_environment(bad):
        assert "bm90LWEta2V5" not in p and keys["NOCTORNAL_EGRESS_CLIENT_KEY"] not in p


def test_the_sample_origin_is_never_asked_for_egress_keys():
    env = {**PRODUCTION, **PROXY, "NOCTORNAL_SAMPLE_ORIGIN": "https://samples.unit.example",
           "NOCTORNAL_BASE_URL": "https://console.unit.example",
           "NOCTORNAL_PUBLIC_ORIGIN": "https://samples.unit.example"}
    assert _egress_problems(env) == []


class FakeConn:
    """Answers the two queries outbound_uses asks, nothing else."""

    def __init__(self, polled: bool, routes=0, personas=0, passive=0):
        self.polled, self.counts = polled, (routes, personas, passive)

    def execute(self, sql, *_a):
        answer = (self.polled,) if "parser_key" in sql else self.counts
        return type("R", (), {"fetchone": lambda _self: answer})()


def test_production_without_a_proxy_refuses_to_start_with_outbound_uses(monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "relay.unit.example")
    with pytest.raises(RuntimeError) as caught:
        egress_routes.enforce_production_egress(FakeConn(True, routes=2), env=PRODUCTION)
    text = str(caught.value)
    assert text.startswith("Collection sources are polled from this host")
    assert "email notifications go to an SMTP relay" in text
    assert "2 integration routes are configured" in text
    assert "refuses to start" in text and "relay.unit.example" not in text


def test_nothing_outbound_starts_quietly(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("NOCTORNAL_WEBHOOK_URL", raising=False)
    egress_routes.enforce_production_egress(FakeConn(False), env=PRODUCTION)


def test_with_a_proxy_configured_no_connection_is_opened(monkeypatch):
    import noctornal_api.db as db
    monkeypatch.setattr(db, "connect", lambda: pytest.fail("a connection was opened"))
    egress_routes.enforce_production_egress(env={**PRODUCTION, **PROXY})
    egress_routes.enforce_production_egress(env={})


def test_the_sample_origin_is_not_refused_for_what_api_and_cron_do(monkeypatch):
    import noctornal_api.db as db
    monkeypatch.setattr(db, "connect", lambda: pytest.fail("a connection was opened"))
    egress_routes.enforce_production_egress(env={
        **PRODUCTION, "NOCTORNAL_SAMPLE_ORIGIN": "https://samples.unit.example",
        "NOCTORNAL_BASE_URL": "https://console.unit.example",
        "NOCTORNAL_PUBLIC_ORIGIN": "https://samples.unit.example"})


def _proxy_env(**extra):
    env = {**PRODUCTION, **es.keys(),
           "NOCTORNAL_EGRESS_DATABASE_URL": "postgresql://noctornal_egress:x@postgres/noctornal",
           "NOCTORNAL_EGRESS_LISTEN": "172.31.243.11:3128"}
    env.update(extra)
    return env


def test_a_well_formed_proxy_environment_passes():
    assert egress_proxy.verify_proxy_environment(_proxy_env()) == []


@pytest.mark.parametrize("name", egress_proxy.FORBIDDEN_ENV)
def test_the_proxy_refuses_to_hold_a_platform_secret(name):
    problems = egress_proxy.verify_proxy_environment(_proxy_env(**{name: "value-9f2"}))
    assert problems == [f"This container must not hold {name}: the egress proxy talks to "
                        f"the internet and needs none of the platform's keys."]


@pytest.mark.parametrize("listen", ["0.0.0.0:3128", ":::3128", "[::]:3128"])
def test_the_proxy_refuses_a_wildcard_listen_address(listen):
    problems = egress_proxy.verify_proxy_environment(_proxy_env(NOCTORNAL_EGRESS_LISTEN=listen))
    assert any("wildcard" in p for p in problems), problems


@pytest.mark.parametrize("allow, words", [
    ("10.0.0.0/24", "outside the exits network"),
    ("172.31.243.0/28", "outside the exits network"),
    ("172.31.245.0/28,not-a-net", "not a comma list"),
])
def test_upstream_allow_must_sit_inside_the_exits_network(allow, words):
    problems = egress_proxy.verify_proxy_environment(
        _proxy_env(NOCTORNAL_EGRESS_UPSTREAM_ALLOW=allow))
    assert any(words in p for p in problems), problems


def test_upstream_allow_overlapping_the_internal_networks_is_refused():
    problems = egress_proxy.verify_proxy_environment(_proxy_env(
        NOCTORNAL_EGRESS_UPSTREAM_ALLOW="172.31.245.0/28",
        NOCTORNAL_EGRESS_INTERNAL_CIDRS="172.31.243.0/24,172.31.245.0/24"))
    assert any("overlaps this deployment's own networks" in p for p in problems)


@pytest.mark.parametrize("missing", ["NOCTORNAL_EGRESS_SEAL_KEY",
                                     "NOCTORNAL_EGRESS_FINGERPRINT_KEY",
                                     "NOCTORNAL_EGRESS_CLIENT_KEY",
                                     "NOCTORNAL_EGRESS_DATABASE_URL",
                                     "NOCTORNAL_EGRESS_LISTEN"])
def test_production_refuses_a_missing_key_or_setting(missing):
    env = _proxy_env()
    env.pop(missing)
    problems = egress_proxy.verify_proxy_environment(env)
    assert any(missing in p for p in problems), (missing, problems)


def test_development_needs_only_the_client_and_fingerprint_keys():
    env = {k: v for k, v in es.keys().items()
           if k in ("NOCTORNAL_EGRESS_CLIENT_KEY", "NOCTORNAL_EGRESS_FINGERPRINT_KEY")}
    assert egress_proxy.verify_proxy_environment(env) == []
    assert egress_proxy.verify_proxy_environment({}) != []


def test_no_refusal_quotes_a_value():
    secret = "super-secret-value-7"
    env = _proxy_env(NOCTORNAL_TOTP_KEK=secret, NOCTORNAL_EGRESS_CLIENT_KEY=secret,
                     NOCTORNAL_EGRESS_SEAL_KEY=secret)
    for problem in egress_proxy.verify_proxy_environment(env):
        assert secret not in problem


def test_the_check_command_exits_nonzero_without_a_proxy(monkeypatch):
    env = dict(es.keys(), NOCTORNAL_EGRESS_LISTEN="127.0.0.1:9")
    assert egress_proxy.check(env) == 1
    assert egress.PROXY_URL_ENV == "NOCTORNAL_EGRESS_PROXY_URL"


def test_the_process_refuses_to_serve_with_an_unusable_environment(monkeypatch, capsys):
    es.clear_egress_env(monkeypatch)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
    assert egress_proxy.main(["serve"]) == 2
    err = capsys.readouterr().err
    assert "must not hold NOCTORNAL_TOTP_KEK" in err
    assert "NOCTORNAL_EGRESS_CLIENT_KEY is not a usable key" in err


def test_keys_prints_ids_and_never_a_key(monkeypatch, capsys):
    es.clear_egress_env(monkeypatch)
    monkeypatch.delenv("NOCTORNAL_TOTP_KEK", raising=False)
    for key, value in es.keys(retired=True).items():
        monkeypatch.setenv(key, value)
    assert egress_proxy.main(["keys"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("active  egress:") and "retired egress:" in out
    for value in es.keys(retired=True).values():
        assert value not in out
