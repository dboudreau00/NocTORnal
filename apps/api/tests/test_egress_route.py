"""egress.route_for, the one reader of the network path an outbound
connection takes (2026-09-24; docs/00 decisions 68 and 77, docs/20
section 6.2's decision table and section 7's provider).

Pure: the environment is monkeypatched, the route provider is a fake
module installed in sys.modules (or the real one hidden with a None entry,
so these cells hold whether or not it is installed), and `conn` is a
stand-in: route_for hands it to the provider and reads nothing from it
itself.
"""
from __future__ import annotations

import importlib
import importlib.machinery
import socket
import sys
import types
from uuid import uuid4

import pytest

from noctornal_api import config, egress, egress_policy, pinned_http
from noctornal_api.egress import ProbeVerdict, RouteParts, route_for
from noctornal_api.egress_policy import (
    DECISION_REF,
    RoutePolicy,
    Rule,
    parse_rule,
)

PROFILE = str(uuid4())
TOKEN = "t" * 43
CONN = object()
SMTP_RULE = Rule.for_host("relay.example", {587})
ADMIN_RULE = parse_rule("jira.corp.example@10.20.0.0/24:443")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (config.ENV_VAR, egress.PROXY_URL_ENV, egress_policy.INTERNAL_CIDRS_ENV,
                 "SMTP_HOST", "NOCTORNAL_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def provider(monkeypatch):
    """install(module or None): the provider module route_for will find.
    None hides the module even once the real one exists in the tree."""
    def install(module):
        monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, module)
        egress._reset_route_provider()

    install(None)
    yield install
    egress._reset_route_provider()


def fake_provider(*, contract=1, admin=(ADMIN_RULE,), uses=(), verdict=None, seen=None,
                  drop=()):
    module = types.ModuleType(egress.ROUTE_PROVIDER_MODULE)
    module.__spec__ = importlib.machinery.ModuleSpec(egress.ROUTE_PROVIDER_MODULE, None)
    module.PROVIDER_CONTRACT = contract

    def route_parts(kind, name, *, conn, mode, production, declared, internal, context=None):
        if seen is not None:
            seen.append({"kind": kind, "name": name, "mode": mode, "context": context,
                         "production": production})
        rules = admin if kind == "integration" else ()
        policy = RoutePolicy(kind, rules, narrow=declared,
                             any_public=kind == "persona", internal=internal,
                             admission="local" if mode == "DIRECT" else "proxy")
        return RouteParts(policy, TOKEN if mode == "PROXY" else None)

    module.route_parts = route_parts
    module.boundary_probe = lambda conn, settings: verdict
    module.outbound_uses = lambda conn: list(uses)
    for name in drop:
        delattr(module, name)
    return module


def _call(kind):
    if kind == "passive":
        return route_for("persona", "passive", conn=CONN, context=f"run:{uuid4()}")
    if kind == "profile":
        return route_for("persona", PROFILE, conn=CONN, context=f"run:{uuid4()}")
    return route_for("integration", "smtp", conn=CONN, declared=(SMTP_RULE,))


def _expected(env, proxy, present, kind):
    if proxy == "malformed":
        return "proxy_misconfigured"
    if proxy == "set":
        return ("PROXY", "proxy") if present else "no_route_provider"
    if env == "production" and (present or kind == "profile"):
        return "proxy_required"
    return ("DIRECT", "local")


@pytest.mark.parametrize("env", ["development", "production"])
@pytest.mark.parametrize("proxy", ["none", "set", "malformed"])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("kind", ["passive", "profile", "integration"])
def test_every_cell_of_the_decision_table(monkeypatch, provider, env, proxy, present, kind):
    if env == "production":
        monkeypatch.setenv(config.ENV_VAR, "production")
    if proxy == "set":
        monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    elif proxy == "malformed":
        monkeypatch.setenv(egress.PROXY_URL_ENV, "socks5://egress-proxy:1080")
    if present:
        provider(fake_provider())
    want = _expected(env, proxy, present, kind)
    if isinstance(want, str):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            _call(kind)
        assert caught.value.code == want
        return
    route = _call(kind)
    assert (route.mode, route.policy.admission) == want
    if route.mode == "PROXY":
        assert (route.proxy_host, route.proxy_port, route.token) == ("egress-proxy", 3128, TOKEN)
        assert route.note == egress.PROXY_NOTE
    elif env == "production":
        assert "leaves from this host's own address" in route.note
    else:
        assert route.note == egress.DEV_NOTE
    if kind == "integration" and not present:
        assert route.policy.rules == (SMTP_RULE,) and route.policy.any_public is False
        assert route.policy.allow_loopback is (env == "development")
    if kind != "integration" and not present:
        assert route.policy.rules == () and route.policy.any_public


def test_a_production_persona_route_is_never_direct(monkeypatch, provider):
    monkeypatch.setenv(config.ENV_VAR, "production")
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: pytest.fail("route_for looked a name up"))
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        route_for("persona", PROFILE, conn=CONN, context=f"act:{uuid4()}")
    assert caught.value.code == "proxy_required"
    assert DECISION_REF in str(caught.value)
    passive = route_for("persona", "passive", conn=CONN, context=f"run:{uuid4()}")
    assert passive.mode == "DIRECT"
    assert [str(n) for n in passive.policy.internal] == list(
        egress_policy.DEFAULT_INTERNAL_NETWORKS)


def test_a_proxy_without_a_provider_refuses_every_route(monkeypatch, provider):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    lookups = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: lookups.append(a) or [])
    for kind in ("passive", "profile", "integration"):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            _call(kind)
        assert caught.value.code == "no_route_provider"
        assert "egress-proxy" not in str(caught.value)
    assert lookups == []


@pytest.mark.parametrize("breakage", ["contract", "missing", "import"])
def test_a_provider_that_does_not_match_refuses_every_route(monkeypatch, provider, breakage):
    if breakage == "contract":
        provider(fake_provider(contract=2))
    elif breakage == "missing":
        provider(fake_provider(drop=("boundary_probe",)))
    else:
        provider(fake_provider())

        def boom(name, *args, **kwargs):
            raise RuntimeError("provider module failed")

        monkeypatch.setattr(importlib, "import_module", boom)
    for kind in ("passive", "profile", "integration"):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            _call(kind)
        assert caught.value.code == "no_route_provider"
    assert egress.boundary().in_force is False


def test_declared_is_the_allowlist_without_a_provider_and_a_filter_with_one(provider):
    alone = route_for("integration", "webhook", conn=CONN,
                      declared=(Rule.for_url("https://hooks.example/in"),))
    assert alone.permits("hooks.example", 443) and not alone.permits("jira.corp.example", 443)
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        route_for("integration", "webhook", conn=CONN)
    assert caught.value.code == "route_unknown" and DECISION_REF in str(caught.value)
    provider(fake_provider())
    narrowed = route_for("integration", "smtp", conn=CONN,
                         declared=(parse_rule("jira.corp.example:443"),))
    assert narrowed.permits("jira.corp.example", 443)
    assert narrowed.rules == (ADMIN_RULE,)
    wider = route_for("integration", "smtp", conn=CONN,
                      declared=(parse_rule("other.example:443"),))
    assert not wider.permits("other.example", 443)
    assert not wider.permits("jira.corp.example", 443)


def test_an_integration_route_refuses_a_wide_reserved_or_internal_rule(monkeypatch, provider):
    for text in ("10.0.0.0/8:443", "postgres:5432", "[fe80::/64]:443"):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            route_for("integration", "webhook", conn=CONN, declared=(parse_rule(text),))
        assert caught.value.code == "destination_not_allowed"
    monkeypatch.setenv(config.ENV_VAR, "production")
    for text in ("x.corp.example@172.31.243.0/24:443", "localhost:1025", "127.0.0.1:1025"):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            route_for("integration", "smtp", conn=CONN, declared=(parse_rule(text),))
        assert caught.value.code == "destination_not_allowed"


def test_localhost_is_accepted_for_an_integration_outside_production_only(monkeypatch, provider):
    for host in ("localhost", "127.0.0.1"):
        route = route_for("integration", "smtp", conn=CONN,
                          declared=(Rule.for_host(host, {1025}),))
        assert route.mode == "DIRECT" and route.policy.allow_loopback
    monkeypatch.setenv(config.ENV_VAR, "production")
    with pytest.raises(pinned_http.RouteUnavailable):
        route_for("integration", "smtp", conn=CONN,
                  declared=(Rule.for_host("localhost", {1025}),))


def test_an_unknown_integration_bad_persona_name_or_missing_context_is_a_programming_error(
        provider):
    run = f"run:{uuid4()}"
    for call in (
        lambda: route_for("carrier", "x", conn=CONN),
        lambda: route_for("integration", "fax", conn=CONN, declared=(SMTP_RULE,)),
        lambda: route_for("persona", "not-a-uuid", conn=CONN, context=run),
        lambda: route_for("persona", PROFILE.upper(), conn=CONN, context=run),
        lambda: route_for("persona", PROFILE, conn=CONN),
        lambda: route_for("persona", PROFILE, conn=CONN, context=f"delivery:{uuid4()}"),
        lambda: route_for("integration", "smtp", conn=CONN, context=run,
                          declared=(SMTP_RULE,)),
        lambda: route_for("integration", "smtp", conn=None, declared=(SMTP_RULE,)),
        lambda: route_for("persona", "passive", conn=CONN, context="run:nope"),
        lambda: route_for("integration", "smtp", conn=CONN, declared=("relay:587",)),
    ):
        with pytest.raises(ValueError):
            call()


def test_a_lookup_family_name_is_accepted(provider):
    declared = (Rule.for_url("https://www.virustotal.example/api/v3/"),)
    for name, canonical in (("lookup-virustotal", "lookup-virustotal"),
                            ("lookup-misp", "lookup-misp"),
                            ("lookup-virustotal_v3", "lookup-virustotal-v3"),
                            ("lookup-" + "k" * 33, "lookup-" + "k" * 33)):
        assert route_for("integration", name, conn=CONN, declared=declared).name == canonical
    # A key comes from a provider row, so one that makes no route name is
    # configuration (RouteUnavailable), not a programming error: a
    # 40-character key is allowed by the provider table and still refused
    # here, with a sentence, rather than crashing the lookup.
    for name in ("lookup-", "lookup-" + "k" * 34, "lookup-" + "k" * 40, "lookup-Upper"):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            route_for("integration", name, conn=CONN, declared=declared)
        assert caught.value.code == "route_unknown"
    with pytest.raises(ValueError):
        route_for("integration", "lookups", conn=CONN, declared=declared)


@pytest.mark.parametrize("value", ["http://egress-proxy:3128", "http://172.31.243.11:3128",
                                   "http://egress-proxy:3128/", "http://[fd00::11]:3128"])
def test_proxy_settings_accepts_only_http_with_a_port(value):
    settings = egress.proxy_settings({egress.PROXY_URL_ENV: value})
    assert settings.port == 3128
    assert egress.proxy_problem({egress.PROXY_URL_ENV: value}) is None


@pytest.mark.parametrize("value", [
    "https://egress-proxy:3128", "socks5://egress-proxy:1080", "http://egress-proxy:3128/p",
    "http://user:hunter2hunter2@egress-proxy:3128", "http://egress-proxy",
    "http://egress-proxy:3128?x=1", "http://egress-proxy:3128#f", "http://:3128",
    "http://2130706433:3128", "http://egress-proxy:99999"])
def test_proxy_settings_refuses_everything_else_with_a_sentence(value):
    env = {egress.PROXY_URL_ENV: value}
    problem = egress.proxy_problem(env)
    assert problem and problem.startswith(egress.PROXY_URL_ENV)
    assert "hunter2" not in problem and "egress-proxy" not in problem
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.proxy_settings(env)
    assert caught.value.code == "proxy_misconfigured"
    assert egress.proxy_settings({egress.PROXY_URL_ENV: "  "}) is None


def test_the_context_travels_in_the_wire_username(monkeypatch, provider):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    seen = []
    provider(fake_provider(seen=seen))
    for kind in ("run", "act", "stop"):
        cid = uuid4()
        route = route_for("persona", PROFILE, conn=CONN, context=f"{kind}:{cid}")
        assert route.wire_username == f"persona.{PROFILE}~{kind}.{cid}"
        assert seen[-1]["context"] == f"{kind}:{cid}"
    delivery = uuid4()
    route = route_for("integration", "smtp", conn=CONN, declared=(SMTP_RULE,))
    assert route.tagged(f"delivery:{delivery}").wire_username == \
        f"integration.smtp~delivery.{delivery}"


class _Conn:
    def __init__(self, polled):
        self.polled = polled
        self.sql = []

    def execute(self, sql, *args):
        self.sql.append(sql)
        # 2026-09-25: jira and lookups read their own tables
        self.answer = self.polled if "collect.source" in sql else False
        return self

    def fetchone(self):
        return (self.answer,)


def test_outbound_uses_states_presence_and_never_names(monkeypatch, provider):
    """The collection use is a presence, not a count (2026-09-24), and
    only a source the collector would poll is asked about. The
    database half (a MANUAL capture source is not a use) is in
    test_egress_boundary_readiness_pg.py."""
    assert egress.outbound_uses(_Conn(False)) == []
    conn = _Conn(True)
    assert egress.outbound_uses(conn) == [egress.COLLECTION_USE]
    assert "parser_key" in conn.sql[0] and "is_active" in conn.sql[0]
    assert "count(" not in conn.sql[0].lower()
    assert not any(ch.isdigit() for ch in egress.COLLECTION_USE)
    monkeypatch.setenv("SMTP_HOST", "relay.secret-name.example")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.secret-name.example/x")
    provider(fake_provider(uses=("2 integration routes are active",)))
    uses = egress.outbound_uses(_Conn(True))
    assert uses == ["collection sources are polled from this host",
                    "email notifications go to an SMTP relay",
                    "notifications are posted to a webhook",
                    "2 integration routes are active"]
    assert not any("secret-name" in u for u in uses)


def test_the_config_refusals_read_the_same_parse(monkeypatch):
    base = {config.ENV_VAR: "production"}
    for name, value, phrase in (
            (egress.PROXY_URL_ENV, "https://hunter2hunter2@egress.example:3128",
             "is not an http:// address"),
            (egress_policy.INTERNAL_CIDRS_ENV, "hunter2hunter2/99", "is not a comma list")):
        problems = config.verify_environment({**base, name: value})
        mine = [p for p in problems if p.startswith(name)]
        assert len(mine) == 1 and phrase in mine[0], problems
        assert "hunter2" not in " ".join(problems)
    problems = config.verify_environment({**base, egress.PROXY_URL_ENV: "http://egress-proxy:3128"})
    assert not [p for p in problems if egress.PROXY_URL_ENV in p]
    assert config.verify_environment({egress.PROXY_URL_ENV: "socks5://x:1"}) == []


def test_a_malformed_internal_list_is_a_configuration_refusal(monkeypatch, provider):
    monkeypatch.setenv(egress_policy.INTERNAL_CIDRS_ENV, "not-a-network")
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        _call("passive")
    assert caught.value.code == "config_error"


def test_egress_re_exports_the_route_errors():
    assert egress.RouteUnavailable is pinned_http.RouteUnavailable
    assert egress.DestinationRefused is pinned_http.DestinationRefused


def test_the_boundary_says_whether_it_is_in_force(monkeypatch, provider):
    assert egress.boundary() == egress.Boundary("DIRECT", None, False, egress.HOST_NOTE)
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    b = egress.boundary()
    assert (b.mode, b.proxy, b.in_force) == ("PROXY", "egress-proxy:3128", False)
    provider(fake_provider(verdict=ProbeVerdict(True, "ok")))
    assert egress.boundary().in_force is True
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://user:pw@egress-proxy:3128")
    b = egress.boundary()
    assert (b.mode, b.proxy, b.in_force) == ("PROXY", None, False)
    assert "pw@" not in b.note


def test_a_provider_without_a_context_parameter_is_still_called(monkeypatch, provider):
    """The context is offered only to a provider whose route_parts takes
    it, so docs/20 section 7's signature stays the contract."""
    module = fake_provider()

    def strict(kind, name, *, conn, mode, production, declared, internal):
        return RouteParts(RoutePolicy(kind, admission="local", any_public=True), None)

    module.route_parts = strict
    provider(module)
    assert route_for("persona", "passive", conn=CONN, context=f"run:{uuid4()}").mode == "DIRECT"
