"""The route provider behind egress.route_for (S2, 2026-09-24; docs/20
sections 6.2 and 7).

Every decision-table cell that involves the provider, with real rows:
development DIRECT under a profile's policy, under the declared rules where
no administrator route exists and under the built-in passive policy where
no passive default does; PROXY with the token and the same policy the proxy
builds; production without a proxy refused. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from dataclasses import replace
from uuid import uuid4

import pytest

import egress_support as es
from noctornal_api import config, egress, egress_authz, egress_policy, egress_routes, pinned_http
from noctornal_api.egress_policy import PUBLIC_POLICY, Rule, WireClaim, parse_rule

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egv-"


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


@pytest.fixture(autouse=True)
def env(monkeypatch):
    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    egress._reset_route_provider()
    yield
    egress._reset_route_provider()


def _integration(conn, name, entries, *, active=True):
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = (SELECT id FROM iam.app_user LIMIT 1),
                      retire_reason = 'provider suite' WHERE name = %s AND retired_at IS NULL""",
                 (name,))
    rid = conn.execute(
        "INSERT INTO collect.egress_integration_route (name, description, is_active) "
        "VALUES (%s, %s, %s) RETURNING id", (name, f"{PREFIX}route", active)).fetchone()[0]
    for entry in entries:
        conn.execute("INSERT INTO collect.egress_destination (route_id, entry, note) "
                     "VALUES (%s, %s, 'provider suite')", (rid, entry))
    return rid


def _retire(conn, name):
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = (SELECT id FROM iam.app_user LIMIT 1),
                      retire_reason = 'provider suite' WHERE name = %s AND retired_at IS NULL""",
                 (name,))


def test_route_for_finds_this_provider_by_name():
    provider = egress._route_provider()
    assert provider is egress_routes
    assert provider.PROVIDER_CONTRACT == egress.PROVIDER_CONTRACT == 1


def test_development_direct_takes_a_profile_policy(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", ports=(443, 8443),
                     any_public_host=False, suffixes=("forum.example",),
                     cidrs=("203.0.113.0/24",), exit_kind=None)
    route = egress.route_for("persona", str(pid), conn=conn,
                             context="run:00000000-0000-4000-8000-000000000001")
    assert (route.mode, route.policy.admission, route.token) == ("DIRECT", "local", None)
    assert route.permits("www.forum.example", 443)
    assert not route.permits("www.forum.example", 80)
    assert not route.permits("elsewhere.example", 443)
    assert route.policy.refuse_special_names


def test_development_passive_without_a_default_is_the_alpha6_public_policy(conn):
    conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                 "WHERE is_passive_default")
    route = egress.route_for("persona", "passive", conn=conn,
                             context="run:00000000-0000-4000-8000-000000000002")
    assert route.mode == "DIRECT"
    assert route.policy == replace(PUBLIC_POLICY, internal=())
    assert route.permits("any.example", 8080)


def test_an_integration_with_no_row_is_its_declared_rules_in_development(conn):
    # A lookup provider no route was ever made for: no row at all.
    name = "lookup-never" + uuid4().hex[:8]
    route = egress.route_for("integration", name, conn=conn,
                             declared=(Rule.for_host("relay.example", {587}),))
    assert route.permits("relay.example", 587) and not route.permits("relay.example", 25)
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.route_for("integration", name, conn=conn)
    assert caught.value.code == "route_unknown"


def test_a_retired_route_stays_refused_rather_than_falling_back_to_declared(conn):
    _integration(conn, "smtp", ["relay.example:587"])
    _retire(conn, "smtp")
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.route_for("integration", "smtp", conn=conn,
                         declared=(Rule.for_host("relay.example", {587}),))
    assert caught.value.code == "route_retired"


def test_declared_rules_narrow_an_administrator_route_and_never_widen_it(conn):
    _integration(conn, "webhook", ["hooks.example:443", "other.example:443"])
    try:
        route = egress.route_for("integration", "webhook", conn=conn,
                                 declared=(Rule.for_host("hooks.example", {443}),))
        assert route.permits("hooks.example", 443)
        assert not route.permits("other.example", 443)
        wider = egress.route_for("integration", "webhook", conn=conn,
                                 declared=(Rule.for_host("third.example", {443}),))
        assert not wider.permits("third.example", 443)
    finally:
        _retire(conn, "webhook")


def test_proxy_mode_carries_the_token_and_the_policy_the_proxy_builds(conn, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://127.0.0.1:3128")
    _integration(conn, "webhook", ["hooks.example:443"])
    try:
        route = egress.route_for("integration", "webhook", conn=conn)
        assert route.mode == "PROXY" and route.policy.admission == "proxy"
        assert route.token == egress_routes.route_token("integration.webhook",
                                                        es.CLIENT_KEY)
        decision = egress_authz.authorise(
            conn, WireClaim("integration", "webhook", None, None), "hooks.example", 443,
            production=False, internal=())
        assert decision.policy.rules == route.policy.rules
        assert replace(decision.policy, admission="proxy") == route.policy
    finally:
        _retire(conn, "webhook")


def test_proxy_mode_refuses_a_profile_with_no_exit_and_retired_or_inactive_routes(
        conn, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://127.0.0.1:3128")
    pid = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    context = "act:00000000-0000-4000-8000-000000000003"
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.route_for("persona", str(pid), conn=conn, context=context)
    assert caught.value.code == "no_exit"
    conn.execute("UPDATE collect.egress_profile SET is_active = false WHERE id = %s", (pid,))
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.route_for("persona", str(pid), conn=conn, context=context)
    assert caught.value.code == "route_inactive"
    conn.execute("UPDATE collect.egress_profile SET retired_at = now(), retired_by = "
                 "(SELECT id FROM iam.app_user LIMIT 1), retire_reason = 'done now' "
                 "WHERE id = %s", (pid,))
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.route_for("persona", str(pid), conn=conn, context=context)
    assert caught.value.code == "route_retired"
    # Through a proxy the built-in development passive policy does not
    # exist: no passive default is route_unknown.
    conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                 "WHERE is_passive_default")
    with pytest.raises(pinned_http.RouteUnavailable) as caught:
        egress.route_for("persona", "passive", conn=conn,
                         context="run:00000000-0000-4000-8000-000000000004")
    assert caught.value.code == "route_unknown"


def test_a_proxy_without_a_client_key_is_config_error(conn, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://127.0.0.1:3128")
    monkeypatch.delenv("NOCTORNAL_EGRESS_CLIENT_KEY")
    _integration(conn, "webhook", ["hooks.example:443"])
    try:
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            egress.route_for("integration", "webhook", conn=conn)
        assert caught.value.code == "config_error"
        assert "NOCTORNAL_EGRESS_CLIENT_KEY" in str(caught.value)
    finally:
        _retire(conn, "webhook")


def test_production_with_no_proxy_refuses_every_route_once_the_provider_exists(
        conn, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, "production")
    for kind, name, context in (("persona", "passive", "run:00000000-0000-4000-8000-000000000005"),
                                ("integration", "smtp", None)):
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            egress.route_for(kind, name, conn=conn, context=context,
                             declared=(Rule.for_host("relay.example", {587}),)
                             if kind == "integration" else ())
        assert caught.value.code == "proxy_required"


def test_in_production_an_integration_entry_may_not_name_the_exits_network(conn):
    internal = egress_routes.integration_internal((), True)
    problems = egress_policy.validate_rule(parse_rule("tor@172.31.245.0/24:9050"),
                                           kind="integration", production=True,
                                           internal=internal)
    assert problems and "own networks" in problems[0]


def test_outbound_uses_counts_and_never_names(conn):
    _integration(conn, "webhook", ["secret-host.example:443"])
    try:
        uses = egress_routes.outbound_uses(conn)
        text = " ".join(uses)
        assert "integration route" in text
        assert "secret-host" not in text and "webhook" not in text
    finally:
        _retire(conn, "webhook")


def test_the_telegram_preset_keeps_ipv4_and_passes_validation(monkeypatch):
    """Telegram's IPv6 blocks are /48 and /32, wider than the /64 cap, and
    the client connects over IPv4, so the preset carries IPv4 only."""
    import types

    from noctornal_api import egress_policy
    fake = types.ModuleType("noctornal_api.telegram")
    fake.TELEGRAM_DC_NETWORKS = ("149.154.160.0/20", "91.108.4.0/22",
                                 "2001:b28:f23d::/48", "2a0a:f280::/32")
    monkeypatch.setitem(__import__("sys").modules, "noctornal_api.telegram", fake)
    preset = egress_routes.presets()["telegram"]
    assert preset["cidrs"] == ["149.154.160.0/20", "91.108.4.0/22"]
    assert preset["ports"] == [443, 80, 5222]
    for cidr in preset["cidrs"]:
        rule = Rule(frozenset(preset["ports"]), network=cidr)
        assert egress_policy.validate_rule(rule, kind="persona", production=True,
                                           internal=()) == []


def test_without_the_telegram_module_there_is_no_preset(monkeypatch):
    monkeypatch.setitem(__import__("sys").modules, "noctornal_api.telegram", None)
    assert "telegram" not in egress_routes.presets()
