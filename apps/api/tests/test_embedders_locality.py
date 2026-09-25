"""Where the model endpoint is, and so which destination it is (F6.2,
embeddings, 2026-09-24).

The locality comes from the route and the one lookup pinned_http makes
(docs/20 section 9), never from a lookup of our own.
Only a loopback answer on a DIRECT route, outside production, with
NOCTORNAL_EMBED_MEANING_LOCAL_HOST naming the host, is this host
(Destination.MODEL_HOST). Everything else is outside it (MODEL_REMOTE),
where invariant 8's floor applies: the old "platform network" proof let
a LAN box take RED on the shipped development install, and the egress
proxy refuses the deployment's own networks, so a production platform
endpoint could not be configured anyway.

No database, no network.
"""
from __future__ import annotations

import socket

import pytest

from embedding_stub import NoRoutes
from noctornal_api import egress, embedders as E
from noctornal_api.egress import Destination
from noctornal_api.egress_policy import EgressRoute, RoutePolicy, Rule
from noctornal_api.embeddings import Item, meaning_gate


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL",
                 "NOCTORNAL_EGRESS_INTERNAL_CIDRS"):
        monkeypatch.delenv(name, raising=False)


def _settings(url: str, local: str | None = None, **extra) -> E.MeaningSettings:
    env = {E.URL_ENV: url, E.MODEL_ENV: "m", E.CEILING_ENV: "RED", **extra}
    if local:
        env[E.LOCAL_HOST_ENV] = local
    cfg = E.configured(env)
    assert cfg.meaning_settings is not None, cfg.problems
    return cfg.meaning_settings


def _open(settings):
    return E.open_endpoint(settings, conn=NoRoutes())


def test_a_declared_loopback_endpoint_is_this_host():
    endpoint = _open(_settings("http://127.0.0.1:8080/v1", local="127.0.0.1"))
    assert endpoint.locality.kind == "this_host"
    assert endpoint.destination is Destination.MODEL_HOST
    assert endpoint.locality.words == "on this host"


def test_the_name_localhost_declared_is_this_host():
    endpoint = _open(_settings("http://localhost:8080/v1", local="localhost"))
    assert endpoint.destination is Destination.MODEL_HOST


def test_an_undeclared_loopback_endpoint_is_outside_this_host():
    """A loopback port can be a tunnel to another machine: without the
    operator's statement it is judged as outside."""
    endpoint = _open(_settings("http://127.0.0.1:8080/v1"))
    assert endpoint.locality.kind == "loopback_undeclared"
    assert endpoint.destination is Destination.MODEL_REMOTE


def test_a_lan_host_declared_local_is_still_outside_and_refuses_red():
    """On the development install a declared LAN box never takes
    AMBER_STRICT or RED."""
    endpoint = _open(_settings("http://192.168.1.50:8080/v1", local="192.168.1.50"))
    assert endpoint.locality.kind == "private_network"
    assert endpoint.destination is Destination.MODEL_REMOTE
    item = Item("document", None, None, "text", 4, "RED", frozenset(), "FORUM_POST",
                "XENFORO", None)
    settings = _settings("http://192.168.1.50:8080/v1", local="192.168.1.50",
                         **{E.AUTHORITY_ENV: "DPIA-2026-14"})
    assert meaning_gate(item, destination=endpoint.destination,
                        settings=settings) == "above_platform_floor"


def test_production_never_treats_an_endpoint_as_this_host(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    with pytest.raises(E.EndpointError) as caught:
        _open(_settings("http://127.0.0.1:8080/v1", local="127.0.0.1"))
    assert caught.value.reason in ("unrouted", "route_refused")
    # Production leaves only through the proxy (docs/00 decision 68;
    # 2026-09-25), so the second half asks through a proxied route.
    _proxied(monkeypatch, Rule.for_host("10.20.0.7", {8080}))
    endpoint = _open(_settings("http://10.20.0.7:8080/v1", local="10.20.0.7"))
    assert endpoint.destination is Destination.MODEL_REMOTE


def _proxied(monkeypatch, rule: Rule):
    def fake_route_for(kind, name, *, conn, context=None, declared=()):
        assert (kind, name) == ("integration", "embeddings")
        policy = RoutePolicy("integration", (rule,), any_public=False, admission="proxy")
        return EgressRoute("integration", "embeddings", "PROXY", policy,
                           proxy_host="127.0.0.1", proxy_port=3128, token="t" * 43)
    monkeypatch.setattr(egress, "route_for", fake_route_for)


def test_a_name_through_the_proxy_is_never_looked_up_here(monkeypatch):
    _proxied(monkeypatch, Rule.for_host("models.example.org", {443}))

    def no_lookup(*_a, **_k):
        raise AssertionError("the embedder looked a name up itself")
    monkeypatch.setattr(socket, "getaddrinfo", no_lookup)
    endpoint = _open(_settings("https://models.example.org/v1"))
    assert endpoint.locality.kind == "internet"
    assert endpoint.destination is Destination.MODEL_REMOTE
    assert endpoint.hop is None


def test_a_named_private_network_through_the_proxy_is_a_private_network(monkeypatch):
    _proxied(monkeypatch, Rule.for_host("gpu.lab.example", {8080},
                                        network="10.30.0.0/24"))
    endpoint = _open(_settings("http://gpu.lab.example:8080/v1"))
    assert endpoint.locality.kind == "private_network"
    assert endpoint.destination is Destination.MODEL_REMOTE


def test_loopback_through_the_proxy_is_refused(monkeypatch):
    _proxied(monkeypatch, Rule.for_host("127.0.0.1", {8080}))
    with pytest.raises(E.EndpointError) as caught:
        _open(_settings("http://127.0.0.1:8080/v1", local="127.0.0.1"))
    assert caught.value.reason == "route_refused"


@pytest.mark.parametrize("url", ["http://169.254.169.254/v1", "http://[fe80::1]:80/v1",
                                 "http://0.0.0.0:80/v1", "http://224.0.0.1:80/v1",
                                 "http://metadata.google.internal/v1"])
def test_refused_addresses_are_configuration_problems(url):
    cfg = E.configured({E.URL_ENV: url, E.MODEL_ENV: "m", E.CEILING_ENV: "AMBER"})
    assert cfg.meaning_settings is None
    assert any(E.URL_ENV in p for p in cfg.problems)


def test_a_local_host_that_is_not_the_urls_host_is_a_problem():
    cfg = E.configured({E.URL_ENV: "http://127.0.0.1:8080/v1", E.MODEL_ENV: "m",
                        E.CEILING_ENV: "AMBER", E.LOCAL_HOST_ENV: "127.0.0.2"})
    assert cfg.meaning_settings is None
    assert any(E.LOCAL_HOST_ENV in p for p in cfg.problems)


def test_a_wide_or_public_network_is_a_problem():
    for value in ("10.0.0.0/8", "8.8.8.0/24"):
        cfg = E.configured({E.URL_ENV: "http://gpu.lab.example:8080/v1",
                            E.MODEL_ENV: "m", E.CEILING_ENV: "AMBER",
                            E.NETWORK_ENV: value})
        assert cfg.meaning_settings is None, value
        assert any(E.NETWORK_ENV in p for p in cfg.problems)
