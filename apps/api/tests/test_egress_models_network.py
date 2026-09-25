"""The production `models` network is reachable through an embeddings entry
that names it, and `exits` never is (S2, 2026-09-25; docs/20 section 9).

integration_internal once listed the models network among the deployment's
own networks, so validate_rule refused `model@172.31.246.0/24:8080` and the
proxy's admission refused the model's answer anyway: the local model server
the README puts there could never be reached. The exits network, where a
Tor or VPN sidecar sits, must stay unnameable, or an integration could leave
through a persona's exit. Pure: no database, no network (a fake resolver).
"""
from __future__ import annotations

import ipaddress
import socket
from uuid import uuid4

import pytest

from noctornal_api import egress_policy, egress_routes
from noctornal_api.egress_policy import Refusal, parse_rule, validate_rule
from noctornal_api.egress_routes import IntegrationRow, integration_internal, integration_policy

OWN = tuple(ipaddress.ip_network(n) for n in egress_policy.DEFAULT_INTERNAL_NETWORKS)


def _problems(entry: str) -> list[str]:
    return validate_rule(parse_rule(entry), kind="integration", production=True,
                         internal=integration_internal(OWN, True))


def test_an_embeddings_entry_may_name_the_models_network_in_production():
    assert _problems("model@172.31.246.0/24:8080") == []


@pytest.mark.parametrize("entry", ["tor@172.31.245.0/24:9050", "172.31.245.0/24:8118",
                                   "hooks@172.31.243.0/24:8000"])
def test_no_integration_entry_may_name_the_exits_or_the_deployments_own_networks(entry):
    problems = _problems(entry)
    assert any("own networks" in p for p in problems)


def test_only_the_exits_network_is_added_and_only_in_production():
    assert integration_internal(OWN, True) == OWN + (egress_routes.EXITS_NETWORK,)
    assert egress_routes.MODELS_NETWORK not in integration_internal(OWN, True)
    assert integration_internal(OWN, False) == OWN


def _route(entries) -> IntegrationRow:
    return IntegrationRow(uuid4(), "embeddings", True, False, 60, 300, 8,
                          tuple((uuid4(), e) for e in entries))


def test_the_proxy_admits_the_models_answer_and_refuses_an_exits_answer(monkeypatch):
    """What the proxy does for an integration tunnel: check_destination,
    then one lookup with every answer admitted under the entry's network."""
    policy = integration_policy(_route(["model@172.31.246.0/24:8080"]),
                                internal=OWN, production=True)
    rule = egress_policy.check_destination(policy, "model", 8080)
    assert rule is not None
    answers = {"model": "172.31.246.7"}

    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    pinned = egress_policy.resolve_and_pin("model", 8080, policy=policy, rule=rule,
                                           route_label="integration:embeddings")
    assert [str(a[3][0]) for a in pinned.addresses] == ["172.31.246.7"]
    # A model name that answers with a sidecar's address on `exits` is
    # outside the entry's network and inside the deployment's own.
    answers["model"] = "172.31.245.3"
    with pytest.raises(Refusal):
        egress_policy.resolve_and_pin("model", 8080, policy=policy, rule=rule,
                                      route_label="integration:embeddings")
