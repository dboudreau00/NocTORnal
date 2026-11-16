"""The egress boundary under a NetworkPolicy (decision 239).

Every pod has a default route, whatever its NetworkPolicy says: a policy drops packets at the node and does
not remove the route. So the route-table rule of `egress_routes.boundary_probe` ("no default route") would be
red in every pod, and a plugin that ignores NetworkPolicy could not be told from one that enforces it. In a
pod, with NOCTORNAL_EGRESS_BOUNDARY=network_policy, the boundary is instead proved by a canary: a connection to
a host and port the policy must not let this process reach. Only a connection that goes UNANSWERED passes.

The mode is honoured only where the kubelet's variable (KUBERNETES_SERVICE_HOST) is set, so a compose
deployment cannot switch the route-table rule off by typing a variable, and unset it is the rule it was.

Pure: no database. The proxy half is the contract cases' stub proxy; what the network answers is said by the
tests (a loopback host can neither drop a packet nor be policed).
"""
from __future__ import annotations

import socket

import pytest
from test_config_boot import _production

import egress_support as es
from egress_contract_cases import StubProxy
from noctornal_api import config, egress, egress_policy, egress_routes, pinned_http
from noctornal_api.egress import ProxySettings

POD_ENV = egress_policy.POD_ENV
BOUNDARY_ENV = egress_policy.BOUNDARY_ENV
CANARY_ENV = egress_policy.CANARY_ENV
CANARY = "10.99.0.9:9"
CLUSTER_NETWORKS = "10.96.0.0/12,10.244.0.0/16,192.168.0.0/16"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv(POD_ENV, raising=False)
    egress._reset_route_provider()
    yield
    egress._reset_route_provider()


@pytest.fixture
def stub():
    with StubProxy(key=es.CLIENT_KEY) as proxy:
        yield proxy


def _settings(stub):
    return ProxySettings("127.0.0.1", stub.port)


@pytest.fixture
def pod(monkeypatch, tmp_path):
    """A pod that asks for the mode, with the cluster's own networks declared, a default route (every pod
    has one) and the cluster's resolver."""
    monkeypatch.setenv(POD_ENV, "10.96.0.1")
    monkeypatch.setenv(BOUNDARY_ENV, "network_policy")
    monkeypatch.setenv(CANARY_ENV, CANARY)
    monkeypatch.setenv(egress_policy.INTERNAL_CIDRS_ENV, CLUSTER_NETWORKS)
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: True)
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 10.96.0.10\nsearch noctornal.svc.cluster.local\noptions ndots:5\n",
                      encoding="ascii")
    monkeypatch.setattr(egress_routes, "_RESOLV", str(resolv))


@pytest.fixture
def network(monkeypatch):
    """Says what the network does with the connect to the canary, and records the addresses it was tried at."""
    tried: list = []

    def answer(outcome):
        errors = {"timed_out": TimeoutError("timed out"),
                  "refused": ConnectionRefusedError("refused"),
                  "unreachable": OSError(113, "no route to host")}

        def attempt(_family, _kind, _proto, sockaddr, _timeout):
            tried.append(sockaddr)
            if outcome != "connected":
                raise errors[outcome]

        monkeypatch.setattr(pinned_http, "_canary_attempt", attempt)
        return tried

    return answer


# ---------------------------------------------------------------------------
# The settings
# ---------------------------------------------------------------------------

def test_the_mode_is_refused_outside_a_pod():
    problem = egress_policy.boundary_problem({BOUNDARY_ENV: "network_policy", CANARY_ENV: CANARY})
    assert problem is not None
    assert BOUNDARY_ENV in problem and POD_ENV in problem and "for a pod" in problem
    assert egress_policy.boundary_problem(
        {BOUNDARY_ENV: "network_policy", CANARY_ENV: CANARY, POD_ENV: "10.96.0.1"}) is None
    # A production boot says so by name, and quotes no value.
    problems = config.verify_environment({**_production(), BOUNDARY_ENV: "network_policy",
                                          CANARY_ENV: CANARY})
    assert any(BOUNDARY_ENV in p and POD_ENV in p for p in problems), problems
    assert not any(CANARY in p for p in problems)
    ok = config.verify_environment({**_production(), BOUNDARY_ENV: "network_policy",
                                    CANARY_ENV: CANARY, POD_ENV: "10.96.0.1",
                                    egress_policy.INTERNAL_CIDRS_ENV: CLUSTER_NETWORKS})
    assert not any(BOUNDARY_ENV in p or CANARY_ENV in p for p in ok), ok


@pytest.mark.parametrize("value", ["route_table", "NETWORK_POLICY", "network-policy", "1", "on",
                                   "networkpolicy"])
def test_any_other_value_is_refused_and_unset_or_blank_is_the_route_table_rule(value):
    problem = egress_policy.boundary_problem({BOUNDARY_ENV: value, POD_ENV: "10.96.0.1",
                                              CANARY_ENV: CANARY})
    assert problem and BOUNDARY_ENV in problem and "network_policy" in problem
    assert value not in problem.replace("network_policy", "")
    assert egress_policy.boundary_problem({}) is None
    assert egress_policy.boundary_problem({BOUNDARY_ENV: ""}) is None
    assert egress_policy.boundary_problem({BOUNDARY_ENV: "  ", POD_ENV: "10.96.0.1"}) is None


def test_the_mode_needs_a_well_formed_canary():
    base = {BOUNDARY_ENV: "network_policy", POD_ENV: "10.96.0.1"}
    missing = egress_policy.boundary_problem(base)
    assert missing and CANARY_ENV in missing and "not set" in missing
    assert egress_policy.boundary_problem({**base, CANARY_ENV: "  "}) == missing
    for bad in ("egress-canary", "egress-canary:0", "egress-canary:99999", "http://c:9", "c:9/x",
                "c :9", " c:9", "c:9 ", "[::1:9", "10.0.0.1:port", "a b:9"):
        problem = egress_policy.boundary_problem({**base, CANARY_ENV: bad})
        assert problem and CANARY_ENV in problem and "HOST:PORT" in problem, bad
    for good in (CANARY, "egress-canary.noctornal.svc.cluster.local:9", "[fd00::9]:9", "canary:65535"):
        assert egress_policy.boundary_problem({**base, CANARY_ENV: good}) is None, good


def test_a_malformed_canary_is_refused_even_when_the_mode_is_unset():
    """The analysis worker's self-test dials the canary too, so a canary that cannot be tried is not left
    to be skipped quietly."""
    problems = config.verify_environment({**_production(), CANARY_ENV: "not a canary"})
    assert any(CANARY_ENV in p and "HOST:PORT" in p for p in problems), problems
    assert not any(CANARY_ENV in p for p in config.verify_environment({**_production(), CANARY_ENV: CANARY}))


def test_a_development_process_is_not_refused_by_a_boot_check():
    assert config.verify_environment({BOUNDARY_ENV: "nonsense"}) == []


# ---------------------------------------------------------------------------
# The probe
# ---------------------------------------------------------------------------

def test_a_canary_that_times_out_passes_and_says_a_default_route_is_normal_in_a_pod(
        stub, pod, network):
    tried = network("timed_out")
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert verdict.ok, verdict
    assert "refused a private destination" in verdict.evidence
    assert "did not answer" in verdict.evidence
    assert "default route, as every pod does" in verdict.caveat
    assert "the network policy, not the route table" in verdict.caveat
    # Nothing was dialled but the canary's own literal address, on its own port.
    assert tried == [("10.99.0.9", 9)]


def test_the_route_table_is_not_what_decides_in_the_mode_and_its_fact_is_still_reported(
        stub, pod, network, monkeypatch):
    """A pod's table has a default route and the row passes; a table without one, or one that cannot be read,
    changes nothing about the verdict, and each is said in the caveat as it is."""
    network("timed_out")
    for route, words in ((True, "has a default route, as every pod does"),
                         (False, "has no default route, which a pod does not usually lack"),
                         (None, "routes could not be read here")):
        monkeypatch.setattr(egress_routes, "_has_default_route", lambda route=route: route)
        verdict = egress_routes.boundary_probe(None, _settings(stub))
        assert verdict.ok and words in verdict.caveat, (route, verdict)
        assert "the network policy, not the route table" in verdict.caveat


def test_a_canary_that_answers_fails_with_the_cni_action(stub, pod, network):
    network("connected")
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok
    assert "NetworkPolicy is not enforced for this pod" in verdict.evidence
    assert "the boundary is not in force" in verdict.evidence
    assert "enforces NetworkPolicy" in verdict.action and "CNI" in verdict.action


@pytest.mark.parametrize("outcome, why", [
    ("refused", "the canary refused the connection"),
    ("unreachable", "the canary could not be reached"),
])
def test_a_refused_canary_fails_as_cannot_tell(stub, pod, network, outcome, why):
    network(outcome)
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok
    assert "Cannot tell whether the network policy is enforced" in verdict.evidence
    assert why in verdict.evidence and "rejects instead of dropping" in verdict.evidence
    assert "NetworkPolicy is not enforced" not in verdict.evidence
    assert "egress canary" in verdict.action


def test_a_canary_that_does_not_resolve_is_cannot_tell(stub, pod, network, monkeypatch):
    network("timed_out")
    monkeypatch.setenv(CANARY_ENV, "egress-canary.noctornal.svc.cluster.local:9")

    real = socket.getaddrinfo

    def nothing(host, *a, **k):
        if host.startswith("egress-canary"):
            raise socket.gaierror("no such name")
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", nothing)
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok and "the canary's name did not resolve" in verdict.evidence


def test_a_canary_outside_the_declared_networks_is_never_dialled(stub, pod, network, monkeypatch):
    """The probe stays inside the cluster: an answer that is public, or in a network nobody declared, is
    refused before the first connect, and the sentence says so."""
    tried = network("timed_out")
    for canary in ("203.0.113.9:9", "172.31.243.9:9", "8.8.8.8:53"):
        monkeypatch.setenv(CANARY_ENV, canary)
        verdict = egress_routes.boundary_probe(None, _settings(stub))
        assert not verdict.ok, canary
        assert "outside the deployment's own networks" in verdict.evidence
        assert "so it was not dialled" in verdict.evidence
    assert tried == []


def test_every_answer_of_a_name_must_be_inside_before_any_is_dialled(pod, network, monkeypatch):
    tried = network("timed_out")

    def answers(*_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.96.0.50", 9)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 9))]

    monkeypatch.setattr(socket, "getaddrinfo", answers)
    nets = egress_policy.internal_networks({egress_policy.INTERNAL_CIDRS_ENV: CLUSTER_NETWORKS},
                                           production=True)
    assert pinned_http.canary_connect("canary.svc", 9, networks=nets) == "outside"
    assert tried == []


def test_the_canary_connect_says_what_a_network_does(monkeypatch):
    tried = []
    nets = egress_policy.internal_networks({egress_policy.INTERNAL_CIDRS_ENV: CLUSTER_NETWORKS},
                                           production=True)
    outcomes = {"timed_out": TimeoutError(), "refused": ConnectionRefusedError(),
                "reset": ConnectionResetError(), "unreachable": OSError(113, "no route")}
    for name, error in outcomes.items():
        def attempt(*_a, error=error):
            raise error

        monkeypatch.setattr(pinned_http, "_canary_attempt", attempt)
        expected = {"reset": "refused"}.get(name, name)
        assert pinned_http.canary_connect("10.99.0.9", 9, networks=nets) == expected, name
    monkeypatch.setattr(pinned_http, "_canary_attempt", lambda *a: tried.append(a))
    assert pinned_http.canary_connect("10.99.0.9", 9, networks=nets) == "connected"
    assert set(pinned_http.CANARY_OUTCOMES) >= {"connected", "timed_out", "refused", "unreachable",
                                                "unresolved", "outside"}


def test_a_name_with_two_addresses_passes_only_when_neither_answers(monkeypatch):
    nets = egress_policy.internal_networks({egress_policy.INTERNAL_CIDRS_ENV: CLUSTER_NETWORKS},
                                           production=True)
    both = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.96.0.50", 9)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.96.0.51", 9))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: both)

    def first_times_out_second_answers(_f, _k, _p, sockaddr, _t):
        if sockaddr[0] == "10.96.0.50":
            raise TimeoutError
    monkeypatch.setattr(pinned_http, "_canary_attempt", first_times_out_second_answers)
    assert pinned_http.canary_connect("canary.svc", 9, networks=nets) == "connected"

    def first_times_out_second_refuses(_f, _k, _p, sockaddr, _t):
        raise TimeoutError if sockaddr[0] == "10.96.0.50" else ConnectionRefusedError
    monkeypatch.setattr(pinned_http, "_canary_attempt", first_times_out_second_refuses)
    assert pinned_http.canary_connect("canary.svc", 9, networks=nets) == "refused"


def test_the_canary_connect_on_real_sockets_is_connected_or_refused_and_sends_nothing():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    try:
        assert pinned_http.canary_connect("127.0.0.1", port, networks=()) == "connected"
        listener.settimeout(2)
        conn, _ = listener.accept()
        conn.settimeout(2)
        assert conn.recv(16) == b""
        conn.close()
    finally:
        listener.close()
    # The port is shut now: a reset, which a plugin that rejects instead of dropping also sends.
    assert pinned_http.canary_connect("127.0.0.1", port, networks=(), timeout=3.0) in (
        "refused", "unreachable")


def test_the_mode_is_not_honoured_outside_a_pod_and_the_route_table_rule_still_holds(
        stub, pod, network, monkeypatch):
    """The setting alone proves nothing: without the kubelet's variable the probe judges the route table, so
    a compose container with a direct route out is still the bypass sentence."""
    network("timed_out")
    monkeypatch.delenv(POD_ENV)
    assert egress_routes.boundary_mode() is None
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok and "the proxy can be bypassed" in verdict.evidence
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: False)
    monkeypatch.setattr(egress_routes, "_uses_docker_dns", lambda: False)
    assert egress_routes.boundary_probe(None, _settings(stub)).ok


def test_the_route_table_rule_still_holds_when_the_mode_is_unset(stub, network, monkeypatch):
    """Nothing about compose changes unless the variable says so: no canary is dialled, and a default
    route is the bypass sentence."""
    tried = network("timed_out")
    monkeypatch.setenv(POD_ENV, "10.96.0.1")
    monkeypatch.setenv(CANARY_ENV, CANARY)
    assert egress_routes.boundary_mode() is None
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: True)
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok and "the proxy can be bypassed" in verdict.evidence
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: False)
    monkeypatch.setattr(egress_routes, "_uses_docker_dns", lambda: False)
    passed = egress_routes.boundary_probe(None, _settings(stub))
    assert passed.ok and "canary" not in passed.evidence and not passed.caveat
    assert tried == []


def test_a_blank_mode_is_the_route_table_rule(stub, monkeypatch):
    monkeypatch.setenv(POD_ENV, "10.96.0.1")
    monkeypatch.setenv(BOUNDARY_ENV, "   ")
    assert egress_routes.boundary_mode() is None


def test_the_proxy_half_still_comes_first(pod, network):
    """A key the proxy refuses fails the row whatever the canary says."""
    network("timed_out")
    with StubProxy(key=b"z" * 32) as other:
        verdict = egress_routes.boundary_probe(None, _settings(other))
    assert not verdict.ok and "NOCTORNAL_EGRESS_CLIENT_KEY differs" in verdict.evidence


def test_a_missing_canary_in_the_mode_fails_the_row_by_name(stub, pod, network, monkeypatch):
    tried = network("timed_out")
    monkeypatch.delenv(CANARY_ENV)
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok and CANARY_ENV in verdict.evidence and "cannot tell" in verdict.evidence
    assert tried == []


def test_a_service_name_is_a_proxy_host_the_client_can_dial(monkeypatch):
    """Compose writes the proxy's address as an IP literal; a cluster writes a Service name. Both parse, and
    the name is resolved ONCE by the one proxy client, which refuses only a metadata, link-local, multicast or
    unspecified answer."""
    url = "http://egress-proxy.noctornal.svc.cluster.local:3128"
    assert egress.proxy_problem({egress.PROXY_URL_ENV: url}) is None
    assert egress.proxy_settings({egress.PROXY_URL_ENV: url}) == ProxySettings(
        "egress-proxy.noctornal.svc.cluster.local", 3128)
    assert egress.proxy_problem({egress.PROXY_URL_ENV: "http://egress-proxy:3128"}) is None
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.96.14.2", 3128))])
    hop = pinned_http._proxy_hop("egress-proxy.noctornal.svc.cluster.local", 3128)
    assert [a[3][0] for a in hop.addresses] == ["10.96.14.2"]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 3128))])
    with pytest.raises(pinned_http.RouteUnavailable):
        pinned_http._proxy_hop("egress-proxy", 3128)


def test_the_probe_reaches_a_stub_proxy_by_name(stub, monkeypatch):
    """The whole probe, to a proxy named rather than written as an address."""
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: False)
    monkeypatch.setattr(egress_routes, "_uses_docker_dns", lambda: False)
    verdict = egress_routes.boundary_probe(None, ProxySettings("localhost", stub.port))
    assert verdict.ok, verdict


# ---------------------------------------------------------------------------
# What the caveat says about names
# ---------------------------------------------------------------------------

def test_the_dns_caveat_names_the_cluster_resolver(stub, pod, network):
    network("timed_out")
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert verdict.ok
    assert "the cluster's DNS and forwards names outside the cluster to its upstream" in verdict.caveat
    assert "Docker" not in verdict.caveat
    assert "10.96.0.10" not in verdict.caveat


def test_an_unreadable_resolver_file_is_a_caveat_in_the_mode(stub, pod, network, monkeypatch, tmp_path):
    network("timed_out")
    monkeypatch.setattr(egress_routes, "_RESOLV", str(tmp_path / "absent"))
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert verdict.ok and "resolver file could not be read" in verdict.caveat


def test_the_resolver_reader_lists_nameservers_and_docker_is_still_found(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("# generated\nnameserver 10.96.0.10\nnameserver fd00::a\nsearch x\n",
                      encoding="ascii")
    monkeypatch.setattr(egress_routes, "_RESOLV", str(resolv))
    assert egress_routes._nameservers() == ["10.96.0.10", "fd00::a"]
    assert egress_routes._uses_docker_dns() is False
    resolv.write_text("nameserver 127.0.0.11\n", encoding="ascii")
    assert egress_routes._uses_docker_dns() is True
    resolv.write_text("nameserver\n", encoding="ascii")
    assert egress_routes._nameservers() == []
    monkeypatch.setattr(egress_routes, "_RESOLV", str(tmp_path / "missing"))
    assert egress_routes._nameservers() is None and egress_routes._uses_docker_dns() is None


def test_the_compose_caveat_is_what_it_was_when_the_mode_is_unset(stub, monkeypatch, tmp_path):
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: False)
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.11\n", encoding="ascii")
    monkeypatch.setattr(egress_routes, "_RESOLV", str(resolv))
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert verdict.ok and "Docker's embedded resolver forwards them" in verdict.caveat
    resolv.write_text("nameserver 10.96.0.10\n", encoding="ascii")
    assert egress_routes.boundary_probe(None, _settings(stub)).caveat is None


def test_the_pod_variable_is_the_one_the_worker_reads():
    from noctornal_api import analysis_worker
    assert analysis_worker.POD_ENV == egress_policy.POD_ENV == "KUBERNETES_SERVICE_HOST"
