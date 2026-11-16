"""A pod must declare the cluster's own networks (decision 239).

`NOCTORNAL_EGRESS_INTERNAL_CIDRS` is the list of the deployment's own networks: no route may overlap it and no
answer inside it is admitted. In production it defaults to the compose stack's four subnets, which in a cluster
are no network at all, so a pod that left it blank would silently guard nothing: a hostile forum name that
resolved into the service network would pass the internal-address check. In a pod (the kubelet's
KUBERNETES_SERVICE_HOST is set) a blank list is therefore refused at start, and so is a list that does not hold
the cluster's service address. Outside a pod nothing changes.

Pure: no database. Every environment is a dictionary.
"""
from __future__ import annotations

import ipaddress
import os

from test_config_boot import _production
from test_egress_refusals import _proxy_env

from noctornal_api import config, egress_policy, egress_proxy

POD = egress_policy.POD_ENV
CIDRS = egress_policy.INTERNAL_CIDRS_ENV
SERVICE = "10.96.0.1"
CLUSTER = "10.244.0.0/16,10.96.0.0/12,192.168.0.0/16"
COMPOSE = ",".join(egress_policy.DEFAULT_INTERNAL_NETWORKS)


def _named(problems):
    return [p for p in problems if CIDRS in p or POD in p]


def test_in_a_pod_a_blank_internal_cidr_list_is_refused_not_defaulted_to_the_compose_subnets():
    for blank in (None, "", "   ", "\t"):
        env = {POD: SERVICE} if blank is None else {POD: SERVICE, CIDRS: blank}
        problem = egress_policy.cluster_problem(env)
        assert problem is not None, blank
        assert CIDRS in problem and "the compose subnets" in problem
        assert "pod, service and node networks" in problem
        # The default is what `internal_networks` would have used, which is the very thing refused.
        assert egress_policy.internal_networks(env, production=True) == tuple(
            ipaddress.ip_network(n) for n in egress_policy.DEFAULT_INTERNAL_NETWORKS)
    problems = config.verify_environment({**_production(), POD: SERVICE})
    assert len(_named(problems)) == 1 and "pod, service and node networks" in _named(problems)[0]
    assert egress_policy.cluster_problem({POD: SERVICE, CIDRS: CLUSTER}) is None
    assert _named(config.verify_environment({**_production(), POD: SERVICE, CIDRS: CLUSTER})) == []


def test_a_list_that_misses_the_clusters_service_address_is_refused():
    for listed in ("10.244.0.0/16", COMPOSE, "10.96.0.2/32", "10.97.0.0/16,10.244.0.0/16"):
        problem = egress_policy.cluster_problem({POD: SERVICE, CIDRS: listed})
        assert problem is not None, listed
        assert "service network" in problem and POD in problem and CIDRS in problem
    for listed in (CLUSTER, "10.96.0.0/12", "10.96.0.1/32", "0.0.0.0/0"):
        assert egress_policy.cluster_problem({POD: SERVICE, CIDRS: listed}) is None, listed
    # A list that holds the service network and not the pod network is the operator's to complete: the one
    # address every pod is told is what can be checked.
    assert egress_policy.cluster_problem({POD: SERVICE, CIDRS: "10.96.0.0/12"}) is None


def test_an_ipv6_cluster_is_checked_the_same_way():
    host = "fd00:10:96::1"
    assert egress_policy.cluster_problem({POD: host, CIDRS: "fd00:10:96::/112"}) is None
    assert egress_policy.cluster_problem({POD: host, CIDRS: "10.96.0.0/12"}) is not None
    assert egress_policy.cluster_problem({POD: "::ffff:10.96.0.1", CIDRS: "10.96.0.0/12"}) is None


def test_a_service_address_that_is_not_an_address_cannot_be_checked_and_is_refused():
    problem = egress_policy.cluster_problem({POD: "kubernetes.default", CIDRS: CLUSTER})
    assert problem is not None and "not an IP address" in problem and "kubernetes.default" not in problem


def test_a_malformed_list_is_the_other_sentence_and_not_repeated_here():
    env = {POD: SERVICE, CIDRS: "10.96.0.0/12,not-a-network"}
    assert egress_policy.cluster_problem(env) is None
    problems = config.verify_environment({**_production(), **env})
    assert [p for p in problems if CIDRS in p] == [
        f"{CIDRS} is not a comma list of networks, so the deployment's own networks cannot be kept "
        f"out of every route."]


def test_outside_a_pod_nothing_changes():
    for env in ({}, {CIDRS: ""}, {CIDRS: COMPOSE}, {CIDRS: "10.1.0.0/16"}, {POD: ""}, {POD: "  "}):
        assert egress_policy.cluster_problem(env) is None, env
    # The compose default is what it was, and a production boot that is not in a pod has nothing to say.
    assert egress_policy.internal_networks({}, production=True) == tuple(
        ipaddress.ip_network(n) for n in egress_policy.DEFAULT_INTERNAL_NETWORKS)
    assert egress_policy.internal_networks({}, production=False) == ()
    assert _named(config.verify_environment(_production())) == []
    assert _named(config.verify_environment({**_production(), CIDRS: COMPOSE})) == []


def test_development_is_never_refused_for_it():
    assert config.verify_environment({POD: SERVICE}) == []
    assert config.refuse_unsafe_job_environment("collection_poll", {POD: SERVICE}) == []
    assert egress_proxy.verify_proxy_environment(
        {k: v for k, v in _proxy_env().items() if k != "NOCTORNAL_ENV"} | {POD: SERVICE}) == []


def test_the_proxy_and_the_jobs_make_the_same_refusal():
    api = _named(config.verify_environment({**_production(), POD: SERVICE}))
    assert len(api) == 1
    sentence = api[0].rstrip(".")
    proxy = _named(egress_proxy.verify_proxy_environment(_proxy_env(**{POD: SERVICE})))
    assert [p.rstrip(".") for p in proxy] == [sentence]
    for job in ("notify_drain", "collection_poll", "lookup_drain", "embed_pass", "collector"):
        lines = _named(config.refuse_unsafe_job_environment(job, {**_production(), POD: SERVICE},
                                                            holds_persona_key=job in (
                                                                "collector", "collection_poll")))
        assert len(lines) == 1, job
        assert lines[0].startswith(f"{job}: refusing to run: ") and sentence in lines[0]
    # With the networks declared, none of the three says anything.
    declared = {POD: SERVICE, CIDRS: CLUSTER}
    assert _named(config.verify_environment({**_production(), **declared})) == []
    assert _named(egress_proxy.verify_proxy_environment(_proxy_env(**declared))) == []
    assert _named(config.refuse_unsafe_job_environment(
        "notify_drain", {**_production(), **declared})) == []


def test_a_job_that_sends_nothing_out_is_not_asked_for_the_networks():
    """The migration job holds the owner's DSN and routes no connection; a Lab worker told it sends nothing
    out is not asked either. Neither is held to a list it would never read."""
    env = {**_production(), POD: SERVICE}
    assert _named(config.refuse_unsafe_job_environment("migrate", env, holds_owner_credential=True)) == []
    assert _named(config.refuse_unsafe_job_environment("lab_triage", env, whole_environment=True,
                                                       outbound=False)) == []
    assert _named(config.refuse_unsafe_job_environment("sample_screen", env,
                                                       whole_environment=True)) != []


def test_the_init_container_that_waits_for_the_schema_is_not_asked_for_the_networks(monkeypatch, capsys):
    """scripts/wait_for_schema.py routes no connection, so a pod that holds it back until the migration
    Job has run is not refused for a list it would never read."""
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "u17_wait_for_schema", Path(__file__).resolve().parents[3] / "scripts" / "wait_for_schema.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The process's own environment is replaced whole, so nothing the suite sets (the inline collector, a
    # persona key) is what is refused here.
    monkeypatch.setattr(os, "environ", {**_production(), POD: SERVICE})
    monkeypatch.setattr(module.readyz, "schema_problem", lambda: None)
    assert module.main([]) == 0
    assert capsys.readouterr().err == ""
    # The same pod, asked as a job that routes a connection would be, is refused for the missing list.
    assert _named(config.refuse_unsafe_job_environment("wait_for_schema"))


def test_the_sample_origin_is_not_asked_for_the_networks():
    env = {**_production(), POD: SERVICE, "NOCTORNAL_SAMPLE_ORIGIN": "https://samples.unit.example",
           "NOCTORNAL_BASE_URL": "https://console.unit.example",
           "NOCTORNAL_PUBLIC_ORIGIN": "https://samples.unit.example"}
    assert _named(config.verify_environment(env)) == []


def test_no_refusal_quotes_a_value():
    env = {**_production(), POD: "10.96.77.31", CIDRS: "10.244.0.0/16"}
    for problem in _named(config.verify_environment(env)):
        assert "10.96.77.31" not in problem and "10.244.0.0/16" not in problem
    assert "10.96.77.31" not in egress_policy.cluster_problem(
        {POD: "10.96.77.31", CIDRS: "10.244.0.0/16"})
    assert "kubernetes.default" not in egress_policy.cluster_problem(
        {POD: "kubernetes.default", CIDRS: "10.244.0.0/16"})
