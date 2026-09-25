"""The egress readiness rows (S2, 2026-09-24).

egress_boundary is THE boundary row; its PROXY branch is the route
provider's boundary_probe, driven here against the contract cases' stub
proxy (which answers the probe route as docs/20 section 8.5 (2) says) and
against scripted answers. The two
new rows, egress_routes_cover_sources and egress_exits_open, are read over
the database. No probe sends a packet off this host, and none makes a DNS
query: a fixed lookup would be a beacon.
"""
from __future__ import annotations

import os
import socket
import sys

import pytest

import egress_support as es
from egress_contract_cases import StubProxy
from noctornal_api import config, egress, egress_routes, readiness
from noctornal_api.egress import ProxySettings

DATABASE_URL = os.environ.get("DATABASE_URL", "")
needs_db = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
PREFIX = "egr-"


@pytest.fixture(autouse=True)
def env(monkeypatch):
    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    egress._reset_route_provider()
    yield
    egress._reset_route_provider()


@pytest.fixture
def stub():
    with StubProxy(key=es.CLIENT_KEY) as proxy:
        yield proxy


@pytest.fixture
def no_default_route(monkeypatch):
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: False)
    monkeypatch.setattr(egress_routes, "_uses_docker_dns", lambda: False)


def _settings(stub):
    return ProxySettings("127.0.0.1", stub.port)


def test_the_probe_passes_only_on_403_blocked_address(stub, no_default_route, monkeypatch):
    asked = []
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **k: asked.append(host) or real(host, *a, **k))
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert verdict.ok, verdict
    assert "refused a private destination" in verdict.evidence
    # Nothing was looked up but the proxy's own literal address.
    assert set(asked) <= {"127.0.0.1"}


def test_a_default_route_is_the_bypass_sentence(stub, monkeypatch):
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: True)
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok and "the proxy can be bypassed" in verdict.evidence


def test_an_unreadable_route_table_and_docker_dns_are_caveats(stub, monkeypatch):
    monkeypatch.setattr(egress_routes, "_has_default_route", lambda: None)
    monkeypatch.setattr(egress_routes, "_uses_docker_dns", lambda: True)
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert verdict.ok
    assert "could not be read here" in verdict.caveat
    assert "leave the host as a lookup" in verdict.caveat


def test_a_different_client_key_is_the_key_sentence(no_default_route):
    with StubProxy(key=b"z" * 32) as other:
        verdict = egress_routes.boundary_probe(None, _settings(other))
    assert not verdict.ok
    assert "NOCTORNAL_EGRESS_CLIENT_KEY differs" in verdict.evidence


@pytest.mark.parametrize("answer, words", [
    (b"HTTP/1.1 403 probe_only\r\nContent-Length: 0\r\n\r\n",
     "did not refuse a loopback destination"),
    (b"HTTP/1.1 200 Connection established\r\n\r\n", "OPENED a tunnel"),
    (b"HTTP/1.1 502 connect_failed\r\nContent-Length: 0\r\n\r\n", "status 502"),
])
def test_any_other_answer_fails_naming_it(stub, no_default_route, answer, words):
    def reply(conn, _host, _port):
        conn.sendall(answer)
        conn.close()

    stub.handler = reply
    verdict = egress_routes.boundary_probe(None, _settings(stub))
    assert not verdict.ok and words in verdict.evidence


def test_no_proxy_listening_fails_with_an_action(no_default_route):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    verdict = egress_routes.boundary_probe(None, ProxySettings("127.0.0.1", port))
    assert not verdict.ok and verdict.action


def test_the_route_table_reader_finds_a_default_route(tmp_path, monkeypatch):
    table = tmp_path / "route"
    table.write_text("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                     "eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n", encoding="ascii")
    monkeypatch.setattr(egress_routes, "_ROUTES", (str(table),))
    assert egress_routes._has_default_route() is True
    table.write_text("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                     "eth0\t00F31FAC\t00000000\t0001\t0\t0\t0\t00FFFFFF\n", encoding="ascii")
    assert egress_routes._has_default_route() is False
    monkeypatch.setattr(egress_routes, "_ROUTES", (str(tmp_path / "missing"),))
    assert egress_routes._has_default_route() is None


def test_the_resolver_file_is_read_and_nothing_is_asked(tmp_path, monkeypatch):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.11\noptions ndots:0\n", encoding="ascii")
    monkeypatch.setattr(egress_routes, "_RESOLV", str(resolv))
    assert egress_routes._uses_docker_dns() is True
    resolv.write_text("nameserver 10.0.0.2\n", encoding="ascii")
    assert egress_routes._uses_docker_dns() is False


def test_the_register_has_one_boundary_row_and_two_new_rows_none_blocking():
    assert readiness.CHECK_NAMES.count("egress_boundary") == 1
    for name in ("egress_routes_cover_sources", "egress_exits_open"):
        assert name in readiness.CHECK_NAMES and name not in readiness.BLOCKING_CHECKS
        assert name not in readiness.CONSEQUENCES
        assert readiness.UI_TARGETS[name] == "admin/egress"
    assert readiness.UI_TARGETS["egress_boundary"] == "admin/egress"


@needs_db
def test_the_boundary_row_calls_this_provider_through_a_proxy(stub, no_default_route,
                                                             monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{stub.port}")
    with connect() as conn:
        check = readiness._egress_boundary(conn)
    assert check.ok and "refused a private destination" in check.evidence


@needs_db
def test_the_boundary_row_fails_for_a_stray_proxy_variable_without_a_provider(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, None)
    egress._reset_route_provider()
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://127.0.0.1:3128")
    with connect() as conn:
        check = readiness._egress_boundary(conn)
    assert not check.ok and "no egress route provider" in check.evidence


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c), es.collection_standin(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


@needs_db
def test_coverage_states_presence_and_never_names_a_source(conn, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, "production")
    conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                 "WHERE is_passive_default")
    sid = es.source(conn, PREFIX, base_url="https://secret-feed.example/rss")
    name = conn.execute("SELECT name FROM collect.source WHERE id = %s", (sid,)).fetchone()[0]
    ok, evidence, action, _caveat = egress_routes.cover_sources(conn)
    assert not ok and "no passive default" in evidence and action
    assert name not in evidence and "secret-feed" not in evidence
    assert not any(ch.isdigit() for ch in evidence)


@needs_db
def test_coverage_in_development_is_a_caveat_not_a_failure(conn):
    conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                 "WHERE is_passive_default")
    es.source(conn, PREFIX)
    ok, _evidence, _action, caveat = egress_routes.cover_sources(conn)
    assert ok and "built-in direct passive policy" in caveat


@needs_db
def test_a_feed_above_the_passive_ceiling_and_a_persona_on_no_exit_are_gaps(conn, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, "production")
    es.profile(conn, PREFIX, ceiling="GREEN", passive=True)
    es.source(conn, PREFIX, classification="RED")
    persona = es.persona(conn, PREFIX, profile=es.profile(conn, PREFIX, kind="VPN",
                                                          exit_kind=None))
    es.source(conn, PREFIX, kind="XENFORO", parser="xenforo", persona=persona)
    ok, evidence, _a, _c = egress_routes.cover_sources(conn)
    assert not ok
    assert "above the passive default's ceiling" in evidence
    assert "cannot carry it" in evidence


@needs_db
def test_exits_open_reads_the_probe_headers(conn, monkeypatch, no_default_route):
    conn.execute("UPDATE collect.egress_profile SET retired_at = now(), is_active = false, "
                 "is_passive_default = false, retired_by = (SELECT id FROM iam.app_user "
                 "LIMIT 1), retire_reason = 'readiness suite' WHERE exit_sealed IS NOT NULL "
                 "AND retired_at IS NULL")
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    blob, kid, fp = es.seal_for(pid, "SOCKS5", "gw.example", 1080)
    conn.execute("""UPDATE collect.egress_profile SET exit_kind = 'SOCKS5', exit_sealed = %s,
                      exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                 (blob, kid, fp, pid))
    ok, evidence, _a, _c = egress_routes.exits_open(conn)
    assert ok and "Development connects directly" in _c
    with es.ProxyRunner() as runner:
        monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{runner.port}")
        ok, evidence, _a, caveat = egress_routes.exits_open(conn)
        assert ok and "opens every one" in evidence, evidence
        conn.execute("UPDATE collect.egress_profile SET exit_fingerprint = '\\x00' "
                     "WHERE id = %s", (pid,))
        ok, evidence, _a, _c = egress_routes.exits_open(conn)
        assert not ok and "cannot open 1 of them" in evidence
    conn.execute("UPDATE collect.egress_profile SET exit_seal_key_id = 'egress:0000000000000000' "
                 "WHERE id = %s", (pid,))
    runner = es.ProxyRunner()
    try:
        monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{runner.port}")
        ok, evidence, _a, _c = egress_routes.exits_open(conn)
        assert not ok and "does not hold the key" in evidence
    finally:
        runner.stop()
