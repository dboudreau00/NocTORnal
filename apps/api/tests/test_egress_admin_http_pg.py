"""Administration, Egress over HTTP (S2, 2026-09-24).

Who each route lets in, the audit row each write leaves, that an exit's
endpoint appears nowhere once sealed, what a widening reports, and the
labels on profiles. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import logging
import os
import socket

import pytest

import egress_support as es

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "ega-"
API = "/api/v1/admin/egress"
SECRET_HOST = "gw.provider-secret.example"
SECRET_USER = "user-zone-gb-secret"
SECRET_PASS = "pass-never-shown-9f2"


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c), es.collection_standin(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


@pytest.fixture
def env(monkeypatch):
    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def client(env):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


@pytest.fixture(scope="module")
def people(conn):
    admin = es.user(conn, "SYS_ADMIN", prefix=PREFIX, clearance="RED")
    officer = es.user(conn, "SECURITY_OFFICER", prefix=PREFIX, clearance="GREEN")
    analyst = es.user(conn, "ANALYST", prefix=PREFIX, clearance="RED")
    return {"admin": admin, "officer": officer, "analyst": analyst}


def _audit(conn, action, object_id=None):
    sql = "SELECT detail FROM audit.event WHERE action = %s"
    params = [action]
    if object_id is not None:
        sql += " AND object_id = %s"
        params.append(object_id)
    return [r[0] for r in conn.execute(sql + " ORDER BY seq", params).fetchall()]


def _create(client, who, **over):
    body = {"name": f"{PREFIX}{os.urandom(3).hex()}", "kind": "RESIDENTIAL",
            "ceiling": "AMBER", "policy": {"allowed_ports": [443],
                                           "allowed_host_suffixes": ["forum.example"]}}
    body.update(over)
    r = client.post(f"{API}/profiles", headers=who, json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


WRITES = [
    ("post", "/profiles", {"name": "egx", "kind": "VPN", "ceiling": "AMBER"}),
    ("patch", "/profiles/00000000-0000-4000-8000-000000000000/policy", {"max_concurrent": 2}),
    ("put", "/profiles/00000000-0000-4000-8000-000000000000/exit", {"exit_kind": "DIRECT"}),
    ("post", "/profiles/00000000-0000-4000-8000-000000000000/passive-default", None),
    ("post", "/profiles/00000000-0000-4000-8000-000000000000/retire", {"reason": "done now"}),
    ("post", "/routes", {"name": "smtp", "description": "the relay route"}),
    ("post", "/routes/00000000-0000-4000-8000-000000000000/destinations",
     {"entry": "relay.example:587", "note": "the relay"}),
]


@pytest.mark.parametrize("method, path, body", WRITES)
def test_every_write_needs_egress_manage_and_a_fresh_sign_in(conn, client, people,
                                                             method, path, body):
    for who, want in ((people["officer"], "missing global permission egress.manage"),
                      (people["analyst"], "missing global permission egress.manage")):
        r = getattr(client, method)(f"{API}{path}", headers=es.session(conn, who),
                                    **({"json": body} if body else {}))
        assert r.status_code == 403 and want in r.json()["detail"], r.text
    stale = es.session(conn, people["admin"], fresh=False)
    r = getattr(client, method)(f"{API}{path}", headers=stale,
                                **({"json": body} if body else {}))
    assert r.status_code == 403 and r.json()["detail"] == "re-authentication required"


def test_the_officer_reads_the_overview_and_the_log_and_an_analyst_does_not(
        conn, client, people):
    officer = es.session(conn, people["officer"])
    assert client.get(API, headers=officer).status_code == 200
    assert client.get(f"{API}/connections", headers=officer).status_code == 200
    assert client.get(f"{API}/connections/verify", headers=officer).json()[
        "first_break_seq"] is None
    analyst = es.session(conn, people["analyst"])
    assert client.get(API, headers=analyst).status_code == 403
    assert client.get(f"{API}/connections", headers=analyst).status_code == 403


def test_a_naive_since_is_refused_in_utc_words(conn, client, people):
    r = client.get(f"{API}/connections?since=2026-09-24T10:00:00",
                   headers=es.session(conn, people["officer"]))
    assert r.status_code == 422 and "Times are UTC" in r.json()["detail"]


def test_each_write_leaves_one_audit_row(conn, client, people):
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin)
    assert len(_audit(conn, "EGRESS_PROFILE_CREATED", pid)) == 1
    r = client.patch(f"{API}/profiles/{pid}/policy", headers=admin,
                     json={"max_concurrent": 2})
    assert r.status_code == 200 and r.json()["widened"] is False
    details = _audit(conn, "EGRESS_PROFILE_POLICY_CHANGED", pid)
    assert len(details) == 1 and details[0]["before"]["max_concurrent"] == 4
    assert details[0]["after"]["max_concurrent"] == 2
    r = client.post(f"{API}/profiles/{pid}/retire", headers=admin,
                    json={"reason": "not needed now"})
    assert r.status_code == 200
    assert len(_audit(conn, "EGRESS_PROFILE_RETIRED", pid)) == 1


def test_an_exit_is_sealed_and_appears_in_no_answer_no_audit_row_and_no_log(
        conn, client, people, caplog):
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin)
    caplog.set_level(logging.DEBUG)
    r = client.put(f"{API}/profiles/{pid}/exit", headers=admin,
                   json={"exit_kind": "HTTPS", "host": SECRET_HOST, "port": 48213,
                         "username": SECRET_USER, "password": SECRET_PASS})
    assert r.status_code == 200, r.text
    answer = r.text + client.get(API, headers=admin).text
    audit_text = json.dumps(_audit(conn, "EGRESS_EXIT_SEALED", pid))
    for secret in (SECRET_HOST, SECRET_USER, SECRET_PASS, "48213"):
        assert secret not in answer and secret not in audit_text
        assert secret not in caplog.text
    body = r.json()
    assert body["key_id"].startswith("egress:") and body["widened"] is True
    assert "cannot be shown again" in body["notice"]


def test_a_cleartext_exit_to_a_public_provider_needs_the_acknowledgement(
        conn, client, people):
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin)
    exit_body = {"exit_kind": "SOCKS5", "host": "gw.residential.example", "port": 1080,
                 "username": "u", "password": "p"}
    r = client.put(f"{API}/profiles/{pid}/exit", headers=admin, json=exit_body)
    assert r.status_code == 409 and "in clear" in r.json()["detail"]
    r = client.put(f"{API}/profiles/{pid}/exit", headers=admin,
                   json=dict(exit_body, cleartext_ack=True))
    assert r.status_code == 200 and r.json()["cleartext_acknowledged"] is True
    assert _audit(conn, "EGRESS_EXIT_SEALED", pid)[-1]["cleartext_acknowledged"] is True


def test_a_widening_reports_the_authorities_it_costs(conn, client, people):
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin)
    persona = es.persona(conn, PREFIX, profile=pid)
    sid = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url="http://forum.example/", persona=persona)
    es.authority(conn, recorder=people["admin"], confirmer=people["officer"],
                 persona=persona, sources=(sid,), classification="AMBER")
    r = client.patch(f"{API}/profiles/{pid}/policy", headers=admin,
                     json={"allowed_ports": [443, 8443]})
    body = r.json()
    assert body["widened"] is True and body["authorities_affected"] == 1
    assert body["personas_affected"] == 1


def test_the_passive_default_moves_in_one_transaction_and_retiring_it_says_so(
        conn, client, people):
    admin = es.session(conn, people["admin"])
    first = _create(client, admin, kind="DATACENTRE",
                    policy={"allowed_ports": [80, 443], "any_public_host": True})
    second = _create(client, admin, kind="DATACENTRE",
                     policy={"allowed_ports": [80, 443], "any_public_host": True})
    assert client.post(f"{API}/profiles/{first}/passive-default",
                       headers=admin).status_code == 200
    r = client.post(f"{API}/profiles/{second}/passive-default", headers=admin)
    assert r.status_code == 200 and r.json()["previous_id"] == first
    count = conn.execute("SELECT count(*) FROM collect.egress_profile "
                         "WHERE is_passive_default").fetchone()[0]
    assert count == 1
    r = client.post(f"{API}/profiles/{second}/retire", headers=admin,
                    json={"reason": "replaced by another"})
    assert r.json()["passive_default_cleared"] is True
    assert "passive default" in r.json()["notice"]


@pytest.mark.parametrize("entry, words", [
    ("*:443", "a destination rule is"),
    (".corp.example:443", "takes no suffix rule"),
    ("postgres:5432", "own services"),
    ("10.0.0.0/8:443", "at most an IPv4 /16"),
    ("jira.corp@172.31.243.0/24:443", "own networks"),
])
def test_an_integration_entry_is_one_exact_egress_policy_rule(conn, client, people,
                                                              monkeypatch, entry, words):
    monkeypatch.setenv("NOCTORNAL_EGRESS_INTERNAL_CIDRS", "172.31.243.0/24,172.31.244.0/24")
    admin = es.session(conn, people["admin"])
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = %s, retire_reason = 'admin suite'
                    WHERE name = 'smtp' AND retired_at IS NULL""", (people["admin"],))
    r = client.post(f"{API}/routes", headers=admin,
                    json={"name": "smtp", "description": f"{PREFIX}relay route"})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    r = client.post(f"{API}/routes/{rid}/destinations", headers=admin,
                    json={"entry": entry, "note": "an attempt"})
    assert r.status_code == 409 and words in r.json()["detail"], r.text
    ok = client.post(f"{API}/routes/{rid}/destinations", headers=admin,
                     json={"entry": "relay.corp.example@10.20.0.0/24:587",
                           "note": "the relay"})
    assert ok.status_code == 201 and ok.json()["entry"] == "relay.corp.example@10.20.0.0/24:587"
    client.post(f"{API}/routes/{rid}/retire", headers=admin, json={"reason": "suite done"})


def test_a_route_name_must_be_a_registered_integration(conn, client, people):
    r = client.post(f"{API}/routes", headers=es.session(conn, people["admin"]),
                    json={"name": "anything", "description": f"{PREFIX}not a route"})
    assert r.status_code == 409 and "registered integration" in r.json()["detail"]


def test_a_green_officer_sees_a_red_profile_as_its_name_and_state_only(
        conn, client, people, monkeypatch):
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin, ceiling="RED")
    body = client.get(API, headers=es.session(conn, people["officer"])).json()
    row = next(p for p in body["profiles"] if p["id"] == pid)
    assert row["withheld"] is True and "policy" not in row
    assert body["withheld"] >= 1
    calls = []
    real = socket.getaddrinfo

    def counting(host, *args, **kwargs):
        calls.append(host)
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", counting)
    r = client.post(f"{API}/check", headers=es.session(conn, people["officer"]),
                    json={"route_kind": "persona", "route_id": pid,
                          "host": "forum.example", "port": 443})
    assert r.status_code == 404
    r = client.post(f"{API}/check", headers=admin,
                    json={"route_kind": "persona", "route_id": pid,
                          "host": "www.forum.example", "port": 443})
    assert r.json()["allowed"] is True
    r = client.post(f"{API}/check", headers=admin,
                    json={"route_kind": "persona", "route_id": pid,
                          "host": "elsewhere.example", "port": 443})
    assert r.json() == {"allowed": False, "reason": "destination_not_allowed",
                        "sentence": "no destination rule of this route names the destination",
                        "entry": None}
    assert not any("example" in str(host) for host in calls), calls


def test_a_profile_is_labelled_by_the_sources_bound_to_it(conn, client, people):
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin, ceiling="GREEN")
    persona = es.persona(conn, PREFIX, profile=pid)
    es.source(conn, PREFIX, kind="XENFORO", parser="xenforo", classification="RED",
              base_url="http://forum.example/", persona=persona)
    body = client.get(API, headers=es.session(conn, people["officer"])).json()
    assert next(p for p in body["profiles"] if p["id"] == pid)["withheld"] is True


def test_admin_access_returns_the_two_egress_booleans(conn, client, people):
    body = client.get("/api/v1/admin/access",
                      headers=es.session(conn, people["admin"])).json()
    assert body["egress_manage"] is True and body["egress_log_read"] is True
    body = client.get("/api/v1/admin/access",
                      headers=es.session(conn, people["officer"])).json()
    assert body["egress_manage"] is False and body["egress_log_read"] is True


def test_the_admin_egress_limit_meters_the_writes(conn, env, people):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, Limit, RateLimiter
    app = create_app()
    limits = dict(LIMITS)
    base = LIMITS["admin.egress"]
    limits["admin.egress"] = Limit("admin.egress", quota=2, per_seconds=3600,
                                   scope=base.scope, burst=2,
                                   on_backend_failure=base.on_backend_failure)
    app.state.limiter = RateLimiter(InProcessBackend(), limits=limits)
    client = TestClient(app)
    admin = es.session(conn, people["admin"])
    codes = [client.post(f"{API}/routes", headers=admin,
                         json={"name": "nope", "description": f"{PREFIX}metered"}).status_code
             for _ in range(3)]
    assert codes[-1] == 429


def test_the_persona_listing_facts_carry_no_exit_field(conn, client, people):
    from noctornal_api.egress_admin import EgressAdminService
    admin = es.session(conn, people["admin"])
    pid = _create(client, admin)
    client.put(f"{API}/profiles/{pid}/exit", headers=admin,
               json={"exit_kind": "HTTPS", "host": SECRET_HOST, "port": 443,
                     "username": SECRET_USER, "password": SECRET_PASS})
    rows = EgressAdminService(conn).listing_facts([{"id": pid, "name": "x"}])
    assert rows[0]["persona_capable"] is True and rows[0]["exit_kind"] == "HTTPS"
    listed = EgressAdminService(conn).listing_for_personas()
    text = json.dumps(listed)
    assert SECRET_HOST not in text and "exit_sealed" not in text
    assert EgressAdminService(conn).check_persona_binding(pid) is None
