"""The Jira client (F7, 2026-09-24): every call goes
through the pinned client on the route "jira" with no redirect followed,
Jira's answers are classified, error text never reaches a stored detail,
values from Jira are shape-checked before any use, and one test speaks to a
loopback stub through the REAL pinned_http.fetch_response.

Pure apart from that one loopback stub, which this file starts itself.
Nothing reaches Atlassian.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from uuid import uuid4

import pytest

from noctornal_api import jira, pinned_http
from outbound_support import FakeRoute, fetched


def _dest(**kw):
    now = datetime.now(timezone.utc)
    values = dict(
        id=uuid4(), label="Jira", base_url="https://jira.example.org", host="jira.example.org",
        port=443, flavour="DATA_CENTER", auth_kind="DC_PAT", auth_user=None,
        credential_ciphertext=b"x", credential_key_id="env:v1", credential_set_at=now,
        credential_set_by=uuid4(), project_key="SOC", issue_type="Task",
        issue_type_id="10001", ceiling="GREEN", field_exposure="SUBJECT",
        kinds=("APPROVAL_REQUESTED",), state="ACTIVE", health="OK", health_detail=None,
        health_changed_at=None, tested_at=now, server_version="9.12.0",
        deployment_type="DataCenter", edit_caveat=None, created_at=now, created_by=uuid4(),
        updated_at=now, updated_by=uuid4(), activated_at=now, retired_at=None)
    values.update(kw)
    return jira.Dest(**values)


class Recorder:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


TOKEN = "pat-SECRET-token-0123456789"


def _client(answers, **kw):
    rec = Recorder(answers)
    route = FakeRoute("jira", frozenset({("jira.example.org", 443)}))
    return jira.JiraClient(_dest(**kw), TOKEN, route=route, fetch=rec), rec


def test_every_call_goes_through_the_jira_route_with_no_redirects():
    client, rec = _client([fetched(200, b'{"displayName": "svc"}')])
    assert client.myself() == "svc"
    url, kw = rec.calls[0]
    assert url == "https://jira.example.org/rest/api/2/myself"
    assert kw["route"].name == "jira" and kw["max_redirects"] == 0
    assert kw["user_agent"] == "NocTORnal-jira/1"
    assert 0 < kw["deadline"] <= jira.REQUEST_SECONDS
    assert kw["headers"]["Authorization"] == "Bearer " + TOKEN
    assert TOKEN in kw["secrets"]


def test_a_redirect_is_reported_with_its_host_and_never_followed():
    client, rec = _client([fetched(302, b"", location="https://login.example.net/sso?x=1")])
    with pytest.raises(jira.JiraHttpError) as info:
        client.project("SOC")
    assert info.value.kind == "REDIRECT"
    assert "login.example.net" in info.value.detail and "sso" not in info.value.detail
    assert len(rec.calls) == 1


def test_a_429_carries_retry_after_in_seconds_and_http_date():
    client, _ = _client([fetched(429, b"", headers={"Retry-After": "120"})])
    with pytest.raises(jira.JiraHttpError) as info:
        client.myself()
    assert info.value.kind == "RATE_LIMITED" and info.value.retry_after == 120.0
    later = "Wed, 21 Oct 2099 07:28:00 GMT"
    client, _ = _client([fetched(429, b"", headers={"Retry-After": later})])
    with pytest.raises(jira.JiraHttpError) as info:
        client.myself()
    assert info.value.retry_after == 86400.0


def test_a_400_stores_error_key_names_and_never_error_text():
    body = json.dumps({"errorMessages": ["OP-KESTREL-26 summary rejected"],
                       "errors": {"summary": "OP-KESTREL-26 is too long",
                                  "labels": "bad"}}).encode()
    client, _ = _client([fetched(400, body)])
    with pytest.raises(jira.JiraHttpError) as info:
        client.create_issue({"summary": "OP-KESTREL-26"})
    detail = info.value.detail
    assert info.value.kind == "INVALID"
    assert "labels" in detail and "summary" in detail
    assert "OP-KESTREL" not in detail and "too long" not in detail


def test_values_from_jira_are_validated_before_use():
    client, _ = _client([fetched(201, b'{"id": "1", "key": "../myself"}')])
    with pytest.raises(jira.JiraHttpError) as info:
        client.create_issue({})
    assert info.value.kind == "INVALID"
    client, _ = _client([fetched(201, b'{"id": "1?x=1", "key": "SOC-1"}')])
    with pytest.raises(jira.JiraHttpError):
        client.create_issue({})
    client, _ = _client([fetched(200, json.dumps(
        {"fields": {"status": {"statusCategory": {"key": "weird"}}}}).encode())])
    with pytest.raises(jira.JiraHttpError):
        client.issue_status("SOC-1")


def test_a_credential_echoed_in_an_error_is_redacted():
    boom = pinned_http.Unreachable("unreachable: proxy said Bearer " + TOKEN)
    client, _ = _client([boom])
    with pytest.raises(jira.JiraHttpError) as info:
        client.myself()
    assert info.value.kind == "UNREACHABLE" and TOKEN not in info.value.detail


def test_search_uses_search_jql_on_cloud_and_search_on_data_center():
    client, rec = _client([fetched(200, b'{"issues": [{"id": "10", "key": "SOC-7"}]}')],
                          flavour="CLOUD", auth_kind="CLOUD_API_TOKEN", auth_user="a@b.c")
    assert client.search_ref("SOC", "abcdefghijklmnop") == ("10", "SOC-7")
    assert rec.calls[0][0].endswith("/rest/api/3/search/jql")
    client, rec = _client([fetched(200, b'{"issues": []}')])
    assert client.search_ref("SOC", "abcdefghijklmnop") is None
    assert rec.calls[0][0].endswith("/rest/api/2/search")
    sent = json.loads(rec.calls[0][1]["body"])
    assert sent["jql"] == 'project = "SOC" AND labels = "noctornal-ref-abcdefghijklmnop"'


def test_the_labels_field_check_reads_fields_on_cloud_and_values_on_dc():
    client, _ = _client([fetched(200, b'{"fields": [{"fieldId": "labels"}]}')],
                        flavour="CLOUD", auth_kind="CLOUD_API_TOKEN", auth_user="a@b.c")
    assert "labels" in client.issue_type_fields("SOC", "10001")
    client, _ = _client([fetched(200, b'{"values": [{"fieldId": "summary"}]}')])
    assert client.issue_type_fields("SOC", "10001") == {"summary"}


# --- the loopback: the real pinned client ---------------------------------------------

class _Stub(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def _answer(self):
        _Stub.seen.append((self.command, self.path, dict(self.headers)))
        if self.path.startswith("/rest/api/2/serverInfo"):
            body = {"deploymentType": "DataCenter", "version": "9.12.0"}
        elif self.path.startswith("/rest/api/2/myself"):
            body = {"displayName": "NocTORnal service"}
        else:
            body = {}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _answer
    do_POST = _answer


def test_the_client_speaks_to_a_loopback_jira_through_fetch_response(monkeypatch):
    from noctornal_api.egress_policy import EgressRoute, RoutePolicy, Rule

    server = HTTPServer(("127.0.0.1", 0), _Stub)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        route = EgressRoute.direct(
            "integration", "jira",
            RoutePolicy("integration", (Rule.for_url(base),), any_public=False,
                        allow_loopback=True))
        client = jira.JiraClient(_dest(base_url=base, host="127.0.0.1", port=port), TOKEN,
                                 route=route)
        assert client.server_info() == ("DataCenter", "9.12.0")
        assert client.myself() == "NocTORnal service"
        method, path, headers = _Stub.seen[-1]
        assert headers.get("Authorization") == "Bearer " + TOKEN
        assert headers.get("User-Agent") == "NocTORnal-jira/1"
    finally:
        server.shutdown()


@pytest.mark.parametrize("address", ["169.254.169.254", "100.100.100.200", "192.0.0.192"])
def test_a_metadata_address_is_refused_even_when_the_route_names_it(address):
    """The metadata set is refused in every mode, even inside a rule's
    network (docs/20 section 2.2), so this is a live check, not a
    skip."""
    from noctornal_api.egress_policy import EgressRoute, RoutePolicy, Rule

    base = f"https://{address}"
    try:
        rule = Rule.for_url(base)
    except Exception:  # noqa: BLE001 - refused as a rule is refused too
        return
    route = EgressRoute.direct("integration", "jira",
                               RoutePolicy("integration", (rule,), any_public=False))
    client = jira.JiraClient(_dest(base_url=base, host=address), TOKEN, route=route)
    with pytest.raises(jira.JiraHttpError) as info:
        client.myself()
    assert info.value.kind == "UNREACHABLE"


# --- hostile answers: nesting (2026-09-25) -----------------------------------------
#
# About 400 KB of brackets, under MAX_RESPONSE_BYTES, made json.loads raise
# RecursionError, which is not a ValueError: it escaped the client, the pass
# and the drain. The depth scan refuses it before json.loads runs.

DEEP = b"[" * 200_000 + b"]" * 200_000


@pytest.mark.parametrize("status", [200, 201])
def test_a_deeply_nested_answer_is_invalid_and_never_a_recursion_error(status):
    client, _ = _client([fetched(status, DEEP)])
    with pytest.raises(jira.JiraHttpError) as info:
        client.myself()
    assert info.value.kind == "INVALID" and "not JSON" in info.value.detail


def test_a_deeply_nested_refusal_still_names_only_the_status():
    client, _ = _client([fetched(400, b'{"errors": ' + DEEP + b"}")])
    with pytest.raises(jira.JiraHttpError) as info:
        client.project("SOC")
    assert info.value.kind == "INVALID"
    assert info.value.detail == "Jira refused the request (HTTP 400)"


def test_nesting_inside_a_string_is_not_nesting():
    """The scan skips string contents and escapes, so a summary full of
    brackets is an ordinary answer."""
    body = json.dumps({"displayName": "[" * 5000 + "\\\"{" * 100}).encode()
    client, _ = _client([fetched(200, body)])
    assert client.myself().startswith("[[[")


def test_the_depth_limit_admits_every_answer_shape_the_client_reads():
    nested = {"projects": [{"issuetypes": [{"fields": {"labels": {"schema": {
        "type": "array", "items": "string"}}}}]}]}
    assert jira._loads(json.dumps(nested).encode()) == nested
    assert jira.MAX_JSON_DEPTH >= 16


# --- NOCTORNAL_JIRA_NETWORK (docs/20 section 9, the Jira row) ---------------------

def _spy_route():
    from outbound_support import route_for_factory
    return route_for_factory({"jira": FakeRoute(
        "jira", frozenset({("jira.internal.example", 443)}))})


def test_the_jira_network_rides_on_the_declared_rule(monkeypatch):
    monkeypatch.setenv(jira.NETWORK_ENV, "10.40.0.0/24")
    rf = _spy_route()
    state = jira.route_state(None, "https://jira.internal.example", "jira.internal.example",
                             443, route_for=rf)
    assert state.ok
    _kind, name, declared = rf.calls[0]
    assert name == "jira" and declared[0].host == "jira.internal.example"
    assert str(declared[0].network) == "10.40.0.0/24"
    monkeypatch.delenv(jira.NETWORK_ENV)
    rf = _spy_route()
    jira.route_state(None, "https://jira.internal.example", "jira.internal.example", 443,
                     route_for=rf)
    assert rf.calls[0][2][0].network is None


def test_a_malformed_jira_network_holds_jira_and_refuses_production(monkeypatch):
    from noctornal_api import config
    monkeypatch.setenv(jira.NETWORK_ENV, "10.40.0.1/24")
    rf = _spy_route()
    state = jira.route_state(None, "https://jira.internal.example", "jira.internal.example",
                             443, route_for=rf)
    assert not state.ok and jira.NETWORK_ENV in state.why and not rf.calls
    problems = config.verify_environment({config.ENV_VAR: "production",
                                          jira.NETWORK_ENV: "hunter2hunter2/99"})
    mine = [p for p in problems if p.startswith(jira.NETWORK_ENV)]
    assert len(mine) == 1 and "hunter2" not in " ".join(problems)
