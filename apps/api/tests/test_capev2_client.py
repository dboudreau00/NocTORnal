"""The CAPEv2 client against a local stub (F14, 2026-09-24).

Every call goes through egress.route_for and the one outbound client; the
network route is always sent; what leaves is the encrypted archive named
for its hash; the token and the user agent are sent; nothing is resent,
and what was or was not sent is decided by what left: a refused connection
is NOT_SENT, a drop after the first byte is UNCONFIRMED however much of the
body went; a redirect is never followed; a 4xx is REJECTED_BY_TARGET; the
report falls back to the IOC summary only when it is too large; the probe
names an instance whose API or web interface answers without a token.
"""
from __future__ import annotations

import hashlib
import io
import re
import socket
import zipfile

import pytest

import capev2_stub
from noctornal_api.samples import archive


class _Conn:
    """A connection with no egress route rows (2026-09-25): the route
    provider asks for an administrator's row first and, in development,
    falls back to the declared rules alone."""

    def execute(self, *_args, **_kwargs):
        return self

    def fetchone(self):
        return None

    def fetchall(self):
        return []


@pytest.fixture
def cape(tmp_path, monkeypatch):
    stub, port, ca, server = capev2_stub.start(tmp_path)
    capev2_stub.configure(monkeypatch, port, ca)
    try:
        yield stub, port
    finally:
        server.shutdown()
        server.server_close()


def _client():
    from noctornal_api.sandbox import sandbox_settings
    from noctornal_api.sandbox_capev2 import CapeV2Client
    settings, problem = sandbox_settings()
    assert problem is None, problem
    return CapeV2Client(settings, conn=_Conn()), settings


def _payload():
    data = b"MZ" + b"\x90" * 2000
    sha = hashlib.sha256(data).hexdigest()
    return archive(data, sha), sha


def _fields(body: bytes) -> dict:
    out = {}
    for name, value in re.findall(
            rb'name="([^"]+)"\r\n\r\n(.*?)\r\n--', body, re.S):
        out[name.decode()] = value
    return out


def test_the_network_route_is_always_sent_and_the_file_is_the_archive(cape):
    stub, _port = cape
    client, _s = _client()
    payload, sha = _payload()
    out = client.submit(payload, sha256_hex=sha, context=f"detonation:{'1' * 8}-1111-1111-1111-{'1' * 12}",
                        network_route="none", timeout_s=120)
    assert out.kind == "CONFIRMED" and out.task_id == 41
    post = stub.requests[-1]
    assert post["method"] == "POST" and post["path"] == "/apiv2/tasks/create/file/"
    fields = _fields(post["body"])
    assert fields["route"] == b"none" and fields["timeout"] == b"120"
    assert f'filename="{sha}.zip"'.encode() in post["body"]
    start = post["body"].index(b"PK\x03\x04")
    assert post["body"][start + 6] & 1, "flag bit 0: the entry is encrypted"
    assert b"\r\n\r\nMZ" not in post["body"]
    # The archive round-trips with the public password.
    blob = post["body"][start:post["body"].rindex(b"\r\n--")]
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        assert z.read(f"{sha}.bin", pwd=b"infected")[:2] == b"MZ"


def test_the_token_and_user_agent_are_sent(cape):
    stub, _port = cape
    client, _s = _client()
    payload, sha = _payload()
    client.submit(payload, sha256_hex=sha, context=_ctx(), network_route="none",
                  timeout_s=60)
    post = stub.requests[-1]
    assert post["authorization"] == f"Token {capev2_stub.TOKEN}"
    assert post["user_agent"] == "NocTORnal-sandbox/1"


def _ctx():
    return "detonation:22222222-2222-2222-2222-222222222222"


def test_a_post_whose_connection_drops_after_the_body_is_never_resent(cape):
    stub, _port = cape
    stub.post_mode = "drop"
    client, _s = _client()
    payload, sha = _payload()
    out = client.submit(payload, sha256_hex=sha, context=_ctx(),
                        network_route="none", timeout_s=60)
    assert out.kind == "UNCONFIRMED"
    assert sum(1 for r in stub.requests if r["method"] == "POST") == 1


def test_a_drop_halfway_through_the_body_is_unconfirmed(cape):
    stub, _port = cape
    stub.post_mode = "drop_mid_body"
    client, _s = _client()
    data = b"MZ" + bytes(range(256)) * 20000
    sha = hashlib.sha256(data).hexdigest()
    out = client.submit(archive(data, sha), sha256_hex=sha, context=_ctx(),
                        network_route="none", timeout_s=60)
    assert out.kind == "UNCONFIRMED"


def test_a_refused_connection_is_not_sent(tmp_path, monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    ca, _c, _k = capev2_stub.certificates(tmp_path)
    capev2_stub.configure(monkeypatch, port, ca)
    client, _s = _client()
    payload, sha = _payload()
    out = client.submit(payload, sha256_hex=sha, context=_ctx(),
                        network_route="none", timeout_s=60)
    assert out.kind == "NOT_SENT"


def test_a_redirect_is_never_followed(cape):
    stub, _port = cape
    stub.post_mode = "redirect"
    client, _s = _client()
    payload, sha = _payload()
    out = client.submit(payload, sha256_hex=sha, context=_ctx(),
                        network_route="none", timeout_s=60)
    assert out.kind == "REJECTED_BY_TARGET"
    assert [r["path"] for r in stub.requests] == ["/apiv2/tasks/create/file/"]


def test_a_4xx_answer_is_rejected_by_target_and_truncated(cape):
    stub, _port = cape
    stub.post_mode = "reject"
    client, _s = _client()
    payload, sha = _payload()
    out = client.submit(payload, sha256_hex=sha, context=_ctx(),
                        network_route="none", timeout_s=60)
    assert out.kind == "REJECTED_BY_TARGET" and len(out.detail) <= 300
    stub.post_mode = "error"
    assert client.submit(payload, sha256_hex=sha, context=_ctx(),
                         network_route="none", timeout_s=60).kind == "REJECTED_BY_TARGET"
    stub.post_mode = "fail"
    assert client.submit(payload, sha256_hex=sha, context=_ctx(),
                         network_route="none", timeout_s=60).kind == "UNCONFIRMED"


def test_the_report_cap_falls_back_to_iocs_and_nothing_else_does(cape):
    stub, _port = cape
    client, _s = _client()
    stub.reports[7] = b'{"x": "' + b"a" * 5000 + b'"}'
    stub.iocs[7] = b'{"iocs": true}'
    got = client.report(7, context=_ctx(), max_bytes=1000)
    assert (got.source, got.truncated, got.data) == ("iocs", True, b'{"iocs": true}')
    got = client.report(7, context=_ctx(), max_bytes=100_000)
    assert got.source == "json" and not got.truncated


def test_every_call_goes_through_the_egress_route(cape):
    """The client's route names the configured sandbox and nothing else: a
    destination the route does not name is refused before any connection,
    and a sandbox URL no rule can admit is NOT_SENT with nothing dialled."""
    from dataclasses import replace

    from noctornal_api.pinned_http import DestinationRefused, fetch_response
    from noctornal_api.sandbox_capev2 import CapeV2Client
    stub, port = cape
    client, settings = _client()
    route = client.route(_ctx())
    assert route.route_id == "integration:sandbox"
    assert route.permits("127.0.0.1", port)
    assert not route.permits("127.0.0.1", port + 1)
    with pytest.raises(DestinationRefused):
        fetch_response(f"https://127.0.0.1:{port + 1}/apiv2/", route=route,
                       max_redirects=0)
    wrong = replace(settings, base="https://169.254.169.254")
    out = CapeV2Client(wrong, conn=_Conn()).submit(
        b"PK", sha256_hex="0" * 64, context=_ctx(), network_route="none",
        timeout_s=60)
    assert out.kind == "NOT_SENT" and stub.requests == []


def test_the_probe_accepts_an_authenticated_instance(cape):
    stub, _port = cape
    client, _s = _client()
    probe = client.probe(context="check:33333333-3333-3333-3333-333333333333")
    assert probe.ok and probe.token_accepted and not probe.open_without_token
    assert probe.error is None


def test_the_probe_reports_an_open_api(cape):
    stub, _port = cape
    stub.auth_enforced = False
    client, _s = _client()
    probe = client.probe(context="check:33333333-3333-3333-3333-333333333333")
    assert not probe.ok and probe.open_without_token
    assert any(p.startswith("apiv2/") for p in probe.open_paths)


def test_the_probe_reports_an_open_web_interface(cape):
    stub, _port = cape
    stub.web_open = True
    client, _s = _client()
    probe = client.probe(context="check:33333333-3333-3333-3333-333333333333")
    assert not probe.ok and probe.open_paths == ("/analysis/1/",)


def test_the_probe_reports_a_refused_token(cape, monkeypatch):
    from noctornal_api import sandbox
    stub, _port = cape
    monkeypatch.setenv(sandbox.TOKEN_ENV, "wrong-token-value")
    client, _s = _client()
    probe = client.probe(context="check:33333333-3333-3333-3333-333333333333")
    assert not probe.ok and not probe.token_accepted


@pytest.mark.parametrize("code", ["connect_failed", "upstream_timeout",
                                  "route_inactive", "name_not_found"])
def test_a_proxy_that_refuses_the_tunnel_is_not_sent(code, monkeypatch):
    """Through the egress proxy (docs/20 section 8.2), a CAPE that is
    down answers as the proxy's refusal of the CONNECT, before any byte of
    the request reaches it: NOT_SENT, never "sent and the answer lost".
    The stub proxy (egress_contract_cases) speaks the wire contract."""
    from egress_contract_cases import StubHarness, StubProxy
    from noctornal_api.egress_policy import Rule
    from noctornal_api.sandbox import sandbox_settings
    from noctornal_api.sandbox_capev2 import CapeV2Client
    capev2_stub.configure(monkeypatch, 8443, __file__)
    monkeypatch.setenv("NOCTORNAL_SANDBOX_URL", "https://cape.lab.example:8443")
    monkeypatch.delenv("NOCTORNAL_SANDBOX_CA_FILE")
    settings, problem = sandbox_settings()
    assert problem is None, problem
    with StubProxy() as stub:
        h = StubHarness(stub)
        route = h.route("integration", "sandbox",
                        rules=(Rule.for_url("https://cape.lab.example:8443/apiv2/"),))
        client = CapeV2Client(settings, conn=_Conn())
        monkeypatch.setattr(client, "route", lambda context: route.tagged(context))
        payload, sha = _payload()
        with h.refusing(code):
            out = client.submit(payload, sha256_hex=sha, context=_ctx(),
                                network_route="none", timeout_s=60)
    assert out.kind == "NOT_SENT", out
