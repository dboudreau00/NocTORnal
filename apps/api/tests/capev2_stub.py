"""A local stand-in for a CAPEv2 web service, for the sandbox suites (F14,
2026-09-24). Not a test module.

No test contacts a real sandbox. This serves the few apiv2 endpoints the
client uses, and the web interface's analysis page, over TLS with a
throwaway CA written to the test's tmp_path (passed as
NOCTORNAL_SANDBOX_CA_FILE), on 127.0.0.1, reached through egress.route_for
with the development route whose declared rule names 127.0.0.1:<port>.
Every request is recorded, so a test can assert what left and in what
order; `on_post` runs INSIDE the upload's handler, before any answer, so a
test can prove what the database held at the moment the bytes arrived.
"""
from __future__ import annotations

import ipaddress
import json
import re
import ssl
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "stub-token-0123456789abcdef"


def certificates(tmp_path):
    """A throwaway CA and a server certificate for 127.0.0.1 it signed."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cape stub CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(
              digital_signature=False, content_commitment=False,
              key_encipherment=False, data_encipherment=False,
              key_agreement=False, key_cert_sign=True, crl_sign=True,
              encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(
              ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                        "127.0.0.1")]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                           critical=False)
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "cape-ca.pem"
    cert_path = tmp_path / "cape.pem"
    key_path = tmp_path / "cape.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return ca_path, cert_path, key_path


class Stub:
    """What the stub does, and what it saw."""

    def __init__(self):
        self.requests: list[dict] = []
        self.auth_enforced = True
        self.web_open = False
        self.post_mode = "ok"      # ok, drop, error, reject, fail, redirect
        self.next_task = 41
        self.statuses: dict[int, str] = {}
        self.reports: dict[int, bytes] = {}
        self.iocs: dict[int, bytes] = {}
        #: A task's raw status answer, in place of the well-formed one.
        self.status_bodies: dict[int, bytes] = {}
        #: A status the status read of a task answers with.
        self.status_fail: dict[int, int] = {}
        #: A status the report and IOC reads of a task answer with.
        self.report_fail: dict[int, int] = {}
        self.on_post = None
        self.lock = threading.Lock()


def _handler(stub: Stub):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            return

        def _authed(self) -> bool:
            return self.headers.get("Authorization") == f"Token {TOKEN}"

        def _send(self, status: int, body: bytes = b"", ctype="application/json",
                  headers: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.close_connection = True

        def _record(self, body: bytes = b""):
            entry = {"method": self.command, "path": self.path,
                     "authorization": self.headers.get("Authorization"),
                     "user_agent": self.headers.get("User-Agent"),
                     "content_type": self.headers.get("Content-Type"),
                     "body": body}
            with stub.lock:
                stub.requests.append(entry)
            return entry

        def do_GET(self):  # noqa: N802 - the stdlib's name
            self._record()
            m = re.match(r"^/analysis/(\d+)/$", self.path)
            if m:
                if stub.web_open:
                    return self._send(200, b"<html>report</html>", "text/html")
                return self._send(302, headers={
                    "Location": f"/accounts/login/?next=/analysis/{m.group(1)}/"})
            if stub.auth_enforced and not self._authed():
                return self._send(401, b'{"detail":"Authentication credentials '
                                       b'were not provided."}')
            if self.headers.get("Authorization") and not self._authed():
                return self._send(403, b'{"detail":"Invalid token."}')
            m = re.match(r"^/apiv2/tasks/view/(\d+)/$", self.path)
            if m:
                task = int(m.group(1))
                if task in stub.status_fail:
                    return self._send(stub.status_fail[task], b"{}")
                if task in stub.status_bodies:
                    return self._send(200, stub.status_bodies[task])
                status = stub.statuses.get(task)
                if status is None:
                    return self._send(200, json.dumps(
                        {"error": True, "error_value": "Task does not exist"}).encode())
                return self._send(200, json.dumps(
                    {"error": False, "data": {"status": status}}).encode())
            m = re.match(r"^/apiv2/tasks/get/(report|iocs)/(\d+)/(json/)?$", self.path)
            if m and int(m.group(2)) in stub.report_fail:
                return self._send(stub.report_fail[int(m.group(2))], b"{}")
            m = re.match(r"^/apiv2/tasks/get/report/(\d+)/json/$", self.path)
            if m:
                return self._send(200, stub.reports.get(int(m.group(1)), b"{}"))
            m = re.match(r"^/apiv2/tasks/get/iocs/(\d+)/$", self.path)
            if m:
                return self._send(200, stub.iocs.get(int(m.group(1)), b"{}"))
            return self._send(404, b"{}")

        def do_POST(self):  # noqa: N802 - the stdlib's name
            length = int(self.headers.get("Content-Length") or 0)
            if stub.post_mode == "drop_mid_body":
                self.rfile.read(max(1, length // 3))
                self._record(b"")
                self.close_connection = True
                self.connection.close()
                return
            body = self.rfile.read(length)
            entry = self._record(body)
            if stub.on_post is not None:
                entry["hook"] = stub.on_post()
            if stub.post_mode == "drop":
                self.close_connection = True
                self.connection.close()
                return
            if stub.post_mode == "redirect":
                return self._send(303, headers={"Location": "/elsewhere/"})
            if stub.post_mode == "reject":
                return self._send(400, b'{"error": true, "error_value": "bad file"}')
            if stub.post_mode == "fail":
                return self._send(500, b"oops")
            if stub.post_mode == "error":
                return self._send(200, b'{"error": true, "error_value": "no machines"}')
            if stub.auth_enforced and not self._authed():
                return self._send(401, b"{}")
            with stub.lock:
                task = stub.next_task
                stub.next_task += 1
            stub.statuses.setdefault(task, "pending")
            return self._send(200, json.dumps(
                {"error": False, "data": {"task_ids": [task]}}).encode())

    return Handler


def start(tmp_path):
    """(stub, port, ca_path, server). The caller shuts the server down."""
    ca_path, cert_path, key_path = certificates(tmp_path)
    stub = Stub()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(stub))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return stub, server.server_address[1], ca_path, server


def configure(monkeypatch, port: int, ca_path, *, exposure="NONE",
              ceiling="AMBER", routes="none,internet", machines="") -> None:
    """The environment for a sandbox at the stub."""
    from noctornal_api import sandbox
    for var in sandbox.ALL_ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(sandbox.PROVIDER_ENV, "capev2")
    monkeypatch.setenv(sandbox.URL_ENV, f"https://127.0.0.1:{port}")
    monkeypatch.setenv(sandbox.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(sandbox.EXPOSURE_ENV, exposure)
    monkeypatch.setenv(sandbox.CEILING_ENV, ceiling)
    monkeypatch.setenv(sandbox.ROUTES_ENV, routes)
    monkeypatch.setenv(sandbox.CA_FILE_ENV, str(ca_path))
    monkeypatch.setenv(sandbox.MIN_INTERVAL_ENV, "0")
    if machines:
        monkeypatch.setenv(sandbox.MACHINES_ENV, machines)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)


def report(sha256: str, **extra) -> bytes:
    """A small CAPE report for the sample."""
    body = {"info": {"id": 41, "version": "2.4-CAPE", "duration": 120,
                     "machine": {"name": "win10"}},
            "target": {"file": {"sha256": sha256, "yara": [{"name": "CapeRuleX"}],
                                "pe": {"imphash": "a" * 32}}},
            "malscore": 7.5, "detections": "AgentTesla",
            "signatures": [{"name": "injection", "severity": 3}],
            "network": {"hosts": [{"ip": "8.8.4.4"}, {"ip": "10.0.0.5"}],
                        "domains": [{"domain": "c2.example.net"}],
                        "http": []},
            "CAPE": {"configs": [{"AgentTesla": {"C2": ["https://evil.example.org/gate"],
                                                 "Version": "3"}}]}}
    body.update(extra)
    return json.dumps(body).encode()


__all__ = ["TOKEN", "Stub", "certificates", "configure", "report", "start"]
