"""The isolated analysis worker over TCP with mutual TLS 1.3 (decision 239).

The worker's Unix socket stays the compose default. Where no volume can be shared (a pod of its own) the
same frames cross TCP under mutual TLS, and because that is a connection that is neither HTTP through the
egress proxy nor a volume, the caller fences it three ways: it dials only loopback or an address inside
the deployment's declared networks (and the address it checked), it trusts only the channel's own CA and
never the system roots, and it requires TLS 1.3 with client certificates. The worker refuses a wildcard
address, a key its children could read, and a client the CA did not issue before it reads a frame.

Every test runs on every platform: the worker is the real `analysis_worker.Worker` on a loopback listener,
its children are real processes, and the certificates are generated here with the `cryptography` package
the repository pins (as capev2_stub.py does). Pure: no database.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from noctornal_api import analysis_runner as ar
from noctornal_api import analysis_worker as aw

SUPERVISED = {"euid": 0, "pid": 7, "capabilities": ["kill", "setgid", "setuid"],
              "no_new_privileges": True, "read_only_root": True, "pids_max": 128,
              "state_left_open": []}
NAME = "analysis-worker.noctornal.svc"


# ---------------------------------------------------------------------------
# A private CA and what it issues
# ---------------------------------------------------------------------------

@dataclass
class Pki:
    ca: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path


def _issue(ca_key, ca_name, cn, sans, usages):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    names = [x509.IPAddress(ipaddress.ip_address(s)) if s[0].isdigit() else x509.DNSName(s)
             for s in sans]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage(usages), critical=False)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert, key


def make_pki(directory: Path, label: str = "a", *, server_names=("127.0.0.1", NAME),
             client_usages=None) -> Pki:
    """A CA of its own, a certificate for the worker (server and client authentication, so its own
    `--check` can present it) and one for a caller (client authentication only)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID as Eku
    from cryptography.x509.oid import NameOID

    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"analysis channel CA {label}")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(
              digital_signature=False, content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
              encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    server, server_key = _issue(ca_key, ca_name, "worker", list(server_names),
                                [Eku.SERVER_AUTH, Eku.CLIENT_AUTH])
    client, client_key = _issue(ca_key, ca_name, "caller", ["127.0.0.1"],
                                client_usages or [Eku.CLIENT_AUTH])
    paths = {}
    for stem, obj in (("ca", ca), ("server", server), ("client", client)):
        paths[stem] = directory / f"{stem}-{label}.pem"
        paths[stem].write_bytes(obj.public_bytes(serialization.Encoding.PEM))
    for stem, key in (("server", server_key), ("client", client_key)):
        paths[f"{stem}_key"] = directory / f"{stem}-{label}.key"
        paths[f"{stem}_key"].write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        os.chmod(paths[f"{stem}_key"], 0o600)
    return Pki(paths["ca"], paths["server"], paths["server_key"], paths["client"],
               paths["client_key"])


@pytest.fixture
def pki(tmp_path):
    return make_pki(tmp_path / "a", "a")


@pytest.fixture
def other_pki(tmp_path):
    return make_pki(tmp_path / "b", "b")


def target_for(pki: Pki, port: int, host: str = "127.0.0.1", **kw) -> ar.TcpTarget:
    return ar.TcpTarget(host, port, str(pki.client_cert), str(pki.client_key), str(pki.ca), **kw)


@contextmanager
def tls_worker(pki: Pki, **kw):
    """The real Worker on a loopback TCP listener under the server side of mutual TLS."""
    context = ar.server_context(str(pki.server_cert), str(pki.server_key), str(pki.ca))
    listener = aw.bind_tcp("127.0.0.1", 0)
    worker = aw.Worker(listener, tls=context, **kw)
    thread = threading.Thread(target=worker.serve_forever, daemon=True)
    thread.start()
    try:
        yield worker, listener.getsockname()[1]
    finally:
        worker.stop()
        thread.join(5)
        listener.close()


def _echo_child(tmp_path, monkeypatch, reply: bytes = b"pong"):
    script = tmp_path / "echo_child.py"
    script.write_text("import sys\nsys.stdin.buffer.readline()\n"
                      f"sys.stdout.buffer.write({reply!r})\n", encoding="utf-8")
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", [sys.executable, str(script)])


def _ask(target, **kw):
    return ar.run_isolated(target, "lab_static", {"mode": "pe"}, (b"MZ",), wall_s=20,
                           stdout_cap=1 << 20, **kw)


@pytest.fixture(autouse=True)
def fresh_verdicts():
    ar.forget_verdicts()
    yield
    ar.forget_verdicts()


# ---------------------------------------------------------------------------
# It works
# ---------------------------------------------------------------------------

def test_a_request_round_trips_over_mutual_tls_on_loopback(pki, tmp_path, monkeypatch):
    _echo_child(tmp_path, monkeypatch)
    with tls_worker(pki) as (_worker, port):
        result = _ask(target_for(pki, port))
        assert result.ok and result.output == b"pong", result
        status = ar.hello(target_for(pki, port))
        assert status["protocol"] == ar.WIRE_VERSION


def test_a_real_child_answers_through_the_tls_channel(pki):
    """Not a stand-in child: the same selftest the register runs, through the same wire."""
    with tls_worker(pki) as (_worker, port):
        result = ar.run_isolated(target_for(pki, port), "lab_static", {"mode": "selftest"}, (),
                                 wall_s=30, stdout_cap=1 << 20)
        assert result.ok, result


def test_status_reports_transport(pki):
    with tls_worker(pki) as (_worker, port):
        assert ar.hello(target_for(pki, port))["transport"] == "tcp_tls"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    try:
        assert aw.Worker(listener).status()["transport"] == "unix"
    finally:
        listener.close()


def test_the_runner_chooses_the_tcp_worker_from_its_settings(pki):
    env = {ar.ADDR_ENV: "127.0.0.1:9443", ar.TLS_CERT_ENV: str(pki.client_cert),
           ar.TLS_KEY_ENV: str(pki.client_key), ar.TLS_CA_ENV: str(pki.ca)}
    choice = ar.runner_choice(env)
    assert choice.mode == "isolated" and choice.socket_path is None
    assert choice.address == ar.TcpTarget("127.0.0.1", 9443, str(pki.client_cert),
                                          str(pki.client_key), str(pki.ca))
    assert choice.target == choice.address and str(choice.target) == "127.0.0.1:9443"
    v6 = ar.runner_choice({**env, ar.ADDR_ENV: "[::1]:9443"})
    assert str(v6.target) == "[::1]:9443" and v6.address.host == "::1"
    assert ar.setting_problem(env) is None


def test_unavailable_says_which_transport_is_silent_and_is_none_when_it_answers(pki):
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    env = {ar.ADDR_ENV: f"127.0.0.1:{port}", ar.TLS_CERT_ENV: str(pki.client_cert),
           ar.TLS_KEY_ENV: str(pki.client_key), ar.TLS_CA_ENV: str(pki.ca)}
    assert ar.unavailable(env) == ar.WORKER_SILENT_TCP
    ar.forget_verdicts()
    with tls_worker(pki) as (_worker, live):
        env[ar.ADDR_ENV] = f"127.0.0.1:{live}"
        assert ar.unavailable(env) is None


# ---------------------------------------------------------------------------
# Who may call it
# ---------------------------------------------------------------------------

def _count_requests(monkeypatch) -> list[int]:
    seen: list[int] = []
    original = aw.Worker._handle

    def counting(self, conn):
        seen.append(1)
        return original(self, conn)

    monkeypatch.setattr(aw.Worker, "_handle", counting)
    return seen


def _peer_without_a_certificate(port: int, ca: Path) -> None:
    """A TLS client that trusts the worker's CA and presents nothing, then tries to send a frame. Every
    way it can fail is an OSError or an empty read: what it must never get is an answer."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(ca))
    context.check_hostname = False
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock = context.wrap_socket(raw)
        sock.settimeout(5)
        sock.sendall(ar.pack_frame({"v": ar.WIRE_VERSION, "id": "0" * 32, "kind": ar.HELLO}))
        assert sock.recv(8) == b""
    except OSError:
        pass
    finally:
        raw.close()


def test_a_client_with_no_certificate_is_refused_before_any_payload_is_read(
        pki, monkeypatch, caplog):
    seen = _count_requests(monkeypatch)
    with tls_worker(pki) as (_worker, port):
        _peer_without_a_certificate(port, pki.ca)
        time.sleep(0.5)
        assert ar.hello(target_for(pki, port))["transport"] == "tcp_tls", "it still serves"
    assert seen == [1], "only the legitimate caller's request was ever read"
    assert "failed its TLS handshake" in caplog.text


def test_a_client_certificate_from_another_ca_is_refused(pki, other_pki, monkeypatch):
    seen = _count_requests(monkeypatch)
    with tls_worker(pki) as (_worker, port):
        # The worker's CA is right, so the caller trusts the worker; the caller's own certificate
        # is another CA's.
        stranger = ar.TcpTarget("127.0.0.1", port, str(other_pki.client_cert),
                                str(other_pki.client_key), str(pki.ca))
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(stranger)
        assert _ask(stranger).failure == "worker_unavailable"
    assert seen == [], "not one frame was read"


def test_the_client_trusts_only_the_channels_own_ca_not_the_system_roots(pki, other_pki):
    context = ar.client_context(target_for(pki, 1))
    loaded = context.get_ca_certs()
    assert len(loaded) == 1, "the system's roots were loaded"
    assert dict(item[0] for item in loaded[0]["subject"])["commonName"] == "analysis channel CA a"
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    # A worker whose certificate another CA issued, however well formed, is not the worker.
    with tls_worker(other_pki) as (_worker, port):
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(target_for(pki, port))


def test_the_client_requires_tls_1_3(pki):
    assert ar.client_context(target_for(pki, 1)).minimum_version == ssl.TLSVersion.TLSv1_3
    context = ar.server_context(str(pki.server_cert), str(pki.server_key), str(pki.ca))
    assert context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert context.verify_mode == ssl.CERT_REQUIRED
    # A worker that offers nothing newer than TLS 1.2 is refused.
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    old.load_cert_chain(str(pki.server_cert), str(pki.server_key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    listener.settimeout(10)

    def serve():
        try:
            conn, _ = listener.accept()
            old.wrap_socket(conn, server_side=True).close()
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(target_for(pki, listener.getsockname()[1]))
    finally:
        thread.join(10)
        listener.close()


def test_the_worker_names_must_match_the_configured_host(pki):
    """A certificate for another name is not the worker the setting names, even from the right CA."""
    with tls_worker(pki) as (_worker, port):
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(target_for(pki, port, host="localhost"))


# ---------------------------------------------------------------------------
# What a caller will dial
# ---------------------------------------------------------------------------

class _NoSocket:
    """Stands in for socket.socket and fails the test the moment anything tries to open one."""

    def __init__(self, *_a, **_k):
        raise AssertionError("a socket was opened")


def _fake_lookup(monkeypatch, answers):
    calls: list[str] = []

    def lookup(host, port, *args, **kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answers(len(calls))]

    monkeypatch.setattr(ar.socket, "getaddrinfo", lookup)
    return calls


def test_the_client_refuses_a_worker_address_outside_the_deployments_own_networks_and_dials_nothing(
        pki, monkeypatch):
    monkeypatch.setattr(ar.socket, "socket", _NoSocket)
    for host in ("203.0.113.5", "8.8.8.8", "169.254.169.254", "10.96.0.9"):
        with pytest.raises(OSError, match="own networks"):
            ar._connect_tcp(target_for(pki, 9443, host=host), env={})
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(target_for(pki, 9443, host=host),
                     connect=lambda t: ar._connect_tcp(t, env={}))
    assert _ask(target_for(pki, 9443, host="203.0.113.5")).failure == "worker_unavailable"


def test_a_declared_network_admits_the_address_and_only_it(pki, monkeypatch):
    """Where the deployment declares its networks, an address inside is dialled (the dial itself is
    stubbed here) and one outside is not."""
    env = {"NOCTORNAL_ENV": "production", "NOCTORNAL_EGRESS_INTERNAL_CIDRS": "10.96.0.0/12,10.244.0.0/16"}
    dialled: list[tuple] = []

    class Refusing:
        def __init__(self, *a, **k):
            pass

        def settimeout(self, _s):
            pass

        def connect(self, sockaddr):
            dialled.append(sockaddr)
            raise ConnectionRefusedError

        def close(self):
            pass

    monkeypatch.setattr(ar.socket, "socket", Refusing)
    for inside in ("10.96.0.9", "10.244.3.4"):
        with pytest.raises(ConnectionRefusedError):
            ar._connect_tcp(target_for(pki, 9443, host=inside), env=env)
    assert [d[0] for d in dialled] == ["10.96.0.9", "10.244.3.4"]
    with pytest.raises(OSError, match="own networks"):
        ar._connect_tcp(target_for(pki, 9443, host="10.200.0.1"), env=env)
    assert len(dialled) == 2
    # Loopback is always the deployment's own.
    with pytest.raises(ConnectionRefusedError):
        ar._connect_tcp(target_for(pki, 9443, host="127.0.0.1"), env=env)


def test_the_client_refuses_a_hostname_that_resolves_to_a_public_address(pki, monkeypatch):
    monkeypatch.setattr(ar.socket, "socket", _NoSocket)
    _fake_lookup(monkeypatch, lambda _n: ["93.184.216.34"])
    with pytest.raises(OSError, match="own networks"):
        ar._connect_tcp(target_for(pki, 9443, host="worker.example"), env={})
    # One loopback answer does not excuse a public one beside it: the name is the worker's only
    # when every answer is.
    _fake_lookup(monkeypatch, lambda _n: ["127.0.0.1", "93.184.216.34"])
    with pytest.raises(OSError, match="own networks"):
        ar._connect_tcp(target_for(pki, 9443, host="worker.example"), env={})
    # An IPv4-mapped address is the IPv4 address it carries.
    monkeypatch.setattr(ar.socket, "getaddrinfo", lambda host, port, *a, **k: [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:93.184.216.34", port, 0, 0))])
    with pytest.raises(OSError, match="own networks"):
        ar._connect_tcp(target_for(pki, 9443, host="worker.example"), env={})


def test_the_client_dials_the_address_it_checked_not_a_second_lookup(pki, monkeypatch):
    """The name is resolved once. Were it resolved again to dial, the answer could change between the
    check and the connection (a rebind); here the second answer would be public, and is never asked."""
    with tls_worker(pki) as (_worker, port):
        calls = _fake_lookup(monkeypatch, lambda n: ["127.0.0.1"] if n == 1 else ["93.184.216.34"])
        target = target_for(pki, port, host=NAME)
        status = ar.hello(target)
        assert status["transport"] == "tcp_tls"
        assert calls == [NAME], "one lookup"


# ---------------------------------------------------------------------------
# The settings
# ---------------------------------------------------------------------------

def _client_env(pki, **extra):
    return {ar.TLS_CERT_ENV: str(pki.client_cert), ar.TLS_KEY_ENV: str(pki.client_key),
            ar.TLS_CA_ENV: str(pki.ca), **extra}


def test_two_transports_set_together_are_refused_by_name(pki):
    both = _client_env(pki, **{ar.SOCKET_ENV: "/run/x/w.sock", ar.ADDR_ENV: "w:9443"})
    problem = ar.setting_problem(both)
    assert ar.SOCKET_ENV in problem and ar.ADDR_ENV in problem and "transport" in problem
    local = ar.setting_problem(_client_env(pki, **{ar.ADDR_ENV: "w:9443", ar.LOCAL_ENV: "1"}))
    assert ar.ADDR_ENV in local and ar.LOCAL_ENV in local
    assert ar.runner_choice(both).mode == "refused"
    # The two refusals that were there before are the same sentences.
    assert ar.setting_problem({ar.SOCKET_ENV: "/run/x/w.sock", ar.LOCAL_ENV: "1"}).startswith(
        f"{ar.SOCKET_ENV} and {ar.LOCAL_ENV} are both set")


def test_addr_and_the_three_tls_paths_are_required_together(pki):
    full = _client_env(pki, **{ar.ADDR_ENV: "worker:9443"})
    assert ar.setting_problem(full) is None
    for name in ar.TLS_ENV:
        short = {k: v for k, v in full.items() if k != name}
        problem = ar.setting_problem(short)
        assert problem and f"{name} is not" in problem, name
        assert "no plaintext form" in problem
        assert ar.runner_choice({**short, "NOCTORNAL_ENV": "production"}).mode == "refused"
        blank = ar.setting_problem({**full, name: "  "})
        assert blank and name in blank
        relative = ar.setting_problem({**full, name: "certs/x.pem"})
        assert relative and name in relative and "absolute" in relative
    assert ar.TLS_CERT_ENV in ar.setting_problem({ar.ADDR_ENV: "worker:9443"})


@pytest.mark.parametrize("value", [
    "worker", "worker:0", "worker:65536", "worker:port", "http://worker:9443", "worker:9443/x",
    " worker:9443", "worker:9443 ", "wor ker:9443", ":9443", "[::1]", "[::1]9443", "[nope]:9443",
    "::1:9443", "worker..x:9443", "-worker:9443", "workeré:9443", "worker:94\n43",
])
def test_an_address_that_is_not_host_and_port_is_refused(pki, value):
    problem = ar.setting_problem(_client_env(pki, **{ar.ADDR_ENV: value}))
    assert problem and ar.ADDR_ENV in problem and "HOST:PORT" in problem, value


@pytest.mark.parametrize("value, expected", [
    ("worker:9443", ("worker", 9443)), ("a.b.svc.cluster.local:1", ("a.b.svc.cluster.local", 1)),
    ("10.0.0.5:65535", ("10.0.0.5", 65535)), ("[2001:db8::1]:9443", ("2001:db8::1", 9443)),
])
def test_an_address_is_read_as_host_and_port(value, expected):
    assert ar.hostport(value) == expected


def test_the_worker_refuses_a_wildcard_listen(pki):
    for listen in ("0.0.0.0:9443", "[::]:9443"):
        env = {ar.LISTEN_ENV: listen, ar.TLS_CERT_ENV: str(pki.server_cert),
               ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(pki.ca)}
        settings, problem = aw.worker_settings(env)
        assert settings is None and "wildcard" in problem and ar.LISTEN_ENV in problem
        assert any("wildcard" in p for p in aw.start_problems(env, facts=SUPERVISED)), listen
    for listen in ("*:9443", "worker:9443", "9443"):
        env = {ar.LISTEN_ENV: listen, ar.TLS_CERT_ENV: str(pki.server_cert),
               ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(pki.ca)}
        settings, problem = aw.worker_settings(env)
        assert settings is None and ar.LISTEN_ENV in problem, listen


def test_the_worker_serves_one_transport_and_needs_the_tls_paths(pki):
    env = {ar.LISTEN_ENV: "127.0.0.1:9443", ar.TLS_CERT_ENV: str(pki.server_cert),
           ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(pki.ca)}
    settings, problem = aw.worker_settings(env)
    assert problem is None and settings["transport"] == "tcp_tls"
    assert settings["listen"] == ("127.0.0.1", 9443) and settings["path"] is None
    both, problem = aw.worker_settings({**env, ar.SOCKET_ENV: "/run/x/w.sock"})
    assert both is None and ar.SOCKET_ENV in problem and ar.LISTEN_ENV in problem
    for name in ar.TLS_ENV:
        short, problem = aw.worker_settings({k: v for k, v in env.items() if k != name})
        assert short is None and name in problem
    unix, problem = aw.worker_settings({ar.SOCKET_ENV: "/run/x/w.sock"})
    assert problem is None and unix["transport"] == "unix" and unix["path"] == "/run/x/w.sock"


@pytest.mark.skipif(os.name != "posix", reason="file modes mean nothing here")
def test_the_worker_refuses_a_key_readable_by_its_children(pki):
    env = {ar.LISTEN_ENV: "127.0.0.1:9443", ar.TLS_CERT_ENV: str(pki.server_cert),
           ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(pki.ca)}
    assert aw.start_problems(env, facts=SUPERVISED) == []
    for mode in (0o640, 0o604, 0o644, 0o660):
        os.chmod(pki.server_key, mode)
        problems = aw.start_problems(env, facts=SUPERVISED)
        assert len(problems) == 1 and ar.TLS_KEY_ENV in problems[0], oct(mode)
        assert str(pki.server_key) not in problems[0]
    os.chmod(pki.server_key, 0o400)
    assert aw.start_problems(env, facts=SUPERVISED) == []
    # A certificate may be read by anyone: it is public.
    os.chmod(pki.server_cert, 0o644)
    assert aw.start_problems(env, facts=SUPERVISED) == []


def test_the_worker_refuses_a_file_it_cannot_read(pki, tmp_path):
    env = {ar.LISTEN_ENV: "127.0.0.1:9443", ar.TLS_CERT_ENV: str(pki.server_cert),
           ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(tmp_path / "absent.pem")}
    problems = aw.start_problems(env, facts=SUPERVISED)
    assert len(problems) == 1 and ar.TLS_CA_ENV in problems[0]


def test_the_worker_still_refuses_a_foreign_environment_in_tcp_mode(pki):
    env = {ar.LISTEN_ENV: "127.0.0.1:9443", ar.TLS_CERT_ENV: str(pki.server_cert),
           ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(pki.ca)}
    assert aw.start_problems(env, facts=SUPERVISED) == []
    for name in ("REDIS_URL", "DATABASE_URL", "NOCTORNAL_TOTP_KEK", "NOCTORNAL_EGRESS_INTERNAL_CIDRS",
                 "SSL_CERT_FILE", ar.ADDR_ENV):
        problems = aw.start_problems({**env, name: "x"}, facts=SUPERVISED)
        assert problems and name in problems[0], name
    # And the supervisor's own rules apply as they do over a socket.
    assert aw.start_problems(env, facts={**SUPERVISED, "euid": 1000})
    assert aw.start_problems(env, facts={**SUPERVISED, "no_new_privileges": False})
    assert aw.start_problems(env, facts={**SUPERVISED, "pid": 1})
    assert aw.start_problems(env, facts={**SUPERVISED, "pids_max": None})
    assert aw.start_problems(env, facts={**SUPERVISED, "state_left_open": ["/tmp"]})


def test_a_production_boot_refuses_an_address_without_the_tls_paths(pki):
    from test_config_boot import _production

    from noctornal_api import config
    env = {**_production(), ar.ADDR_ENV: "analysis-worker:9443"}
    problems = config.verify_environment(env)
    assert any(ar.ADDR_ENV in p and ar.TLS_CERT_ENV in p for p in problems), problems
    ok = {**env, **_client_env(pki)}
    assert not any(ar.ADDR_ENV in p or "NOCTORNAL_ANALYSIS_TLS" in p
                   for p in config.verify_environment(ok))


# ---------------------------------------------------------------------------
# Slow and hostile peers
# ---------------------------------------------------------------------------

def test_a_stalled_handshake_does_not_block_the_accept_loop(pki, monkeypatch):
    monkeypatch.setattr(ar, "HANDSHAKE_TIMEOUT_S", 1.0)
    with tls_worker(pki) as (_worker, port):
        stalled = [socket.create_connection(("127.0.0.1", port), timeout=10) for _ in range(5)]
        try:
            started = time.monotonic()
            assert ar.hello(target_for(pki, port))["transport"] == "tcp_tls"
            assert time.monotonic() - started < 3, "the real caller waited behind the stalled ones"
            # The stalled ones are ended at the deadline, whole: not one read at a time.
            for sock in stalled:
                sock.settimeout(10)
                try:
                    assert sock.recv(1) == b""
                except OSError:
                    pass
            assert time.monotonic() - started < 6
        finally:
            for sock in stalled:
                sock.close()


def test_a_peer_that_trickles_its_handshake_is_ended_at_the_deadline(pki, monkeypatch):
    """A peer that sends a byte now and then keeps every single read alive, so a timeout per read
    would hold the connection for ever; the deadline is on the whole handshake."""
    monkeypatch.setattr(ar, "HANDSHAKE_TIMEOUT_S", 1.0)
    with tls_worker(pki) as (_worker, port):
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            started = time.monotonic()
            ended = False
            while time.monotonic() - started < 6:
                try:
                    sock.sendall(b"\x16")
                    time.sleep(0.3)
                except OSError:
                    ended = True
                    break
            assert ended, "the worker held a half-open handshake past its deadline"
            assert time.monotonic() - started < 5
        finally:
            sock.close()


def _open_idle(port: int, count: int) -> list[socket.socket]:
    """`count` connections that send nothing, as a peer with no certificate would hold them."""
    socks = []
    for _ in range(count):
        try:
            socks.append(socket.create_connection(("127.0.0.1", port), timeout=10))
        except OSError:
            break
    return socks


def test_peers_with_no_certificate_cannot_hold_the_connections_a_certified_caller_needs(
        pki, monkeypatch):
    """The TCP port is reached by whatever the network lets in, and an unauthenticated peer takes a slot
    of the shared cap until its handshake ends. With every slot's worth of idle sockets open, a caller
    the CA issued for is still served at once, because only a few connections may be in their handshake
    and the oldest of them is the one ended; the flood can be renewed and the caller is still served."""
    monkeypatch.setattr(ar, "HANDSHAKE_TIMEOUT_S", 30.0)
    with tls_worker(pki) as (worker, port):
        flood: list[socket.socket] = []
        try:
            for _round in range(3):
                flood += _open_idle(port, aw.MAX_CONNECTIONS)
                started = time.monotonic()
                status = ar.hello(target_for(pki, port))
                assert status["transport"] == "tcp_tls"
                assert time.monotonic() - started < 3, "the caller waited behind the idle peers"
            with worker._handshake_lock:
                assert len(worker._handshaking) <= aw.MAX_HANDSHAKES
        finally:
            for sock in flood:
                sock.close()


def test_a_flooded_worker_still_answers_every_certified_caller_in_a_burst(pki, monkeypatch):
    """Several callers at once, among the idle peers: each is served, since a real handshake is over
    long before the bound is reached by peers that never finish one."""
    monkeypatch.setattr(ar, "HANDSHAKE_TIMEOUT_S", 30.0)
    with tls_worker(pki) as (_worker, port):
        flood = _open_idle(port, aw.MAX_CONNECTIONS)
        try:
            answers: list[str] = []
            lock = threading.Lock()

            def call() -> None:
                got = ar.hello(target_for(pki, port))["transport"]
                with lock:
                    answers.append(got)

            callers = [threading.Thread(target=call) for _ in range(3)]
            for caller in callers:
                caller.start()
                caller.join(10)
            assert answers == ["tcp_tls"] * 3
        finally:
            for sock in flood:
                sock.close()


def test_a_connection_that_finished_its_handshake_is_never_shed_by_a_flood(
        pki, tmp_path, monkeypatch):
    """The bound is on connections still in their handshake. A request in progress holds none of it, so
    a flood arriving while a child works does not cost that request its answer."""
    script = tmp_path / "slow_child.py"
    script.write_text("import sys, time\nsys.stdin.buffer.readline()\ntime.sleep(2)\n"
                      "sys.stdout.buffer.write(b'late')\n", encoding="utf-8")
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", [sys.executable, str(script)])
    monkeypatch.setattr(ar, "HANDSHAKE_TIMEOUT_S", 30.0)
    with tls_worker(pki) as (_worker, port):
        results: list = []
        asker = threading.Thread(target=lambda: results.append(_ask(target_for(pki, port))))
        asker.start()
        time.sleep(0.7)
        flood = _open_idle(port, aw.MAX_CONNECTIONS * 2)
        try:
            asker.join(30)
            assert results and results[0].ok and results[0].output == b"late", results
        finally:
            for sock in flood:
                sock.close()


def test_the_handshake_bound_is_smaller_than_the_cap():
    """A handshake in flight is a connection thread already counted in the cap, so the bound leaves the
    rest of the cap for peers that have shown a certificate."""
    assert 1 <= aw.MAX_HANDSHAKES < aw.MAX_CONNECTIONS


def test_a_slow_honest_peer_finishes_its_handshake_though_the_worker_looks_up_every_few_milliseconds(
        pki, monkeypatch):
    """The worker asks whether its handshake was ended every `HANDSHAKE_POLL_S`, so a peer that is slow
    and not stalled (a loaded caller, a distant one) still gets through: the poll resumes the handshake
    and never restarts it."""
    context = ar.client_context(target_for(pki, 0))
    with tls_worker(pki) as (_worker, port):
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        try:
            time.sleep(10 * ar.HANDSHAKE_POLL_S)
            wrapped = context.wrap_socket(raw, server_hostname=NAME, do_handshake_on_connect=False)
            started = time.monotonic()
            wrapped.do_handshake()
            assert wrapped.version() == "TLSv1.3"
            assert time.monotonic() - started < 3
        finally:
            raw.close()
        assert ar.hello(target_for(pki, port))["transport"] == "tcp_tls"


def test_a_flood_of_failed_handshakes_writes_one_line_a_window_and_counts_the_rest(
        pki, monkeypatch, caplog):
    """A peer that opens connections as fast as it can must not make the log the next thing to fill:
    the first failure in a window is a line, the rest are counted into the next one."""
    import logging
    seen = _count_requests(monkeypatch)
    with tls_worker(pki) as (worker, port):
        with caplog.at_level(logging.WARNING, logger="noctornal.analysis.worker"):
            for _ in range(20):
                plain = socket.create_connection(("127.0.0.1", port), timeout=5)
                plain.sendall(b"not a handshake\r\n")
                plain.close()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and worker._turned_away < 19:
                time.sleep(0.05)
        lines = [r for r in caplog.records if "failed its TLS handshake" in r.getMessage()]
        assert len(lines) == 1, [r.getMessage() for r in lines]
        assert worker._turned_away == 19
        assert ar.hello(target_for(pki, port))["transport"] == "tcp_tls"
        monkeypatch.setattr(aw, "HANDSHAKE_LOG_EVERY_S", 0.0)
        with caplog.at_level(logging.WARNING, logger="noctornal.analysis.worker"):
            plain = socket.create_connection(("127.0.0.1", port), timeout=5)
            plain.sendall(b"not a handshake\r\n")
            plain.close()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and worker._turned_away:
                time.sleep(0.05)
        assert any("19 more since the last report" in r.getMessage() for r in caplog.records)
    assert seen == [1]


def test_a_plaintext_peer_gets_no_answer_and_the_worker_serves_on(pki, monkeypatch):
    seen = _count_requests(monkeypatch)
    with tls_worker(pki) as (_worker, port):
        plain = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            plain.sendall(ar.pack_frame({"v": ar.WIRE_VERSION, "id": "0" * 32, "kind": ar.HELLO}))
            plain.settimeout(5)
            try:
                got = plain.recv(64)
            except OSError:
                got = b""
            assert ar.MAGIC not in got, "a frame was answered in the clear"
        finally:
            plain.close()
        assert ar.hello(target_for(pki, port))["transport"] == "tcp_tls"
    assert seen == [1]


# ---------------------------------------------------------------------------
# The worker's own healthcheck
# ---------------------------------------------------------------------------

def test_check_in_tcp_mode_answers_over_mutual_tls(pki, tmp_path, capsys):
    """`--check` is the pod's own probe: it dials the worker's own listener and presents the worker's own
    certificate as the client's, so that certificate carries both purposes. The listener's address is a pod's
    IP, which no certificate names, so the name is not checked here (and the network fence is not applied:
    it dials the listener it just opened and nothing else)."""
    named = make_pki(tmp_path / "n", "n", server_names=(NAME,))
    with tls_worker(named) as (_worker, port):
        env = {ar.LISTEN_ENV: f"127.0.0.1:{port}", ar.TLS_CERT_ENV: str(named.server_cert),
               ar.TLS_KEY_ENV: str(named.server_key), ar.TLS_CA_ENV: str(named.ca)}
        assert aw.check(env) == 0
        # Another CA's certificate is not the channel's.
        wrong = make_pki(tmp_path / "w", "w")
        assert aw.check({**env, ar.TLS_CERT_ENV: str(wrong.server_cert),
                         ar.TLS_KEY_ENV: str(wrong.server_key)}) == 1
    assert "did not answer" in capsys.readouterr().err
    assert aw.check({ar.LISTEN_ENV: "0.0.0.0:1"}) == 1
    assert aw.check({}) == 1


def test_a_certificate_for_serving_only_cannot_call_the_worker(tmp_path):
    """The caller's certificate must be valid for client authentication: one issued for server
    authentication alone is refused by the worker, whatever CA signed it."""
    from cryptography.x509.oid import ExtendedKeyUsageOID as Eku
    serving = make_pki(tmp_path / "s", "s", client_usages=[Eku.SERVER_AUTH])
    with tls_worker(serving) as (_worker, port):
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(target_for(serving, port))


# ---------------------------------------------------------------------------
# What the child reports of the network (the self-test the register reads)
# ---------------------------------------------------------------------------

def test_a_name_that_does_not_resolve_proves_nothing_and_is_said(monkeypatch):
    """A worker in a pod has no DNS, so every name is "unreachable" there whatever the policy allows;
    the report says which targets were names it could not resolve, apart from one that was tried
    and not answered."""
    from noctornal_api import lab_static
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    shut_port = closed.getsockname()[1]
    closed.close()
    real = socket.getaddrinfo

    def lookup(host, *args, **kwargs):
        if str(host).endswith(".invalid"):
            raise socket.gaierror(socket.EAI_NONAME, "no such name")
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", lookup)
    out = lab_static._exposure({"host": "postgres.noctornal.svc.invalid", "port": 5432,
                                "canary": {"host": "canary.noctornal.svc.invalid", "port": 9}})
    assert out["database_reachable"] is False and out["canary_reachable"] is False
    assert out["unresolved"] == ["database", "canary"]
    tried = lab_static._exposure({"host": "127.0.0.1", "port": shut_port,
                                  "canary": {"host": "127.0.0.1", "port": shut_port}})
    assert tried["database_reachable"] is False and tried["canary_reachable"] is False
    assert tried["unresolved"] == [], "a refused literal was tried, so it is not a lookup failure"
    assert lab_static._exposure({})["unresolved"] == []


def test_the_childs_exposure_report_names_the_database_and_the_canary_separately():
    from noctornal_api import lab_static
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    open_port = listener.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    shut_port = closed.getsockname()[1]
    closed.close()
    try:
        both = lab_static._exposure({"host": "127.0.0.1", "port": shut_port,
                                     "canary": {"host": "127.0.0.1", "port": open_port}})
        assert both["database_reachable"] is False and both["canary_reachable"] is True
        other = lab_static._exposure({"host": "127.0.0.1", "port": open_port,
                                      "canary": {"host": "127.0.0.1", "port": shut_port}})
        assert other["database_reachable"] is True and other["canary_reachable"] is False
        none = lab_static._exposure({})
        assert none["database_reachable"] is None and none["canary_reachable"] is None
        for bad in (None, "x", {"canary": "x"}, {"canary": {"host": "h", "port": True}},
                    {"host": "127.0.0.1", "port": "9"}):
            out = lab_static._exposure(bad)
            assert out["canary_reachable"] is None and out["database_reachable"] is None
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# A pids limit a pod's container cannot read may be declared (decision 239)
# ---------------------------------------------------------------------------

POD = {aw.POD_ENV: "10.96.0.1"}


def _pod_env(pki, **extra):
    return {ar.LISTEN_ENV: "127.0.0.1:9443", ar.TLS_CERT_ENV: str(pki.server_cert),
            ar.TLS_KEY_ENV: str(pki.server_key), ar.TLS_CA_ENV: str(pki.ca), **POD, **extra}


def _facts_in(env, monkeypatch, *, cgroup):
    """`process_facts(env)` with the cgroup saying `cgroup` (None is "max" or unreadable), and the rest of
    the supervisor's facts as a container would have them."""
    monkeypatch.setattr(aw, "read_pids_max", lambda **_: cgroup)
    return {**SUPERVISED, **{k: v for k, v in aw.process_facts(env).items()
                             if k in ("pids_max", "pids_max_source")}}


def test_a_pids_limit_declared_is_used_only_when_the_cgroup_says_max_and_only_inside_the_window(
        pki, monkeypatch):
    need, ceiling = aw.pids_needed(aw.DEFAULT_CONCURRENCY), aw.pids_ceiling(aw.DEFAULT_CONCURRENCY)
    env = _pod_env(pki, **{ar.PIDS_LIMIT_ENV: "128"})
    facts = _facts_in(env, monkeypatch, cgroup=None)
    assert facts["pids_max"] == 128 and facts["pids_max_source"] == "declared"
    assert aw.start_problems(env, facts=facts) == []
    for edge in (need, ceiling):
        said = _facts_in({**env, ar.PIDS_LIMIT_ENV: str(edge)}, monkeypatch, cgroup=None)
        assert aw.start_problems({**env, ar.PIDS_LIMIT_ENV: str(edge)}, facts=said) == []
    for outside, words in ((need - 1, "slots need"), (ceiling + 1, "bounds nothing")):
        bad = {**env, ar.PIDS_LIMIT_ENV: str(outside)}
        problems = aw.start_problems(bad, facts=_facts_in(bad, monkeypatch, cgroup=None))
        assert len(problems) == 1, problems
        assert f"The pids limit declared in {ar.PIDS_LIMIT_ENV} is {outside}" in problems[0]
        assert words in problems[0] and "podPidsLimit" in problems[0]
    # Nothing declared and nothing readable still refuses, and now says how a pod tells the worker.
    nothing = _pod_env(pki)
    problems = aw.start_problems(nothing, facts=_facts_in(nothing, monkeypatch, cgroup=None))
    assert len(problems) == 1 and "no pids limit it can read" in problems[0]
    assert ar.PIDS_LIMIT_ENV in problems[0]


def test_a_readable_cgroup_value_beats_a_declared_one(pki, monkeypatch):
    env = _pod_env(pki, **{ar.PIDS_LIMIT_ENV: "999"})
    facts = _facts_in(env, monkeypatch, cgroup=128)
    assert facts["pids_max"] == 128 and facts["pids_max_source"] == "cgroup"
    assert aw.start_problems(env, facts=facts) == []
    # A cgroup value outside the window is judged as it was, and the declaration cannot rescue it.
    low = _facts_in(env, monkeypatch, cgroup=8)
    problems = aw.start_problems(env, facts=low)
    assert len(problems) == 1 and "The service's pids limit is 8" in problems[0]
    assert ar.PIDS_LIMIT_ENV not in problems[0]


@pytest.mark.parametrize("value", ["abc", "0", "-5", "12.5", "128 ", "1e2", "\uff11\uff12\uff18"])
def test_a_pids_limit_that_is_not_a_whole_number_refuses_the_start_by_name(pki, value):
    env = _pod_env(pki, **{ar.PIDS_LIMIT_ENV: value})
    if value == "128 ":
        # Surrounding space is trimmed, as every other worker setting's is.
        assert aw.declared_pids_limit(env) == (128, None)
        return
    limit, problem = aw.declared_pids_limit(env)
    assert limit is None and ar.PIDS_LIMIT_ENV in problem and "whole number" in problem
    problems = aw.start_problems(env, facts=SUPERVISED)
    assert problems and ar.PIDS_LIMIT_ENV in problems[0]
    assert value.strip() not in problems[0]


def test_a_pids_limit_declared_outside_a_pod_refuses_the_start_and_is_never_used(pki, monkeypatch):
    """A compose deployment cannot switch off "judge the running process" by typing a variable: the
    declaration is honoured only where the kubelet says it is a pod."""
    env = {k: v for k, v in _pod_env(pki, **{ar.PIDS_LIMIT_ENV: "128"}).items() if k != aw.POD_ENV}
    limit, problem = aw.declared_pids_limit(env)
    assert limit is None and "outside a pod" in problem and aw.POD_ENV in problem
    facts = _facts_in(env, monkeypatch, cgroup=None)
    assert facts["pids_max"] is None and facts["pids_max_source"] is None
    problems = aw.start_problems(env, facts=SUPERVISED)
    assert len(problems) == 1 and "outside a pod" in problems[0]
    # Blank is unset, as every other setting's is.
    assert aw.declared_pids_limit({**env, ar.PIDS_LIMIT_ENV: "  "}) == (None, None)
    assert aw.declared_pids_limit({**POD, ar.PIDS_LIMIT_ENV: ""}) == (None, None)


def test_the_hello_says_where_the_pids_limit_came_from(pki, monkeypatch):
    for name, value in {**POD, ar.PIDS_LIMIT_ENV: "128"}.items():
        monkeypatch.setenv(name, value)
    listener = socket.socket()
    try:
        worker = aw.Worker(listener)
        monkeypatch.setattr(aw, "read_pids_max", lambda **_: None)
        said = worker.status()
        assert said["pids_max"] == 128 and said["pids_max_source"] == "declared"
        monkeypatch.setattr(aw, "read_pids_max", lambda **_: 96)
        said = worker.status()
        assert said["pids_max"] == 96 and said["pids_max_source"] == "cgroup"
    finally:
        listener.close()


def test_the_pids_limit_is_the_workers_own_setting_by_exact_name():
    assert ar.PIDS_LIMIT_ENV == "NOCTORNAL_ANALYSIS_PIDS_LIMIT"
    assert ar.PIDS_LIMIT_ENV in ar.WORKER_OWN_ENV
    assert ar.foreign_environment([ar.PIDS_LIMIT_ENV, "NOCTORNAL_ANALYSIS_PIDS_LIMIT_FILE",
                                   "NOCTORNAL_ANALYSIS_PIDS"]) == [
        "NOCTORNAL_ANALYSIS_PIDS", "NOCTORNAL_ANALYSIS_PIDS_LIMIT_FILE"]
