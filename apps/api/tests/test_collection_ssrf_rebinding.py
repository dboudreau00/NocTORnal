"""sec-ssrf-rebinding (2026-09-23): the check and the connect are one lookup.

`collection.fetch()` resolved a watch target's name once to check it, and
`urlopen` resolved it again inside `socket.create_connection` to connect.
A resolver answering a public address to the first lookup and an internal
one to the second (DNS rebinding) walked straight through the check. These
tests stand in a resolver that does exactly that and prove the internal
address is never CONNECTED to: not refused after the fact, never dialled.

The stand-ins. 127.0.0.1 plays the public address: the classifier is told
so about that one address and no other. 127.0.0.2 plays the internal one
and is judged by the real classifier. A listener on 127.0.0.2 records every
TCP connection it accepts, so "never connected" is an observation rather
than an inference.

The fake resolver replaces `socket.getaddrinfo` itself, not a name inside
`collection`, because the second lookup this defect was made of happened
inside the standard library. Anything short of the real function would
have let the old code pass.

Pure: no database, and no network beyond loopback.
"""
from __future__ import annotations

import ast
import http.server
import inspect
import ipaddress
import socket
import socketserver
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest

from noctornal_api import collection
from noctornal_api.collection import CollectionError, fetch

#: The name every test fetches. `.test` is reserved (RFC 2606), so the
#: real resolver could never answer it by accident.
NAME = "feed.rebind.test"
#: Plays a public address. Only this one address is waved through.
PUBLIC = "127.0.0.1"
#: Plays an internal address, and IS one: the real classifier refuses it.
INTERNAL = "127.0.0.2"

PUBLIC_BODY = b"<rss><channel><title>public</title></channel></rss>"
INTERNAL_BODY = b"INTERNAL PAGE"

_REAL_GETADDRINFO = socket.getaddrinfo


class _Handler(http.server.BaseHTTPRequestHandler):
    """Records the path and Host of each request, then answers with a
    redirect when the server has one set for that path, else its body."""

    def do_GET(self):  # noqa: N802 - the stdlib's naming
        server = self.server
        server.seen.append((self.path, self.headers.get("Host")))
        server.conditions.append(self.headers.get("If-None-Match"))
        target = server.redirects.get(self.path)
        if target is not None:
            self.send_response(302)
            if target:
                self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if server.etag and self.headers.get("If-None-Match") == server.etag:
            self.send_response(304)
            self.send_header("ETag", server.etag)
            self.end_headers()
            return
        if server.status != 200:
            self.send_response(server.status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/rss+xml")
        self.send_header("Content-Length", str(len(server.body)))
        if server.etag:
            self.send_header("ETag", server.etag)
        self.end_headers()
        self.wfile.write(server.body)

    def log_message(self, *_args):
        pass


class _Server(http.server.HTTPServer):
    """An HTTP server that remembers every connection it accepted."""

    def __init__(self, address, body: bytes):
        self.body = body
        #: `(path, Host)` of every request answered.
        self.seen: list[tuple[str, str | None]] = []
        #: The peer of every TCP connection accepted, before any HTTP.
        self.connections: list[tuple] = []
        #: `If-None-Match` of every request answered, None when absent.
        self.conditions: list[str | None] = []
        #: path -> Location to answer it with; "" answers a 302 with none.
        self.redirects: dict[str, str] = {}
        #: Sent as ETag, and a matching `If-None-Match` is answered 304.
        self.etag: str | None = None
        #: Any status but 200 is sent with an empty body.
        self.status = 200
        #: Server names clients sent in TLS SNI.
        self.sni: list[str | None] = []
        super().__init__(address, _Handler)

    def server_bind(self):
        # HTTPServer.server_bind asks DNS for the fully qualified name of
        # the bound address, which for 127.0.0.2 can stall; nothing here
        # needs it.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def verify_request(self, request, client_address):
        self.connections.append(client_address)
        return True


def _start(server: _Server) -> threading.Thread:
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05},
        daemon=True)
    thread.start()
    return thread


def _stop(server: _Server) -> None:
    server.shutdown()
    server.server_close()


class _Rebinder:
    """A resolver for NAME that answers `first` to the first lookup and
    `later` to every lookup after it, with the port it was asked for, as
    a real resolver would. Any other name goes to the real resolver."""

    def __init__(self, first: list[str], later: list[str]):
        self.first = first
        self.later = later
        self.lookups = 0

    def __call__(self, host, port, *args, **kwargs):
        if host != NAME:
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)
        self.lookups += 1
        answer = self.first if self.lookups == 1 else self.later
        number = int(port) if port else 0
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                 (address, number)) for address in answer]


@pytest.fixture
def public_standin(monkeypatch):
    """The classifier, told that PUBLIC is public and nothing else."""
    real = collection._is_blocked
    monkeypatch.setattr(
        collection, "_is_blocked",
        lambda address: False if str(address) == PUBLIC else real(address))


@pytest.fixture
def pair(public_standin):
    """A public server and an internal listener on the SAME port, so a
    rebinding resolver can send one name to either with a real resolver's
    answer shape."""
    public = _Server((PUBLIC, 0), PUBLIC_BODY)
    port = public.server_address[1]
    try:
        internal = _Server((INTERNAL, port), INTERNAL_BODY)
    except OSError as exc:
        public.server_close()
        pytest.skip(f"cannot listen on {INTERNAL}:{port} ({exc}); this host "
                    f"has no second loopback address")
    _start(public)
    _start(internal)
    yield public, internal, port
    _stop(public)
    _stop(internal)


# ---------------------------------------------------------------------------
# The defect: a second lookup between the check and the connect
# ---------------------------------------------------------------------------

def test_a_name_that_rebinds_after_the_check_is_never_dialled_internally(
        pair, monkeypatch):
    """The first lookup says public, every later one says internal. The
    old code checked the first answer and connected with the second, so
    the internal listener was dialled and its page came back as the feed.
    Now the one answer checked is the one answer used."""
    public, internal, port = pair
    resolver = _Rebinder(first=[PUBLIC], later=[INTERNAL])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    body, status, _etag, _modified = fetch(
        f"http://{NAME}:{port}/feed", timeout=5)

    assert internal.connections == [], (
        "the internal address was connected to: the name was resolved "
        "again after it was checked")
    assert (body, status) == (PUBLIC_BODY, 200)
    assert resolver.lookups == 1, "one hop is one lookup, not two"
    # The address was pinned; the NAME still addressed the request.
    assert public.seen == [("/feed", f"{NAME}:{port}")]


def test_a_redirect_hop_that_rebinds_is_refused_before_it_is_dialled(
        pair, monkeypatch):
    """A redirect back to the SAME name is the other half of rebinding:
    hop 2 is looked up afresh, and this time the answer is internal. It is
    refused on that answer and never dialled."""
    public, internal, port = pair
    public.redirects["/feed"] = "/next"
    resolver = _Rebinder(first=[PUBLIC], later=[INTERNAL])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    with pytest.raises(CollectionError, match="private address space"):
        fetch(f"http://{NAME}:{port}/feed", timeout=5)

    assert internal.connections == []
    assert resolver.lookups == 2, "one lookup per hop and none in between"
    assert [path for path, _host in public.seen] == ["/feed"]


def test_a_mixed_answer_is_refused_and_neither_address_is_dialled(
        pair, monkeypatch):
    """A name answering public AND internal is refused outright, even
    though only the public half would now be dialled: it is a rebinding
    setup or a misconfiguration, and either wants an analyst's eyes."""
    public, internal, port = pair
    resolver = _Rebinder(first=[PUBLIC, INTERNAL], later=[PUBLIC, INTERNAL])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    with pytest.raises(CollectionError, match="private address space"):
        fetch(f"http://{NAME}:{port}/feed", timeout=5)

    assert public.connections == [] and internal.connections == []


def test_nothing_in_the_collector_hands_a_name_to_the_socket_layer():
    """The regression guard. Every stdlib path that takes a NAME and
    resolves it on the way to a socket (`urlopen`, an opener,
    `create_connection`, a stock `HTTPSConnection`) is the second lookup
    this fix removed. None of them may be called from the collector;
    `_dial` connecting to a checked sockaddr is the only way out."""
    tree = ast.parse(inspect.getsource(collection))
    resolving = {"urlopen", "build_opener", "create_connection",
                 "HTTPSConnection", "HTTPConnection", "OpenerDirector"}
    called = {
        node.func.attr if isinstance(node.func, ast.Attribute)
        else getattr(node.func, "id", None)
        for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert not called & resolving, sorted(called & resolving)


# ---------------------------------------------------------------------------
# What urlopen did for fetch, still done now that fetch dials for itself
# ---------------------------------------------------------------------------

@pytest.fixture
def public_only(public_standin, monkeypatch):
    """One public server, and a resolver that always answers it."""
    server = _Server((PUBLIC, 0), PUBLIC_BODY)
    _start(server)
    resolver = _Rebinder(first=[PUBLIC], later=[PUBLIC])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    yield server, server.server_address[1], resolver
    _stop(server)


def test_a_relative_redirect_is_followed_with_one_lookup_per_hop(public_only):
    server, port, resolver = public_only
    server.redirects["/feed"] = "/next"

    body, status, _etag, _modified = fetch(
        f"http://{NAME}:{port}/feed", timeout=5)

    assert (body, status) == (PUBLIC_BODY, 200)
    assert [path for path, _host in server.seen] == ["/feed", "/next"]
    assert resolver.lookups == 2


def test_the_conditional_get_still_answers_304(public_only):
    """RssAdapter's ETag round trip: the tag comes back on a 200, goes out
    as If-None-Match, and a 304 is an empty answer rather than an error."""
    server, port, _resolver = public_only
    server.etag = '"v1"'
    url = f"http://{NAME}:{port}/feed"

    first = fetch(url, timeout=5)
    again = fetch(url, etag=first[2], timeout=5)

    assert first[:3] == (PUBLIC_BODY, 200, '"v1"')
    assert again == (b"", 304, '"v1"', None)
    assert server.conditions == [None, '"v1"']


def test_the_response_cap_still_holds(public_only):
    _server, port, _resolver = public_only
    with pytest.raises(CollectionError, match="exceeded 16 bytes"):
        fetch(f"http://{NAME}:{port}/feed", timeout=5, max_bytes=16)


def test_an_error_status_is_reported_by_its_code(public_only):
    server, port, _resolver = public_only
    server.status = 503
    with pytest.raises(CollectionError, match="HTTP 503"):
        fetch(f"http://{NAME}:{port}/feed", timeout=5)


def test_a_redirect_with_no_location_is_refused(public_only):
    server, port, _resolver = public_only
    server.redirects["/feed"] = ""
    with pytest.raises(CollectionError, match="no Location header"):
        fetch(f"http://{NAME}:{port}/feed", timeout=5)


# ---------------------------------------------------------------------------
# TLS: the address is pinned, the name is still what is verified
# ---------------------------------------------------------------------------

def _certificates(tmp_path, dns_names: list[str], ip_names: list[str]):
    """A throwaway CA and a server certificate it signed. Returns the CA
    in PEM and the paths of the server's certificate and key."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)

    def usage(*, sign_certs: bool):
        return x509.KeyUsage(
            digital_signature=not sign_certs, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=sign_certs,
            crl_sign=sign_certs, encipher_only=False, decipher_only=False)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            "rebinding test CA")])
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(hours=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                         critical=True)
          .add_extension(usage(sign_certs=True), critical=True)
          .add_extension(
              x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
              critical=False)
          .sign(ca_key, hashes.SHA256()))

    key = ec.generate_private_key(ec.SECP256R1())
    alternative = ([x509.DNSName(n) for n in dns_names]
                   + [x509.IPAddress(ipaddress.ip_address(i))
                      for i in ip_names])
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(
                NameOID.COMMON_NAME, dns_names[0])]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(usage(sign_certs=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(alternative),
                           critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))

    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return (ca.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            cert_path, key_path)


@pytest.fixture
def tls_server(public_standin, tmp_path):
    """Starts an https server on PUBLIC with a certificate for the names
    given; yields the server, its port and a client context trusting the
    test CA and nothing else."""
    started: list[_Server] = []

    def start(dns_names: list[str], ip_names: list[str] = ()):
        ca_pem, cert_path, key_path = _certificates(
            tmp_path, dns_names, list(ip_names))
        server = _Server((PUBLIC, 0), PUBLIC_BODY)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.sni_callback = (
            lambda _sock, name, _ctx: server.sni.append(name))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        _start(server)
        started.append(server)
        return (server, server.server_address[1],
                ssl.create_default_context(cadata=ca_pem))

    yield start
    for server in started:
        _stop(server)


def test_https_dials_the_checked_address_and_speaks_the_name(
        tls_server, monkeypatch):
    """SNI, Host and the certificate all carry the NAME while the socket
    goes to the number that was checked."""
    server, port, client = tls_server([NAME])
    resolver = _Rebinder(first=[PUBLIC], later=[INTERNAL])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    body, status, _etag, _modified = fetch(
        f"https://{NAME}:{port}/feed", timeout=5, tls_context=client)

    assert (body, status) == (PUBLIC_BODY, 200)
    assert server.sni == [NAME]
    assert server.seen == [("/feed", f"{NAME}:{port}")]
    assert resolver.lookups == 1


def test_the_certificate_is_checked_against_the_name_not_the_address(
        tls_server, monkeypatch):
    """The certificate here names another host AND the address dialled.
    Verified against the number, it would pass; pinning must not turn
    into trusting whatever certificate the pinned address presents."""
    server, port, client = tls_server(["elsewhere.test"], [PUBLIC])
    monkeypatch.setattr(socket, "getaddrinfo",
                        _Rebinder(first=[PUBLIC], later=[PUBLIC]))

    with pytest.raises(CollectionError, match="certificate check failed"):
        fetch(f"https://{NAME}:{port}/feed", timeout=5, tls_context=client)
    assert server.seen == [], "no request is sent over an unverified session"


def test_a_tls_context_that_skips_the_name_check_is_refused(monkeypatch):
    """Refused before anything is looked up or dialled."""
    resolver = _Rebinder(first=[PUBLIC], later=[PUBLIC])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    lax = ssl.create_default_context()
    lax.check_hostname = False

    with pytest.raises(CollectionError, match="refusing a TLS context"):
        fetch(f"https://{NAME}/feed", tls_context=lax)
    assert resolver.lookups == 0


def test_a_url_carrying_credentials_is_refused_without_echoing_them(
        monkeypatch):
    """urlopen never sent `user:pass@` either (it took the whole of
    `user:pass@host` for the host name and failed to resolve it); the
    refusal is now by name, made before any lookup, and the message does
    not repeat the secret it refused."""
    resolver = _Rebinder(first=[PUBLIC], later=[PUBLIC])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    with pytest.raises(CollectionError, match="user name or password") as err:
        fetch(f"http://persona:hunter2@{NAME}/rss")
    assert "hunter2" not in str(err.value)
    assert resolver.lookups == 0
