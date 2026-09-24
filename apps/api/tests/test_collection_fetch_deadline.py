"""c2 (2026-09-24): one watched source could hold the collector for ever.

`fetch(timeout=...)` bounded each socket operation and nothing bounded the
call. A far end answering `Content-Length: 16000000` and then sending one
byte every few seconds kept every single recv inside the timeout, so the
read never returned: the source's poll lock and its RUNNING run row stayed
held, the pass it was in never finished, and in the production cron loop
the notification drain queued behind that pass never ran again. The same
held for a header line that never ends.

The fix is one wall-clock allowance per fetch, `max_seconds`, enforced by a
watchdog that shuts the socket down under a read that outlives it. These
tests drip on purpose and assert the call comes back inside its allowance
with the allowance named as the reason.

Every drip here is over TLS, or is a TLS record, on purpose. A desktop
antivirus that inspects plain HTTP on loopback buffers the body before
the client sees it, so a plain-HTTP drip looks like a per-operation
timeout on such a host and the test would pass against the old code.

Pure: no database, and no network beyond loopback.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time

import pytest
from test_collection_ssrf_rebinding import (
    NAME,
    PUBLIC,
    _certificates,
    _Rebinder,
)

from noctornal_api import collection
from noctornal_api.collection import CollectionError, fetch

#: Far inside the per-operation timeout the tests pass, so no single recv
#: ever times out and only the whole-call allowance can end the fetch.
DRIP_INTERVAL = 0.2
PER_OPERATION = 3.0
ALLOWANCE = 1.5
#: How late a fetch may come back after its allowance runs out: the
#: watchdog's wake-up plus the reader noticing, on a loaded test host.
SLACK = 2.5


class _Drip:
    """A loopback listener that answers every connection with `head` and
    then one byte of `unit` every DRIP_INTERVAL until it is stopped.

    `tls` wraps each accepted connection server side first, so the drip
    arrives inside TLS records, one record per byte. Without it the bytes
    go out raw, which is how the handshake drip below speaks TLS to a
    client that is still waiting for the server's first record.
    """

    def __init__(self, *, head: bytes, unit: bytes,
                 tls: ssl.SSLContext | None, read_request: bool,
                 drip: bool = True):
        self.head = head
        self.unit = unit
        #: False sends `head` and closes: a body that stops short.
        self.drip = drip
        self.tls = tls
        self.read_request = read_request
        self.sent = 0
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((PUBLIC, 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                raw, _peer = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._answer, args=(raw,),
                             daemon=True).start()

    def _answer(self, raw: socket.socket) -> None:
        conn = raw
        try:
            raw.settimeout(10)
            if self.tls is not None:
                conn = self.tls.wrap_socket(raw, server_side=True)
            if self.read_request:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    request += chunk
            conn.sendall(self.head)
            while self.drip and not self.stop.wait(DRIP_INTERVAL):
                conn.sendall(self.unit)
                self.sent += 1
        except OSError:
            # The client cutting the connection is the outcome under test.
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        self.listener.close()


@pytest.fixture
def drip(tmp_path, monkeypatch):
    """Starts a `_Drip` on PUBLIC; yields a starter returning the server
    and a client context that trusts the throwaway CA.

    The classifier is told PUBLIC is public and nothing else, as
    test_collection_ssrf_rebinding.py's `public_standin` does, and NAME
    always resolves to it."""
    started: list[_Drip] = []
    real = collection._is_blocked
    monkeypatch.setattr(
        collection, "_is_blocked",
        lambda address: False if str(address) == PUBLIC else real(address))
    monkeypatch.setattr(socket, "getaddrinfo",
                        _Rebinder(first=[PUBLIC], later=[PUBLIC]))

    def start(*, head: bytes, unit: bytes = b"x", tls: bool = True,
              read_request: bool = True, drip: bool = True):
        ca_pem, cert_path, key_path = _certificates(tmp_path, [NAME], [])
        server_context = None
        if tls:
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(cert_path, key_path)
        server = _Drip(head=head, unit=unit, tls=server_context,
                       read_request=read_request, drip=drip)
        started.append(server)
        return server, ssl.create_default_context(cadata=ca_pem)

    yield start
    for server in started:
        server.close()


def _timed_fetch(server: _Drip, client: ssl.SSLContext):
    began = time.monotonic()
    with pytest.raises(CollectionError) as err:
        fetch(f"https://{NAME}:{server.port}/feed", timeout=PER_OPERATION,
              max_seconds=ALLOWANCE, tls_context=client)
    return time.monotonic() - began, str(err.value)


def test_a_body_dripped_a_byte_at_a_time_ends_inside_the_allowance(drip):
    """The reported failure: a 200 declaring sixteen million bytes, then a
    byte every DRIP_INTERVAL. Before the fix this read never returned."""
    server, client = drip(
        head=b"HTTP/1.1 200 OK\r\nContent-Length: 16000000\r\n\r\n")

    elapsed, message = _timed_fetch(server, client)

    assert "second budget" in message, message
    assert elapsed < ALLOWANCE + SLACK, (
        f"fetch took {elapsed:.1f}s against an allowance of {ALLOWANCE}s")
    assert server.sent >= 2, (
        "the server never got to drip, so this proved nothing about a "
        "read that keeps receiving")


def test_a_header_line_that_never_ends_ends_inside_the_allowance(drip):
    """The same hang one step earlier, inside `getresponse()`: a header
    line one byte at a time, each byte well inside the per-operation
    timeout."""
    server, client = drip(head=b"HTTP/1.1 200 OK\r\nX-Drip: ", unit=b"a")

    elapsed, message = _timed_fetch(server, client)

    assert "second budget" in message, message
    assert elapsed < ALLOWANCE + SLACK
    assert server.sent >= 2


def test_a_tls_handshake_dripped_a_byte_at_a_time_ends_inside_the_allowance(
        drip):
    """The server's first TLS record header, declaring a sixteen kilobyte
    handshake record, then its body a byte at a time. OpenSSL waits for the
    whole record before it parses any of it, so every recv succeeds and
    the handshake never finishes.

    CPython already runs one handshake under one socket timeout, so this
    was never unbounded; what is pinned here is that the ALLOWANCE governs
    it when less of the allowance is left than a full timeout, and that
    the error then names the allowance rather than a timeout."""
    server, client = drip(head=b"\x16\x03\x03\x40\x00", unit=b"\x00",
                          tls=False, read_request=False)

    elapsed, message = _timed_fetch(server, client)

    assert "second budget" in message, message
    assert elapsed < ALLOWANCE + SLACK
    assert server.sent >= 2


def test_a_body_that_stops_short_of_its_declared_length_is_refused(drip):
    """What a cut read looks like from inside: `HTTPResponse.read(n)`
    hands back a short body without complaint when the connection ends
    early. A partial feed is not the feed, so it is refused by name."""
    server, client = drip(
        head=b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n<rss>",
        drip=False)

    with pytest.raises(CollectionError, match="short of the length"):
        fetch(f"https://{NAME}:{server.port}/feed", timeout=PER_OPERATION,
              max_seconds=10, tls_context=client)


def test_no_address_is_dialled_once_the_allowance_is_spent(monkeypatch):
    """`_dial` tried every pinned address at the full timeout each, on
    every hop. Once the allowance is gone it tries none, and says why."""
    created: list[tuple] = []

    class Counting(socket.socket):
        def __init__(self, *args, **kwargs):
            created.append(args)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(socket, "socket", Counting)
    hop = collection._Hop(
        "http", NAME, 80, "/",
        tuple((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
               (f"192.0.2.{n}", 80)) for n in (1, 2, 3)))
    spent = collection._Deadline(0.0)

    with pytest.raises(CollectionError, match="second budget"):
        collection._dial(hop, 15.0, spent)
    assert created == [], "an address was dialled after the allowance ran out"


def test_the_default_allowance_is_what_the_rss_adapter_gets(monkeypatch):
    """The adapter passes no allowance of its own, so the signature's
    default is the bound every scheduled poll and every Run press is held
    to. Pinned so it cannot quietly become None, or a figure longer than
    a cron pass."""
    import inspect

    seen: dict = {}

    def recording(url, **kwargs):
        seen.update(kwargs)
        return b"", 304, None, None

    default = inspect.signature(fetch).parameters["max_seconds"].default
    assert default == collection.MAX_FETCH_SECONDS
    assert 0 < collection.MAX_FETCH_SECONDS <= 120

    monkeypatch.setattr(collection, "fetch", recording)
    collection.RssAdapter().fetch(base_url=f"https://{NAME}/feed")
    assert seen.get("max_seconds", default) == default
