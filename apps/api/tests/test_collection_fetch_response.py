"""fetch_response, the superset every outbound consumer needs (2026-09-24;
docs/00 decision 72, docs/20 section 5.5), through
collection.fetch_response so the collector's public_standin seam applies:
127.0.0.1 plays the public address, as in test_collection_ssrf_rebinding.

Pure: no database, and no network beyond loopback.
"""
from __future__ import annotations

import email.parser
import email.policy
import http.server
import socket
import socketserver
import threading
import time
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone

import pytest
from test_collection_ssrf_rebinding import NAME, PUBLIC, _Rebinder

from noctornal_api import collection, pinned_http
from noctornal_api.collection import CollectionError, fetch, fetch_response
from noctornal_api.pinned_http import BodyStream, FilePart, multipart


class _Handler(http.server.BaseHTTPRequestHandler):
    def _answer(self):
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        server.requests.append({"method": self.command, "path": self.path,
                                "headers": self.headers, "body": body})
        status, headers, payload = server.script.get(self.path, (200, {}, b"feed"))
        self.send_response(status)
        for name, value in headers.items():
            for one in value if isinstance(value, list) else [value]:
                self.send_header(name, one)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_HEAD = _answer  # noqa: N815 - the stdlib's naming

    def log_message(self, *_args):
        pass


class _Scripted(http.server.HTTPServer):
    def __init__(self, host=PUBLIC):
        self.requests: list[dict] = []
        self.script: dict[str, tuple] = {}
        super().__init__((host, 0), _Handler)
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@pytest.fixture
def standin(monkeypatch):
    real = collection._is_blocked
    monkeypatch.setattr(collection, "_is_blocked",
                        lambda a: False if str(a) == PUBLIC else real(a))
    resolver = _Rebinder(first=[PUBLIC], later=[PUBLIC])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    return resolver


@pytest.fixture
def server(standin):
    s = _Scripted()
    yield s
    s.shutdown()
    s.server_close()


def _url(server, path="/feed", name=NAME):
    return f"http://{name}:{server.server_port}{path}"


def test_fetch_keeps_its_return_shape_and_messages(server):
    server.script["/feed"] = (200, {"ETag": '"v2"', "Last-Modified": "Mon, 01 Jan 2024"}, b"x")
    assert fetch(_url(server), timeout=5) == (b"x", 200, '"v2"', "Mon, 01 Jan 2024")
    request = server.requests[-1]
    assert request["headers"]["User-Agent"] == "NocTORnal-collector/1"
    assert request["headers"]["Connection"] == "close"
    assert request["headers"]["Accept-Encoding"] == "identity"


def test_non_2xx_raises_http_status_error_that_is_a_collection_error(server):
    server.script["/feed"] = (401, {}, b"")
    with pytest.raises(CollectionError) as caught:
        fetch_response(_url(server), timeout=5)
    assert isinstance(caught.value, pinned_http.HttpStatusError)
    assert caught.value.status == 401 and str(caught.value) == "HTTP 401"
    assert caught.value.request_sent and caught.value.request_complete


def test_retry_after_parses_seconds_and_http_date_and_is_clamped(server):
    soon = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=120), usegmt=True)
    for header, low, high in (("30", 30, 30), (soon, 100, 121), ("999999", 86400, 86400),
                              ("Mon, 01 Jan 2001 00:00:00 GMT", 0, 0), ("soon", None, None)):
        server.script["/feed"] = (429, {"Retry-After": header}, b"")
        with pytest.raises(pinned_http.HttpStatusError) as caught:
            fetch_response(_url(server), timeout=5)
        value = caught.value.retry_after
        if low is None:
            assert value is None
        else:
            assert low <= value <= high, (header, value)


def test_accept_status_returns_a_404_with_its_body(server):
    server.script["/feed"] = (404, {"Content-Type": "application/json; charset=utf-8"},
                              b'{"missing": true}')
    fetched = fetch_response(_url(server), accept_status={404}, timeout=5)
    assert fetched.status == 404 and fetched.body == b'{"missing": true}'
    assert fetched.media_type == "application/json"


def test_the_excerpt_is_capped_and_redacted_and_can_be_switched_off(server):
    secret = "hunter2hunter2-lookup-key"
    server.script["/feed"] = (400, {}, (f"bad key {secret}\x07\x1b[31m" + "y" * 600).encode())
    with pytest.raises(pinned_http.HttpStatusError) as caught:
        fetch_response(_url(server), timeout=5, secrets=(secret,), max_redirects=0)
    excerpt = caught.value.excerpt
    assert secret not in excerpt and "[REDACTED]" in excerpt
    assert "\x07" not in excerpt and "\x1b" not in excerpt
    assert len(excerpt.encode()) <= 300 + len("[REDACTED]")
    with pytest.raises(pinned_http.HttpStatusError) as caught:
        fetch_response(_url(server), timeout=5, error_excerpt=False)
    assert caught.value.excerpt == ""


def test_credential_requests_refuse_to_follow_only_when_they_could(server):
    url = _url(server)
    refused = [dict(method="POST", body=b"{}"), dict(body=b"x"),
               dict(headers={"Authorization": "Bearer abc"}),
               dict(secrets=("a-live-secret",))]
    for kwargs in refused:
        with pytest.raises(ValueError):
            fetch_response(url, max_redirects=3, redirects="follow", timeout=5, **kwargs)
        fetch_response(url, max_redirects=0, timeout=5, **kwargs)
    with pinned_http.secret_in_scope("live-secret-in-url"):
        with pytest.raises(ValueError):
            fetch_response(url + "?k=live-secret-in-url", timeout=5)
    # A GET carrying a credential header may follow on its own origin.
    fetch_response(url, headers={"Authorization": "Bearer abc"},
                   redirects="same_origin", timeout=5)
    # A body never follows, not even on its own origin.
    for kwargs in (dict(method="POST", body=b"{}"), dict(method="PUT")):
        with pytest.raises(ValueError):
            fetch_response(url, redirects="same_origin", timeout=5, **kwargs)
    # One request per accepted call; nothing was sent for a refused one.
    assert len(server.requests) == len(refused) + 1


def test_max_redirects_zero_never_follows(server, standin):
    second = _Scripted()
    try:
        target = f"http://other.rebind.test:{second.server_port}/next?page=abcdefgh12345&x=1"
        server.script["/feed"] = (302, {"Location": target}, b"ignored body")
        fetched = fetch_response(_url(server), max_redirects=0,
                                 accept_status={302}, timeout=5)
        assert fetched.status == 302 and fetched.body == b""
        assert fetched.location == target, "the raw Location, query kept"
        with pytest.raises(pinned_http.HttpStatusError) as caught:
            fetch_response(_url(server), max_redirects=0, timeout=5)
        assert caught.value.location == f"http://other.rebind.test:{second.server_port}/next"
        assert caught.value.location_host == "other.rebind.test"
        assert caught.value.excerpt == ""
        assert second.requests == []
    finally:
        second.shutdown()
        second.server_close()


def test_a_same_origin_302_keeps_its_query_for_the_caller(server):
    """Fetched.location is what the collection RunContext follows, so it is
    the URL the server named, not a redacted copy."""
    server.script["/feed"] = (302, {"Location": "/login?next=%2Fforum%2Fthread&token_hint=abcdefgh12"}, b"")
    fetched = fetch_response(_url(server), max_redirects=0, accept_status={302}, timeout=5)
    assert fetched.location == _url(server, "/login?next=%2Fforum%2Fthread&token_hint=abcdefgh12")


def test_a_redirect_beyond_a_positive_limit_is_too_many_redirects_with_the_collectors_text(server):
    server.script["/feed"] = (302, {"Location": "/a"}, b"")
    server.script["/a"] = (302, {"Location": "/b"}, b"")
    with pytest.raises(pinned_http.RedirectRefused) as caught:
        fetch_response(_url(server), max_redirects=1, timeout=5)
    assert caught.value.code == "too_many_redirects"
    assert str(caught.value) == ("more than 1 redirects. A chain this long is a loop or "
                                 "an attempt to exhaust the validator, and neither is a feed")


def test_same_origin_refuses_a_redirect_to_another_origin_and_sends_nothing_there(server):
    second = _Scripted()
    try:
        server.script["/feed"] = (302, {"Location": f"http://{NAME}:{second.server_port}/x"}, b"")
        with pytest.raises(pinned_http.RedirectRefused) as caught:
            fetch_response(_url(server), redirects="same_origin", timeout=5)
        assert caught.value.code == "off_origin_redirect"
        assert second.requests == []
    finally:
        second.shutdown()
        second.server_close()


def test_same_origin_follows_a_redirect_on_the_same_origin(server):
    server.script["/feed"] = (301, {"Location": "/moved"}, b"")
    fetched = fetch_response(_url(server), redirects="same_origin", timeout=5)
    assert fetched.url == _url(server, "/moved") and fetched.redirects == 1


def test_the_final_url_is_reported_after_redirects(server):
    server.script["/feed"] = (307, {"Location": "/a"}, b"")
    server.script["/a"] = (308, {"Location": "/b"}, b"")
    fetched = fetch_response(_url(server), timeout=5)
    assert fetched.url == _url(server, "/b") and fetched.redirects == 2
    assert fetched.via == "DIRECT" and fetched.peer == PUBLIC


@pytest.mark.parametrize("name", ["Host", "connection", "Content-Length",
                                  "Transfer-Encoding", "User-Agent",
                                  "Proxy-Authorization", "Proxy-Connection", "TE",
                                  "Upgrade", "Keep-Alive", "Expect", "Accept-Encoding"])
def test_headers_cannot_override_host_connection_length_agent_encoding_or_proxy_headers(
        server, name):
    with pytest.raises(ValueError):
        fetch_response(_url(server), headers={name: "x"}, max_redirects=0, timeout=5)
    assert server.requests == []


def test_header_values_and_counts_are_bounded(server):
    for headers in ({"X-A": "one\r\nX-Injected: 1"}, {"X-A": "a" * 8193},
                    {"Bad Name": "x"}, {f"X-{i}": "v" for i in range(33)},
                    {"X-A": "1", "x-a": "2"}):
        with pytest.raises(ValueError):
            fetch_response(_url(server), headers=headers, max_redirects=0, timeout=5)


def test_user_agent_none_sends_no_header(server):
    fetch_response(_url(server), user_agent=None, timeout=5)
    assert "User-Agent" not in server.requests[-1]["headers"]
    fetch_response(_url(server), user_agent="NocTORnal-jira/1", timeout=5)
    assert server.requests[-1]["headers"]["User-Agent"] == "NocTORnal-jira/1"


def test_set_cookie_is_readable_from_the_headers(server):
    server.script["/feed"] = (200, {"Set-Cookie": ["a=1; Path=/", "b=2; Path=/"]}, b"")
    fetched = fetch_response(_url(server), timeout=5)
    assert fetched.headers.get_all("Set-Cookie") == ["a=1; Path=/", "b=2; Path=/"]


# ---------------------------------------------------------------------------
# Sent against lost: the three facts
# ---------------------------------------------------------------------------

class _Raw:
    """A loopback listener running `behave(conn)` for each connection."""

    def __init__(self, behave):
        self.listener = socket.socket()
        self.listener.bind((PUBLIC, 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.behave = behave
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn):
        try:
            self.behave(conn)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.listener.close()


def _read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _reset(conn):
    import struct
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def test_request_sent_means_any_byte(standin):
    def half_then_reset(conn):
        head = _read_head(conn)
        assert head
        conn.recv(10)
        _reset(conn)

    def all_then_close(conn):
        data = _read_head(conn)
        while len(data) < 200000:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk

    chunk = b"z" * 65536
    for behave, complete in ((half_then_reset, False), (all_then_close, True)):
        raw = _Raw(behave)
        # Far more than the socket buffers hold, so the reset lands while
        # the body is still being written; a body the server reads whole.
        body = (BodyStream(len(chunk) * 512, iter([chunk] * 512)) if not complete
                else b"z" * 100000)
        try:
            with pytest.raises(pinned_http.RequestUncertain) as caught:
                fetch_response(f"http://{NAME}:{raw.port}/up", method="POST",
                               body=body, max_redirects=0, timeout=5)
            assert caught.value.request_sent and caught.value.connected
            assert caught.value.request_complete is complete, behave.__name__
        finally:
            raw.close()
    listener = socket.socket()
    listener.bind((PUBLIC, 0))
    port = listener.getsockname()[1]
    listener.close()
    with pytest.raises(pinned_http.Unreachable) as caught:
        fetch_response(f"http://{NAME}:{port}/up", method="POST", body=b"x",
                       max_redirects=0, timeout=5)
    assert type(caught.value) is pinned_http.Unreachable
    assert caught.value.request_sent is False and caught.value.connected is False
    assert caught.value.code == "connect_refused"


def test_a_body_stream_is_held_to_its_declared_length(server):
    for chunks in ([b"abc", b"def"], [b"abcdefg"]):
        with pytest.raises(pinned_http.RequestUncertain) as caught:
            fetch_response(_url(server), method="POST",
                           body=BodyStream(6, iter(chunks + [b"XYZ"])),
                           max_redirects=0, timeout=5)
        assert caught.value.code == "body_length_mismatch"
    with pytest.raises(pinned_http.RequestUncertain) as caught:
        fetch_response(_url(server), method="POST", body=BodyStream(10, iter([b"short"])),
                       max_redirects=0, timeout=5)
    assert caught.value.code == "body_length_mismatch"
    assert all(b"XYZ" not in r["body"] for r in server.requests)
    fetch_response(_url(server), method="POST", body=BodyStream(6, iter([b"abc", b"def"])),
                   max_redirects=0, timeout=5)
    assert server.requests[-1]["body"] == b"abcdef"


def test_a_post_body_read_slowly_by_the_far_end_ends_inside_the_allowance(standin):
    def slow_reader(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        _read_head(conn)
        for _ in range(100):
            time.sleep(0.2)
            if not conn.recv(1):
                return

    raw = _Raw(slow_reader)
    began = time.monotonic()
    try:
        with pytest.raises(pinned_http.DeadlineExceeded) as caught:
            fetch_response(f"http://{NAME}:{raw.port}/up", method="POST",
                           body=b"q" * (8 * 1024 * 1024), max_redirects=0, timeout=3,
                           deadline=1.5)
    finally:
        raw.close()
    assert time.monotonic() - began < 1.5 + 2.5
    assert caught.value.request_sent


def test_the_deadline_accepts_seconds_or_a_shared_entered_deadline(standin):
    def drip(conn):
        _read_head(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
        for _ in range(50):
            time.sleep(0.1)
            conn.sendall(b"a")

    raw = _Raw(drip)
    url = f"http://{NAME}:{raw.port}/slow"
    try:
        began = time.monotonic()
        with pytest.raises(pinned_http.DeadlineExceeded):
            fetch_response(url, timeout=3, deadline=1.0)
        assert time.monotonic() - began < 1.0 + 2.5
        with pinned_http.Deadline(1.2) as shared:
            with pytest.raises(pinned_http.DeadlineExceeded):
                fetch_response(url, timeout=3, deadline=shared)
            with pytest.raises(pinned_http.DeadlineExceeded):
                fetch_response(url, timeout=3, deadline=shared)
        with pytest.raises(ValueError):
            fetch_response(url, deadline=pinned_http.Deadline(5))
    finally:
        raw.close()


def test_max_seconds_and_max_bytes_are_bounded(server):
    for kwargs in (dict(max_seconds=0), dict(max_seconds=901), dict(max_bytes=-1),
                   dict(max_bytes=256 * 1024 * 1024 + 1), dict(max_redirects=11),
                   dict(redirects="none"), dict(method="TRACE"), dict(timeout=0),
                   dict(body="text"), dict(user_agent="x\r\ny")):
        with pytest.raises(ValueError):
            fetch_response(_url(server), **kwargs)
    assert server.requests == []


def test_response_too_large_is_its_own_type(server):
    server.script["/feed"] = (200, {}, b"x" * 64)
    with pytest.raises(pinned_http.ResponseTooLarge) as caught:
        fetch_response(_url(server), max_bytes=16, timeout=5)
    assert caught.value.max_bytes == 16 and "exceeded 16 bytes" in str(caught.value)


def test_multipart_shape_and_length(server):
    stream, content_type = multipart(
        {"options": "procmemdump=1", "timeout": "300"},
        [FilePart("file", "sampleé.bin", "application/octet-stream", b"\x00MZ\x90"),
         FilePart("extra", "big.bin", "application/octet-stream",
                  BodyStream(5, iter([b"12", b"345"])))])
    fetch_response(_url(server), method="POST", body=stream,
                   headers={"Content-Type": content_type}, max_redirects=0, timeout=5)
    sent = server.requests[-1]["body"]
    assert len(sent) == stream.length
    message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + sent)
    parts = {part.get_param("name", header="content-disposition"): part
             for part in message.iter_parts()}
    assert parts["options"].get_content() == "procmemdump=1"
    assert parts["file"].get_content() == b"\x00MZ\x90"
    assert parts["extra"].get_content() == b"12345"
    for bad in ({"a\"b": "x"}, {"a\rb": "x"}):
        with pytest.raises(ValueError):
            multipart(bad, [])
    for part in (FilePart("f", 'a".bin', "text/plain", b""),
                 FilePart("f", "a.bin", "text/plain\r\nX-Evil: 1", b""),
                 FilePart("f", "a\x00.bin", "text/plain", b"")):
        with pytest.raises(ValueError):
            multipart({}, [part])


def test_unresolvable_host_is_permanent_only_for_nxdomain(monkeypatch):
    def failing(errno):
        def resolver(*_a, **_k):
            raise socket.gaierror(errno, "no")
        return resolver

    monkeypatch.setattr(socket, "getaddrinfo", failing(socket.EAI_NONAME))
    with pytest.raises(pinned_http.UnresolvableHost) as caught:
        fetch_response("https://openpgpkey.gone.example/.well-known/", timeout=5)
    assert caught.value.permanent and str(caught.value) == \
        "cannot resolve openpgpkey.gone.example"
    monkeypatch.setattr(socket, "getaddrinfo", failing(socket.EAI_AGAIN))
    with pytest.raises(pinned_http.UnresolvableHost) as caught:
        fetch_response("https://slow.example/", timeout=5)
    assert not caught.value.permanent
