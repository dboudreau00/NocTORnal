"""The live socket's credential-free refusals, read where they happen: at
the ASGI layer, and under the real server.

`test_live_pg` drives the socket through Starlette's `TestClient`, and a
`TestClient` completes the close handshake in-process, so it cannot tell
a refusal sent before `accept()` from one sent after. That difference is
the whole of the 2026-09-09 finding (W1): under uvicorn's `websockets`
backend -- `--ws auto` with `websockets` installed, which is what every
launch script runs -- a close sent AFTER `accept()` writes the close
frame and then holds the transport for a ten-second `close_timeout`
waiting for the peer's echo, while a close sent BEFORE is an HTTP 403
and an immediate `transport.close()`. A hostile peer that never echoed
therefore held one TCP connection per refused socket for ten seconds,
uncounted by the budget that had refused it, and the ceiling reported
zero.

Two kinds of test, on purpose:

* The ASGI-stream tests hand the real app a websocket scope and record
  every message it sends. They are cheap and deterministic, and they
  assert the one fact the fix rests on: the refusal is the FIRST message,
  with no `websocket.accept` in front of it.
* The hostile-run test starts uvicorn in a thread, with the backend the
  launch scripts select, and drives raw TCP sockets that complete the
  upgrade and then send nothing: no hello, no close echo. It reads
  `server_state.connections`, the set every uvicorn protocol removes
  itself from in `connection_lost`, so the number it asserts on is the
  server's own count of held transports and not a proxy for it. Run
  against the post-accept version of the refusal on 2026-09-09 it held
  thirty-two connections for the full ten seconds; against the
  pre-accept version it was back to the two budgeted sockets within a
  second.

Env-gated on DATABASE_URL like the other socket tests: the app comes from
`create_app()`, and one test here mints a session to fill the hub.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import os
import socket
import threading
import time
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "live-hs-%@noctornal.test"
LIVE = "/api/v1/live"
# TEST-NET (RFC 5737), so a leaked fixture value can never be a real peer.
PEER_A = "203.0.113.20"
STRICT = "NOCTORNAL_SESSION_STRICT_BINDING"
LOGGER = "noctornal.live"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub}")
    c.close()


def _app():
    """The real app with the limiter swapped for an in-process one, the
    shape `test_live_pg._app` uses, so two tests do not share a meter."""
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return app


def _token(conn) -> str:
    """A session for a fresh user, minted the way `bootstrap.py session`
    does. Strict binding is off in every test here, so the socket accepts
    a session that was never bound to an address."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    uid = PgUserStore(conn).create_user(
        f"live-hs-{uuid4().hex[:8]}@noctornal.test", "Live", "x" * 20)
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _budget(monkeypatch, *, pending: int, per_peer: int = 8,
            hello: float = 20.0):
    """Shrink the budget for one test, and start it from a fresh sampler
    so a line written by an earlier test does not swallow this one's.
    `raising=False` on the sampler so the same test runs against the
    pre-2026-09-09 module, where it did not exist, and fails on
    behaviour rather than on a missing attribute."""
    from noctornal_api.http.routers import live
    monkeypatch.delenv(STRICT, raising=False)
    monkeypatch.delenv("NOCTORNAL_LIVE", raising=False)
    monkeypatch.setattr(live, "_MAX_PENDING", pending)
    monkeypatch.setattr(live, "_MAX_PENDING_PER_PEER", per_peer)
    monkeypatch.setattr(live, "_HELLO_SECONDS", hello)
    sampler = getattr(live, "_SampledWarning", None)
    if sampler is not None:
        monkeypatch.setattr(live, "_refusals", sampler(), raising=False)
    return live


def _sent_by(app, *, ip: str = PEER_A) -> list[dict]:
    """Hand `app` one websocket scope from `ip` and return every ASGI
    message it sent, in order.

    `receive` yields `websocket.connect` once and then a disconnect, so a
    handler that accepted and sat waiting for a hello sees the peer leave
    and returns: the drive terminates either way, and the stream shows
    which way it went. Under `asyncio.run` on this thread, not on a
    `TestClient` portal, precisely so nothing completes a close handshake
    on the app's behalf.
    """
    sent: list[dict] = []
    inbound = iter([{"type": "websocket.connect"},
                    {"type": "websocket.disconnect", "code": 1006}])

    async def receive():
        try:
            return next(inbound)
        except StopIteration:  # pragma: no cover -- a handler that reads on
            await asyncio.sleep(3600)  # after the disconnect is itself a bug

    async def send(message):
        sent.append(message)

    scope = {
        "type": "websocket", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "ws", "path": LIVE, "raw_path": LIVE.encode(), "root_path": "",
        "query_string": b"", "headers": [(b"host", b"testserver")],
        "client": (ip, 40000), "server": ("testserver", 80), "subprotocols": [],
        "state": {},
    }
    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=10))
    return sent


def _types(sent: list[dict]) -> list[str]:
    return [m["type"] for m in sent]


# --- the ASGI send stream: no accept in front of a refusal ---------------

def test_a_full_budget_is_refused_before_accept(monkeypatch):
    """With the budget full of one silent socket, the next socket from the
    same peer gets `websocket.close` as the FIRST message the app sends.
    Before the fix the stream read accept-then-close, and under uvicorn
    that accept is what armed the ten-second linger."""
    from fastapi.testclient import TestClient
    live = _budget(monkeypatch, pending=1, per_peer=1)
    app = _app()
    with TestClient(app, client=(PEER_A, 40000)) as client:
        with client.websocket_connect(LIVE):
            assert live._pending.count == 1
            sent = _sent_by(app)
    assert _types(sent) == ["websocket.close"], (
        f"the refusal was not the first message; the app sent {_types(sent)}")
    assert sent[0]["code"] == 1008
    assert sent[0]["reason"] == "too many pending sockets"
    assert live._pending.count == 0


def test_the_off_switch_refuses_before_accept(monkeypatch):
    """`NOCTORNAL_LIVE=0` had the same accept-then-close shape, and the
    same uncounted linger, as the budget refusal. It is one of the three
    credential-free refusals, so it is sent the same way."""
    _budget(monkeypatch, pending=4)
    monkeypatch.setenv("NOCTORNAL_LIVE", "0")
    sent = _sent_by(_app())
    assert _types(sent) == ["websocket.close"], _types(sent)
    assert sent[0]["code"] == 1013
    assert sent[0]["reason"] == "live updates are disabled"


def test_a_full_hub_refuses_before_accept(conn, monkeypatch):
    """The hub ceiling is the third credential-free refusal. It used to be
    checked inside `_handshake`, after `accept()`; with one authenticated
    subscriber holding a ceiling of one, the next socket's stream must
    open with the 1013 close and nothing in front of it."""
    from fastapi.testclient import TestClient
    live = _budget(monkeypatch, pending=4)
    monkeypatch.setattr(live, "_MAX_SOCKETS", 1)
    token = _token(conn)
    app = _app()
    with TestClient(app, client=(PEER_A, 40000)) as client:
        with client.websocket_connect(LIVE) as first:
            first.send_json({"token": token})
            assert first.receive_json()["type"] == "ready"
            assert live._hub.count == 1
            sent = _sent_by(app)
    assert _types(sent) == ["websocket.close"], _types(sent)
    assert sent[0]["code"] == 1013
    assert sent[0]["reason"] == "too many live subscribers"
    assert live._pending.count == 0
    assert live._hub.count == 0


def test_refusals_are_logged_sampled_not_per_connection(monkeypatch, caplog):
    """One WARNING per window, carrying the count, not one per refused
    connection. The refusal is reached with no credential and no completed
    handshake, so a line per attempt would let one address write the log
    as fast as it can open TCP connections. Before the fix twenty refusals
    were twenty lines."""
    from fastapi.testclient import TestClient
    live = _budget(monkeypatch, pending=1, per_peer=1)
    app = _app()
    with TestClient(app, client=(PEER_A, 40000)) as client:
        with client.websocket_connect(LIVE):
            with caplog.at_level(logging.WARNING, logger=LOGGER):
                for _ in range(20):
                    assert _types(_sent_by(app)) == ["websocket.close"]
                lines = [r.getMessage() for r in caplog.records
                         if r.name == LOGGER and "refused" in r.getMessage()]
                assert len(lines) == 1, (
                    f"{len(lines)} warning lines for 20 refusals; one address "
                    f"chose the log volume")
                assert "1 refusal(s) since the last line" in lines[0]
                # Once the window has passed, the next refusal writes a
                # line that stands for everything the window swallowed.
                monkeypatch.setattr(live, "_REFUSAL_LOG_SECONDS", 0.0)
                _sent_by(app)
                lines = [r.getMessage() for r in caplog.records
                         if r.name == LOGGER and "refused" in r.getMessage()]
                assert len(lines) == 2
                assert "20 refusal(s) since the last line" in lines[1], lines[1]


# --- the hostile run: the server's own connection set ---------------------

def _wait(cond, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


@contextlib.contextmanager
def _server(app):
    """uvicorn on an ephemeral loopback port, in a thread, with the
    backend the launch scripts get (`ws="auto"`). The listening socket is
    bound here so the port is known before the server thread starts."""
    import uvicorn
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, ws="auto", lifespan="off",
        log_config=None, log_level="warning", access_log=False,
        timeout_graceful_shutdown=3)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]},
                              daemon=True, name="uvicorn-under-test")
    thread.start()
    try:
        assert _wait(lambda: server.started, 10.0), "uvicorn did not start"
        yield server, port
    finally:
        server.should_exit = True
        thread.join(15)
        sock.close()


def _upgrade(port: int) -> tuple[socket.socket, int]:
    """Open a raw TCP connection, send a well-formed upgrade request, and
    read the status line. The socket is returned OPEN and is never
    written to again: this is the peer that neither says hello nor echoes
    a close frame, and whether the server keeps its transport up is the
    thing under test."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall((f"GET {LIVE} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
               "Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
               "\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/1.1 ") else 0
    return s, status


def test_a_hostile_peer_holds_nothing_past_the_budget(monkeypatch):
    """The measurement the finding asked for. Two silent sockets fill a
    budget of two; thirty more from the same address are refused; and the
    server's own connection set must be back to two promptly -- well
    inside the ten-second close timeout that a post-accept refusal would
    have held every one of the thirty for.

    Asserted on `server_state.connections` rather than on anything the
    app reports, because the app was what reported zero while the
    transports were held. The refused sockets must also have been
    answered with a 403, never a 101: a 101 means a handshake completed
    and a close frame was written, which is exactly the frame a hostile
    peer declines to echo.
    """
    from uvicorn.protocols.websockets.websockets_sansio_impl import (
        WebSocketsSansIOProtocol)
    live = _budget(monkeypatch, pending=2, per_peer=2, hello=30.0)
    flood = 30
    opened: list[socket.socket] = []
    with _server(_app()) as (server, port):
        # The backend the launch scripts select. A different one is a
        # different server, and this measurement would not be of the
        # shipped one.
        assert server.config.ws_protocol_class is WebSocketsSansIOProtocol

        held = [_upgrade(port) for _ in range(2)]
        opened += [s for s, _ in held]
        assert [status for _, status in held] == [101, 101]
        assert _wait(lambda: live._pending.count == 2, 2.0)

        refused = [_upgrade(port) for _ in range(flood)]
        opened += [s for s, _ in refused]
        at_flood = len(server.server_state.connections)
        started = time.monotonic()
        settled = _wait(lambda: len(server.server_state.connections) <= 2, 3.0)
        elapsed = time.monotonic() - started
        try:
            assert settled, (
                f"{len(server.server_state.connections)} server-side connections "
                f"still held {elapsed:.1f}s after {flood} refusals from one "
                f"address ({at_flood} at the flood); the budget is 2")
            assert {status for _, status in refused} == {403}, (
                "a refused socket completed the handshake, so it was sent a "
                "close frame the peer can withhold")
            assert live._pending.count == 2
            assert len(server.server_state.connections) == 2

            # The two that were counted give their slots back when they go,
            # so the budget is a budget and not a slow lockout.
            for s, _ in held:
                s.close()
            assert _wait(lambda: live._pending.count == 0, 5.0)
        finally:
            for s in opened:
                s.close()
