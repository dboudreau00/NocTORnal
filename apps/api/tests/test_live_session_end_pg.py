"""The live socket ends when the session behind it does (2026-09-23).

ux01-firstrun:live-dot-green-on-dead-session. The socket was validated at
its handshake and never again, so after the 30-minute idle expiry, a
sign-out elsewhere or a revocation, the console kept a green "Live" dot
and the first colleague's edit then fired a refetch that threw the analyst
to the sign-in form at a moment of somebody else's choosing. The stream now
asks on every idle ping, without sliding the session, and closes with the
policy code and `SESSION_ENDED_REASON`, which the console turns into a
signed-out dot and the in-place sign-in.

**The email prefix is `lsend-` and must stay unique.**

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

LIVE = "/api/v1/live"
PEER = "203.0.113.41"      # TEST-NET, never a real peer


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'lsend-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'lsend-%@noctornal.test'")
    c.close()


@pytest.fixture
def live(monkeypatch):
    """The router, pinging every fifth of a second and with strict binding
    off, so a minted session with no address is accepted."""
    from noctornal_api.http.routers import live as module
    monkeypatch.delenv("NOCTORNAL_SESSION_STRICT_BINDING", raising=False)
    monkeypatch.setattr(module, "_PING_SECONDS", 0.2)
    return module


def _app():
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return app


def _session(conn):
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    uid = PgUserStore(conn).create_user(
        f"lsend-{uuid4().hex[:8]}@noctornal.test", "Live End", "x" * 20)
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return record.id, token


def test_a_socket_on_a_revoked_session_closes_with_the_session_reason(conn, live):
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    session_id, token = _session(conn)
    with TestClient(_app(), client=(PEER, 40000)) as client:
        with client.websocket_connect(LIVE) as ws:
            ws.send_json({"token": token})
            assert ws.receive_json()["type"] == "ready"
            # Alive: the quiet socket pings.
            assert ws.receive_json()["type"] == "ping"
            conn.execute("UPDATE iam.session SET revoked_at = now(), "
                         "revoke_reason = 'logout' WHERE id = %s", (session_id,))
            with pytest.raises(WebSocketDisconnect) as closed:
                for _ in range(20):
                    ws.receive_json()
    assert closed.value.code == 1008
    assert closed.value.reason == live.SESSION_ENDED_REASON == "session ended"


def test_an_idle_expired_session_ends_its_socket_and_asking_slides_nothing(conn, live):
    """Asking must not keep the session alive: `touch=False`, or a console
    that is merely open would never reach its idle timeout (final review
    C20)."""
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    session_id, token = _session(conn)
    with TestClient(_app(), client=(PEER, 40001)) as client:
        with client.websocket_connect(LIVE) as ws:
            ws.send_json({"token": token})
            assert ws.receive_json()["type"] == "ready"
            conn.execute("UPDATE iam.session SET last_seen_at = now() - interval "
                         "'31 minutes' WHERE id = %s", (session_id,))
            seen = conn.execute("SELECT last_seen_at FROM iam.session WHERE id = %s",
                                (session_id,)).fetchone()[0]
            with pytest.raises(WebSocketDisconnect) as closed:
                for _ in range(20):
                    ws.receive_json()
    assert closed.value.code == 1008 and closed.value.reason == "session ended"
    after = conn.execute("SELECT last_seen_at FROM iam.session WHERE id = %s",
                         (session_id,)).fetchone()[0]
    assert after == seen, "the liveness check slid the session's idle window"


def test_session_alive_answers_without_touching(conn):
    from noctornal_api.http.routers.live import _session_alive
    session_id, token = _session(conn)
    before = conn.execute("SELECT last_seen_at FROM iam.session WHERE id = %s",
                          (session_id,)).fetchone()[0]
    assert _session_alive(token) is True
    assert _session_alive("not-a-token") is False
    after = conn.execute("SELECT last_seen_at FROM iam.session WHERE id = %s",
                         (session_id,)).fetchone()[0]
    assert after == before
