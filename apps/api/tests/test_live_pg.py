"""The live change socket (Phase 2's last gap).

Two properties carry the weight, and neither is about latency:

1. **The event carries no case content.** It says "case X changed, kind
   node" and nothing else, so the client refetches through the ordinary
   gated endpoints. That is why this layer never has to re-implement
   classification and compartment filtering — filtering this codebase has
   got wrong in five separate places (docs/17 F19).

2. **Authorisation is re-checked on every delivery.** A socket is
   long-lived and an assignment is not. F19's headline finding was a
   notification centre that checked once and never again; a socket
   authorised only at connect is that defect with a longer half-life.

Env-gated on DATABASE_URL. The end-to-end WebSocket handshake is exercised
by `scripts/` against a running server; these test the pieces that decide
things.
"""
from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from datetime import date
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "live-%@noctornal.test"
LIVE = "/api/v1/live"
# TEST-NET addresses (RFC 5737), so a leaked fixture value can never be a
# real peer.
PEER_A = "203.0.113.20"
PEER_B = "198.51.100.30"
STRICT = "NOCTORNAL_SESSION_STRICT_BINDING"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        # The socket tests below mint sessions; a session row references
        # its user, so it goes first.
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub}")
    c.close()


def _user(conn, clearance="RED", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"live-{uuid4().hex[:8]}@noctornal.test", "Live", "x" * 20)
    # Since 0059 every compartment column is bound to iam.compartment. This
    # helper writes whatever it is handed, so it registers it first rather
    # than trusting the caller to have done so -- two helpers of this shape
    # were refused on CI's fresh database on 2026-09-09 while passing here.
    for key in compartments:
        conn.execute(
            "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
            "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    return uid


def _case(conn, owner, classification="GREEN", compartments=()):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-LIVE-{uuid4().hex[:6]}", title="Live",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


def _node(conn, case_id, owner, label):
    """Through the real write path. Invariant 1 refuses a raw INSERT — a
    node must carry a supporting assertion at commit — so a probe that
    tries to shortcut it is stopped by the system working."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label,
        created_by=owner, classification="GREEN",
        assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=owner,
            reliability="B", credibility="2",
            rationale="live socket test"))


# --- the payload says nothing -------------------------------------------

def test_a_change_event_carries_no_case_content(conn):
    """The whole safety argument for this design in one assertion. If an
    event ever carries a label, an id or a value, this layer acquires a
    filtering responsibility — and that is the responsibility this
    codebase has repeatedly failed to discharge correctly."""
    from noctornal_api.db import connect
    from noctornal_api.http.routers.live import CHANNEL

    owner = _user(conn)
    case_id = _case(conn, owner)

    heard: list[dict] = []

    def listen():
        c = connect()
        c.execute(f"LISTEN {CHANNEL}")
        for note in c.notifies(timeout=6):
            heard.append(json.loads(note.payload))
        c.close()

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    time.sleep(0.8)          # let LISTEN register before the write

    _node(conn, case_id, owner, "a handle")
    time.sleep(2.0)

    events = [h for h in heard if h.get("kind") == "node"]
    assert events, "no change event was published for a node write"
    assert set(events[0]) == {"case_id", "kind", "op"}, (
        f"the event carries more than an id, a kind and an operation: "
        f"{events[0]}")


def test_one_event_per_statement_not_per_row(conn):
    """A bulk write of four hundred edges should wake a client once. The
    triggers are FOR EACH STATEMENT for this reason, and the client
    refetches the whole projection anyway."""
    from noctornal_api.db import connect
    from noctornal_api.http.routers.live import CHANNEL

    owner = _user(conn)
    case_id = _case(conn, owner)
    for i in range(3):
        _node(conn, case_id, owner, f"handle-{i}")

    heard: list[dict] = []

    def listen():
        c = connect()
        c.execute(f"LISTEN {CHANNEL}")
        for note in c.notifies(timeout=6):
            heard.append(json.loads(note.payload))
        c.close()

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    time.sleep(0.8)
    # ONE statement touching all three.
    conn.execute("UPDATE core.node SET updated_at = now() WHERE case_id = %s",
                 (case_id,))
    time.sleep(2.0)

    node_events = [h for h in heard
                   if h.get("kind") == "node"
                   and h.get("case_id") == str(case_id)]
    assert len(node_events) == 1, (
        f"a 3-row statement produced {len(node_events)} events; the trigger "
        f"is row-level rather than statement-level")


# --- the gate ------------------------------------------------------------

def test_the_gate_accepts_an_assigned_analyst(conn):
    from noctornal_api.http.routers.live import _may_read
    owner = _user(conn)
    case_id = _case(conn, owner)
    assert _may_read(conn, owner, case_id, None) is True


def test_the_gate_refuses_an_unassigned_analyst(conn):
    from noctornal_api.http.routers.live import _may_read
    owner, stranger = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    assert _may_read(conn, stranger, case_id, None) is False


def test_the_gate_refuses_after_the_assignment_expires(conn):
    """The re-check is per delivery precisely so this transition is
    observed. A socket authorised once at connect would keep streaming for
    as long as the tab stayed open."""
    from noctornal_api.http.routers.live import _may_read
    owner, alice = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    conn.execute(
        """INSERT INTO iam.case_assignment
               (case_id, user_id, role_key, granted_by, expires_at)
           VALUES (%s, %s, 'ANALYST', %s, now() + interval '1 hour')""",
        (case_id, alice, owner))
    assert _may_read(conn, alice, case_id, None) is True

    conn.execute("UPDATE iam.case_assignment SET expires_at = now() - "
                 "interval '1 minute' WHERE case_id = %s AND user_id = %s",
                 (case_id, alice))
    assert _may_read(conn, alice, case_id, None) is False


def test_the_gate_refuses_a_clearance_below_the_case(conn):
    from noctornal_api.http.routers.live import _may_read
    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="RED")
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'GREEN' "
                 "WHERE id = %s", (owner,))
    assert _may_read(conn, owner, case_id, None) is False


def test_a_nonexistent_case_is_refused_not_crashed(conn):
    """And with the same answer an unassigned case gives, so the socket is
    not an existence oracle."""
    from noctornal_api.http.routers.live import _may_read
    assert _may_read(conn, _user(conn), uuid4(), None) is False


def test_the_gate_needs_a_real_classification(conn):
    """A regression for the bug that shipped in the first draft of this
    router: `resolve()` was called with `object_classification=None`, which
    raises rather than denies — so the socket died with a 1011 and read as
    "the live feature is broken" instead of "this call was wrong". The case
    row is read and its own labels are passed, exactly as
    `deps.effective_labels` does."""
    import inspect

    from noctornal_api.http.routers import live
    body = inspect.getsource(live._may_read)
    assert "object_classification=None" not in body
    assert 'FROM core."case"' in body


# --- what reaches which subscriber --------------------------------------

def test_an_event_for_another_case_is_not_delivered(conn):
    from noctornal_api.http.routers.live import _relevant
    mine, theirs = uuid4(), uuid4()
    me = uuid4()
    assert _relevant({"case_id": str(theirs), "kind": "node", "op": "INSERT"},
                     me, mine) is None
    assert _relevant({"case_id": str(mine), "kind": "node", "op": "INSERT"},
                     me, mine) == {"type": "change", "kind": "node",
                                   "op": "INSERT"}


def test_a_notification_reaches_only_its_recipient(conn):
    """Delivered on identity rather than case: the badge is per-recipient,
    and the read filter in `NotificationService.inbox` decides whether the
    row is actually visible."""
    from noctornal_api.http.routers.live import _relevant
    me, somebody = uuid4(), uuid4()
    assert _relevant({"recipient_id": str(somebody), "kind": "notification"},
                     me, None) is None
    assert _relevant({"recipient_id": str(me), "kind": "notification"},
                     me, None) == {"type": "change", "kind": "notification"}


def test_a_subscriber_with_no_case_gets_no_graph_events(conn):
    """Subscribing to nothing must not become subscribing to everything."""
    from noctornal_api.http.routers.live import _relevant
    assert _relevant({"case_id": str(uuid4()), "kind": "node", "op": "INSERT"},
                     uuid4(), None) is None


def test_live_can_be_switched_off(conn, monkeypatch):
    """LISTEN holds a database connection open per client and does not work
    at all behind PgBouncer in transaction mode. Better an operator turns
    it off explicitly than discovers it silently never fires."""
    from noctornal_api.http.routers.live import _live_enabled
    monkeypatch.delenv("NOCTORNAL_LIVE", raising=False)
    assert _live_enabled() is True
    monkeypatch.setenv("NOCTORNAL_LIVE", "0")
    assert _live_enabled() is False
    monkeypatch.setenv("NOCTORNAL_LIVE", "false")
    assert _live_enabled() is False


def test_the_reconnect_backoff_gives_up(conn):
    """A client that retries forever against a server that has said no is
    an attack in the audit log. The ceiling is asserted in the UI source
    because that is where the loop lives."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
          / "http" / "static" / "app.js").read_text(encoding="utf-8")
    assert "_wsRetry >= 6" in js
    assert "Math.min(30000" in js


def test_the_token_is_not_in_the_socket_url(conn):
    """A URL lands in proxy logs, browser history and `Referer`, and this
    one would carry a session bearer token. WebSocket has no header API in
    the browser, so it goes in the first frame."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
          / "http" / "static" / "app.js").read_text(encoding="utf-8")
    start = js.index("function connectLive")
    body = js[start:js.index("\nfunction disconnectLive")]
    assert "new WebSocket(" in body
    socket_line = body[body.index("new WebSocket("):]
    socket_line = socket_line[:socket_line.index("\n")]
    assert "token" not in socket_line, (
        "the session token is in the WebSocket URL: " + socket_line)


def test_the_socket_is_closed_when_the_session_ends(conn):
    """A socket left open on a dead session keeps a database connection
    LISTENing on the server for as long as the tab lives."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
          / "http" / "static" / "app.js").read_text(encoding="utf-8")
    start = js.index("function endSession")
    assert "disconnectLive()" in js[start:start + 900]


def test_a_burst_is_coalesced(conn):
    """A bulk import fires one event per statement and an import is many
    statements. Refetching the projection per event would turn somebody
    else's write into our own denial of service."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
          / "http" / "static" / "app.js").read_text(encoding="utf-8")
    assert "_refetchSoon = debounce(" in js


# --- the pending budget: sockets are counted from before accept() --------
#
# Until 2026-09-09 `_MAX_SOCKETS` was compared against the number of
# AUTHENTICATED subscribers, and nothing counted a socket between
# `accept()` and its hello frame: the rate-limit middleware is an
# `@app.middleware("http")` and never runs for a websocket scope. A peer
# with no session could open sockets until the process ran out of
# descriptors and hold each for the whole ten-second hello deadline while
# the ceiling reported zero. These tests drive the real app through
# Starlette's TestClient: `with TestClient(...)` shares one event loop
# across every socket it opens, which is what lets several sit open at
# once the way an attacker's would.

def _app():
    """The real app with the limiter swapped for an in-process one, so two
    tests in one process do not share a meter -- the shape
    `test_session_binding_pg._app` uses."""
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return app


def _client(app, ip: str):
    """A client whose sockets arrive FROM `ip`, opened as a context manager
    so that all of them run on one portal (one event loop)."""
    from fastapi.testclient import TestClient
    return TestClient(app, client=(ip, 40000))


def _token(conn, user_id) -> str:
    """A session minted directly, the way `bootstrap.py session` does. With
    strict binding off (every test below clears the flag) the socket
    accepts a session that was never bound to an address."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), user_id, mfa_satisfied=True)
    return token


def _budget(monkeypatch, *, pending: int, per_peer: int = 8,
            hello: float = 20.0):
    """Shrink the budget for a test. `raising=False` so that the SAME test
    runs against the pre-2026-09-09 module, where these names did not
    exist, and reaches its behavioural assertion -- the N+1th socket being
    parked for the deadline and closing with "no credentials" -- before
    any line that reads the counter fails on the missing attribute. Run
    that way on 2026-09-09: the three regression tests below fail on
    behaviour first, the hub-ceiling test on the attribute."""
    from noctornal_api.http.routers import live
    monkeypatch.delenv(STRICT, raising=False)
    monkeypatch.setattr(live, "_MAX_PENDING", pending, raising=False)
    monkeypatch.setattr(live, "_MAX_PENDING_PER_PEER", per_peer, raising=False)
    monkeypatch.setattr(live, "_HELLO_SECONDS", hello, raising=False)
    return live


def test_pending_sockets_are_budgeted_from_accept(conn, monkeypatch):
    """N sockets that never say hello fill the budget; the N+1th is refused
    at once with the policy close, not parked for the hello deadline; and
    a slot given back admits an authenticated socket that streams. Before
    the change the N+1th was accepted and sat silent for ten seconds, so
    the reason it eventually closed with was "no credentials" and the
    refusal took the whole deadline to arrive.
    """
    from starlette.websockets import WebSocketDisconnect
    live = _budget(monkeypatch, pending=3, per_peer=3)
    token = _token(conn, _user(conn))

    with _client(_app(), PEER_A) as client:
        held = [client.websocket_connect(LIVE) for _ in range(3)]
        for h in held:
            h.__enter__()
        try:
            started = time.monotonic()
            with pytest.raises(WebSocketDisconnect) as refused:
                with client.websocket_connect(LIVE) as extra:
                    extra.receive_json()
            assert refused.value.code == 1008
            assert refused.value.reason == "too many pending sockets"
            assert time.monotonic() - started < 5, (
                "the refusal waited for the hello deadline instead of "
                "arriving on the budget check")
            assert live._pending.count == 3

            # A slot handed back is a slot somebody else can use -- and the
            # authenticated path still works while the other two sit there.
            held.pop().__exit__(None, None, None)
            assert live._pending.count == 2
            with client.websocket_connect(LIVE) as ws:
                ws.send_json({"token": token})
                assert ws.receive_json()["type"] == "ready"
        finally:
            for h in held:
                h.__exit__(None, None, None)
    assert live._pending.count == 0, "a closed socket kept its pending slot"


def test_a_slow_hello_past_the_deadline_frees_its_slot(conn, monkeypatch):
    """A socket that runs out the hello deadline is closed on the
    CONFIGURED deadline and its slot comes back, so a budget that was full
    of silent sockets empties itself. Before the change the deadline was a
    literal ten seconds the environment could not shorten, and the socket
    was not counted anywhere while it waited -- so there was nothing to
    free and this assertion on timing could not have been written."""
    from starlette.websockets import WebSocketDisconnect
    live = _budget(monkeypatch, pending=2, hello=0.5)
    token = _token(conn, _user(conn))

    with _client(_app(), PEER_A) as client:
        with contextlib.ExitStack() as stack:
            held = [stack.enter_context(client.websocket_connect(LIVE))
                    for _ in range(2)]
            started = time.monotonic()
            for h in held:
                with pytest.raises(WebSocketDisconnect) as timed_out:
                    h.receive_json()
                assert timed_out.value.code == 1008
                assert timed_out.value.reason == "no credentials"
            # Timing FIRST: on the pre-change module this is the line that
            # fails, ten seconds in, before the counter is ever read. That
            # sockets are counted while silent is asserted by the two
            # tests around this one.
            assert time.monotonic() - started < 3, (
                "the hello deadline is not the configured one")
            assert live._pending.count == 0, (
                "a socket closed on the deadline kept its slot")

            # The budget that was full a moment ago now admits a socket,
            # and that socket authenticates and streams.
            with client.websocket_connect(LIVE) as ws:
                ws.send_json({"token": token})
                assert ws.receive_json()["type"] == "ready"


def test_the_per_peer_budget_is_keyed_on_the_address_http_uses(conn, monkeypatch):
    """The contract crosses two files, so this test reads both.

    The per-peer bucket is keyed on `limits.client_ip`, the same function
    that keys a 429 and the session binding, trusted-hop counting
    included. Two consequences, both asserted: a second peer is a second
    bucket, so one address filling its own budget does not touch another
    analyst's socket; and behind ONE trusted proxy hop the key is the
    forwarded address, not the proxy's, so sockets from different clients
    behind the same proxy are not made to share a bucket -- and the key
    the socket used is exactly what `client_ip` computes for an HTTP
    request carrying the same headers. Before the change there was no
    per-peer accounting at all, so the second socket from one peer was
    simply accepted.
    """
    from starlette.requests import Request
    from starlette.websockets import WebSocketDisconnect

    from noctornal_api.http.limits import client_ip
    live = _budget(monkeypatch, pending=10, per_peer=1)
    monkeypatch.delenv("NOCTORNAL_TRUSTED_PROXY_HOPS", raising=False)
    token = _token(conn, _user(conn))
    app = _app()

    with _client(app, PEER_A) as a, _client(app, PEER_B) as b:
        with a.websocket_connect(LIVE):
            with pytest.raises(WebSocketDisconnect) as refused:
                with a.websocket_connect(LIVE) as second:
                    second.receive_json()
            assert refused.value.code == 1008
            assert refused.value.reason == "too many pending sockets"
            # Peer B is another bucket: admitted, authenticated, streaming,
            # while A's silent socket is still held.
            with b.websocket_connect(LIVE) as ws:
                ws.send_json({"token": token})
                assert ws.receive_json()["type"] == "ready"
        assert live._pending.count == 0

        # One trusted hop: the key is what the proxy forwarded.
        monkeypatch.setenv("NOCTORNAL_TRUSTED_PROXY_HOPS", "1")
        with a.websocket_connect(LIVE, headers={"X-Forwarded-For": "10.0.0.1"}), \
                a.websocket_connect(LIVE, headers={"X-Forwarded-For": "10.0.0.2"}):
            assert live._pending.count == 2
            for forwarded in ("10.0.0.1", "10.0.0.2"):
                as_http = Request({
                    "type": "http", "method": "GET", "path": LIVE,
                    "headers": [(b"x-forwarded-for", forwarded.encode())],
                    "client": (PEER_A, 40000), "query_string": b""})
                assert live._pending.count_for(client_ip(as_http)) == 1, (
                    f"the socket did not key its bucket on the address "
                    f"HTTP would have used for {forwarded}")
            # And the same forwarded address a second time is the same
            # bucket, full.
            with pytest.raises(WebSocketDisconnect) as refused:
                with a.websocket_connect(
                        LIVE, headers={"X-Forwarded-For": "10.0.0.1"}) as third:
                    third.receive_json()
            assert refused.value.reason == "too many pending sockets"
        assert live._pending.count == 0


def test_a_full_hub_refuses_before_the_hello(conn, monkeypatch):
    """The subscriber ceiling, exercised end to end for the first time. NOT
    a regression for 2026-09-09 -- this check predates it -- but nothing
    had ever driven it, and the pending budget was written on the claim
    that this ceiling holds for authenticated sockets. A second subscriber
    past the ceiling is refused with 1013 without being asked for a hello,
    while the first keeps streaming."""
    from starlette.websockets import WebSocketDisconnect
    live = _budget(monkeypatch, pending=10)
    monkeypatch.setattr(live, "_MAX_SOCKETS", 1)
    token = _token(conn, _user(conn))

    with _client(_app(), PEER_A) as client:
        with client.websocket_connect(LIVE) as first:
            first.send_json({"token": token})
            assert first.receive_json()["type"] == "ready"
            assert live._hub.count == 1
            with pytest.raises(WebSocketDisconnect) as refused:
                with client.websocket_connect(LIVE) as second:
                    second.receive_json()
            assert refused.value.code == 1013
            assert refused.value.reason == "too many live subscribers"
            assert live._pending.count == 0, (
                "a socket refused on the hub ceiling kept its pending slot")
        assert live._hub.count == 0


def test_an_unknown_peer_shares_one_bucket(conn):
    """A socket whose peer address cannot be determined must be bounded
    MORE tightly than a known one, never less: every such socket shares
    the one bucket keyed on the empty string."""
    from noctornal_api.http.routers.live import _PendingBudget
    from noctornal_api.http.routers import live
    budget = _PendingBudget()
    per_peer = live._MAX_PENDING_PER_PEER
    for _ in range(per_peer):
        assert budget.reserve(None) is True
    assert budget.reserve(None) is False, "unknown peers escaped the per-peer ceiling"
    assert budget.count == per_peer and budget.count_for(None) == per_peer
    for _ in range(per_peer):
        budget.release(None)
    assert budget.count == 0 and budget.count_for(None) == 0
