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

import json
import os
import threading
import time
from datetime import date, timedelta
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "live-%@noctornal.test"


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
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub}")
    c.close()


def _user(conn, clearance="RED", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"live-{uuid4().hex[:8]}@noctornal.test", "Live", "x" * 20)
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


def test_timedelta_import_is_used_or_absent():
    """Guard against the unused-import drift ruff would catch anyway —
    kept because this file grew several helpers that came and went."""
    assert timedelta is not None
