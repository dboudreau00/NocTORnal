"""Live change push over a WebSocket (Phase 2's last gap).

Until this existed there was no timer anywhere in `app.js`: two analysts on
one case each saw the graph as it was when they opened it, and a merge one
of them performed was invisible to the other until a manual refresh. In a
tool whose entire premise is that the picture is shared, that is not a
performance nicety.

## The socket is a HINT TO REFETCH, never a data channel

This is the design decision everything else follows from, and it is a
security decision rather than an architectural preference.

An event says only: *case X changed, kind `node`, operation `INSERT`*. It
carries no label, no element id, no content. The client's response is to
refetch through the ordinary REST endpoints, which already apply the
five-part gate and the label filter.

The alternative — pushing the changed rows — would require this layer to
re-implement classification and compartment filtering. That filtering has
now been got wrong in five separate places in this codebase (docs/17 F19:
the notification centre, the outbox drain, evidence egress, report
release, and the sample download path), and there is no reason to believe
a sixth implementation would be the one that is right. So there is no
sixth implementation.

## Authorisation is re-checked on EVERY delivery, not at subscribe

A socket is long-lived and an assignment is not. F19's headline finding
was a notification centre that checked labels at write time and never
again, so an analyst taken off a case kept reading it indefinitely. A
socket authorised once at connect would be the same defect with a longer
half-life — hours rather than a request.

The re-check is one indexed query against `iam.case_assignment` per event,
and events are rare by construction (statement-level triggers, and a case
changes when a human does something). Paying it every time is cheap and
removes a whole class of reasoning about when a subscription goes stale.

## Failure is silent and the client keeps working

If the socket cannot connect, or the database cannot be listened to, the
console behaves exactly as it did before: the analyst refreshes. Nothing
here is load-bearing for correctness, and it must never become so — a
push-based UI that silently stops pushing is worse than one that never
pushed, because people stop refreshing.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from uuid import UUID

import psycopg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from noctornal_api.db import connect
from noctornal_api.security.access import evaluate
from noctornal_api.security.sessions import SessionService
from noctornal_api.stores import PgAccessResolver, PgSessionStore

log = logging.getLogger("noctornal.live")

router = APIRouter(tags=["live"])

CHANNEL = "noctornal_change"

#: How long a listening connection waits before looping. Short enough that
#: a disconnect is noticed promptly, long enough that an idle socket is not
#: a busy loop.
_POLL_SECONDS = 1.0

#: Close codes. 1008 is "policy violation" in RFC 6455, which is the
#: closest standard code for "you did not authenticate".
_CLOSE_UNAUTHENTICATED = 1008


def _live_enabled() -> bool:
    """Off switch. LISTEN holds a database connection open per client, and
    an operator running a large deployment behind PgBouncer in transaction
    mode cannot use it at all — LISTEN is session-scoped and PgBouncer will
    hand the next query to a different backend. Better an operator turns it
    off explicitly than discovers it silently never fires."""
    return os.environ.get("NOCTORNAL_LIVE", "1").lower() not in {"0", "false"}


@router.websocket("/live")
async def live(ws: WebSocket) -> None:
    """Stream change hints for one case.

    The token arrives in the first message rather than in a query string:
    a URL lands in proxy logs, browser history and `Referer`, and this one
    would carry a session bearer token. WebSocket has no header API in the
    browser, so the first frame is the only place left.
    """
    await ws.accept()
    if not _live_enabled():
        await ws.close(code=1013, reason="live updates are disabled")
        return

    try:
        hello = await asyncio.wait_for(ws.receive_json(), timeout=10)
    except (TimeoutError, asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no credentials")
        return

    token = (hello or {}).get("token")
    raw_case = (hello or {}).get("case_id")
    if not isinstance(token, str) or not token:
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no credentials")
        return
    try:
        case_id = UUID(raw_case) if raw_case else None
    except (TypeError, ValueError):
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="bad case id")
        return

    auth = connect()
    try:
        result = SessionService(PgSessionStore(auth)).validate(token)
        if not result.ok:
            await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="invalid session")
            return
        user_id = result.session.user_id
        mfa_at = result.session.mfa_satisfied_at
        # The gate, before anything is streamed. Same failure as the REST
        # layer: no distinction between "no such case" and "not yours".
        if case_id is not None and not _may_read(auth, user_id, case_id, mfa_at):
            await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no such case")
            return
        await ws.send_json({"type": "ready", "case_id": str(case_id)
                            if case_id else None})
        await _stream(ws, auth, user_id, case_id, mfa_at)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 — a dropped socket must not 500 the app
        log.exception("live socket failed")
        with contextlib.suppress(Exception):
            await ws.close(code=1011, reason="internal error")
    finally:
        auth.close()


def _may_read(conn: psycopg.Connection, user_id: UUID, case_id: UUID,
              mfa_at) -> bool:
    """The five-part gate, through the one `evaluate()` every other path
    uses. `case.read` is the right permission: this stream tells a caller
    only that the case changed, which is exactly what reading it would.

    The CASE's own labels are resolved and passed, exactly as
    `deps.effective_labels` does when there is no element. `resolve()`
    parses whatever it is given and a `None` classification raises
    `AccessResolutionError` — so passing None here did not fail open, it
    failed the whole socket with a 1011. Loud, but for the wrong reason,
    and it would have read as "the live feature is broken" rather than
    "this call was wrong".

    A case that does not exist returns False, which the caller reports as
    "no such case" — the same answer an unassigned one gets, so the socket
    is not an existence oracle either.
    """
    row = conn.execute(
        'SELECT classification, compartments FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None:
        return False
    ctx = PgAccessResolver(conn).resolve(
        user_id=user_id, case_id=case_id, permission_key="case.read",
        object_classification=row[0],
        object_compartments=frozenset(row[1] or []),
        mfa_satisfied_at=mfa_at)
    return evaluate(ctx).allowed


async def _stream(ws: WebSocket, auth: psycopg.Connection, user_id: UUID,
                  case_id: UUID | None, mfa_at) -> None:
    """LISTEN on a dedicated connection and forward what this caller may see.

    A SECOND connection, not the one that authenticated: `LISTEN` is
    session-scoped and holds the connection for the life of the socket, and
    tying up the authenticating connection would mean the re-check below
    could not run.
    """
    listener = connect()
    try:
        listener.execute(f"LISTEN {CHANNEL}")
        while True:
            # `notifies()` blocks, so it runs off the event loop. A
            # generator with a timeout gives us a chance to notice a closed
            # socket rather than blocking until the next database write.
            events = await asyncio.to_thread(_drain, listener, _POLL_SECONDS)
            for payload in events:
                message = _relevant(payload, user_id, case_id)
                if message is None:
                    continue
                # RE-CHECKED PER DELIVERY. A socket outlives an assignment;
                # F19's headline finding was exactly this shape with a
                # shorter half-life.
                if case_id is not None and not _may_read(auth, user_id,
                                                         case_id, mfa_at):
                    await ws.close(code=_CLOSE_UNAUTHENTICATED,
                                   reason="access changed")
                    return
                await ws.send_json(message)
            # A zero-length drain is the keepalive opportunity: if the peer
            # has gone, this raises and the socket is cleaned up.
            if not events:
                await ws.send_json({"type": "ping"})
    finally:
        with contextlib.suppress(Exception):
            listener.execute(f"UNLISTEN {CHANNEL}")
        listener.close()


def _drain(listener: psycopg.Connection, seconds: float) -> list[dict]:
    """Collect whatever arrived within `seconds`. Runs on a worker thread."""
    out: list[dict] = []
    gen = listener.notifies(timeout=seconds)
    for note in gen:
        try:
            out.append(json.loads(note.payload))
        except (ValueError, TypeError):
            # A malformed payload is a bug in the trigger, not something to
            # take a client's socket down for.
            log.warning("unparseable change payload: %r", note.payload)
    return out


def _relevant(payload: dict, user_id: UUID, case_id: UUID | None) -> dict | None:
    """Filter to what this subscriber asked for and may have.

    Note what is NOT here: any decision about labels. The event carries no
    content, so there is nothing to filter — the client refetches through
    the gated endpoints and they decide. That is the point of the design.
    """
    kind = payload.get("kind")
    if kind == "notification":
        # Delivered on identity, not on case: the badge is per-recipient,
        # and the read filter in `NotificationService.inbox` decides
        # whether the row is actually visible.
        if str(payload.get("recipient_id")) != str(user_id):
            return None
        return {"type": "change", "kind": "notification"}
    if case_id is None:
        return None
    if str(payload.get("case_id")) != str(case_id):
        return None
    return {"type": "change", "kind": kind, "op": payload.get("op")}
