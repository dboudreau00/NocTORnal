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

## ONE listener for the whole process, not one per socket

The first version of this file opened two Postgres connections per
client — one to `LISTEN`, one held open to re-check authorisation — and
blocked a thread-pool worker per client waiting on notifications.

That works with one analyst and falls over with ten. Postgres ships with
`max_connections = 100`; twenty-five people with two browser tabs each
would consume every one of them, and the failure would arrive as the API
being unable to serve *any* request — a total outage caused by people
leaving tabs open overnight. `asyncio.to_thread` has the same shape: its
default pool is `min(32, cpu + 4)` workers, so enough sockets starve every
other thread-pool user in the process.

So there is exactly one `LISTEN` connection and one worker thread per
process, and sockets subscribe to it in memory. Authorisation re-checks
borrow a short-lived connection instead of holding one.

## Authorisation is re-checked on EVERY delivery, not at subscribe

A socket is long-lived and an assignment is not. F19's headline finding
was a notification centre that checked labels at write time and never
again, so an analyst taken off a case kept reading it indefinitely. A
socket authorised once at connect would be the same defect with a longer
half-life — hours rather than a request.

The re-check is one indexed query, and events are rare by construction
(statement-level triggers, and a case changes when a human does
something). Paying it every time is cheap and removes a whole class of
reasoning about when a subscription goes stale.

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

#: How long the single listener waits per loop. Short enough that a stopped
#: process is noticed promptly, long enough that an idle deployment is not
#: a busy loop.
_POLL_SECONDS = 1.0

#: A backstop on concurrent sockets. Each one costs an asyncio task and a
#: bounded queue — cheap — but "cheap" times unbounded is still an outage,
#: and a refusal an operator can see beats a process that slowly stops
#: responding.
_MAX_SOCKETS = int(os.environ.get("NOCTORNAL_LIVE_MAX_SOCKETS", "200"))

#: Per-subscriber buffer. A client that cannot keep up is DISCONNECTED
#: rather than queued indefinitely: these are hints to refetch, so a
#: backlog of them is worthless, and an unbounded queue behind a stalled
#: socket is a memory leak with a timer on it.
_QUEUE_DEPTH = 32

_CLOSE_UNAUTHENTICATED = 1008
_CLOSE_BUSY = 1013


class _Hub:
    """One LISTEN connection per process, fanned out in memory.

    Started lazily on the first subscriber and stopped when the last one
    leaves, so a deployment where nobody opens the console holds no
    database connection at all.
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()

    @property
    def count(self) -> int:
        return len(self._subscribers)

    async def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_DEPTH)
        async with self._lock:
            self._subscribers.add(queue)
            if self._task is None or self._task.done():
                self._stop.clear()
                self._task = asyncio.create_task(self._run())
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Stop the listener when the last subscriber leaves.

        By SETTING A FLAG the loop checks, not by cancelling the task.
        `asyncio.to_thread` cannot be cancelled: cancelling the task raises
        `CancelledError` at the await point immediately and leaves the
        worker thread inside `notifies()`, still using the connection. The
        cleanup in `finally` then tried to `UNLISTEN` and close a
        connection another thread was reading, both raised, both were
        suppressed — and the connection stayed open for the life of the
        process.

        Measured, not reasoned: `pg_stat_activity` showed one idle backend
        with `LISTEN noctornal_change` still there after every socket had
        gone. One per worker process, forever.

        The task is awaited outside the lock so that a new subscriber
        arriving during the (up to `_POLL_SECONDS`) shutdown is not blocked
        behind it.
        """
        task = None
        async with self._lock:
            self._subscribers.discard(queue)
            if not self._subscribers and self._task is not None:
                self._stop.set()
                task, self._task = self._task, None
        if task is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(task, timeout=_POLL_SECONDS * 5)

    async def _run(self) -> None:
        """Hold the one LISTEN connection and fan out what arrives."""
        listener = await asyncio.to_thread(connect)
        try:
            await asyncio.to_thread(listener.execute, f"LISTEN {CHANNEL}")
            while not self._stop.is_set():
                events = await asyncio.to_thread(
                    _drain, listener, _POLL_SECONDS)
                for payload in events:
                    for queue in list(self._subscribers):
                        try:
                            queue.put_nowait(payload)
                        except asyncio.QueueFull:
                            # The slow client's problem, not everybody
                            # else's. It sees a closed socket and
                            # reconnects, which also refetches.
                            pass
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — never take the process down
            log.exception("live listener stopped; clients fall back to refresh")
        finally:
            # The loop has exited, so no worker thread is inside
            # `notifies()` any more and these can actually run.
            with contextlib.suppress(Exception):
                await asyncio.to_thread(listener.execute, f"UNLISTEN {CHANNEL}")
            with contextlib.suppress(Exception):
                await asyncio.to_thread(listener.close)


_hub = _Hub()


def _live_enabled() -> bool:
    """Off switch. `LISTEN` is session-scoped, so an operator running
    behind PgBouncer in transaction mode cannot use this at all — PgBouncer
    hands the next query to a different backend. Better that they turn it
    off explicitly than discover it silently never fires."""
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
        await ws.close(code=_CLOSE_BUSY, reason="live updates are disabled")
        return
    if _hub.count >= _MAX_SOCKETS:
        log.warning("live socket refused: %d already open", _hub.count)
        await ws.close(code=_CLOSE_BUSY, reason="too many live subscribers")
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

    # Authenticate on a SHORT-LIVED connection, released immediately. The
    # first version held this one open for the life of the socket, which is
    # how twenty-five people with two tabs each exhausted Postgres.
    try:
        session = await asyncio.to_thread(_authenticate, token, case_id)
    except Exception:  # noqa: BLE001
        log.exception("live authentication failed")
        await ws.close(code=1011, reason="internal error")
        return
    if session is None:
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no such case")
        return
    user_id, mfa_at = session

    queue = await _hub.subscribe()
    try:
        await ws.send_json({"type": "ready",
                            "case_id": str(case_id) if case_id else None})
        await _stream(ws, queue, user_id, case_id, mfa_at)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 — a dropped socket must not 500 the app
        log.exception("live socket failed")
        with contextlib.suppress(Exception):
            await ws.close(code=1011, reason="internal error")
    finally:
        await _hub.unsubscribe(queue)


def _authenticate(token: str, case_id: UUID | None):
    """Validate the session and the case gate on one borrowed connection.

    Returns `(user_id, mfa_at)` or None. Runs on a worker thread because
    psycopg is synchronous, and the connection is closed before returning
    so nothing is held for the life of the socket.
    """
    conn = connect()
    try:
        result = SessionService(PgSessionStore(conn)).validate(token)
        if not result.ok:
            return None
        user_id = result.session.user_id
        mfa_at = result.session.mfa_satisfied_at
        if case_id is not None and not _may_read(conn, user_id, case_id, mfa_at):
            return None
        return user_id, mfa_at
    finally:
        conn.close()


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
    and it read as "the live feature is broken" rather than "this call was
    wrong".

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


def _recheck(user_id: UUID, case_id: UUID, mfa_at) -> bool:
    """Borrow a connection, re-run the gate, give it back."""
    conn = connect()
    try:
        return _may_read(conn, user_id, case_id, mfa_at)
    finally:
        conn.close()


async def _stream(ws: WebSocket, queue: asyncio.Queue, user_id: UUID,
                  case_id: UUID | None, mfa_at) -> None:
    """Forward what this caller may see, until the socket goes away.

    Waits on the queue AND on the socket at the same time. Waiting only on
    the queue means a disconnect is not noticed until the next send — the
    idle ping, up to 25 seconds later — so a subscriber slot, and with it
    the process's share of `_MAX_SOCKETS`, stays held long after the
    analyst closed the tab. Measured: the listener connection was still
    open four seconds after every client had gone, and released by
    twenty-five.

    A client that reconnects on a flaky link would churn through slots
    faster than they are returned, and the refusal would look like the
    server being broken.
    """
    receiver = asyncio.create_task(ws.receive())
    getter: asyncio.Task | None = None
    try:
        while True:
            if getter is None or getter.done():
                getter = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait(
                {receiver, getter}, timeout=25,
                return_when=asyncio.FIRST_COMPLETED)

            if receiver in done:
                # Anything from the client ends the stream. The protocol is
                # one-way after the hello frame, so a frame is either a
                # disconnect or a client doing something unexpected, and
                # neither is a reason to keep streaming case activity.
                return

            if getter in done:
                payload = getter.result()
                getter = None
                message = _relevant(payload, user_id, case_id)
                if message is None:
                    continue
                # RE-CHECKED PER DELIVERY. A socket outlives an assignment;
                # F19's headline finding was this shape with a shorter
                # half-life.
                if case_id is not None and not await asyncio.to_thread(
                        _recheck, user_id, case_id, mfa_at):
                    await ws.close(code=_CLOSE_UNAUTHENTICATED,
                                   reason="access changed")
                    return
                await ws.send_json(message)
                continue

            # Neither fired: idle. The ping catches a peer that vanished
            # without closing — a laptop lid, a dropped VPN — which the
            # receive above cannot see.
            await ws.send_json({"type": "ping"})
    finally:
        for task in (receiver, getter):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task


def _drain(listener: psycopg.Connection, seconds: float) -> list[dict]:
    """Collect whatever arrived within `seconds`. Runs on a worker thread."""
    out: list[dict] = []
    for note in listener.notifies(timeout=seconds):
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
