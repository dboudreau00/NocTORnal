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

## A socket is COUNTED FROM `accept()`, not from authentication

Until 2026-09-09 the only ceiling in this file, `_MAX_SOCKETS`, was
compared against the number of AUTHENTICATED subscribers, and nothing
else on the way in counted anything: the HTTP rate-limit middleware is
registered with `@app.middleware("http")` and is never run for a
`websocket` scope. So the window between `accept()` and the hello frame
— an asyncio task and a buffered connection each, held for the whole
hello deadline — was open to anyone with a TCP connection. The pool
could be exhausted with no session at all, and the ceiling reported
zero while it happened. `_PendingBudget` below is the fix; the record
of what was wrong is on `live()`.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from uuid import UUID

import psycopg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from noctornal_api.db import connect
from noctornal_api.http.deps import refuse_unbound_session
from noctornal_api.http.limits import client_ip
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

#: Sockets that have been accepted and have not yet authenticated. A
#: SEPARATE, smaller budget from `_MAX_SOCKETS`, because the two states
#: cost different things and are held by different people: a subscriber
#: has spent a valid session to get its slot, a pending socket has spent
#: nothing but a TCP handshake. Sized as a quarter of the subscriber
#: ceiling by default; a deployment that sees a real burst of console
#: opens at shift change can raise it. Zero refuses every socket, which
#: is a second off switch nobody should need -- `NOCTORNAL_LIVE=0` is
#: the one that is documented. Added 2026-09-09; see `live()` for what
#: the absence of this counter allowed.
_MAX_PENDING = int(os.environ.get(
    "NOCTORNAL_LIVE_MAX_PENDING", str(max(1, _MAX_SOCKETS // 4))))

#: How many of those one peer address may hold at once. A browser sends
#: its hello in the `open` handler, so a legitimate socket is pending for
#: a round trip; even a NAT with a floor of analysts behind it does not
#: keep eight open at once without something being wrong on their side.
_MAX_PENDING_PER_PEER = int(os.environ.get(
    "NOCTORNAL_LIVE_MAX_PENDING_PER_PEER", "8"))

#: How long an accepted socket may sit without sending its hello. The
#: value has been ten seconds since the file was written; what changed on
#: 2026-09-09 is that a socket waiting it out now holds a counted slot,
#: so the deadline bounds a budget instead of bounding nothing.
_HELLO_SECONDS = float(os.environ.get("NOCTORNAL_LIVE_HELLO_SECONDS", "10"))

#: Per-subscriber buffer. A client that cannot keep up is DISCONNECTED
#: rather than queued indefinitely: these are hints to refetch, so a
#: backlog of them is worthless, and an unbounded queue behind a stalled
#: socket is a memory leak with a timer on it.
_QUEUE_DEPTH = 32

#: RFC 6455 "policy violation". One code for every refusal that is the
#: caller's doing -- no credentials, a bad case id, a pending budget it
#: has filled -- and the reason string says which. The console stops
#: reconnecting on this code and backs off on every other close (app.js
#: connectLive; test_ui_invariants binds the two), so this is the one
#: code that must mean "the server decided" and nothing else.
_CLOSE_POLICY = 1008
_CLOSE_UNAUTHENTICATED = _CLOSE_POLICY
_CLOSE_BUSY = 1013


class _PendingBudget:
    """Slots for sockets that are not yet subscribed: reserved BEFORE
    `accept()`, held through the hello and authentication.

    A socket takes a slot before `accept()` and gives it back when its
    handshake ends -- authenticated and about to be handed to the hub, or
    refused and closed -- so the count is of every socket the process is
    holding on behalf of someone who has not yet proved who they are. Two ceilings: `_MAX_PENDING` for the process,
    and `_MAX_PENDING_PER_PEER` keyed on the SAME address the HTTP rate
    limiter and the login binding use -- `limits.client_ip`, trusted-hop
    counting included -- so that behind a proxy the key is the analyst's
    address and not the proxy's, exactly as it is for a 429. A socket
    whose peer is unknown shares ONE bucket rather than escaping the
    per-peer ceiling: unknown must bound more tightly, never less.

    What the count does NOT cover, stated so nobody reads it as more
    than it is. A socket refused because the budget is full is closed
    BEFORE `accept()`, and under uvicorn's `websockets` backend -- the
    one every launch script selects, since `--ws auto` picks it whenever
    `websockets` is installed -- a pre-accept close is an HTTP 403
    followed by an immediate `transport.close()`. There is no close
    handshake for the peer to withhold, so a refused socket holds no
    connection past the turn that refused it; measured on 2026-09-09 by
    `test_live_handshake_pg`, which reads the server's own connection
    set. A socket closed AFTER `accept()` -- a bad hello, a missed
    deadline -- is different: that backend writes the close frame and
    then keeps the transport up for its hard-coded ten-second
    `close_timeout` waiting for the peer's echo, and this budget hands
    the slot back when `close()` returns, not when the transport goes.
    A peer that was accepted and then refused therefore keeps one TCP
    connection lingering, uncounted, for those ten seconds, and by
    cycling hellos one address can stack at most a per-peer budget's
    worth of them per hello round trip. That residual is the server's
    close handshake, not this budget's accounting; what changed on
    2026-09-09 is that the REFUSAL itself -- the path reached with no
    handshake completed, from one address, without limit -- no longer
    lingers at all.

    A plain `threading.Lock`, not an asyncio one: nothing here awaits,
    and the counters must stay right even when more than one event-loop
    thread drives sockets in one process, which Starlette's `TestClient`
    does whenever it is not used as a context manager.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0
        self._per_peer: dict[str, int] = {}

    @property
    def count(self) -> int:
        return self._total

    def count_for(self, peer: str | None) -> int:
        return self._per_peer.get(peer or "", 0)

    def reserve(self, peer: str | None) -> bool:
        """Take a slot, or say no. Both ceilings are read at call time so
        a test, or an operator restarting one worker with a new value,
        sees the change without re-importing the module."""
        key = peer or ""
        with self._lock:
            if self._total >= _MAX_PENDING:
                return False
            if self._per_peer.get(key, 0) >= _MAX_PENDING_PER_PEER:
                return False
            self._total += 1
            self._per_peer[key] = self._per_peer.get(key, 0) + 1
            return True

    def release(self, peer: str | None) -> None:
        key = peer or ""
        with self._lock:
            self._total -= 1
            left = self._per_peer.get(key, 0) - 1
            if left <= 0:
                self._per_peer.pop(key, None)
            else:
                self._per_peer[key] = left


_pending = _PendingBudget()

#: How often the refusal WARNING may be written. One line per refused
#: connection would let the peer being refused choose how fast the log
#: grows: the refusal is answered with no credential and no completed
#: handshake, so it is the cheapest thing this file does, and a line per
#: attempt from one address is an amplifier, not a record. One line per
#: window, carrying the count, records the campaign the way
#: `RateLimiter.should_audit` records a throttled subject. Added
#: 2026-09-09 with the pre-accept refusal it describes.
_REFUSAL_LOG_SECONDS = 10.0


class _SampledWarning:
    """At most one log line per `_REFUSAL_LOG_SECONDS`, carrying the count
    of everything the window swallowed, so the operator reads "412 refused
    since the last line" rather than 412 lines whose volume the refused
    peer chose. The window is read at call time so a test can shrink it.
    A `threading.Lock` for the reason `_PendingBudget` has one: nothing
    here awaits, and more than one loop thread may call it.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: float | None = None
        self._since = 0

    def note(self) -> int | None:
        """Count one refusal. Returns how many refusals the due line stands
        for -- on the first ever, and on the first after each window -- and
        None when this one is to be swallowed into the next line's count."""
        now = time.monotonic()
        with self._lock:
            self._since += 1
            if self._last is not None and now - self._last < _REFUSAL_LOG_SECONDS:
                return None
            self._last = now
            n, self._since = self._since, 0
            return n


_refusals = _SampledWarning()


def _refused(reason: str, ip: str | None) -> None:
    """Record a pre-accept refusal, sampled. The line names the reason of
    the refusal that made it due; the count behind it may include the
    other credential-free reason, which is the point of one sampler: the
    operator wants the size of the campaign, not one meter per excuse."""
    n = _refusals.note()
    if n is not None:
        log.warning("live socket refused before accept: %s (%d refusal(s) "
                    "since the last line; %d subscribed, %d pending, %d "
                    "pending from this peer)", reason, n, _hub.count,
                    _pending.count, _pending.count_for(ip))


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

    ## Counted from `accept()`, not from authentication

    Until 2026-09-09 the only ceiling here was `_MAX_SOCKETS`, compared
    against `_hub.count` -- and the hub only hears about a socket after it
    has authenticated. The window between `accept()` and the hello frame
    was counted by nobody: not by the hub, and not by the rate-limit
    middleware, which is registered with `@app.middleware("http")` and is
    never run for a `websocket` scope. So a peer with no session at all
    could open sockets until the server ran out of descriptors, send
    nothing, and hold every one of them for the full hello deadline -- an
    asyncio task and a buffered connection each -- while `_hub.count`
    reported zero. The pool could be exhausted with no credential
    presented, and the module docstring's "a refusal an operator can see"
    described only the sockets an attacker would never bother to
    authenticate.

    Now a socket takes a slot in `_pending` before it is accepted and gives
    it back when its handshake ends, authenticated or refused, and a full
    budget -- process-wide or per peer -- is refused with the policy close
    code. The
    subscriber ceiling is checked twice on purpose: before `accept()`, so
    a full hub costs the caller no handshake and this process no database
    round trip, and again after authentication, because up to
    `_MAX_PENDING` sockets can pass the first check together and a check
    that is only ever made before the count moves was never actually a
    ceiling.

    ## Refused BEFORE `accept()`, because a refused socket must hold nothing

    Every refusal that needs no credential -- the off switch, a full hub,
    a full budget -- is sent before the handshake completes. The first
    version of this budget, earlier on 2026-09-09, sent them after it, on
    the argument that a pre-accept close reaches a browser as a bare error
    with no code, and that was wrong in the one way that mattered. Under
    uvicorn's `websockets` backend a POST-accept close writes the close
    frame and then arms a ten-second timer before dropping the transport,
    waiting for the peer's echo, and `run_asgi` leaves the transport up
    while that timer is armed. A peer that never echoed held one TCP
    connection per refusal for ten seconds -- not counted by `_pending`,
    which had just refused it, and invisible to `_hub.count`, which was
    zero -- so the path added to close the hole was itself the hole:
    reachable from one address, with no session, with no limit. A
    PRE-accept close on that backend is an HTTP 403 and an immediate
    `transport.close()`: no frame, no echo to wait for, nothing held. The
    code-and-reason argument bought nothing in any case; the shipped
    client (`connectLive` in `app.js`) reconnects with the same backoff
    on every close and never reads the code. What remains is stated on
    `_PendingBudget` so it is not mistaken for fixed: a socket refused
    AFTER `accept()` still lingers for the server's ten seconds after its
    slot is handed back. Measured on 2026-09-09 under uvicorn 0.52.4 with
    websockets 17.1, by `test_live_handshake_pg` and by a twelve-second
    sampling run of the same flood: two silent sockets held, thirty
    refusals from the same address. Pre-accept, every refusal was a 403
    and the server's own connection set read two from the first sample
    (0.2 s) onward. Post-accept, every refusal was a 101 and the set read
    thirty-two through nine seconds, then fell to two between 9.8 s and
    10.3 s -- the backend's close timeout, and nothing this file did.
    """
    # The peer this socket arrived from. `client_ip` is typed for a
    # `Request` but only ever touches `.headers.getlist` and `.client`,
    # which a Starlette `WebSocket` has for the same reason -- both are
    # `HTTPConnection` -- so the socket gets the SAME address the rate
    # limiter and the login handler compute, X-Forwarded-For hop counting
    # included. It keys the per-peer pending bucket and, later, the
    # session binding check; computing it differently here would make the
    # binding comparison fail for every deployment behind a proxy.
    ip = client_ip(ws)
    # None of these three has called `accept()`. That is the whole fix
    # (see the docstring): a close sent now is an HTTP 403 and a dropped
    # transport, not a frame the peer can decline to answer.
    if not _live_enabled():
        await ws.close(code=_CLOSE_BUSY, reason="live updates are disabled")
        return
    if _hub.count >= _MAX_SOCKETS:
        _refused("too many live subscribers", ip)
        await ws.close(code=_CLOSE_BUSY, reason="too many live subscribers")
        return
    if not _pending.reserve(ip):
        _refused("too many pending sockets", ip)
        await ws.close(code=_CLOSE_POLICY, reason="too many pending sockets")
        return
    try:
        await ws.accept()
        auth = await _handshake(ws, ip)
    finally:
        # ONE release, whichever of the handshake's refusals was taken. A
        # slot leaked on any of them would turn the budget into a slow
        # lockout of the live feature for everyone.
        _pending.release(ip)
    if auth is None:
        return
    user_id, mfa_at, case_id = auth

    if _hub.count >= _MAX_SOCKETS:
        log.warning("live socket refused: %d already open", _hub.count)
        await ws.close(code=_CLOSE_BUSY, reason="too many live subscribers")
        return
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


async def _handshake(ws: WebSocket, ip: str | None):
    """The pre-subscribe half of the socket: wait for the hello, then
    authenticate it. Returns `(user_id, mfa_at, case_id)`, or None after
    having closed the socket with a reason the client can act on.

    Split out of `live()` on 2026-09-09 so that the pending slot is
    released by ONE `finally` around this call rather than before each
    of the five refusals below. Every one of them is necessarily sent
    after `accept()` -- each needs a frame the peer sent -- and so every
    one carries the ten-second linger `_PendingBudget` describes. The hub
    ceiling used to be checked here first, after the handshake; it moved
    to `live()`, in front of `accept()`, with the other credential-free
    refusals, and the check that actually holds is the one `live()`
    makes after authentication, because everything pending can pass a
    pre-accept check at once.

    The hello deadline is `_HELLO_SECONDS`, not a literal: before this
    the ten seconds were written into the call, so nothing could shorten
    it for a test or a deployment under load, and a socket that ran it
    out was not counted anywhere while it did.
    """
    try:
        hello = await asyncio.wait_for(ws.receive_json(),
                                       timeout=_HELLO_SECONDS)
    except (TimeoutError, asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        # Under uvicorn a close after the peer has already gone raises
        # rather than no-ops; a peer that left before saying hello is not
        # worth a traceback in the server log.
        with contextlib.suppress(Exception):
            await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no credentials")
        return None

    token = (hello or {}).get("token")
    raw_case = (hello or {}).get("case_id")
    if not isinstance(token, str) or not token:
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no credentials")
        return None
    try:
        case_id = UUID(raw_case) if raw_case else None
    except (TypeError, ValueError):
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="bad case id")
        return None

    # Authenticate on a SHORT-LIVED connection, released immediately. The
    # first version held this one open for the life of the socket, which is
    # how twenty-five people with two tabs each exhausted Postgres. The
    # peer address and client software are read on the event loop and
    # handed to the worker thread: `_authenticate` runs off the loop and
    # has no request object of its own.
    user_agent = ws.headers.get("user-agent")
    try:
        session = await asyncio.to_thread(
            _authenticate, token, case_id, ip, user_agent)
    except Exception:  # noqa: BLE001
        log.exception("live authentication failed")
        await ws.close(code=1011, reason="internal error")
        return None
    if session is None:
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no such case")
        return None
    user_id, mfa_at = session
    return user_id, mfa_at, case_id


def _authenticate(token: str, case_id: UUID | None, ip: str | None,
                  user_agent: str | None):
    """Validate the session and the case gate on one borrowed connection.

    Returns `(user_id, mfa_at)` or None. Runs on a worker thread because
    psycopg is synchronous, and the connection is closed before returning
    so nothing is held for the life of the socket.

    The order is `deps.current_user`'s, deliberately and exactly:
    validate WITHOUT touching, apply strict binding, and only then slide
    the idle window. Until 2026-09-02 this called `validate(token)` with
    `touch` defaulting to True and never consulted the binding at all,
    which made this socket the hole in a control that was disclosed as
    covering "validation". With NOCTORNAL_SESSION_STRICT_BINDING=1 a
    stolen token refused on every HTTP request was still accepted here --
    and because `_may_read` re-runs the five-part gate, the attacker read
    exactly what the victim could read. Worse, the unconditional touch
    meant each reconnect slid `last_seen_at`, so the 30-minute idle
    timeout never fired and the replay kept the victim's session alive
    for as long as the attacker kept the socket cycling.

    The case gate runs AFTER the touch, as it does over HTTP: failing
    `case.read` is an authorization outcome and does not make the session
    itself less alive. Failing the binding check does, and that is why
    only the binding check sits before the touch.
    """
    conn = connect()
    try:
        service = SessionService(PgSessionStore(conn))
        result = service.validate(token, touch=False)
        if not result.ok:
            return None
        s = result.session
        if refuse_unbound_session(conn, s, ip=ip, user_agent=user_agent,
                                  path="websocket"):
            return None
        s = service.touch(s)
        user_id, mfa_at = s.user_id, s.mfa_satisfied_at
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
