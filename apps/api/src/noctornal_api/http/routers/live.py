"""Live change push over a WebSocket.

The socket is a hint to refetch, never a data channel: an event names only the case, the kind and
the operation, and the client refetches through the gated REST endpoints, so this layer never
filters content by label. A hint about an element above the subscriber is not sent (the NOTIFY
payload carries its labels, migration 0146), and authorisation is re-checked on every delivery,
since a socket outlives an assignment. One LISTEN connection and one worker thread serve the
process, so open tabs cannot exhaust Postgres connections or the thread pool. Nothing here is
load-bearing for correctness: "ready" is sent only once the LISTEN is registered. The socket takes
the session cookie, so it checks `Origin` (`_cross_site_upgrade`), and sockets are counted from
`accept()` (`_PendingBudget`), since the HTTP rate limiter never runs for a websocket scope.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from dataclasses import replace
from uuid import UUID

import psycopg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

# The request role's connections, as HTTP's are.
from noctornal_api.db import connect_request, connect_timeout_seconds
from noctornal_api.http.deps import (
    SESSION_COOKIE,
    refuse_unbindable_session,
    refuse_unbound_session,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import client_ip
from noctornal_api.samples import normalise_origin, origin_split, public_origin
from noctornal_api.security.access import (
    AccessResolutionError,
    evaluate,
    tlp_from_name,
)
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

#: Sockets accepted but not yet authenticated: a separate, smaller budget from `_MAX_SOCKETS`,
#: since a subscriber has spent a valid session for its slot and a pending socket only a TCP
#: handshake. A quarter of the subscriber ceiling by default; raise it for a real burst of
#: console opens at shift change. Zero refuses every socket; `NOCTORNAL_LIVE=0` is the documented
#: off switch.
_MAX_PENDING = int(os.environ.get(
    "NOCTORNAL_LIVE_MAX_PENDING", str(max(1, _MAX_SOCKETS // 4))))

#: How many of those one peer address may hold at once. A browser sends
#: its hello in the `open` handler, so a legitimate socket is pending for
#: a round trip; even a NAT with a floor of analysts behind it does not
#: keep eight open at once without something being wrong on their side.
_MAX_PENDING_PER_PEER = int(os.environ.get(
    "NOCTORNAL_LIVE_MAX_PENDING_PER_PEER", "8"))

#: How long an accepted socket may sit without sending its hello, holding a counted pending slot.
_HELLO_SECONDS = float(os.environ.get("NOCTORNAL_LIVE_HELLO_SECONDS", "10"))

#: The longest first frame the handshake will parse, in characters. The hello is
#: `{"token": ..., "case_id": ...}` (a token is 43 characters, a case id 36), and it is the one
#: input parsed before the sender is known; the HTTP body ceiling never sees a websocket frame.
#: The bound also keeps the nesting a JSON parser can be made to walk short.
_HELLO_MAX_CHARS = 4096

#: The longest session token a hello may name, and it must be ASCII (a real one is 43 URL-safe
#: characters). The token is hashed as UTF-8 before lookup, and a lone surrogate escape in the hello
#: decodes to text that cannot be encoded; anything else is the same refusal as no token.
_TOKEN_MAX_CHARS = 512

#: The largest WebSocket frame the server reads, in bytes: every launch line gives uvicorn this as
#: `--ws-max-size` (`test_ws_max_size_is_on_every_launch_line`), since its default is 16 MiB and
#: the hello's length check runs only after the whole frame is buffered. After the hello the
#: channel is one-way.
WS_MAX_SIZE = 8192


class _UnusableHello(Exception):
    """The first frame cannot be read as a hello at all. `reason` is the
    close reason sent with the policy close."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


async def _read_hello(ws: WebSocket):
    """Read the first frame and decode it, or raise `_UnusableHello`.

    Not `ws.receive_json()`, which raises KeyError on a binary frame and RecursionError on deep
    nesting: here the frame's kind and size are decided before anything is parsed, and every way
    the parse can fail is named."""
    message = await ws.receive()
    if message.get("type") == "websocket.disconnect":
        raise WebSocketDisconnect(message.get("code", 1000),
                                  message.get("reason"))
    text = message.get("text")
    if not isinstance(text, str) or len(text) > _HELLO_MAX_CHARS:
        # A binary frame, or one no hello is long enough to be. The same
        # close the other well-formed-but-wrong shapes get.
        raise _UnusableHello("bad hello")
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        # Not JSON, or JSON nested past the interpreter's limit: what a
        # peer that sent no hello at all is told, as it always was.
        raise _UnusableHello("no credentials") from exc


#: Per-subscriber buffer. A client that cannot keep up is DISCONNECTED
#: rather than queued indefinitely: these are hints to refetch, so a
#: backlog of them is worthless, and an unbounded queue behind a stalled
#: socket is a memory leak with a timer on it.
_QUEUE_DEPTH = 32

#: RFC 6455 "policy violation": one code for every refusal that is the caller's doing, with the
#: reason saying which. The console stops reconnecting on this code and backs off on any other
#: (app.js connectLive; test_ui_invariants binds the two), so it means only "the server decided".
_CLOSE_POLICY = 1008
_CLOSE_UNAUTHENTICATED = _CLOSE_POLICY
_CLOSE_BUSY = 1013

#: The reason sent with the policy close when the session behind a socket has gone (expiry,
#: sign-out, revocation), as distinct from the case gate refusing it. The console reads it to show
#: the live dot as signed out and offer the in-place sign-in.
SESSION_ENDED_REASON = "session ended"

#: How long a quiet socket waits before it pings, and so the longest a dead
#: session keeps a socket open. A module value so a test can shorten it.
_PING_SECONDS = 25.0


class _PendingBudget:
    """Slots for sockets that are not yet subscribed: reserved before `accept()`, held through the
    hello and authentication, and given back when the handshake ends.

    Two ceilings: `_MAX_PENDING` for the process, and `_MAX_PENDING_PER_PEER` keyed on
    `limits.client_ip`, as the HTTP rate limiter is, so behind a proxy the key is the analyst's
    address; an unknown peer shares one bucket, since unknown must bound more tightly. A socket
    refused for a full budget is closed before `accept()` and holds no connection; one closed after
    it keeps its TCP connection, uncounted, for uvicorn's ten-second `close_timeout`. A
    `threading.Lock`, not an asyncio one: nothing awaits, and more than one event-loop thread may
    drive sockets in one process.
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

#: How often the refusal warning may be written. A line per refused connection would let the
#: refused peer choose how fast the log grows; one line per window, carrying the count, records the
#: campaign as `RateLimiter.should_audit` records a throttled subject.
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
        log.warning("live socket refused before accept: %s (%d %s since "
                    "the last line; %d subscribed, %d pending, %d "
                    "pending from this peer)", reason, n,
                    "refusal" if n == 1 else "refusals", _hub.count,
                    _pending.count, _pending.count_for(ip))


class ListenerUnavailable(Exception):
    """The hub could not register its LISTEN, so a write made now would
    reach nobody. `subscribe` raises it instead of handing back a queue
    nothing will ever fill."""


#: Seconds beyond the database connect timeout a socket waits for the hub's
#: LISTEN to be registered before it is told the channel is unavailable.
_LISTEN_GRACE_SECONDS = 5.0


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
        # One stop flag and one registration future per run of the listener, not per hub: a
        # subscriber arriving while the previous run winds down would otherwise clear the flag the
        # old run is about to read, and two listeners would fan out every event twice.
        self._stop = asyncio.Event()
        self._registered: asyncio.Future | None = None

    @property
    def count(self) -> int:
        return len(self._subscribers)

    async def subscribe(self) -> asyncio.Queue:
        """Add a subscriber and return its queue once the LISTEN is registered.

        Not before: the socket says "ready" on this return, and a write between "ready" and the
        registration would be missed. A listener that cannot register raises `ListenerUnavailable`
        and leaves no subscriber behind, so the socket closes and the console retries and says so.
        The wait is outside the lock, which `unsubscribe` takes.
        """
        queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_DEPTH)
        async with self._lock:
            self._subscribers.add(queue)
            if self._task is None or self._task.done():
                self._stop = stop = asyncio.Event()
                self._registered = registered = (
                    asyncio.get_running_loop().create_future())
                self._task = asyncio.create_task(self._run(stop, registered))
            registered = self._registered
        try:
            listening = await asyncio.wait_for(
                asyncio.shield(registered),
                timeout=connect_timeout_seconds() + _LISTEN_GRACE_SECONDS)
        except TimeoutError:
            listening = False
        except BaseException:
            # Cancelled while waiting (the socket went away): leave nothing
            # behind, or the hub's count and its listener never come down.
            await self.unsubscribe(queue)
            raise
        if not listening:
            await self.unsubscribe(queue)
            raise ListenerUnavailable("the change channel could not be listened to")
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Stop the listener when the last subscriber leaves.

        By setting a flag the loop checks, not by cancelling the task: `asyncio.to_thread` cannot
        be cancelled, and cancelling would leave the worker thread inside `notifies()` holding the
        LISTEN connection open for the life of the process. The task is awaited outside the lock,
        so a new subscriber arriving during the (up to `_POLL_SECONDS`) shutdown is not blocked.
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

    async def _run(self, stop: asyncio.Event, registered: asyncio.Future) -> None:
        """Hold the one LISTEN connection and fan out what arrives.

        `registered` is resolved True once the LISTEN has run, and False if
        this run ends without it, so a subscriber waiting on it is released
        either way (`subscribe`)."""
        listener = None
        try:
            listener = await asyncio.to_thread(connect_request)
            await asyncio.to_thread(listener.execute, f"LISTEN {CHANNEL}")
            if not registered.done():
                registered.set_result(True)
            while not stop.is_set():
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
            if not registered.done():
                registered.set_result(False)
            # The loop has exited, so no worker thread is inside
            # `notifies()` any more and these can actually run.
            if listener is not None:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(
                        listener.execute, f"UNLISTEN {CHANNEL}")
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(listener.close)


_hub = _Hub()


def _live_enabled() -> bool:
    """Off switch. `LISTEN` is session-scoped, so an operator running
    behind PgBouncer in transaction mode cannot use this at all — PgBouncer
    hands the next query to a different backend. Better that they turn it
    off explicitly than discover it silently never fires."""
    return os.environ.get("NOCTORNAL_LIVE", "1").lower() not in {"0", "false"}


def _request_origin(ws: WebSocket) -> str | None:
    """The origin this upgrade actually arrived on, or None.

    Built from the request's `Host` and scheme, `x-forwarded-proto` first, because behind the
    production Caddy the socket reaches uvicorn as `ws` while the browser speaks `wss`. Trusting
    `Host` is safe here, unlike in `samples.origin_split`, because it is only ever compared with
    `Origin`: a cross-site page cannot make the two agree, since script sets neither on an upgrade,
    and a caller that forges both is not a browser and could send its token in the first frame.
    """
    host = ws.headers.get("host")
    if not host:
        return None
    proto = (ws.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    if not proto:
        # `ws`/`wss` are the upgrade's own schemes; the Origin header is
        # always written with the http/https pair, so map before comparing.
        proto = "https" if ws.url.scheme in ("wss", "https") else "http"
    if proto not in ("http", "https"):
        return None
    return normalise_origin(f"{proto}://{host}")


def _cross_site_upgrade(ws: WebSocket) -> str | None:
    """Why this upgrade must be refused, or None to let it through.

    Cross-site WebSocket hijacking: any page may open a socket here with no preflight, and the
    browser attaches `__Host-session`, which this socket accepts. `SameSite=strict` does not cover
    a sibling subdomain, which is same-site, so there this comparison is the whole defence. It
    fires on the cookie being present, since `_handshake` prefers it to the frame token; it compares
    with `public_origin()`, the origin this process is served at; and it lets through a request
    with no `Origin`, which no browser sends on an upgrade. An `Origin` matching either the
    configured origin or the one the request arrived on (`_request_origin`) is accepted, so a
    console opened at localhost against a 127.0.0.1 binding still works.
    """
    if not ws.cookies.get(SESSION_COOKIE):
        return None
    origin = ws.headers.get("origin")
    if origin is None:
        return None
    # Both sides through `normalise_origin`, so "the same origin" means what it means to the
    # download check and the CSP. `allow_path` on ours alone: `NOCTORNAL_BASE_URL` may carry a path
    # prefix and an `Origin` header may not, so a header with a path normalises to None and is
    # refused, as is `Origin: null`.
    here = normalise_origin(public_origin(), allow_path=True)
    arrived = _request_origin(ws)
    if here is None and arrived is None:
        return "cross-origin upgrade refused: this process has no valid origin"
    theirs = normalise_origin(origin)
    # Either the configured origin or the one the request arrived on: the launcher binds
    # 127.0.0.1:8000 and a developer opens localhost:8000. The second is not weaker; see
    # `_request_origin` for why a cross-site page cannot satisfy it.
    if theirs is not None and theirs in (here, arrived):
        return None
    # Our origin, not theirs: theirs they already have. No close reason here echoes a caller's
    # string, since RFC 6455 leaves 123 bytes for a reason; the caller's origin goes in the log line.
    return ("cross-origin upgrade refused: this socket is served at "
            f"{here or arrived}")


@router.websocket("/live")
async def live(ws: WebSocket) -> None:
    """Stream change hints for one case.

    The credential is the session cookie; a first-frame token is the fallback for a caller with no
    cookie jar (`_handshake`), and never the query string, which lands in logs and `Referer`.
    Every refusal that needs no credential (the off switch, the sample-origin process, a cross-site
    upgrade, a full hub or pending budget) is sent before `accept()`: under uvicorn's `websockets`
    backend that is an HTTP 403 and a dropped transport, while a close after `accept()` holds the
    connection for a ten-second close timeout. Each socket holds a `_pending` slot from before
    `accept()` until its handshake ends. The sample-origin check is the only copy of invariant 10
    for this route, since http middleware never runs for a websocket scope (`test_live_origin`).
    The subscriber ceiling is checked again after authentication, since every pending socket can
    pass the first check at once.
    """
    # The peer, by the same `client_ip` the rate limiter and login use (a `WebSocket` is an
    # `HTTPConnection` too), forwarded-hop counting included. It keys the per-peer pending bucket
    # and the session binding check, which would fail behind a proxy if computed differently.
    ip = client_ip(ws)
    # None of these five refusals has called `accept()`, so each is an HTTP 403 and a dropped
    # transport, not a frame the peer can decline to answer. The origin refusal is among them
    # because a hostile page causes it: a lingering version would be one any visited site could aim.
    if not _live_enabled():
        await ws.close(code=_CLOSE_BUSY, reason="live updates are disabled")
        return
    # Invariant 10, and the only place it holds for an upgrade: the sample-origin gate is http
    # middleware (`_allowed_on_sample_origin`), which never sees a websocket scope, so this is not
    # redundant. `origin_split().serves_here` is the middleware's own verdict, False when the split
    # is unconfigured. No `_refused` line: the answer is the deployment's, not the caller's.
    if origin_split().serves_here:
        await ws.close(code=_CLOSE_BUSY,
                       reason="this process is the sample origin and serves "
                              "sample and exhibit downloads only")
        return
    if _hub.count >= _MAX_SOCKETS:
        _refused("too many live subscribers", ip)
        await ws.close(code=_CLOSE_BUSY, reason="too many live subscribers")
        return
    # BEFORE the pending reserve, not after: a cross-site flood that took
    # a slot on its way to being refused would spend the budget analysts
    # need, and this check reads two headers and one environment variable
    # -- nothing the budget is there to protect.
    cross_site = _cross_site_upgrade(ws)
    if cross_site is not None:
        # Both origins in one line: the security officer wants the one that tried, the operator
        # what this process serves, and the peer sees neither. `!r` and a slice on the caller's
        # header, so a newline cannot forge a second log line and one header cannot fill the line.
        _refused(f"cross-origin upgrade from "
                 f"{(ws.headers.get('origin') or '')[:100]!r}: {cross_site}",
                 ip)
        await ws.close(code=_CLOSE_POLICY, reason=cross_site)
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
    user_id, mfa_at, case_id, token = auth

    if _hub.count >= _MAX_SOCKETS:
        log.warning("live socket refused: %d already open", _hub.count)
        await ws.close(code=_CLOSE_BUSY, reason="too many live subscribers")
        return
    # "ready" is sent only after the hub's LISTEN is registered, or a write in the gap would be
    # missed under a green Live dot. A hub that cannot register ends the socket instead, with a
    # code the console retries on.
    try:
        queue = await _hub.subscribe()
    except ListenerUnavailable:
        log.warning("live socket closed: the change channel could not be "
                    "listened to")
        with contextlib.suppress(Exception):
            await ws.close(code=_CLOSE_BUSY, reason="live updates are unavailable")
        return
    try:
        await ws.send_json({"type": "ready",
                            "case_id": str(case_id) if case_id else None})
        await _stream(ws, queue, user_id, case_id, mfa_at, token=token)
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 — a dropped socket must not 500 the app
        log.exception("live socket failed")
        with contextlib.suppress(Exception):
            await ws.close(code=1011, reason="internal error")
    finally:
        await _hub.unsubscribe(queue)


async def _handshake(ws: WebSocket, ip: str | None):
    """The pre-subscribe half of the socket: wait for the hello, then authenticate it.

    Returns `(user_id, mfa_at, case_id, token)`, or None after closing the socket with a reason the
    client can act on. The token is kept so the stream can ask, without sliding it, whether the
    session is still alive (`_session_alive`). A separate function so one `finally` around the call
    releases the pending slot; its refusals all follow `accept()` and carry the linger
    `_PendingBudget` describes.
    """
    try:
        hello = await asyncio.wait_for(_read_hello(ws),
                                       timeout=_HELLO_SECONDS)
    except (TimeoutError, asyncio.TimeoutError, WebSocketDisconnect):
        # Under uvicorn a close after the peer has already gone raises
        # rather than no-ops; a peer that left before saying hello is not
        # worth a traceback in the server log.
        with contextlib.suppress(Exception):
            await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no credentials")
        return None
    except _UnusableHello as unusable:
        # A binary frame, an over-long one, text that is not JSON, JSON nested too deep to parse.
        with contextlib.suppress(Exception):
            await ws.close(code=_CLOSE_UNAUTHENTICATED, reason=unusable.reason)
        return None

    # The hello is untrusted input that arrives before any credential is checked, so any shape but
    # an object with a text or null case_id is refused. A JSON null reads as an empty hello.
    if hello is None:
        hello = {}
    if not isinstance(hello, dict) or not isinstance(
            hello.get("case_id"), (str, type(None))):
        with contextlib.suppress(Exception):
            await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="bad hello")
        return None
    frame_token = hello.get("token")
    raw_case = hello.get("case_id")
    # The cookie first, the frame token second: `__Host-session` holds the raw session token, the
    # same string `_authenticate` validates, and it is `HttpOnly`, so no script can read it out,
    # while a frame token exists in page memory. The frame token is kept for
    # `scripts/bootstrap.py session`, the operator recovery path, which has no cookie jar. The hello
    # is required of everyone because it carries the case id; a missing or null case id subscribes
    # to notifications alone, as the console does while no case is open.
    token = ws.cookies.get(SESSION_COOKIE) or frame_token
    if (not isinstance(token, str) or not token or not token.isascii()
            or len(token) > _TOKEN_MAX_CHARS):
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="no credentials")
        return None
    try:
        case_id = UUID(raw_case) if raw_case else None
    except (TypeError, ValueError):
        await ws.close(code=_CLOSE_UNAUTHENTICATED, reason="bad case id")
        return None

    # Authenticate on a short-lived connection, released at once, so open sockets hold no Postgres
    # connection. The peer address and user agent are read here and handed to the worker thread,
    # where `_authenticate` has no request object of its own.
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
    return user_id, mfa_at, case_id, token


def _authenticate(token: str, case_id: UUID | None, ip: str | None,
                  user_agent: str | None):
    """Validate the session and the case gate on one borrowed connection.

    Returns `(user_id, mfa_at)` or None. Runs on a worker thread because psycopg is synchronous,
    and closes the connection before returning. The order is `deps.current_user`'s: validate
    without touching, apply strict binding, and only then slide the idle window, so a token refused
    over HTTP is refused here and a reconnect loop cannot keep a stolen session alive. The case gate
    runs after the touch, since failing `case.read` does not make the session less alive.
    """
    conn = connect_request()
    try:
        service = SessionService(PgSessionStore(conn))
        result = service.validate(token, touch=False)
        if not result.ok:
            return None
        s = result.session
        if refuse_unbound_session(conn, s, ip=ip, user_agent=user_agent,
                                  path="websocket"):
            return None
        # Bound before the touch, as over HTTP (deps.current_user).
        try:
            refuse_unbindable_session(conn, s, token)
        except Problem:
            return None
        s = service.touch(s)
        if s is None:
            # Ended between the read and the slide: refused like any dead session.
            return None
        user_id, mfa_at = s.user_id, s.mfa_satisfied_at
        if case_id is not None and not _may_read(conn, user_id, case_id, mfa_at):
            return None
        return user_id, mfa_at
    finally:
        conn.close()


def _may_read(conn: psycopg.Connection, user_id: UUID, case_id: UUID,
              mfa_at, *, count_use: bool = True) -> bool:
    """The five-part gate, through the one `evaluate()` every other path uses, on `case.read`:
    this stream tells a caller only that the case changed, which is what reading it would.

    The case's own labels are passed, as `deps.effective_labels` does with no element, since
    `resolve()` raises on a None classification. A case that does not exist returns False, the same
    "no such case" an unassigned one gets, so the socket is no existence oracle.
    """
    # The case's labels as lock facts (`iam.case_facts`): the re-check runs on an unbound
    # connection, which row-level security would show no case row at all.
    row = conn.execute(
        "SELECT classification, compartments FROM iam.case_facts(%s)",
        (case_id,)).fetchone()
    if row is None:
        return False
    ctx = PgAccessResolver(conn).resolve(
        user_id=user_id, case_id=case_id, permission_key="case.read",
        object_classification=row[0],
        object_compartments=frozenset(row[1] or []),
        mfa_satisfied_at=mfa_at, count_use=count_use)
    return evaluate(ctx).allowed


def _recheck(user_id: UUID, case_id: UUID, mfa_at) -> bool:
    """Borrow a connection, re-run the gate, give it back.

    Asked without counting a break-glass use: the socket's opening counted once at its gate, and
    this re-asks before each delivery only so a revoked assignment stops the stream."""
    conn = connect_request()
    try:
        return _may_read(conn, user_id, case_id, mfa_at, count_use=False)
    finally:
        conn.close()


#: The change kinds whose payload names the labels of what changed: node and edge from
#: `core.announce_change` (migration 0146), and proposal from `proposals.announce`. Every other
#: kind is delivered on the case alone. A labelled kind that arrives with no labels is dropped:
#: what cannot be placed is not announced.
_LABELLED_KINDS = frozenset({"node", "edge", "proposal"})


def _labels_readable(conn: psycopg.Connection, user_id: UUID, case_id: UUID,
                     mfa_at, labels) -> bool:
    """Whether the subscriber may read at least one element a change hint stands for.

    A hint about restricted writes alone would be a timing channel. The NOTIFY payload carries the
    distinct (classification, compartments) pairs (migration 0146; a tie's is joined with its
    endpoints'), each composed with the case's labels as `deps.effective_labels` does and put to the
    gate as a `case.read` question. One readable pair delivers the hint; none, or `null` labels,
    drops it. The labels never reach the client."""
    if not isinstance(labels, list) or not labels:
        return False
    row = conn.execute(
        "SELECT classification, compartments FROM iam.case_facts(%s)",
        (case_id,)).fetchone()
    if row is None:
        return False
    try:
        case_cls, case_comp = tlp_from_name(row[0]), frozenset(row[1] or [])
        ctx = PgAccessResolver(conn).resolve(
            user_id=user_id, case_id=case_id, permission_key="case.read",
            object_classification=row[0], object_compartments=case_comp,
            mfa_satisfied_at=mfa_at, count_use=False)
        for pair in labels:
            if not (isinstance(pair, list) and len(pair) == 2
                    and isinstance(pair[0], str)
                    and isinstance(pair[1], (list, type(None)))):
                continue
            try:
                element_cls = tlp_from_name(pair[0])
            except (AccessResolutionError, ValueError, KeyError):
                continue  # a label this build does not know is not readable
            element = replace(
                ctx,
                object_classification=max(case_cls, element_cls),
                object_compartments=case_comp | frozenset(
                    c for c in (pair[1] or []) if isinstance(c, str)))
            if evaluate(element).allowed:
                return True
        return False
    except AccessResolutionError:
        return False


def _change_visible(user_id: UUID, case_id: UUID, mfa_at, labels) -> bool:
    """`_labels_readable` on a connection of its own."""
    conn = connect_request()
    try:
        return _labels_readable(conn, user_id, case_id, mfa_at, labels)
    finally:
        conn.close()


def _delivery_verdict(user_id: UUID, case_id: UUID | None, mfa_at,
                      payload: dict) -> str:
    """What to do with one hint, on ONE borrowed connection: `"close"` when
    the subscriber may no longer read the case at all (the per-delivery
    re-check, `_recheck`), `"drop"` when the hint stands for elements the
    subscriber may not read, `"send"` otherwise."""
    if case_id is None:
        return "send"
    conn = connect_request()
    try:
        if not _may_read(conn, user_id, case_id, mfa_at, count_use=False):
            return "close"
        if payload.get("kind") in _LABELLED_KINDS and not _labels_readable(
                conn, user_id, case_id, mfa_at, payload.get("labels")):
            return "drop"
        return "send"
    finally:
        conn.close()


def _session_alive(token: str) -> bool:
    """Whether the session this socket opened on still stands: not revoked, not past its absolute
    limit, not idle past its window.

    `touch=False`: asking must not keep the session alive, or the idle timeout would never fire
    for a tab that is merely open."""
    conn = connect_request()
    try:
        return SessionService(PgSessionStore(conn)).validate(
            token, touch=False).ok
    finally:
        conn.close()


async def _stream(ws: WebSocket, queue: asyncio.Queue, user_id: UUID,
                  case_id: UUID | None, mfa_at, *,
                  token: str | None = None) -> None:
    """Forward what this caller may see, until the socket goes away.

    Waits on the queue and the socket together, so a disconnect frees its subscriber slot at once
    rather than at the next idle ping. The session is asked about on every idle ping and before
    every delivery, and a dead one ends the socket with the policy close and
    `SESSION_ENDED_REASON`.
    """
    receiver = asyncio.create_task(ws.receive())
    getter: asyncio.Task | None = None

    async def session_gone() -> bool:
        if token is None or await asyncio.to_thread(_session_alive, token):
            return False
        # A peer that left meanwhile makes the close raise; it is gone
        # either way.
        with contextlib.suppress(Exception):
            await ws.close(code=_CLOSE_POLICY, reason=SESSION_ENDED_REASON)
        return True

    try:
        while True:
            # Only when there is no getter, never because the last one is done: a getter is set to
            # None once its result is read, so one done here finished during the idle branch and
            # holds an unread hint. The `wait` below returns at once for it and the loop reads it.
            if getter is None:
                getter = asyncio.create_task(queue.get())
            done, _ = await asyncio.wait(
                {receiver, getter}, timeout=_PING_SECONDS,
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
                # A change delivered to a dead session would only fire a
                # refetch that 401s; the close says so first.
                if await session_gone():
                    return
                # Re-checked per delivery, since a socket outlives an assignment. The same
                # connection decides whether the hint is about anything this subscriber may read, so
                # nothing is pushed about an element above them.
                verdict = await asyncio.to_thread(
                    _delivery_verdict, user_id, case_id, mfa_at, payload)
                if verdict == "close":
                    await ws.close(code=_CLOSE_UNAUTHENTICATED,
                                   reason="access changed")
                    return
                if verdict == "drop":
                    continue
                await ws.send_json(message)
                continue

            # Neither fired: idle. The ping catches a peer that vanished
            # without closing — a laptop lid, a dropped VPN — which the
            # receive above cannot see; the session check catches a session
            # that ended while the socket stayed up.
            if await session_gone():
                return
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
    """Filter to what this subscriber asked for and may have: which case and which kind.

    No decision about labels is made here, and the message carries none; `_delivery_verdict` reads
    the payload's labels and never sends them on, and the client's refetch is gated again.
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
