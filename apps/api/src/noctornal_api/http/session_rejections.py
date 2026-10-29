"""What a refused session token leaves in the audit log.

An unauthenticated caller must not be able to append to the hash-chained log (`ratelimit.py`
decision 43(d)). A token that matches no session writes no row, only a count in one sampled log
line per `UNKNOWN_LOG_SECONDS`. A token naming a real session that is revoked or expired writes a
row, since someone holds a credential that worked once, with the source address hash and at most
once per session per `REJECTION_WINDOW_SECONDS`, so the rows are bounded by real sessions, which
nobody outside can mint. The window lives in this process: one API process holds the bound
exactly, N processes N times it.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from uuid import UUID

from fastapi import Request

from noctornal_api.http.limits import client_ip

log = logging.getLogger("noctornal.api")

#: One AUTH_SESSION_REJECTED row per real session per this many seconds.
REJECTION_WINDOW_SECONDS = 300.0
#: How many sessions the window remembers; the least recently written is
#: forgotten first, so memory is bounded whatever the caller sends.
REMEMBERED_SESSIONS = 10_000
#: At most one log line per this many seconds for tokens matching nothing.
UNKNOWN_LOG_SECONDS = 30.0


class _Window:
    """Whether a row for this session is due, remembering when the last
    one was written. A lock because the ASGI threadpool runs dependencies
    on more than one thread."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: OrderedDict[UUID, float] = OrderedDict()

    def due(self, session_id: UUID) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._seen.get(session_id)
            if last is not None and now - last < REJECTION_WINDOW_SECONDS:
                return False
            self._seen[session_id] = now
            self._seen.move_to_end(session_id)
            while len(self._seen) > REMEMBERED_SESSIONS:
                self._seen.popitem(last=False)
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


class _Sampler:
    """At most one line per window, carrying the count it stands for."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: float | None = None
        self._since = 0

    def note(self) -> int | None:
        now = time.monotonic()
        with self._lock:
            self._since += 1
            if self._last is not None and now - self._last < UNKNOWN_LOG_SECONDS:
                return None
            self._last = now
            n, self._since = self._since, 0
            return n


_window = _Window()
_unknown = _Sampler()


def ip_hash(request: Request) -> bytes | None:
    """The hash of the address the rate limiter and the session binding
    read (`client_ip`), the same value `routers/auth._ip_hash` records."""
    ip = client_ip(request)
    return hashlib.sha256(ip.encode()).digest() if ip else None


def record_rejected_session(conn, request: Request, result) -> None:
    """Record one refused presentation as the module docstring says.
    `result` is the `ValidationResult` that failed."""
    session_id = getattr(result, "session_id", None)
    if session_id is None:
        n = _unknown.note()
        if n is not None:
            # The noun agrees with the count (no bracketed plural).
            log.warning("refused %d session %s that matched no session "
                        "since the last line", n,
                        "token" if n == 1 else "tokens")
        return
    if not _window.due(session_id):
        return
    from noctornal_api.http.deps import audit_auth_event
    audit_auth_event(conn, "AUTH_SESSION_REJECTED", None, None,
                     {"reason": result.reason, "session_id": str(session_id)},
                     ip_hash=ip_hash(request))
