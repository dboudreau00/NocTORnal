"""The one outbound HTTP client (2026-09-24; docs/00 decisions 72 and 77,
docs/20 section 5).

Every process that makes an outbound HTTP request makes it here: the
collector through collection.fetch and collection.fetch_response, and every
integration (Jira, the webhook, WKD, the lookups, the embeddings endpoint,
the CAPEv2 sandbox) by importing this module. Before 2026-09-24 the only
hardened client was collection.fetch, and each integration that needed
HTTP would have written its own extension of it: a urllib3 pool that
resent a POST after an SSLError, a `set_tunnel` proxy path that dialled
the proxy and shook hands outside the watchdog, a classifier admitting
metadata addresses. Seven clients would have been seven places for the
next SSRF.

## What it promises

- It connects only to an address it checked (DIRECT) or tunnels to the
  NAME through the egress proxy (PROXY), and there is no second lookup
  anywhere for an answer to change in (sec-ssrf-rebinding, 2026-09-23).
- One wall-clock allowance bounds a whole call, every hop, the proxy dial,
  the CONNECT exchange, the TLS handshake, the request and the response,
  enforced by a watchdog that cuts the socket under a read still going
  when it runs out (c2, 2026-09-24).
- It never retries. Retry policy is the caller's, so a POST is never sent
  twice, and a request counts as sent the moment its first byte is
  written, so a custody record errs towards "may have been disclosed".
- A credential never rides a redirect off its origin, and a request with a
  body never follows a redirect at all.
- Every message it reports from elsewhere passes through `redact()`, and
  nothing from a proxy reply is reflected but a known code.

It takes its route from egress.route_for and applies the route's policy
through egress_policy, the one classifier. It carries no classifier of its
own and no public switch to change one: the collector's test seam reaches
the private `_fetch_response` only.
"""
from __future__ import annotations

import base64
import contextvars
import email.utils
import hashlib
import hmac
import http.client
import ipaddress
import re
import secrets as _secrets
import socket
import ssl
import threading
import time
import unicodedata
import urllib.parse
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import NamedTuple

from noctornal_api import egress_policy
from noctornal_api.egress_policy import (
    CODE_EXCEPTION,
    METADATA_ADDRESSES,
    PROXY_STATUS,
    WIRE_CODES,
    EgressRoute,
    Refusal,
    Unresolvable,
    explain,
)
from noctornal_api.wording import count_of

# ---------------------------------------------------------------------------
# Constants (docs/20 section 5.3)
# ---------------------------------------------------------------------------

#: Honest about being a collector. A user-agent that impersonates a browser
#: is a decision with a legal dimension (docs/16 L3), not a default.
COLLECTOR_USER_AGENT = "NocTORnal-collector/1"
LOOKUP_USER_AGENT = "NocTORnal-lookup/1"

#: A redirect chain longer than this is either a loop or an attempt to
#: exhaust the validator. urllib's own default is 10.
MAX_REDIRECTS = 5

#: How much of a response body is worth reading. 16 MiB is far above any
#: legitimate RSS or forum page and far below what it takes to hurt the
#: collector. There is no "unlimited" option on purpose: the one host in
#: this system holding every persona credential should not have a code
#: path whose memory use is chosen by a monitored source.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024

#: The whole of one call, by the wall clock, when the caller names no
#: allowance: every hop, every connect attempt, the TLS handshake, the
#: headers and the body, together.
#:
#: c2 (2026-09-24): `timeout` was the only limit, and it is a limit on ONE
#: socket operation. A server that answers `Content-Length: 16000000` and
#: then sends a byte every ten seconds keeps every single recv inside it,
#: so the read ran for as long as the far end liked, and the far end is by
#: the collector's own account the people under investigation. One such
#: source held its poll lock and its RUNNING run row for ever, stopped the
#: pass it was in, and in the production cron loop stopped the
#: notification drain queued behind that pass. A minute is generous for
#: anything a feed legitimately is, and it makes one slow source cost a
#: pass a minute rather than the whole pass; scripts/collection_poll.py
#: keeps a clock of its own for the pass.
MAX_FETCH_SECONDS = 60.0
LOOKUP_MAX_SECONDS = 20.0
#: No call may ask for longer: the largest any consumer needs is a CAPEv2
#: upload of a big sample (min(900, 60 + one second per MiB)).
MAX_SECONDS_CEILING = 900.0
#: How early a socket timeout capped at the time left may wake and still
#: be read as the allowance running out (Deadline.ran_out). Windows'
#: socket timer is coarser than the monotonic clock.
TIMEOUT_SLACK = 0.1
#: The largest max_bytes a call may ask for (a CAPEv2 report is 64 MiB by
#: default).
MAX_BODY_CAP = 256 * 1024 * 1024

#: The statuses followed, each hop re-checked. urllib's own set.
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
#: Set by this module or never. accept-encoding is here because http.client
#: drops its own identity header once a caller sets one, and the body cap
#: would then bound only the compressed bytes.
FORBIDDEN_HEADERS = frozenset({
    "host", "connection", "content-length", "transfer-encoding", "user-agent",
    "proxy-authorization", "proxy-connection", "te", "upgrade", "keep-alive",
    "expect", "accept-encoding",
})
#: Headers that carry no credential, so a GET carrying only these may
#: follow a redirect anywhere the policy allows.
SAFE_FOLLOW_HEADERS = frozenset({"accept", "accept-language", "if-none-match",
                                 "if-modified-since"})
MAX_HEADERS = 32
MAX_HEADER_VALUE = 8192
EXCERPT_BYTES = 300
CONNECT_HEAD_MAX_BYTES = 8192
CONNECT_HEAD_MAX_LINES = 32
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_USER_AGENT_MAX = 512
_RETRY_AFTER_MAX = 86400.0


# ---------------------------------------------------------------------------
# Errors (docs/20 section 5.2)
# ---------------------------------------------------------------------------

class CollectionError(Exception):
    """The root of every refusal and failure of an outbound request and of
    the collection domain. The name is historical: it moved here from
    collection.py because the transport raises it and has to sit at the
    bottom of the import chain, and collection re-exports it, so every
    `except CollectionError` still catches everything below."""


class OutboundError(CollectionError):
    """One outbound call that did not produce an answer. `code` is from
    egress_policy.CODES, and three facts are set by the exchange (never by
    the Deadline, which cannot know them):

    - `connected`: a connection to the target, or a tunnel to it, was open;
    - `request_sent`: at least one byte of the request (line, headers or
      body) was written towards the target. False is the custody fact
      "nothing of the request left this host towards the target";
    - `request_complete`: every byte of the request was written.
    """

    code = "unreachable"

    def __init__(self, message: str, *, code: str | None = None,
                 connected: bool = False, request_sent: bool = False,
                 request_complete: bool = False):
        super().__init__(message)
        if code is not None:
            self.code = code
        self.connected = connected
        self.request_sent = request_sent
        self.request_complete = request_complete

    def _facts(self, facts: _Facts) -> OutboundError:
        self.connected = self.connected or facts.connected
        self.request_sent = self.request_sent or facts.request_sent
        self.request_complete = self.request_complete or facts.request_complete
        return self


class DestinationRefused(OutboundError):
    """The policy refused the destination: every egress_policy Refusal, with
    its code and its message unchanged, and a proxy reply whose code maps
    here."""

    code = "destination_not_allowed"

    def __init__(self, message: str, *, host: str | None = None, **kw):
        super().__init__(message, **kw)
        self.host = host


class UnresolvableHost(OutboundError):
    """The name could not be resolved. `permanent` is the resolver (or the
    proxy's 502 name_not_found) saying it does not exist, so the WKD
    fallback can tell "no such host" from "try again"."""

    code = "resolve_failed"

    def __init__(self, host: str, *, permanent: bool, **kw):
        kw.setdefault("code", "name_not_found" if permanent else "resolve_failed")
        super().__init__(f"cannot resolve {host}", **kw)
        self.host = host
        self.permanent = permanent


class RouteUnavailable(OutboundError):
    """The route cannot be used. Its message never names the proxy's
    address: a library's "Could not connect to proxy host:port" would carry
    an exit into a stored error_detail."""

    code = "route_unknown"


class Unreachable(OutboundError):
    """The target could not be reached, and nothing of the request was
    sent (request_sent False), unless it is the subclass below."""


class RequestUncertain(Unreachable):
    """At least one request byte was written and the exchange did not
    complete: the far end may have acted on it (a delivery is UNCERTAIN, a
    detonation UNCONFIRMED). Also the body_length_mismatch of a
    BodyStream."""

    code = "request_uncertain"


class CertificateRefused(Unreachable):
    code = "certificate"


class DeadlineExceeded(OutboundError):
    code = "deadline"


class ResponseTooLarge(OutboundError):
    code = "response_too_large"

    def __init__(self, message: str, *, max_bytes: int, **kw):
        super().__init__(message, **kw)
        self.max_bytes = max_bytes


class ResponseTruncated(OutboundError):
    code = "response_truncated"


class RedirectRefused(OutboundError):
    code = "too_many_redirects"


class HttpStatusError(OutboundError):
    """A status the caller did not accept. str(exc) is exactly "HTTP
    {status}", as the collector always said."""

    code = "http_status"

    def __init__(self, status: int, *, retry_after: float | None, excerpt: str,
                 location: str | None, location_host: str | None, headers,
                 **kw):
        kw.setdefault("connected", True)
        kw.setdefault("request_sent", True)
        kw.setdefault("request_complete", True)
        super().__init__(f"HTTP {status}", **kw)
        self.status = status
        self.retry_after = retry_after
        self.excerpt = excerpt
        self.location = location
        self.location_host = location_host
        self.headers = headers


#: egress_policy.CODE_EXCEPTION with its names turned into these classes.
EXCEPTION_FOR_CODE: dict[str, type[OutboundError]] = {
    code: globals()[name] for code, name in CODE_EXCEPTION.items()}


# ---------------------------------------------------------------------------
# Redaction, moved verbatim from collection.py
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|"
               r"authorization|cookie|session|passphrase|credential|bearer|"
               r"auth|otp|totp|pin)([\"'\s:=]+)([^\s\"',;&]+)"),
    re.compile(r"(?i)(https?://)([^:/@\s]+):([^@\s]+)@"),
    # An unlabelled high-entropy run: a cookie, a bearer token, a session
    # id. Requires a digit AND a letter so ordinary long words in error
    # prose survive -- an error nobody can read is its own failure.
    re.compile(r"\b(?=[A-Za-z0-9+/=_\-]{24,})"
               r"(?=[A-Za-z0-9+/=_\-]*[0-9])(?=[A-Za-z0-9+/=_\-]*[A-Za-z])"
               r"[A-Za-z0-9+/=_\-]{24,}\b"),
    # `user:pass` alone on a line: the shape a form echo takes, with no key
    # name anywhere near it.
    re.compile(r"(?m)^(\s*)([^\s:|]{1,64})([:|])([^\s:|]{4,})\s*$"),
    # `anything=<long opaque value>`. The field NAME is not the signal --
    # `p=` is a real one in real feeds, and that is precisely what a
    # keyword list cannot express. The length floor is what keeps ordinary
    # prose readable: assignments in an error message with an eight-plus
    # character unbroken value are overwhelmingly parameters, not English.
    re.compile(r"([A-Za-z0-9_.\-]{1,40})=([^\s,;&\"'<>]{8,})"),
]

#: Below this length an exact-match replacement does more harm than good:
#: a four-character secret appearing inside ordinary words would shred the
#: message it is supposed to keep readable. Same floor and same reasoning
#: as `pgp.MIN_CONFIRMABLE_LENGTH`.
MIN_REDACTABLE_LENGTH = 6

#: Secrets that are live RIGHT NOW, for the duration of a `PersonaVault.use`
#: block. A ContextVar rather than a global so concurrent workers do not
#: share -- and so a secret cannot outlive its block by being forgotten.
_LIVE_SECRETS: contextvars.ContextVar[tuple[str, ...]] = contextvars.ContextVar(
    "noctornal_live_secrets", default=())


def _secret_forms(value: str):
    """The shapes one secret takes on the way into an error message.

    A password does not usually appear verbatim in the thing that leaks
    it. It appears percent-encoded in a request line, form-encoded in a
    body echo, and base64'd in a Basic-auth header -- and a redactor that
    only knows the raw form catches none of those.
    """
    yield value
    yield urllib.parse.quote(value, safe="")
    yield urllib.parse.quote_plus(value)
    yield base64.b64encode(value.encode("utf-8")).decode("ascii")


@contextmanager
def secret_in_scope(*values: str):
    """Register secrets as live, so `redact` removes them exactly.

    docs/17 F15(j). Shape-matching is a backstop for secrets we do not
    hold; for the one we just handed to an adapter, exact removal is
    strictly better and is the only defence that does not depend on
    guessing what the remote server will call it.
    """
    live = tuple(v for v in values if v and len(v) >= MIN_REDACTABLE_LENGTH)
    token = _LIVE_SECRETS.set(_LIVE_SECRETS.get() + live)
    try:
        yield
    finally:
        _LIVE_SECRETS.reset(token)


def redact(text: str | None, *, secrets: tuple[str, ...] = ()) -> str:
    """Mask anything that looks like a credential, and anything that IS one.

    Applied to EVERY adapter error before it reaches the database. A
    persona's password lands in an HTTP error body far more often than
    anybody expects -- a 401 that echoes the submitted form, a proxy error
    quoting the request line, a library that stringifies its config.

    Two layers, and the order is the point:

    1. **Exact.** Every secret currently live in a `PersonaVault.use`
       block, in each of the forms it takes on the wire. This is the layer
       that actually holds invariant 7, because it does not depend on the
       remote server labelling the field in a way we anticipated.
    2. **Structural**, for secrets we do not hold: labelled fields, URL
       credentials, unlabelled high-entropy runs, bare `user:pass` lines.
       docs/17 F15(j) is right that a keyword list alone is not enough --
       `pass`, `p=`, `credential` and any unlabelled echo walk through one.
    """
    if not text:
        return ""
    out = text
    for value in tuple(_LIVE_SECRETS.get()) + tuple(secrets):
        if len(value) < MIN_REDACTABLE_LENGTH:
            continue
        for form in _secret_forms(value):
            out = out.replace(form, "[REDACTED]")
    out = _SECRET_PATTERNS[0].sub(r"\1\2[REDACTED]", out)
    out = _SECRET_PATTERNS[1].sub(r"\1\2:[REDACTED]@", out)
    out = _SECRET_PATTERNS[2].sub("[REDACTED]", out)
    out = _SECRET_PATTERNS[3].sub(r"\1\2\3[REDACTED]", out)
    out = _SECRET_PATTERNS[4].sub(r"\1=[REDACTED]", out)
    return out


def live_secret_in(text: str | None) -> bool:
    """True when any live secret appears in `text` in any of its wire
    forms: the credential rule's test for a secret carried in a URL."""
    if not text:
        return False
    for value in _LIVE_SECRETS.get():
        if len(value) < MIN_REDACTABLE_LENGTH:
            continue
        if any(form in text for form in _secret_forms(value)):
            return True
    return False


# ---------------------------------------------------------------------------
# Primitives, moved from collection.py
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Hop:
    """One checked hop: the name a request is addressed to, and the only
    addresses it may be sent to.

    `addresses` is `(family, type, proto, sockaddr)` straight from the ONE
    lookup `resolve` made, every entry already admitted. The dialler
    connects to these and to nothing else, which is the whole of the
    rebinding fix: the answer that was checked is the answer that is used
    (sec-ssrf-rebinding, 2026-09-23). A PROXY hop carries no addresses: the
    proxy is the one resolver at the boundary.

    `fetch_response(hop=...)` accepts only a hop `resolve()` issued for the
    same route and mode, and re-admits its addresses before dialling
    (2026-09-24): a hand-built hop naming 169.254.169.254
    was otherwise a way past the classifier and past the proxy.
    """

    scheme: str
    host: str
    port: int
    selector: str
    addresses: tuple[tuple[int, int, int, tuple], ...]
    locality: str = ""
    via: str = "DIRECT"
    _seal: bytes = field(default=b"", repr=False, compare=False)


#: Per process, never stored: a hop's seal proves `resolve()` issued it in
#: this process for that route, and nothing outside this module can make
#: one.
_HOP_KEY = _secrets.token_bytes(32)


def _route_key(route: EgressRoute) -> str:
    return repr((route.kind, route.name, route.mode, route.context,
                 route.proxy_host, route.proxy_port, hash(route.policy)))


def _hop_mac(hop: Hop, route: EgressRoute) -> bytes:
    material = repr((hop.scheme, hop.host, hop.port, hop.selector, hop.addresses,
                     hop.locality, hop.via, _route_key(route)))
    return hmac.new(_HOP_KEY, material.encode("utf-8"), hashlib.sha256).digest()


def _sealed(hop: Hop, route: EgressRoute) -> Hop:
    return Hop(hop.scheme, hop.host, hop.port, hop.selector, hop.addresses,
               hop.locality, hop.via, _hop_mac(hop, route))


def _cut(sock: socket.socket) -> None:
    """Shut a socket down under whoever is blocked reading it.

    The base class's `shutdown`, called directly, so an `SSLSocket` has its
    descriptor shut and its TLS state left alone: `SSLSocket.shutdown`
    clears `_sslobj`, and doing that from this thread while the reading
    thread is inside `_sslobj.read` would be a race of our own making. A
    socket already closed, or detached by `wrap_socket`, answers OSError,
    and there is nothing left to cut.
    """
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError:
        pass


class Deadline:
    """One wall-clock allowance for a whole call, and the watchdog that
    holds the call to it (c2, 2026-09-24; was collection._Deadline).

    Checking the clock between operations is not enough, because the slow
    operations are the ones that never come back to be checked:
    `BufferedReader.read(n)` loops on recv until it has n bytes and header
    parsing loops on `readline`, each recv getting a fresh `timeout`, over
    TLS as much as over plain TCP. So a timer shuts the socket down
    under the reader when the allowance runs out, which ends a blocked read
    wherever it is, and the reader then finds the allowance `spent()` and
    reports the budget rather than whatever the cut looked like from
    inside (an EOF, a reset, a short body that would otherwise have passed
    as the whole one).

    `left()` is checked before each lookup and each connect attempt, and
    caps each connect, so neither a name with many answers nor a chain of
    redirects can spend more than the allowance either. A lookup itself
    cannot be interrupted from here: the system resolver's own timeout
    bounds it, which is why the promise is that the allowance is CHECKED
    before each lookup, not that it covers one.

    One Deadline watches one socket at a time, so it is shared by
    SEQUENTIAL calls only (a poll's pages, a walk), never by two threads at
    once.
    """

    def __init__(self, seconds: float):
        self.seconds = seconds
        self._at = time.monotonic() + seconds
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._timer: threading.Timer | None = None
        self._entered = False
        self.expired = False

    @property
    def entered(self) -> bool:
        """Inside its `with` block, so the watchdog is armed."""
        return self._entered

    def exceeded(self) -> DeadlineExceeded:
        return DeadlineExceeded(
            f"the fetch took longer than its {self.seconds:g} second budget "
            f"and was abandoned. A source that answers this slowly is either "
            f"struggling or holding the collector on purpose, and either way "
            f"it does not get to hold the rest of the pass")

    def left(self) -> float:
        """Seconds remaining; raises once there are none."""
        remaining = self._at - time.monotonic()
        if self.expired or remaining <= 0:
            raise self.exceeded()
        return remaining

    def spent(self) -> bool:
        """True once the allowance has run out, whether or not the timer
        has fired yet. A socket timeout capped at what was left ends at
        the same instant the timer does, and which of the two wakes first
        must not decide what the error says."""
        return self.expired or time.monotonic() >= self._at

    def ran_out(self, exc: BaseException) -> bool:
        """Whether `exc` is the allowance running out. `spent()`, or a
        socket timeout that woke within TIMEOUT_SLACK of the end: a timeout
        capped at what was left can wake a few milliseconds EARLY on
        Windows (the socket layer's timer is coarser than the monotonic
        clock), and then spent() is still false by a hair and the budget
        was reported as an uncertain request (found under load,
        2026-09-24)."""
        if self.spent():
            return True
        return (isinstance(exc, TimeoutError)
                and time.monotonic() >= self._at - TIMEOUT_SLACK)

    def watch(self, sock: socket.socket | None) -> None:
        """Put `sock` where the watchdog can cut it, or None to stand it
        down. Cut at once if the allowance already ran out, which closes
        the gap between `wrap_socket` detaching the plain socket and the
        TLS one being handed over."""
        with self._lock:
            self._sock = sock
            if self.expired and sock is not None:
                _cut(sock)

    def _expire(self) -> None:
        with self._lock:
            self.expired = True
            if self._sock is not None:
                _cut(self._sock)

    def __enter__(self) -> Deadline:
        self._timer = threading.Timer(
            max(0.0, self._at - time.monotonic()), self._expire)
        # A daemon, so an interpreter shutting down mid fetch is not held
        # open for the rest of the allowance by a timer with nothing to do.
        self._timer.daemon = True
        self._timer.start()
        self._entered = True
        return self

    def __exit__(self, *_exc) -> None:
        self._entered = False
        if self._timer is not None:
            self._timer.cancel()
        self.watch(None)


def _dial(hop: Hop, timeout: float, deadline: Deadline) -> socket.socket:
    """A TCP connection to one of the hop's CHECKED addresses.

    Tries them in the resolver's order, the fallback
    `socket.create_connection` gives, without its lookup: nothing here
    takes a name, so there is no step at which a different answer could
    arrive (sec-ssrf-rebinding, 2026-09-23).

    Each attempt gets `timeout` or what is left of the call's allowance,
    whichever is less, and none starts once the allowance is gone (c2,
    2026-09-24): a name answering eight unreachable addresses used to cost
    eight full timeouts per hop, on every hop.
    """
    failure: OSError | None = None
    for family, kind, proto, sockaddr in hop.addresses:
        attempt = min(timeout, deadline.left())
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(attempt)
            sock.connect(sockaddr)
        except OSError as exc:
            sock.close()
            failure = exc
            continue
        return sock
    raise failure or OSError(f"no address to connect to for {hop.host}")


class _Facts:
    """What the exchange has done so far, for the three facts every
    OutboundError carries."""

    __slots__ = ("connected", "request_sent", "request_complete")

    def __init__(self):
        self.connected = False
        self.request_sent = False
        self.request_complete = False


def _wrap_tls(sock: socket.socket, tls: ssl.SSLContext, host: str,
              deadline: Deadline) -> socket.socket:
    """TLS with SNI and the certificate checked against the NAME, never
    against the number that was dialled, the handshake under the watchdog.

    The handshake is run by hand rather than inside `wrap_socket`, so the
    TLS socket is in the watchdog's reach before the first handshake byte
    is awaited (c2, 2026-09-24)."""
    try:
        wrapped = tls.wrap_socket(sock, server_hostname=host,
                                  do_handshake_on_connect=False)
        deadline.watch(wrapped)
        wrapped.do_handshake()
    except BaseException:
        sock.close()
        raise
    return wrapped


class _PinnedConnection(http.client.HTTPConnection):
    """An `HTTPConnection` whose socket goes to the checked address.

    Everything above the socket is the stdlib's and unchanged: the request
    line, the `Host` header (built from `host`, which is the NAME), chunked
    decoding. `connect` differs, because the stock one hands the name to
    `create_connection`, which is the second lookup rebinding needs; and
    `send` notes the first request byte, the custody fact "sent".
    """

    def __init__(self, hop: Hop, *, timeout: float,
                 tls: ssl.SSLContext | None, deadline: Deadline,
                 facts: _Facts | None = None):
        super().__init__(hop.host, hop.port, timeout=timeout)
        # `putrequest` leaves the port out of `Host` when it equals this,
        # which is what a server expects for 443 as much as for 80.
        self.default_port = 443 if tls is not None else 80
        self._hop = hop
        self._dial_timeout = timeout
        self._tls = tls
        self._deadline = deadline
        self._facts = facts if facts is not None else _Facts()
        self.peer: str | None = None

    def connect(self):
        sock = _dial(self._hop, self._dial_timeout, self._deadline)
        self._deadline.watch(sock)
        self._facts.connected = True
        try:
            self.peer = sock.getpeername()[0]
        except OSError:
            self.peer = None
        if self._tls is not None:
            sock = _wrap_tls(sock, self._tls, self._hop.host, self._deadline)
        self.sock = sock

    def send(self, data):
        # http.client connects lazily inside its first send, so the
        # connection is made here first: a refusal while connecting sent
        # nothing. Then the flag goes up before the write, not after:
        # sendall cannot report partial progress, and a write that failed
        # half way must read as SENT (2026-09-24).
        if self.sock is None:
            self.connect()
        self._facts.request_sent = True
        super().send(data)


class _ProxiedConnection(_PinnedConnection):
    """The same exchange through the egress proxy: the proxy is dialled by
    its own checked address, the CONNECT exchange runs under the watchdog,
    and the TLS handshake with the TARGET's name runs inside the tunnel.
    The target is never resolved here; `set_tunnel` is not used, because it
    dials the proxy and shakes hands outside the watchdog
    (2026-09-24)."""

    def __init__(self, hop: Hop, *, route: EgressRoute, timeout: float,
                 tls: ssl.SSLContext | None, deadline: Deadline,
                 facts: _Facts | None = None):
        super().__init__(hop, timeout=timeout, tls=tls, deadline=deadline,
                         facts=facts)
        self._route = route

    def connect(self):
        sock = _open_tunnel(self._route, self._hop.host, self._hop.port,
                            timeout=self._dial_timeout, deadline=self._deadline)
        self._facts.connected = True
        self.peer = None
        if self._tls is not None:
            sock = _wrap_tls(sock, self._tls, self._hop.host, self._deadline)
        self.sock = sock


def _refuse_unverifying(context: ssl.SSLContext) -> None:
    """A caller's own TLS context (a private CA, a test's) is accepted only
    if it still verifies the certificate AND checks it against the name.
    Without both, TLS proves nothing about who answered, and the address
    pin would be the only thing left standing (sec-ssrf-rebinding,
    2026-09-23)."""
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise OutboundError(
            "refusing a TLS context that does not verify the certificate "
            "against the host name: without that check TLS proves nothing "
            "about who answered", code="tls_context_refused")


# ---------------------------------------------------------------------------
# The proxy client side (docs/20 section 8)
# ---------------------------------------------------------------------------

def _proxy_hop(host: str, port: int) -> Hop:
    """The proxy's own address, resolved ONCE. The proxy is operator
    infrastructure, normally on the internal network, so the public rule
    does not apply to it; a metadata, link-local, multicast or unspecified
    answer is still refused. Nothing here is ever reported with the
    proxy's address in it."""
    unreachable = RouteUnavailable(explain("proxy_unreachable"),
                                   code="proxy_unreachable")
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise unreachable from None
    addresses = []
    for family, kind, proto, _canonical, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise unreachable
        address = ipaddress.ip_address(str(sockaddr[0]).split("%")[0])
        mapped = getattr(address, "ipv4_mapped", None) or address
        if (mapped in METADATA_ADDRESSES or mapped.is_link_local
                or mapped.is_multicast or mapped.is_unspecified):
            raise unreachable
        entry = (family, kind, proto, sockaddr)
        if entry not in addresses:
            addresses.append(entry)
    if not addresses:
        raise unreachable
    return Hop("http", host, port, "", tuple(addresses))


def _authority(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _dial_proxy(host: str, port: int, *, timeout: float,
                deadline: Deadline) -> socket.socket:
    proxy = _proxy_hop(host, port)
    try:
        sock = _dial(proxy, min(timeout, deadline.left()), deadline)
    except OSError as exc:
        if deadline.ran_out(exc):
            raise deadline.exceeded() from None
        raise RouteUnavailable(explain("proxy_unreachable"),
                               code="proxy_unreachable") from None
    deadline.watch(sock)
    sock.settimeout(min(timeout, deadline.left()))
    return sock


def _read_head(sock: socket.socket, deadline: Deadline, timeout: float) -> bytes:
    """The proxy's reply head, read WITHOUT over-reading, under the
    watchdog: every byte after the blank line stays in the socket, because
    a server-first protocol (the SMTP 220 banner) may speak in the same
    segment as the 200.

    MSG_PEEK shows what has arrived; the bytes before the terminator are
    consumed as they come, so a head arriving a byte at a time never spins
    on bytes already seen (2026-09-24)."""
    head = b""
    peek = getattr(socket, "MSG_PEEK", 0)
    while True:
        sock.settimeout(min(timeout, deadline.left()))
        if peek:
            seen = sock.recv(4096, peek)
        else:  # pragma: no cover - every supported platform has MSG_PEEK
            seen = sock.recv(1)
        if not seen:
            raise Unreachable(explain("proxy_protocol"), code="proxy_protocol")
        combined = head + seen
        end = combined.find(b"\r\n\r\n")
        want = (end + 4 - len(head)) if end >= 0 else len(seen)
        if not peek:
            taken = seen
        else:
            taken = b""
            while len(taken) < want:
                chunk = sock.recv(want - len(taken))
                if not chunk:
                    raise Unreachable(explain("proxy_protocol"), code="proxy_protocol")
                taken += chunk
        head += taken
        if (len(head) > CONNECT_HEAD_MAX_BYTES
                or head.count(b"\r\n") > CONNECT_HEAD_MAX_LINES + 1):
            raise Unreachable(explain("proxy_protocol"), code="proxy_protocol")
        if head.endswith(b"\r\n\r\n"):
            return head


_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: (.*))?$")
_GENERIC_CODE = {400: "proxy_protocol", 403: "destination_not_allowed",
                 405: "method_not_allowed", 407: "route_auth_failed",
                 502: "connect_failed", 503: "proxy_busy",
                 504: "upstream_timeout"}


class _ProxyReply(NamedTuple):
    status: int
    code: str | None
    headers: list[tuple[str, str]]


def _parse_head(head: bytes) -> _ProxyReply:
    lines = head[:-4].split(b"\r\n")
    match = _STATUS_LINE.match(lines[0])
    if not match:
        raise Unreachable(explain("proxy_protocol"), code="proxy_protocol")
    status = int(match.group(1))
    reason = (match.group(2) or b"").strip()
    code = None
    if re.fullmatch(rb"[a-z_]{1,64}", reason):
        candidate = reason.decode("ascii")
        if candidate in WIRE_CODES and PROXY_STATUS[candidate] == status:
            code = candidate
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            headers.append((name.strip().decode("latin-1"),
                            value.strip().decode("latin-1")))
    return _ProxyReply(status, code, headers)


def _reply_error(reply: _ProxyReply, host: str) -> OutboundError:
    """The exception for a refusing reply, chosen BY CODE through
    CODE_EXCEPTION. Nothing from the reply is reflected: an unknown reason
    phrase becomes the status's generic code."""
    code = reply.code or _GENERIC_CODE.get(reply.status, "proxy_protocol")
    if code in ("name_not_found", "resolve_failed"):
        return UnresolvableHost(host, permanent=code == "name_not_found")
    cls = EXCEPTION_FOR_CODE[code]
    message = f"{host}: " + explain(code)
    if cls is DestinationRefused:
        return DestinationRefused(message, host=host, code=code)
    return cls(message, code=code)


def _connect_request(authority: str, username: str, token: str) -> bytes:
    credentials = base64.b64encode(f"{username}:{token}".encode("ascii")).decode("ascii")
    return (f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"Proxy-Authorization: Basic {credentials}\r\n"
            f"\r\n").encode("ascii")


def _open_tunnel(route: EgressRoute, host: str, port: int, *, timeout: float,
                 deadline: Deadline) -> socket.socket:
    """A tunnel to host:port through the egress proxy, by NAME (never an
    address resolved here), authenticated as the route. Returns the plain
    socket, watched by `deadline`, with nothing of the far end's bytes
    consumed."""
    sock = _dial_proxy(route.proxy_host, route.proxy_port, timeout=timeout,
                       deadline=deadline)
    try:
        sock.sendall(_connect_request(_authority(host, port), route.wire_username,
                                      route.token))
        reply = _parse_head(_read_head(sock, deadline, timeout))
    except OutboundError:
        sock.close()
        raise
    except OSError as exc:
        sock.close()
        if deadline.ran_out(exc):
            raise deadline.exceeded() from None
        raise Unreachable(explain("proxy_protocol"), code="proxy_protocol") from None
    if reply.status != 200:
        sock.close()
        raise _reply_error(reply, host)
    sock.settimeout(timeout)
    return sock


class ProbeReply(NamedTuple):
    status: int
    code: str | None
    headers: dict[str, str]


#: The two headers only the readiness probe route's 403 may carry.
_PROBE_HEADERS = ("x-egress-keys", "x-egress-unopenable")


def probe_proxy(host: str, port: int, *, token: str, target_host: str,
                target_port: int, deadline: Deadline,
                timeout: float = 5.0) -> ProbeReply:
    """One CONNECT as `probe.readiness`, for the egress_boundary readiness
    probe of the route provider (2026-09-24): the
    probe reads the X-Egress-Keys and X-Egress-Unopenable headers the
    pinned client never exposes, and this gives it the same resolve-once
    proxy hop, head reader and watchdog rather than a second client. The
    probe route reaches nothing: a 200 is closed at once and reported.
    `deadline` is an ENTERED Deadline."""
    if not isinstance(deadline, Deadline) or not deadline.entered:
        raise ValueError("probe_proxy takes an entered Deadline")
    target = egress_policy.normalise_host(target_host)
    sock = _dial_proxy(host, port, timeout=timeout, deadline=deadline)
    try:
        sock.sendall(_connect_request(_authority(target, target_port),
                                      "probe.readiness", token))
        reply = _parse_head(_read_head(sock, deadline, timeout))
    except OSError as exc:
        if deadline.ran_out(exc):
            raise deadline.exceeded() from None
        raise Unreachable(explain("proxy_protocol"), code="proxy_protocol") from None
    finally:
        deadline.watch(None)
        sock.close()
    kept = {}
    for name, value in reply.headers:
        lowered = name.lower()
        if lowered in _PROBE_HEADERS and re.fullmatch(r"[A-Za-z0-9 ,._-]{0,256}", value):
            kept[lowered] = value
    return ProbeReply(reply.status, reply.code, kept)


# ---------------------------------------------------------------------------
# resolve (docs/20 section 5.6)
# ---------------------------------------------------------------------------

def _route_label(route: EgressRoute) -> str | None:
    return None if route.kind == "persona" else route.name


def _refused(refusal: Refusal) -> DestinationRefused | RouteUnavailable:
    if CODE_EXCEPTION.get(refusal.code) == "RouteUnavailable":
        return RouteUnavailable(str(refusal), code=refusal.code)
    return DestinationRefused(str(refusal), host=refusal.host, code=refusal.code)


def _resolve(url: str, *, route: EgressRoute,
             _blocked_override: Callable | None = None) -> Hop:
    try:
        target = egress_policy.split_url(url)
        label = _route_label(route)
        rule = egress_policy.check_destination(
            route.policy, target.host, target.port, route_label=label,
            _blocked_override=_blocked_override)
        if route.mode == "PROXY":
            hop = Hop(target.scheme, target.host, target.port, target.selector,
                      (), "proxied", "PROXY")
        else:
            if egress_policy.is_onion(target.host):
                # An onion name never reaches this host's resolver; it works
                # only through a proxy route with a Tor exit.
                raise Refusal("onion_not_allowed",
                              f"{target.host}: " + explain("onion_not_allowed"),
                              host=target.host)
            pinned = egress_policy.resolve_and_pin(
                target.host, target.port, policy=route.policy, rule=rule,
                route_label=label, _blocked_override=_blocked_override)
            hop = Hop(target.scheme, target.host, target.port, target.selector,
                      pinned.addresses, pinned.locality, "DIRECT")
    except Refusal as refusal:
        raise _refused(refusal) from None
    except Unresolvable as failure:
        raise UnresolvableHost(failure.host, permanent=failure.permanent) from None
    return _sealed(hop, route)


def resolve(url: str, *, route: EgressRoute) -> Hop:
    """Check and pin one URL on `route` without sending anything: split,
    check_destination, then on a DIRECT route the one lookup (hop.locality
    from its answers), on a PROXY route no lookup at all (hop.locality
    "proxied"). For a consumer that must decide on the address class
    before it sends (embeddings), then `fetch_response(hop=hop,
    max_redirects=0)` with no second lookup."""
    return _resolve(url, route=route)


def _readmit(hop: Hop, route: EgressRoute, _blocked_override) -> None:
    """A DIRECT hop's addresses, admitted again under the route's policy
    before any is dialled, so even a sealed hop cannot carry an address
    the policy refuses today."""
    try:
        rule = egress_policy.check_destination(
            route.policy, hop.host, hop.port, route_label=_route_label(route),
            _blocked_override=_blocked_override)
        for _family, _kind, _proto, sockaddr in hop.addresses:
            address = ipaddress.ip_address(str(sockaddr[0]).split("%")[0])
            egress_policy.admit(address, policy=route.policy, rule=rule,
                                _blocked_override=_blocked_override)
    except Refusal as refusal:
        raise _refused(Refusal(refusal.code, f"{hop.host}: " + explain(refusal.code),
                               host=hop.host)) from None


def _check_given_hop(hop: Hop, url: str, route: EgressRoute, _blocked_override) -> None:
    if not isinstance(hop, Hop):
        raise ValueError("hop is a Hop from resolve()")
    try:
        target = egress_policy.split_url(url)
    except Refusal as refusal:
        raise _refused(refusal) from None
    if (hop.scheme, hop.host, hop.port, hop.selector) != tuple(target):
        raise ValueError("the hop does not match the URL")
    if hop.via != route.mode:
        raise ValueError("a hop is used only on a route of the mode that issued it")
    if not hmac.compare_digest(hop._seal, _hop_mac(hop, route)):
        raise ValueError("a hop is accepted only as resolve() issued it for this route")
    if hop.via == "DIRECT":
        _readmit(hop, route, _blocked_override)


# ---------------------------------------------------------------------------
# Bodies
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BodyStream:
    """A request body of a declared length, sent as it is read. The stream
    is counted: a chunk that would carry it past `length` is refused before
    it is written, and a stream ending short is
    RequestUncertain(body_length_mismatch). One pass only."""

    length: int
    chunks: Iterable[bytes]

    def __post_init__(self):
        if not isinstance(self.length, int) or self.length < 0:
            raise ValueError("a body stream's length is a whole number of bytes")


class FilePart(NamedTuple):
    name: str
    filename: str
    content_type: str
    data: bytes | BodyStream


_UNSAFE_PART = re.compile(r"[\r\n\x00\"]")


def _part_text(value: str, what: str) -> bytes:
    if not isinstance(value, str) or _UNSAFE_PART.search(value):
        raise ValueError(f"a multipart {what} may not carry CR, LF, NUL or a double quote")
    return value.encode("utf-8")


def multipart(fields: Mapping[str, str], files: Sequence[FilePart]
              ) -> tuple[BodyStream, str]:
    """A multipart/form-data body as a BodyStream, and its Content-Type:
    the CAPEv2 upload with no requests or urllib3 underneath. Names,
    filenames and content types carrying CR, LF, NUL or a double quote are
    refused, because each is written into a part header (part header
    injection)."""
    boundary = _secrets.token_hex(16).encode("ascii")
    pieces: list[bytes | BodyStream] = []
    for name, value in fields.items():
        pieces.append(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\""
                      + _part_text(name, "field name") + b"\"\r\n\r\n"
                      + str(value).encode("utf-8") + b"\r\n")
    for part in files:
        name = _part_text(part.name, "field name")
        filename = _part_text(part.filename, "filename")
        content_type = _part_text(part.content_type, "content type")
        pieces.append(b"--" + boundary + b"\r\nContent-Disposition: form-data; name=\""
                      + name + b"\"; filename=\"" + filename + b"\"\r\nContent-Type: "
                      + content_type + b"\r\n\r\n")
        data = part.data
        if isinstance(data, (bytes, bytearray, memoryview)):
            pieces.append(bytes(data))
        elif isinstance(data, BodyStream):
            pieces.append(data)
        else:
            raise ValueError("a file part's data is bytes or a BodyStream")
        pieces.append(b"\r\n")
    pieces.append(b"--" + boundary + b"--\r\n")
    length = sum(p.length if isinstance(p, BodyStream) else len(p) for p in pieces)

    def chunks():
        for piece in pieces:
            if isinstance(piece, BodyStream):
                yield from _counted(piece)
            else:
                yield piece

    return (BodyStream(length, chunks()),
            f"multipart/form-data; boundary={boundary.decode('ascii')}")


class _BodyLengthMismatch(Exception):
    pass


def _counted(stream: BodyStream):
    sent = 0
    for chunk in stream.chunks:
        chunk = bytes(chunk)
        if sent + len(chunk) > stream.length:
            raise _BodyLengthMismatch()
        sent += len(chunk)
        yield chunk
    if sent != stream.length:
        raise _BodyLengthMismatch()


# ---------------------------------------------------------------------------
# fetch_response (docs/20 section 5.5)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Fetched:
    """One accepted answer. `url` is the final URL after redirects (a
    login wall is told by where it landed). `location` is set only for an
    unfollowed 3xx, and it is the RAW absolute Location (joined, query
    kept, not redacted), because a caller following it (the collector's
    same-origin walk) must follow the URL the server named; only an
    error's copy is stripped and redacted (2026-09-24)."""

    status: int
    headers: http.client.HTTPMessage
    body: bytes
    url: str
    media_type: str
    etag: str | None
    last_modified: str | None
    redirects: int
    via: str
    peer: str | None
    location: str | None


def _validate_headers(headers: Mapping[str, str] | None) -> list[tuple[str, str]]:
    if headers is None:
        return []
    items = list(headers.items())
    if len(items) > MAX_HEADERS:
        raise ValueError(f"at most {MAX_HEADERS} headers")
    seen = set()
    for name, value in items:
        if not isinstance(name, str) or not _HEADER_NAME.match(name):
            raise ValueError("a header name is letters, digits and hyphens")
        lowered = name.lower()
        if lowered in FORBIDDEN_HEADERS:
            raise ValueError(f"the {name} header is set by the client, never by a caller")
        if lowered in seen:
            raise ValueError(f"the {name} header is given twice")
        seen.add(lowered)
        if (not isinstance(value, str) or len(value) > MAX_HEADER_VALUE
                or any(c in value for c in "\r\n\x00")):
            raise ValueError(f"the {name} header value is not a single line")
    return items


def _deadline_for(deadline, max_seconds: float):
    """A new Deadline to enter, or the caller's entered one to share.

    A number is its own allowance, bounded by MAX_SECONDS_CEILING and
    never cut to max_seconds: the CAPEv2 row passes up to 900 seconds and
    the embeddings row up to 300, and a numeric deadline silently cut to
    the 60 second default broke both (2026-09-24)."""
    if deadline is None:
        return Deadline(max_seconds), True
    if isinstance(deadline, Deadline):
        if not deadline.entered:
            raise ValueError("a shared Deadline must be entered by its owner")
        return deadline, False
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise ValueError("deadline is None, a number of seconds or an entered Deadline")
    if not 0 < deadline <= MAX_SECONDS_CEILING:
        raise ValueError(f"a deadline is above 0 and at most {MAX_SECONDS_CEILING:g} seconds")
    return Deadline(float(deadline)), True


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        seconds = float(value)
    else:
        try:
            when = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, min(_RETRY_AFTER_MAX, seconds))


def _excerpt(data: bytes) -> str:
    text = data[:EXCERPT_BYTES].decode("utf-8", "replace")
    text = "".join(" " if c in "\r\n\t" else c for c in text
                   if c in "\r\n\t" or unicodedata.category(c) != "Cc")
    return redact(text)


def _stripped_location(absolute: str) -> tuple[str, str | None]:
    parts = urllib.parse.urlsplit(absolute)
    host = parts.hostname
    netloc = host or ""
    if host and ":" in host:
        netloc = f"[{host}]"
    try:
        if parts.port is not None:
            netloc += f":{parts.port}"
    except ValueError:
        pass
    stripped = urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    return redact(stripped), (redact(host) if host else None)


def _media_type(headers) -> str:
    raw = headers.get("Content-Type") if headers is not None else None
    if not raw:
        return ""
    return raw.split(";", 1)[0].strip().lower()


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        target = egress_policy.split_url(url)
    except Refusal:
        return None
    return target.scheme, target.host, target.port


def _one_exchange(hop: Hop, *, route: EgressRoute, method: str,
                  headers: list[tuple[str, str]], body, timeout: float,
                  tls: ssl.SSLContext | None, deadline: Deadline,
                  plan: Callable[[int], str], max_bytes: int):
    """One request on one hop and its answer: (status, headers, data,
    peer). `plan(status)` says what of the body to read: "body" (to
    max_bytes, the cap and short-body refusals applied), "excerpt" (at
    most EXCERPT_BYTES, for an error) or "none". Every error raised
    carries the three facts as they stood."""
    facts = _Facts()
    connection = None
    try:
        if hop.via == "PROXY":
            connection = _ProxiedConnection(hop, route=route, timeout=timeout,
                                            tls=tls, deadline=deadline, facts=facts)
        else:
            connection = _PinnedConnection(hop, timeout=timeout, tls=tls,
                                           deadline=deadline, facts=facts)
        send_body = body
        send_headers = dict(headers)
        if isinstance(body, BodyStream):
            send_headers["Content-Length"] = str(body.length)
            send_body = _counted(body)
        connection.request(method, hop.selector, body=send_body, headers=send_headers)
        facts.request_complete = True
        response = connection.getresponse()
        status = response.status
        wanted = plan(status)
        data = b""
        if wanted == "body" and method != "HEAD" and status not in (204, 304):
            # Capped, and read one byte past the cap so the difference
            # between "exactly at the limit" and "more coming" is
            # knowable. The cap bounds the MEMORY; the time is bounded by
            # `deadline`, whose watchdog ends this read wherever it has got
            # to (c2, 2026-09-24).
            data = response.read(max_bytes + 1)
            if deadline.spent():
                raise deadline.exceeded()
            if len(data) > max_bytes:
                raise ResponseTooLarge(
                    f"response exceeded {max_bytes} bytes and was "
                    f"abandoned. A feed larger than this is either a "
                    f"misconfiguration or something aimed at the "
                    f"collector; raise max_bytes deliberately if it is "
                    f"the first.", max_bytes=max_bytes)
            if response.length:
                # `HTTPResponse.read(n)` returns a short body without
                # complaint when the connection ends before the declared
                # Content-Length, and that is also exactly what a read cut
                # by the watchdog looks like. A partial feed is not the
                # feed, so it is refused (c2, 2026-09-24).
                raise ResponseTruncated(
                    f"the response ended "
                    f"{count_of(response.length, 'byte', 'bytes')} short of "
                    f"the length it declared and was abandoned")
        elif wanted == "excerpt" and method != "HEAD":
            try:
                data = response.read(EXCERPT_BYTES)
            except (http.client.HTTPException, OSError):
                data = b""
        return status, response.headers, data, connection.peer
    except OutboundError as exc:
        exc._facts(facts)
        raise
    except _BodyLengthMismatch:
        raise RequestUncertain(
            "unreachable: the request body was not the length it declared, so "
            "the far end may have acted on part of it",
            code="body_length_mismatch")._facts(facts) from None
    except ssl.SSLCertVerificationError as exc:
        raise CertificateRefused(
            f"certificate check failed for {hop.host}: "
            f"{redact(exc.verify_message or str(exc))}")._facts(facts) from exc
    except (http.client.HTTPException, OSError, UnicodeError) as exc:
        if deadline.ran_out(exc):
            # The watchdog cut the socket, and this is how the cut looked
            # from inside the read. The budget is the reason, so the
            # budget is what is reported.
            raise deadline.exceeded()._facts(facts) from exc
        message = f"unreachable: {redact(str(exc))}"
        if facts.request_sent:
            raise RequestUncertain(message)._facts(facts) from exc
        code = ("connect_refused" if isinstance(exc, ConnectionRefusedError)
                and hop.via == "DIRECT" and not facts.connected else "unreachable")
        raise Unreachable(message, code=code)._facts(facts) from exc
    finally:
        deadline.watch(None)
        if connection is not None:
            connection.close()


def _credential_bearing(method: str, headers: list[tuple[str, str]], body,
                        secrets: tuple[str, ...], url: str) -> bool:
    return (method not in ("GET", "HEAD") or body is not None
            or any(name.lower() not in SAFE_FOLLOW_HEADERS for name, _ in headers)
            or bool(secrets) or live_secret_in(url))


def fetch_response(url: str, *, route: EgressRoute, method: str = "GET",
                   headers: Mapping[str, str] | None = None, body=None,
                   accept_status: Iterable[int] = frozenset(),
                   max_redirects: int = MAX_REDIRECTS, redirects: str = "follow",
                   user_agent: str | None = COLLECTOR_USER_AGENT,
                   etag: str | None = None, timeout: float = 15.0,
                   max_bytes: int = MAX_RESPONSE_BYTES,
                   max_seconds: float = MAX_FETCH_SECONDS, deadline=None,
                   tls_context: ssl.SSLContext | None = None, hop: Hop | None = None,
                   secrets: tuple[str, ...] = (), error_excerpt: bool = True,
                   ) -> Fetched:
    """One outbound HTTP request on `route`, from egress.route_for.

    Argument rules are ValueError, a programming error never reachable
    from input. `deadline` is None (a new allowance of `max_seconds`), a
    number of seconds (its own allowance, at most MAX_SECONDS_CEILING), or
    an ENTERED Deadline shared by sequential calls, which alone bounds the
    call. `max_redirects=0` never follows: a 3xx is then an ordinary
    status, a Fetched when it is in `accept_status` (with `location` set
    and no body read), otherwise HttpStatusError with `location` and
    `location_host`. `redirects="same_origin"` refuses a hop to another
    scheme, host or port and sends nothing there. No call is ever retried.
    """
    return _fetch_response(
        url, route=route, method=method, headers=headers, body=body,
        accept_status=accept_status, max_redirects=max_redirects,
        redirects=redirects, user_agent=user_agent, etag=etag, timeout=timeout,
        max_bytes=max_bytes, max_seconds=max_seconds, deadline=deadline,
        tls_context=tls_context, hop=hop, secrets=secrets,
        error_excerpt=error_excerpt)


def _fetch_response(url: str, *, route: EgressRoute, method: str = "GET",
                    headers: Mapping[str, str] | None = None, body=None,
                    accept_status: Iterable[int] = frozenset(),
                    max_redirects: int = MAX_REDIRECTS, redirects: str = "follow",
                    user_agent: str | None = COLLECTOR_USER_AGENT,
                    etag: str | None = None, timeout: float = 15.0,
                    max_bytes: int = MAX_RESPONSE_BYTES,
                    max_seconds: float = MAX_FETCH_SECONDS, deadline=None,
                    tls_context: ssl.SSLContext | None = None,
                    hop: Hop | None = None, secrets: tuple[str, ...] = (),
                    error_excerpt: bool = True,
                    _blocked_override: Callable | None = None) -> Fetched:
    """fetch_response with the collector's classifier seam. Only
    collection.py's two wrappers pass `_blocked_override`."""
    # --- argument rules -------------------------------------------------
    if not isinstance(route, EgressRoute):
        raise ValueError("route is an EgressRoute from egress.route_for")
    if method not in METHODS:
        raise ValueError(f"method is one of {sorted(METHODS)}")
    items = _validate_headers(headers)
    if not (body is None or isinstance(body, (bytes, bytearray, memoryview, BodyStream))):
        raise ValueError("body is None, bytes or a BodyStream")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout is above 0")
    if not 0 < max_seconds <= MAX_SECONDS_CEILING:
        raise ValueError(f"max_seconds is above 0 and at most {MAX_SECONDS_CEILING:g}")
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= MAX_BODY_CAP:
        raise ValueError("max_bytes is from 0 to MAX_BODY_CAP")
    if redirects not in ("follow", "same_origin"):
        raise ValueError("redirects is 'follow' or 'same_origin'")
    if not isinstance(max_redirects, int) or not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects is from 0 to 10")
    if hop is not None and max_redirects != 0:
        raise ValueError("a pre-resolved hop is used only with max_redirects=0")
    if user_agent is not None and (len(user_agent) > _USER_AGENT_MAX
                                   or "\r" in user_agent or "\n" in user_agent):
        raise ValueError("user_agent is None or one short line")
    if etag is not None and any(c in etag for c in "\r\n\x00"):
        raise ValueError("etag is one line")
    secrets = tuple(secrets)
    accept = frozenset(accept_status)
    with secret_in_scope(*secrets):
        if max_redirects > 0:
            if method not in ("GET", "HEAD") or body is not None:
                # A body cannot be sent twice (a BodyStream is one pass) and
                # 301, 302 and 303 rewrite the method, so a request with a
                # body never follows (2026-09-24).
                raise ValueError(
                    "a request with a body, or a method other than GET or "
                    "HEAD, never follows a redirect: pass max_redirects=0")
            if redirects == "follow" and _credential_bearing(method, items, body,
                                                             secrets, url):
                raise ValueError(
                    "a request carrying credentials or a body may not follow "
                    "redirects to another origin: pass max_redirects=0 or "
                    "redirects='same_origin'")
        if tls_context is not None:
            _refuse_unverifying(tls_context)
        if hop is not None:
            _check_given_hop(hop, url, route, _blocked_override)
        allowance, owned = _deadline_for(deadline, max_seconds)
        if owned:
            with allowance:
                return _walk(url, route=route, method=method, items=items, body=body,
                             accept=accept, max_redirects=max_redirects,
                             redirects=redirects, user_agent=user_agent, etag=etag,
                             timeout=timeout, max_bytes=max_bytes,
                             deadline=allowance, tls_context=tls_context, hop=hop,
                             error_excerpt=error_excerpt,
                             _blocked_override=_blocked_override)
        return _walk(url, route=route, method=method, items=items, body=body,
                     accept=accept, max_redirects=max_redirects,
                     redirects=redirects, user_agent=user_agent, etag=etag,
                     timeout=timeout, max_bytes=max_bytes, deadline=allowance,
                     tls_context=tls_context, hop=hop, error_excerpt=error_excerpt,
                     _blocked_override=_blocked_override)


#: A redirect refused after its answer came back: the request that drew it
#: was sent in full and answered.
_ANSWERED = {"connected": True, "request_sent": True, "request_complete": True}


def _walk(url, *, route, method, items, body, accept, max_redirects, redirects,
          user_agent, etag, timeout, max_bytes, deadline, tls_context, hop,
          error_excerpt, _blocked_override) -> Fetched:
    """The hops of one call, each re-checked and re-resolved (DIRECT) or
    re-tunnelled (PROXY). Redirects are followed here, never inside the
    HTTP library: urlopen used to follow them internally, so hops 2..N
    were reached with no check at all (docs/17 F15(f))."""
    context = tls_context
    origin = _origin(url)
    seen = [url]
    followed = 0
    current = url
    given = hop
    request_headers: list[tuple[str, str]] = []
    if user_agent is not None:
        request_headers.append(("User-Agent", user_agent))
    # One request per connection, as urlopen sent it: a kept-alive socket
    # would outlive the hop it was checked for.
    request_headers.append(("Connection", "close"))
    if etag:
        request_headers.append(("If-None-Match", etag))
    request_headers.extend(items)
    following = max_redirects > 0

    def plan(status: int) -> str:
        if status in REDIRECT_CODES and following:
            return "none"
        if 300 <= status < 400:
            return "none"
        if status == 304:
            return "none"
        if 200 <= status < 300 or status in accept:
            return "body"
        return "excerpt" if error_excerpt else "none"

    while True:
        # Before the lookup, which is the one step the watchdog cannot
        # interrupt: a chain of redirects is not a way to buy time.
        deadline.left()
        current_hop = given if given is not None else _resolve(
            current, route=route, _blocked_override=_blocked_override)
        given = None
        if current_hop.scheme == "https" and context is None:
            # The platform trust store with hostname checking, created only
            # once an https hop needs it.
            context = ssl.create_default_context()
        status, headers, data, peer = _one_exchange(
            current_hop, route=route, method=method, headers=request_headers,
            body=body, timeout=timeout,
            tls=context if current_hop.scheme == "https" else None,
            deadline=deadline, plan=plan, max_bytes=max_bytes)
        via = current_hop.via
        if status == 304 and 304 in accept:
            return Fetched(304, headers, b"", current, _media_type(headers),
                           headers.get("ETag"), headers.get("Last-Modified"),
                           followed, via, peer, None)
        raw_location = headers.get("Location")
        if status in REDIRECT_CODES and following:
            if not raw_location:
                raise RedirectRefused(f"HTTP {status} with no Location header",
                                      code="no_location", **_ANSWERED)
            # Relative targets are legal and common; resolve against the
            # hop we are ON, not against the original URL.
            target = urllib.parse.urljoin(current, raw_location)
            if target in seen:
                # Agreed, not a bracketed plural (README screenshot set
                # review, 2026-09-23): the count is known when the line is
                # written.
                raise RedirectRefused(
                    f"redirect loop at {followed + 1} "
                    f"{'hop' if followed == 0 else 'hops'}", code="redirect_loop",
                    **_ANSWERED)
            if followed >= max_redirects:
                raise RedirectRefused(
                    f"more than {max_redirects} redirects. A chain this long is "
                    f"a loop or an attempt to exhaust the validator, and neither "
                    f"is a feed", code="too_many_redirects", **_ANSWERED)
            if redirects == "same_origin" and _origin(target) != origin:
                raise RedirectRefused(explain("off_origin_redirect"),
                                      code="off_origin_redirect", **_ANSWERED)
            seen.append(target)
            followed += 1
            current = target
            continue
        absolute = (urllib.parse.urljoin(current, raw_location)
                    if raw_location and 300 <= status < 400 else None)
        if 200 <= status < 300 or status in accept:
            return Fetched(status, headers, data, current, _media_type(headers),
                           headers.get("ETag"), headers.get("Last-Modified"),
                           followed, via, peer, absolute)
        location = location_host = None
        if absolute is not None:
            location, location_host = _stripped_location(absolute)
        raise HttpStatusError(
            status, retry_after=_retry_after(headers.get("Retry-After")),
            excerpt=_excerpt(data) if error_excerpt and not 300 <= status < 400 else "",
            location=location, location_host=location_host, headers=headers)


# ---------------------------------------------------------------------------
# open_connection (docs/20 section 5.7)
# ---------------------------------------------------------------------------

def open_connection(route: EgressRoute, host: str, port: int, *, timeout: float,
                    deadline: Deadline, tls: ssl.SSLContext | None = None
                    ) -> socket.socket:
    """A socket to host:port on `route`, for a protocol that is not HTTP
    (the SMTP relay). DIRECT: checked, resolved once and dialled by number;
    PROXY: the CONNECT tunnel, which leaves a server-first banner in the
    socket. `tls` wraps it (implicit TLS on 465) with the certificate
    checked against `host`, under the watchdog.

    `deadline` must be an ENTERED Deadline, because the socket outlives
    this call: it is returned watched by that Deadline, a caller that
    replaces the socket (STARTTLS) re-watches the new one, and the caller
    exits the Deadline when the session ends."""
    if not isinstance(route, EgressRoute):
        raise ValueError("route is an EgressRoute from egress.route_for")
    if not isinstance(deadline, Deadline) or not deadline.entered:
        raise ValueError("open_connection takes an entered Deadline")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout is above 0")
    label = _route_label(route)
    try:
        name = egress_policy.normalise_host(host)
        rule = egress_policy.check_destination(route.policy, name, port,
                                               route_label=label)
        if route.mode == "DIRECT":
            if egress_policy.is_onion(name):
                raise Refusal("onion_not_allowed",
                              f"{name}: " + explain("onion_not_allowed"), host=name)
            pinned = egress_policy.resolve_and_pin(name, port, policy=route.policy,
                                                   rule=rule, route_label=label)
    except Refusal as refusal:
        raise _refused(refusal) from None
    except Unresolvable as failure:
        raise UnresolvableHost(failure.host, permanent=failure.permanent) from None
    facts = _Facts()
    try:
        if route.mode == "DIRECT":
            hop = Hop("tcp", name, port, "", pinned.addresses, pinned.locality)
            sock = _dial(hop, timeout, deadline)
            deadline.watch(sock)
        else:
            sock = _open_tunnel(route, name, port, timeout=timeout, deadline=deadline)
        facts.connected = True
        if tls is not None:
            sock = _wrap_tls(sock, tls, name, deadline)
        sock.settimeout(timeout)
        return sock
    except OutboundError as exc:
        exc._facts(facts)
        raise
    except ssl.SSLCertVerificationError as exc:
        raise CertificateRefused(
            f"certificate check failed for {name}: "
            f"{redact(exc.verify_message or str(exc))}")._facts(facts) from exc
    except (OSError, UnicodeError) as exc:
        if deadline.ran_out(exc):
            raise deadline.exceeded()._facts(facts) from exc
        code = ("connect_refused" if isinstance(exc, ConnectionRefusedError)
                and not facts.connected else "unreachable")
        raise Unreachable(f"unreachable: {redact(str(exc))}",
                          code=code)._facts(facts) from exc
