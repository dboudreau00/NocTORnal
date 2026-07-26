"""Phase 4 -- collection: the adapter interface, the scheduler, the persona
vault and watch matching (docs/04).

The `collect.*` schema has existed since Phase 0. This is the code, and it
arrives LAST among the buildable phases on purpose. docs/09:

    The graph and assertion layer must work end to end before collection
    is switched on. Pointing a firehose at a half-built model produces a
    landfill you then have to clean by hand.

## Invariant 7 is the shape of this module

    Credentials never leave the collector. `collection_account.secret_*`
    is decrypted only inside the collection worker, never in the API
    process, never serialised to a response, never logged.

So `PersonaVault.use()` is a CONTEXT MANAGER that hands a secret to a
callback and drops it, and there is no `get_secret()` anywhere. That is not
politeness -- a function returning a plaintext credential is a function
somebody will call from a request handler, and then the secret is in a
traceback, a log line and an error response. A shape that cannot be misused
is worth more than a rule that must be remembered.

`redact()` exists for the same reason and is applied to every adapter error
before it is stored: a persona's password lands in an HTTP error body far
more often than anybody expects.

## The scheduler is polite by construction

docs/04 asks for jitter and per-source `max_rps`, and the reason is
operational security rather than courtesy. A collector that polls exactly
every 300 seconds is a collector that a competent forum admin can pick out
of an access log in an afternoon -- and a burnt persona is expensive and
slow to replace.

So `next_due_at` adds jitter as a PERCENTAGE of the interval, and
`RateLimiter` spaces requests per source. Both are deliberately visible in
the run record, because "why did this poll at 04:12" should be answerable.

## Operational separation is enforced, not advised

docs/04: "One persona ↔ one egress profile. Enforced with a constraint, not
a convention. Two personas sharing an exit IP can be correlated by any
competent forum admin, and you lose both at once."

`check_egress_separation()` is that check. It is not a database constraint
because an egress profile legitimately serves many personas across DIFFERENT
sources over time -- what must not happen is two personas on the same
profile being live simultaneously against the same source. That is a
temporal condition, and stating it honestly as a check with a reason beats
a constraint that is either wrong or unenforceable.

## What is NOT built, and why

- **No live adapters except RSS.** XenForo, MyBB and Telegram each need a
  real target to develop against and a persona to develop with, and both are
  authorisation questions (docs/16 L3) rather than coding ones. The
  interface is here and the RSS adapter proves the pipeline end to end.
- **No scheduler process.** `due_sources()` reports and `run_once()` acts;
  nothing loops. Same reasoning as decisions 30 and 46 -- a collector that
  runs itself on a timer nobody watches is how a persona gets burnt at 3am.
- **No SSRF protection yet.** Watch targets are user-supplied URLs, which is
  exactly the SSRF surface docs/09 names. `fetch()` refuses non-HTTP schemes
  and private address literals, which is a floor and not a solution -- DNS
  rebinding is not addressed. Recorded in docs/16.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import ipaddress
import random
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security import envelope

#: docs/04's persona lifecycle. A burnt persona never returns to HEALTHY:
#: reusing one that a forum admin has already flagged is how you burn the
#: next one too.
HEALTHY, COOLDOWN, LOCKED, BURNED = "HEALTHY", "COOLDOWN", "LOCKED", "BURNED"
_TERMINAL = frozenset({BURNED})

#: Private ranges an outbound fetch must never reach. A floor, not a
#: solution -- see the module docstring and docs/16.
#:
#: docs/17 F15(f): the enumerated list missed `::ffff:127.0.0.1` (the
#: IPv4-mapped form of loopback, which `ip_address` parses as IPv6 and
#: which no entry here matched), the unspecified address `::`, and the
#: 100.64/10, 192.0.0/24 and 198.18/15 ranges. Enumerating was the
#: mistake -- `_is_blocked` below asks the address what it IS and uses
#: this list only for the cases the stdlib does not classify.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "0.0.0.0/8",
        # Carrier-grade NAT: inside a provider's network, not the public
        # internet, and reachable from a cloud instance.
        "100.64.0.0/10",
        # IETF protocol assignments, which include 192.0.0.192 -- the
        # shape of a metadata endpoint.
        "192.0.0.0/24",
        # Benchmarking. Routed internally in more networks than you would
        # expect.
        "198.18.0.0/15",
        # The unspecified address. `http://[::]/` and `http://0.0.0.0/`
        # both reach the local host on most stacks.
        "::/128",
        # Deprecated IPv6 site-local. RFC 3879 deprecated it, so Python's
        # `ipaddress` reports is_private=False, is_global=TRUE and
        # is_reserved=False -- none of the stdlib predicates fire, and
        # `fc00::/7` does not cover it. Still routed internally on any
        # network that predates ULA, which is most of the ones that have
        # an internal IPv6 plan at all.
        "fec0::/10",
    )
]

#: The cloud metadata endpoint, by name and by address. Not private space
#: -- 169.254.169.254 IS in link-local, but the alias hosts are not, and
#: reaching any of them from a collector is credential theft against
#: ourselves rather than an SSRF against somebody else.
_METADATA_HOSTS = frozenset({
    "metadata.google.internal", "metadata.goog", "instance-data",
    "metadata.azure.com",
})

#: A redirect chain longer than this is either a loop or an attempt to
#: exhaust the validator. urllib's own default is 10.
MAX_REDIRECTS = 5

#: How much of a response body is worth reading. 16 MiB is far above any
#: legitimate RSS or forum page and far below what it takes to hurt the
#: collector. There is no "unlimited" option on purpose: the one host in
#: this system holding every persona credential should not have a code
#: path whose memory use is chosen by a monitored source.
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Ask the address what it is, then check the ranges the stdlib misses.

    `ipv4_mapped` is the load-bearing line: `::ffff:127.0.0.1` parses as an
    IPv6Address, is not `is_loopback`, and matched no entry in the
    enumerated list -- so it was a complete bypass of this check with a
    two-character prefix.
    """
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    sixtofour = getattr(address, "sixtofour", None)
    if sixtofour is not None:
        # 2002::/16 embeds an IPv4 address; if the embedded one is
        # internal, so is the tunnel.
        if _is_blocked(sixtofour):
            return True
    if (address.is_loopback or address.is_private or address.is_link_local
            or address.is_multicast or address.is_reserved
            or address.is_unspecified):
        return True
    return any(address in network for network in _BLOCKED_NETWORKS)


def _resolve_and_check(url: str) -> str:
    """Validate ONE hop. Returns the host, raises if it must not be reached.

    Split out of `fetch` because it has to run on every redirect target as
    well as the first URL -- docs/17 F15(f). `urlopen` follows redirects
    internally, so hops 2..N used to be reached with no check at all: a
    public host returning `302 -> http://127.0.0.1/` fetched the internal
    page, which is the whole SSRF this function exists to stop, arrived at
    by the one route nobody looked at.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise CollectionError(
            f"refusing scheme {parsed.scheme!r}: only http and https are "
            f"fetched, and file:// or gopher:// in a watch target is an "
            f"attempt rather than a mistake")
    host = parsed.hostname
    if not host:
        raise CollectionError("no host in URL")
    if host.lower().rstrip(".") in _METADATA_HOSTS:
        raise CollectionError(
            f"{host} is a cloud metadata endpoint. Reaching it from a "
            f"collector steals our own credentials, which is worse than the "
            f"SSRF this check is usually about")
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError as exc:
        raise CollectionError(f"cannot resolve {host}") from exc
    if not resolved:
        raise CollectionError(f"cannot resolve {host}")
    for address in resolved:
        # A host with ONE internal answer is refused even if it also has
        # public ones: which answer the connect() uses is not ours to
        # choose, and a mixed answer is the classic rebinding setup.
        if _is_blocked(ipaddress.ip_address(address.split("%")[0])):
            raise CollectionError(
                f"{host} resolves into private address space, which a watch "
                f"target must not: that is the SSRF shape docs/09 names")
    return host


class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    """Turns a redirect into an HTTPError so the caller can re-validate.

    Returning None from `redirect_request` makes urllib raise instead of
    following, which is exactly what is wanted: the decision to follow has
    to be ours, because following is what crosses the boundary.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CollectionError(Exception):
    pass


class PersonaUnavailable(CollectionError):
    """The persona cannot be used right now -- cooling down, locked or
    burnt. A distinct type because the caller's response differs: a
    cooldown is a wait, a burn is a replacement."""


# ---------------------------------------------------------------------------
# Redaction -- applied before any adapter error is stored
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


# ---------------------------------------------------------------------------
# The persona vault (invariant 7)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Persona:
    id: UUID
    source_id: UUID
    handle: str
    status: str
    cooldown_until: datetime | None
    egress_profile_id: UUID | None
    last_used_at: datetime | None
    burn_reason: str | None

    def is_usable(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self.status in _TERMINAL or self.status == LOCKED:
            return False
        if self.cooldown_until and self.cooldown_until > now:
            return False
        return True


class PersonaVault:
    """Envelope-encrypted persona credentials.

    **There is deliberately no `get_secret()`.** `use()` is a context
    manager that hands the plaintext to a block and drops it. A function
    that RETURNS a credential is a function somebody calls from a request
    handler, and then the secret is in a traceback, a log line and an error
    response. Invariant 7 is easier to hold with a shape that cannot be
    misused than with a rule that must be remembered.
    """

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def store(self, persona_id: UUID, secret: str, *, actor_id: UUID) -> None:
        ciphertext, key_id = envelope.encrypt(secret)
        self._c.execute(
            """UPDATE collect.collection_account
                  SET secret_ciphertext = %s, secret_key_id = %s,
                      secret_rotated_at = now()
                WHERE id = %s""", (ciphertext, key_id, persona_id))
        self._audit(actor_id, "PERSONA_SECRET_STORED", persona_id, {})

    @contextmanager
    def use(self, persona_id: UUID, *, actor_id: UUID, purpose: str):
        """Yield the plaintext for the duration of a block, then drop it.

        Every use is audited with a purpose, because docs/05 requires
        "every persona use" to be logged and a use with no stated purpose
        is not reviewable.
        """
        row = self._c.execute(
            """SELECT secret_ciphertext, secret_key_id, status, cooldown_until
                 FROM collect.collection_account WHERE id = %s""",
            (persona_id,)).fetchone()
        if row is None:
            raise CollectionError("no such persona")
        if row[2] in _TERMINAL:
            raise PersonaUnavailable(
                f"this persona is {row[2]} and must not be used again: "
                f"re-using one a forum admin has already flagged is how you "
                f"burn the next one too")
        if row[2] == LOCKED:
            raise PersonaUnavailable("this persona is locked")
        if row[3] and row[3] > datetime.now(timezone.utc):
            raise PersonaUnavailable(
                f"this persona is cooling down until {row[3].isoformat()}; a "
                f"persona active 24/7 is a bot and reads as one (docs/04)")
        if not row[0]:
            raise CollectionError("this persona has no stored credential")

        self._audit(actor_id, "PERSONA_USED", persona_id, {"purpose": purpose})
        secret = envelope.decrypt(bytes(row[0]), key_id=row[1])
        try:
            # For exactly as long as the plaintext is live, `redact` knows
            # it verbatim and in its wire forms (docs/17 F15(j)). This is
            # the layer that holds invariant 7 when a remote server echoes
            # the credential back under a field name nobody anticipated.
            with secret_in_scope(secret):
                yield secret
        finally:
            # Python cannot guarantee the string is gone, and pretending
            # otherwise would be worse than saying so: the real control is
            # that it never left this frame.
            del secret
            self._c.execute(
                "UPDATE collect.collection_account SET last_used_at = now() "
                "WHERE id = %s", (persona_id,))

    def set_status(self, persona_id: UUID, status: str, *, actor_id: UUID,
                   reason: str | None = None,
                   cooldown: timedelta | None = None) -> None:
        """Move a persona through the lifecycle.

        BURNED is terminal and requires a reason: the reason is what stops
        the next analyst quietly reusing it, and "burnt" with no explanation
        reads as "somebody was being careful once".
        """
        if status not in {HEALTHY, COOLDOWN, LOCKED, BURNED}:
            raise CollectionError(f"unknown persona status {status!r}")
        if status == BURNED and not (reason or "").strip():
            raise CollectionError(
                "a burn has to say what burnt it: without a reason the next "
                "analyst has nothing to avoid repeating")
        current = self._c.execute(
            "SELECT status FROM collect.collection_account WHERE id = %s",
            (persona_id,)).fetchone()
        if current and current[0] == BURNED and status != BURNED:
            raise CollectionError(
                "a burnt persona does not come back: reusing one a forum "
                "admin has already flagged burns the next one too")
        until = (datetime.now(timezone.utc) + cooldown) if cooldown else None
        self._c.execute(
            """UPDATE collect.collection_account
                  SET status = %s, cooldown_until = %s, burn_reason = %s
                WHERE id = %s""",
            (status, until, (reason or "").strip() or None, persona_id))
        self._audit(actor_id, f"PERSONA_{status}", persona_id,
                    {"reason": reason, "cooldown_until":
                     until.isoformat() if until else None})

    def check_egress_separation(self, source_id: UUID) -> list[dict]:
        """docs/04: one persona, one egress profile.

        "Two personas sharing an exit IP can be correlated by any competent
        forum admin, and you lose both at once."

        NOT a database constraint, deliberately: an egress profile
        legitimately serves many personas across DIFFERENT sources over
        time. What must not happen is two live personas on the same profile
        against the SAME source. That is a temporal condition, and a check
        with a stated reason beats a constraint that is either wrong or
        unenforceable.
        """
        rows = self._c.execute(
            """SELECT egress_profile_id, count(*), array_agg(handle)
                 FROM collect.collection_account
                WHERE source_id = %s AND egress_profile_id IS NOT NULL
                  AND status NOT IN ('BURNED', 'LOCKED')
                GROUP BY egress_profile_id HAVING count(*) > 1""",
            (source_id,)).fetchall()
        return [{"egress_profile_id": str(r[0]), "persona_count": r[1],
                 "handles": list(r[2]),
                 "risk": "two live personas share an exit against one source; "
                         "a forum admin correlating them loses you both"}
                for r in rows]

    def _audit(self, actor_id: UUID, action: str, persona_id: UUID,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, detail)
               VALUES (%s, 'USER', %s, 'collection_account', %s, %s)""",
            (actor_id, action, persona_id, Json(detail)))


# ---------------------------------------------------------------------------
# The adapter interface
# ---------------------------------------------------------------------------

@dataclass
class Item:
    """One thing a collector found. Deliberately flat and small: an adapter
    that has to construct a graph element is an adapter that can write the
    graph, and invariant 3 says it cannot."""

    external_id: str
    url: str | None = None
    title: str | None = None
    body: str = ""
    author_handle: str | None = None
    posted_at: datetime | None = None
    thread_ref: str | None = None
    raw: dict = field(default_factory=dict)

    @property
    def content_sha256(self) -> bytes:
        return hashlib.sha256(
            f"{self.external_id}\x1f{self.title or ''}\x1f{self.body}".encode()
        ).digest()


@dataclass
class FetchResult:
    items: list[Item] = field(default_factory=list)
    etag: str | None = None
    last_modified: str | None = None
    http_status: int | None = None
    cursor: dict = field(default_factory=dict)


class Adapter:
    """What a collector must implement.

    `fetch` returns ITEMS, never graph elements. An adapter that could
    construct a node would be an extractor writing the graph, and invariant
    3 says extractors propose. Everything an adapter produces lands as a
    `collect.document` and reaches the graph only through the proposal
    queue a human works.
    """

    key: str = "abstract"
    version: str = "0"

    def fetch(self, *, base_url: str, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None
              ) -> FetchResult:
        raise NotImplementedError


class RssAdapter(Adapter):
    """The simplest adapter, and the one that proves the pipeline.

    docs/09 puts RSS first for exactly that reason: it needs no persona, no
    authorisation and no target that can notice it, so the plumbing can be
    proved before any of the risk arrives.

    Parsed with the stdlib XML parser and **entity resolution disabled**:
    an XXE in a feed you did not write is a file-read primitive, and a feed
    is by definition attacker-adjacent.
    """

    key = "rss"
    version = "1"

    def fetch(self, *, base_url: str, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None
              ) -> FetchResult:
        body, status, new_etag, last_modified = fetch(base_url, etag=etag)
        if status == 304 or not body:
            return FetchResult(items=[], etag=etag, http_status=status)
        return FetchResult(items=parse_rss(body), etag=new_etag,
                           last_modified=last_modified, http_status=status)


#: Anything that could introduce an entity. A feed is attacker-adjacent by
#: definition -- it is a document written by the people under investigation.
_DOCTYPE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)


#: The XML prolog ends at the first element start-tag. Anything before it
#: is a declaration, comment or processing instruction — the only region
#: where a DTD may legally appear (CP1).
_ROOT_START = re.compile(rb"<[A-Za-z_]")


def _root_element_offset(body: bytes, cap: int = 1 << 20) -> int:
    """Where the prolog ends, capped so a body with no root element does
    not turn the DOCTYPE scan into a full pass over 16 MiB."""
    match = _ROOT_START.search(body[:cap])
    return match.start() if match else min(len(body), cap)


def parse_rss(body: bytes) -> list[Item]:
    """Minimal RSS/Atom parsing that REFUSES a DOCTYPE.

    `defusedxml` would be the right dependency and is not one. Without it,
    the honest defence is to refuse the construct rather than to try to
    neuter it: a feed has no legitimate need for a DOCTYPE or an internal
    entity, and refusing both closes XXE and billion-laughs outright
    instead of relying on a parser flag whose name and effect have changed
    between Python versions.

    An XXE in a feed you did not write is a file-read primitive on the
    collector, which is the host holding every persona credential.
    """
    from xml.etree import ElementTree

    # CP1 (2026-07-26): scan up to the ROOT ELEMENT, not a fixed 8 KiB.
    #
    # The window was `body[:8192]` while bodies up to 16 MiB are accepted,
    # so an 8 KiB XML comment ahead of the DTD walked straight past the
    # regex. ElementTree resolves no external entities and modern libexpat
    # caps entity amplification, so the demonstrated harm is limited — but
    # this is the check that is supposed to make those two facts
    # irrelevant, and a defence with a documented bypass is not one.
    #
    # The prolog is everything before the first element start-tag that is
    # not a comment, PI or declaration. Scanning to the first `<` that
    # begins a name character bounds the work without bounding the
    # coverage: a DTD cannot legally appear after the root element starts,
    # so anything past that point is not a prolog DTD.
    prolog_end = _root_element_offset(body)
    if _DOCTYPE.search(body[:prolog_end]):
        raise CollectionError(
            "refusing a feed containing a DOCTYPE or ENTITY declaration: a "
            "feed has no legitimate need for one, and an XXE here is a "
            "file-read primitive on the host holding every persona "
            "credential")

    try:
        root = ElementTree.fromstring(body)
    except Exception as exc:  # noqa: BLE001 - a broken feed is not a crash
        raise CollectionError(f"feed did not parse: {type(exc).__name__}") from exc

    items: list[Item] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag not in {"item", "entry"}:
            continue
        fields: dict[str, str] = {}
        for child in element:
            name = child.tag.rsplit("}", 1)[-1].lower()
            if name == "link" and not (child.text or "").strip():
                fields["link"] = child.attrib.get("href", "")
            else:
                fields[name] = (child.text or "").strip()
        external = (fields.get("guid") or fields.get("id")
                    or fields.get("link") or fields.get("title") or "")
        if not external:
            continue
        items.append(Item(
            external_id=external,
            url=fields.get("link"),
            title=fields.get("title"),
            body=fields.get("description") or fields.get("summary")
            or fields.get("content") or "",
            author_handle=fields.get("author") or fields.get("creator"),
            raw=fields,
        ))
    return items


def fetch(url: str, *, etag: str | None = None,
          timeout: float = 15.0,
          max_redirects: int = MAX_REDIRECTS,
          max_bytes: int = MAX_RESPONSE_BYTES
          ) -> tuple[bytes, int, str | None, str | None]:
    """An outbound HTTP GET with the floor of SSRF protection.

    Refuses non-HTTP schemes and addresses that resolve into private space,
    and re-validates **every redirect hop** rather than the first URL only.

    **This is a floor, not a solution**: DNS rebinding defeats a
    resolve-then-connect check -- the name is resolved once here and again
    by the socket layer, and nothing stops those two answers differing. The
    real fix is a proxy that enforces the policy at connect time. Recorded
    in docs/16 rather than implied by its presence.

    What it is no longer missing (docs/17 F15(f)): redirects. `urlopen`
    followed them internally, so hops 2..N were reached with no check at
    all and a public host answering `302 -> http://127.0.0.1/` fetched the
    internal page. The module docstring named DNS rebinding as the known
    gap and did not mention this one, so the stated floor was not the
    actual floor.
    """
    opener = urllib.request.build_opener(_NoAutoRedirect)
    seen = [url]
    for hop in range(max_redirects + 1):
        current = seen[-1]
        _resolve_and_check(current)
        request = urllib.request.Request(current, headers={
            # Honest about being a collector. A user-agent that impersonates
            # a browser is a decision with a legal dimension (docs/16 L3),
            # not a default.
            "User-Agent": "NocTORnal-collector/1",
            **({"If-None-Match": etag} if etag else {}),
        })
        try:
            with opener.open(request, timeout=timeout) as response:
                # Capped, and read one byte past the cap so the difference
                # between "exactly at the limit" and "more coming" is
                # knowable. `timeout` is urllib's PER-SOCKET-OPERATION
                # timeout, not a transfer budget: a server drip-feeding one
                # chunk every few seconds keeps an uncapped `read()` alive
                # indefinitely while the buffer grows. Everything reached
                # through here is attacker-adjacent by this module's own
                # definition -- "a document written by the people under
                # investigation" -- and the host holding every persona
                # credential is the one doing the reading.
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise CollectionError(
                        f"response exceeded {max_bytes} bytes and was "
                        f"abandoned. A feed larger than this is either a "
                        f"misconfiguration or something aimed at the "
                        f"collector; raise max_bytes deliberately if it is "
                        f"the first.")
                return (body, response.status,
                        response.headers.get("ETag"),
                        response.headers.get("Last-Modified"))
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                return b"", 304, etag, None
            if exc.code not in {301, 302, 303, 307, 308}:
                raise CollectionError(f"HTTP {exc.code}") from exc
            location = exc.headers.get("Location")
            if not location:
                raise CollectionError(
                    f"HTTP {exc.code} with no Location header") from exc
            # Relative targets are legal and common; resolve against the
            # hop we are ON, not against the original URL.
            target = urllib.parse.urljoin(current, location)
            if target in seen:
                raise CollectionError(
                    f"redirect loop at {hop + 1} hop(s)") from exc
            seen.append(target)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise CollectionError(f"unreachable: {redact(str(exc))}") from exc
    raise CollectionError(
        f"more than {max_redirects} redirects. A chain this long is a loop "
        f"or an attempt to exhaust the validator, and neither is a feed")


# ---------------------------------------------------------------------------
# The scheduler
# ---------------------------------------------------------------------------

def next_due_at(last_ok: datetime | None, interval_s: int, jitter_pct: int,
                *, now: datetime | None = None,
                rng: random.Random | None = None) -> datetime:
    """When to poll next, with jitter as a PERCENTAGE of the interval.

    docs/04 asks for jitter and the reason is operational security, not
    courtesy: a collector that polls exactly every 300 seconds is one a
    competent forum admin picks out of an access log in an afternoon, and a
    burnt persona is expensive and slow to replace.

    Jitter is symmetric around the interval rather than added to it -- only
    ever adding makes the MINIMUM gap the interval, which is still a
    signature.
    """
    now = now or datetime.now(timezone.utc)
    if last_ok is None:
        # A source that has NEVER been polled is due now, not one interval
        # from now. Waiting the interval first means a newly-added source
        # sits idle for its whole period and somebody concludes the
        # collector is broken -- which is how a working system gets
        # "fixed".
        return now
    base = last_ok + timedelta(seconds=interval_s)
    if jitter_pct <= 0:
        return base
    generator = rng or random.Random()
    spread = interval_s * (jitter_pct / 100.0)
    return base + timedelta(seconds=generator.uniform(-spread, spread))


class RateLimiter:
    """Per-source `max_rps`, spaced rather than bursted.

    docs/04 asks for it globally through Redis; this is the durable half
    and it is honest about being that. A burst that respects an average is
    still a burst, and a burst is what gets noticed.

    docs/17 F15(i): the state used to live on the INSTANCE, and
    `CollectionService` is constructed per request, so the dict was always
    empty and this never spaced anything. It now reads and writes
    `collect.source.last_request_at`, which survives the process and is
    shared between workers -- the property that actually matters. A Redis
    token bucket remains the right optimisation; it is no longer the fix
    for a correctness bug.
    """

    def __init__(self, conn: psycopg.Connection | None = None, *,
                 sleep=time.sleep, clock=time.monotonic):
        self._c = conn
        self._last: dict[UUID, float] = {}
        self._sleep = sleep
        self._clock = clock

    def wait(self, source_id: UUID, max_rps: float) -> float:
        if max_rps <= 0:
            return 0.0
        gap = 1.0 / max_rps
        delay = 0.0
        if self._c is not None:
            # `now()` is the TRANSACTION timestamp in Postgres and would
            # be identical for two calls in one transaction; clock_timestamp
            # is the wall clock, which is what a gap between requests means.
            row = self._c.execute(
                """SELECT extract(epoch FROM
                              clock_timestamp() - last_request_at)
                     FROM collect.source WHERE id = %s""",
                (source_id,)).fetchone()
            elapsed = float(row[0]) if row and row[0] is not None else None
            if elapsed is not None and 0 <= elapsed < gap:
                delay = gap - elapsed
                self._sleep(delay)
            self._c.execute(
                "UPDATE collect.source SET last_request_at = clock_timestamp() "
                "WHERE id = %s", (source_id,))
            return delay

        # No connection: in-process only, which is what the unit tests use
        # and what a caller gets if they construct this by hand. Kept so
        # the class is still testable without a database, and NOT the
        # default anywhere real.
        now = self._clock()
        previous = self._last.get(source_id)
        if previous is not None and now - previous < gap:
            delay = gap - (now - previous)
            self._sleep(delay)
        self._last[source_id] = self._clock()
        return delay


@dataclass
class RunResult:
    run_id: UUID
    items_seen: int = 0
    items_new: int = 0
    watch_hits: int = 0
    error: str | None = None


class CollectionService:
    def __init__(self, conn: psycopg.Connection,
                 adapters: dict[str, Adapter] | None = None,
                 limiter: RateLimiter | None = None):
        self._c = conn
        self._adapters = adapters or {"rss": RssAdapter()}
        self._limiter = limiter or RateLimiter(conn)

    def due_sources(self, *, now: datetime | None = None,
                    rng: random.Random | None = None) -> list[dict]:
        """What is ready to poll. Reports; does not act.

        Nothing loops here. A collector that runs itself on a timer nobody
        watches is how a persona gets burnt at 3am, and the same reasoning
        (decisions 30, 46) applies: the seam is deliberate.

        It also does not ROLL here. docs/17 F15(i): this used to compute
        `next_due_at` freshly on every call, so the schedule was re-rolled
        every time anybody looked and the realised interval depended on how
        often the scheduler polls. Frequent polling collapsed the variance
        toward the floor -- a regular cadence, which is the signature
        jitter exists to avoid. The schedule is now stored, rolled once
        when a run finishes, and read as-is.
        """
        now = now or datetime.now(timezone.utc)
        rows = self._c.execute(
            """SELECT id, kind, name, base_url, poll_interval_s, jitter_pct,
                      max_rps, parser_key, last_ok_at, consecutive_failures,
                      health, next_due_at
                 FROM collect.source
                WHERE is_active ORDER BY next_due_at NULLS FIRST""").fetchall()
        due = []
        for row in rows:
            when = row[11]
            if when is None:
                # A source added before 0042, or one whose schedule was
                # never set. Roll it ONCE and persist, rather than treating
                # a missing schedule as "not due" and never polling it.
                when = next_due_at(row[8], row[4], row[5], now=now, rng=rng)
                self._c.execute(
                    "UPDATE collect.source SET next_due_at = %s WHERE id = %s",
                    (when, row[0]))
            if when <= now:
                due.append({
                    "id": row[0], "kind": row[1], "name": row[2],
                    "base_url": row[3], "max_rps": float(row[6] or 1),
                    "parser_key": row[7], "due_at": when.isoformat(),
                    "consecutive_failures": row[9], "health": row[10],
                })
        return due

    def _reschedule(self, source_id: UUID, *,
                    rng: random.Random | None = None) -> datetime:
        """Roll the next due time ONCE, after a poll, and store it."""
        row = self._c.execute(
            "SELECT poll_interval_s, jitter_pct FROM collect.source "
            "WHERE id = %s", (source_id,)).fetchone()
        when = next_due_at(datetime.now(timezone.utc), row[0], row[1], rng=rng)
        self._c.execute(
            "UPDATE collect.source SET next_due_at = %s WHERE id = %s",
            (when, source_id))
        return when

    def run_once(self, source_id: UUID, *, actor_id: UUID,
                 persona_id: UUID | None = None,
                 watch_id: UUID | None = None) -> RunResult:
        """One poll. Every outcome is a `collection_run` row, including the
        failures -- parser health is only knowable if the failures are
        recorded as carefully as the successes."""
        source = self._c.execute(
            """SELECT base_url, parser_key, max_rps, classification,
                      default_reliability
                 FROM collect.source WHERE id = %s""", (source_id,)).fetchone()
        if source is None:
            raise CollectionError("no such source")
        adapter = self._adapters.get(source[1])
        if adapter is None:
            raise CollectionError(
                f"no adapter registered for parser_key {source[1]!r}")

        run_id = self._c.execute(
            """INSERT INTO collect.collection_run
                   (source_id, watch_id, collection_account_id, status,
                    parser_version)
               VALUES (%s, %s, %s, 'RUNNING', %s) RETURNING id""",
            (source_id, watch_id, persona_id, adapter.version)).fetchone()[0]
        result = RunResult(run_id=run_id)

        self._limiter.wait(source_id, float(source[2] or 1))
        try:
            fetched = adapter.fetch(base_url=source[0])
        except Exception as exc:  # noqa: BLE001 - every failure is a row
            # REDACTED before it is stored. A persona's password lands in an
            # HTTP error body far more often than anybody expects.
            message = redact(str(exc))[:2000]
            self._c.execute(
                """UPDATE collect.collection_run
                      SET status = 'FAILED', finished_at = now(),
                          error_class = %s, error_detail = %s
                    WHERE id = %s""",
                (type(exc).__name__, message, run_id))
            self._record_failure(source_id, type(exc).__name__)
            # Rescheduled on failure too. A source that only reschedules on
            # success is one that retries as fast as the scheduler runs the
            # moment it breaks -- which is a hammering pattern aimed at a
            # site that has just started refusing us.
            self._reschedule(source_id)
            result.error = message
            return result

        result.items_seen = len(fetched.items)
        for item in fetched.items:
            if self._store_document(source_id, run_id, watch_id, item,
                                    classification=source[3]):
                result.items_new += 1
        result.watch_hits = self._match_watches(source_id, run_id,
                                                fetched.items)

        self._c.execute(
            """UPDATE collect.collection_run
                  SET status = 'OK', finished_at = now(), items_seen = %s,
                      items_new = %s, http_status = %s, etag = %s,
                      last_modified = %s
                WHERE id = %s""",
            (result.items_seen, result.items_new, fetched.http_status,
             fetched.etag, fetched.last_modified, run_id))
        self._c.execute(
            """UPDATE collect.source
                  SET last_ok_at = now(), consecutive_failures = 0,
                      health = 'OK'
                WHERE id = %s""", (source_id,))
        self._reschedule(source_id)
        return result

    def _store_document(self, source_id: UUID, run_id: UUID,
                        watch_id: UUID | None, item: Item,
                        classification: str) -> bool:
        """Deduped on content hash, versioned rather than overwritten.

        An edited forum post is a NEW version, not a correction: what the
        actor said and what they later said instead are both facts, and
        overwriting loses the more interesting one.
        """
        digest = item.content_sha256
        existing = self._c.execute(
            """SELECT id FROM collect.document
                WHERE source_id = %s AND content_sha256 = %s LIMIT 1""",
            (source_id, digest)).fetchone()
        if existing:
            return False
        previous = self._c.execute(
            """SELECT id, version FROM collect.document
                WHERE source_id = %s AND external_id = %s
                ORDER BY version DESC LIMIT 1""",
            (source_id, item.external_id)).fetchone()
        self._c.execute(
            """INSERT INTO collect.document
                   (source_id, collection_run_id, watch_id, external_id,
                    external_url, thread_ref, author_handle, posted_at,
                    title, body_text, content_sha256, version, supersedes_id,
                    classification, category)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       %s, 'FORUM_POST')""",
            (source_id, run_id, watch_id, item.external_id, item.url,
             item.thread_ref, item.author_handle, item.posted_at, item.title,
             item.body, digest, (previous[1] + 1) if previous else 1,
             previous[0] if previous else None, classification))
        return True

    def _match_watches(self, source_id: UUID, run_id: UUID,
                       items: list[Item]) -> int:
        """Keyword, selector and regex matching into `watch_hit`.

        Suppression is applied HERE rather than at notification time,
        because docs/04 wants repeated hits on the same thread collapsed
        into one with a running count -- and a suppression that happens
        after the row is written is a suppression that still filled the
        table.
        """
        watches = self._c.execute(
            """SELECT id, case_id, keywords, selector_watch, regexes,
                      priority, suppress_window_s
                 FROM collect.watch
                WHERE source_id = %s AND is_active""", (source_id,)).fetchall()
        hits = 0
        for watch in watches:
            (watch_id, _case_id, keywords, selectors, regexes, priority,
             suppress) = watch
            for item in items:
                haystack = f"{item.title or ''}\n{item.body}".lower()
                matched: list[str] = []
                for needle in (keywords or []):
                    if needle and needle.lower() in haystack:
                        matched.append(f"keyword:{needle}")
                for needle in (selectors or []):
                    if needle and needle.lower() in haystack:
                        matched.append(f"selector:{needle}")
                for pattern in (regexes or []):
                    try:
                        if pattern and re.search(pattern, haystack, re.I):
                            matched.append(f"regex:{pattern}")
                    except re.error:
                        # A watch with a broken pattern must not stop the
                        # other watches from matching.
                        continue
                if not matched:
                    continue
                document = self._c.execute(
                    """SELECT id FROM collect.document
                        WHERE source_id = %s AND external_id = %s
                        ORDER BY version DESC LIMIT 1""",
                    (source_id, item.external_id)).fetchone()
                if document is None:
                    continue
                if self._suppressed(watch_id, item.thread_ref
                                    or item.external_id, suppress):
                    continue
                self._c.execute(
                    """INSERT INTO collect.watch_hit
                           (watch_id, document_id, matched_on, score)
                       VALUES (%s, %s, %s, %s)""",
                    # `score` is inverted from `priority`: docs/04 numbers
                    # priority 1 as the most urgent, and a score wants the
                    # opposite sense so ORDER BY score DESC is the queue.
                    (watch_id, document[0], Json(matched), 10 - (priority or 3)))
                hits += 1
        if hits:
            self._c.execute(
                "UPDATE collect.watch SET last_hit_at = now() "
                "WHERE source_id = %s", (source_id,))
        return hits

    def _suppressed(self, watch_id: UUID, thread: str | None,
                    window_s: int | None) -> bool:
        if not window_s or not thread:
            return False
        row = self._c.execute(
            """SELECT 1 FROM collect.watch_hit wh
                 JOIN collect.document d ON d.id = wh.document_id
                WHERE wh.watch_id = %s
                  AND coalesce(d.thread_ref, d.external_id) = %s
                  AND wh.created_at > now() - (%s || ' seconds')::interval
                LIMIT 1""", (watch_id, thread, window_s)).fetchone()
        return row is not None

    def _record_failure(self, source_id: UUID, error_class: str) -> None:
        """Parser health. docs/04 asks for drift alerting, and the signal is
        consecutive failures rather than a rate: a parser that broke this
        morning fails every time, and a rate over a week hides that."""
        self._c.execute(
            """UPDATE collect.source
                  SET consecutive_failures = consecutive_failures + 1,
                      health = CASE
                        WHEN consecutive_failures + 1 >= 5 THEN 'BROKEN'
                        WHEN consecutive_failures + 1 >= 2 THEN 'DEGRADED'
                        ELSE 'OK' END
                WHERE id = %s""", (source_id,))

    def unhealthy_sources(self) -> list[dict]:
        """Sources that have actually FAILED, not sources nobody has polled.

        `WHERE health <> 'OK'` looked right and was not: a source that has
        never run carries the default health with zero failures, so every
        newly added source appeared on the alert list next to a parser that
        genuinely broke. Found by looking at the rendered list — three
        entries, one real.

        That matters more than it sounds. This list exists because "a
        parser that stopped matching fails silently unless somebody is
        watching", and a list padded with non-alerts is one people stop
        watching. Never-polled sources are reported separately, because
        "added and never collected" is also worth knowing — it is just not
        the same thing as broken.
        """
        rows = self._c.execute(
            """SELECT id, name, health, consecutive_failures, last_ok_at
                 FROM collect.source
                WHERE is_active
                  AND (consecutive_failures > 0
                       OR (health <> 'OK' AND last_ok_at IS NOT NULL))
                ORDER BY consecutive_failures DESC""").fetchall()
        return [{"id": str(r[0]), "name": r[1], "health": r[2],
                 "consecutive_failures": r[3],
                 "last_ok_at": r[4].isoformat() if r[4] else None,
                 "note": "a parser that stopped matching is usually the site "
                         "changing its markup, and it fails silently unless "
                         "somebody is watching this"}
                for r in rows]

    def never_polled_sources(self) -> list[dict]:
        """Active, configured, and never successfully collected from.

        Not an error and not healthy either. A source somebody added and
        nobody ever ran is the quiet way a collection plan turns out to
        have been aspirational.
        """
        rows = self._c.execute(
            """SELECT id, name, kind, created_at, consecutive_failures
                 FROM collect.source
                WHERE is_active AND last_ok_at IS NULL
                  AND consecutive_failures = 0
                ORDER BY created_at""").fetchall()
        return [{"id": str(r[0]), "name": r[1], "kind": r[2],
                 "created_at": r[3].isoformat() if r[3] else None,
                 "consecutive_failures": r[4],
                 "note": "configured but never collected from"}
                for r in rows]
