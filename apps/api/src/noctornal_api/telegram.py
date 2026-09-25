"""Telegram MTProto collection (roadmap F5.2 and F5.3, 2026-09-24;
docs/00 decisions 68, 69 and 77).

A Telegram chat is read by ONE persona: a real Telegram account whose
MTProto session is sealed in the persona's credential column, which reaches
Telegram only through that persona's egress profile on the egress proxy
(SOCKS5, docs/20 section 8.4), and which reads a chat only under a collection
authority two people confirmed. This module is the part that needs no
library: the constants, the typed ids, the chat references, the sealed
secret's shape, the outcome exceptions and the adapter. It never imports
Telethon; telegram_wire.py is the only module that does, and only inside
functions, so a build without the optional `telegram` extra imports this
module, lists the gap, and refuses every Telegram act with one sentence.

## What leaves the host

The persona's encrypted MTProto session to Telegram's data centres, through
the egress proxy and its exit: chat ids, access hashes and message ids.
Never case data, never a watch term, never a selector: matching happens on
this server after the messages arrive, and the adapter never searches,
never marks anything read, never sends, never joins on a poll and never
downloads media (docs/16 L1).

## Outcomes

Every answer Telegram gives is one of the exceptions below, each a subclass
of the collection foundation's class of the same meaning with a fixed
sentence and never Telethon's text. The foundation's record_outcome turns
each into the persona's machine hold or lock, the notification and the
audit row, for a poll and for an attended act alike, before the persona
lock is released.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import ipaddress
import json
import random
import re
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from noctornal_api.collection import (
    BUDGET_SPENT,
    ITEM_SKIPPED,
    Adapter,
    CollectionError,
    EgressUnavailable,
    FetchResult,
    Item,
    PersonaSuspended,
    RateLimited,
    RunWarning,
    SourceBlocked,
    SourceRow,
    WorkAbandoned,
    secret_in_scope,
)
from noctornal_api.wording import agree, count_of

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: One poll's session, and an attended act's. The poll's run_seconds (120)
#: is the session, its backstop and the persona gap, so the cron reserves
#: the whole poll before it starts one.
TELEGRAM_RUN_SECONDS = 90.0
TELEGRAM_ACT_SECONDS = 30.0
#: How long past its budget a session thread is waited for before it is
#: abandoned (and the persona rests, WorkAbandoned).
BACKSTOP_SECONDS = 10.0
#: No RPC is started with less than this left of the session: a call that
#: the budget would cut adds nothing but a half-open request.
RPC_TIMEOUT_SECONDS = 10.0

FIRST_POLL_MESSAGES = 200
MAX_MESSAGES_PER_RUN = 500
PAGE_SIZE = 100
RECHECK_HOURS = 48
RECHECK_MAX_IDS = 100
MIN_POLL_INTERVAL_S = 300
PERSONA_MIN_GAP_S = 20.0
RESOLVE_DIALOG_LIMIT = 500
ABANDONED_COOLDOWN_S = 900.0
MAX_MESSAGE_CHARS = 16384
MAX_NAME_CHARS = 256
MAX_REF_CHARS = 200

#: What a text cut to its cap ends with. The output, marker included, is
#: at most the cap (a 256-character name with a
#: marker appended failed the database's own cap and wedged the chat).
TRUNCATION_MARK = " [cut]"

#: Telegram's published data-centre networks, fetched 2026-09-24 from
#: https://core.telegram.org/resources/cidr.txt. IPv4 only: the client
#: connects with use_ipv6 False, and the IPv6 blocks (/48 and /32) are wider
#: than egress_policy's /64 rule cap, so the egress proxy's 'telegram' preset,
#: which reads this constant, could not save them (2026-09-24). A new
#: Telegram range fails closed until this list is updated.
TELEGRAM_DC_NETWORKS: tuple[str, ...] = (
    "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22",
    "91.108.12.0/22", "149.154.160.0/20", "91.105.192.0/23",
    "91.108.20.0/22", "185.76.151.0/24",
)
#: The same list's IPv6 half, recorded and unused while use_ipv6 is False.
TELEGRAM_DC_NETWORKS_IPV6: tuple[str, ...] = (
    "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48",
    "2001:b28:f23c::/48", "2a0a:f280::/32",
)
TELEGRAM_DC_PORTS: tuple[int, ...] = (443, 80, 5222)

_DC_NETWORKS = tuple(ipaddress.ip_network(n) for n in TELEGRAM_DC_NETWORKS)

#: The typed forms telegram_id_norm produces, as the migrations' CHECKs
#: spell them (test_telegram_ids holds the two texts equal).
UID_PATTERN = r"^u:[1-9][0-9]{0,19}$"
CHAT_PATTERN = r"^[cg]:[1-9][0-9]{0,19}$"
CHANNEL_PATTERN = r"^c:[1-9][0-9]{0,19}$"
PEER_PATTERN = r"^[ucg]:[1-9][0-9]{0,19}$"
SERVICE_ACTION_PATTERN = r"^[A-Za-z]{1,64}$"
MEDIA_KIND_PATTERN = r"^[a-z_]{1,32}$"

_UID = re.compile(UID_PATTERN)
_CHAT = re.compile(CHAT_PATTERN)
_PEER = re.compile(PEER_PATTERN)
_SERVICE_ACTION = re.compile(SERVICE_ACTION_PATTERN)
_MEDIA_KIND = re.compile(MEDIA_KIND_PATTERN)

#: What Telegram is told the persona's device is: the five fields, with
#: their lengths. Without them Telegram sees this server's platform string
#: and the library's version.
DEVICE_FIELDS: dict[str, tuple[int, int]] = {
    "device_model": (1, 64),
    "system_version": (1, 64),
    "app_version": (1, 32),
    "lang_code": (2, 8),
    "system_lang_code": (2, 16),
}
_DEVICE_WORDS = {
    "device_model": "device model", "system_version": "system version",
    "app_version": "app version", "lang_code": "language code",
    "system_lang_code": "system language code",
}
_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")

CLIENT_MISSING = ("The Telegram client library is not installed. Install "
                  "noctornal-api with the telegram extra.")
NO_PROXY_SENTENCE = ("Telegram is reached only through the egress proxy, and "
                     "none is configured. A direct connection would show "
                     "Telegram this server's own address.")
EGRESS_REFUSED_SENTENCE = (
    "The egress proxy refused the connection to Telegram's data centre: the "
    "persona's route, its authority or its destination policy does not allow "
    "it. The egress log says which.")
INVITE_SENTENCE = ("An invite link joins a private chat. Join it from the "
                   "persona's own device, then add the chat by its id.")
USER_REF_SENTENCE = ("A user id is a one-to-one conversation, not a chat. Add "
                     "a group or a channel.")
REFERENCE_SHAPE_SENTENCE = (
    "Give a public chat as @name or t.me/name, or a chat the persona is in by "
    "its id: c:<id>, g:<id> or the Bot API form -100<id>.")


# ---------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------

def client_available() -> tuple[bool, str]:
    """(installed, sentence): Telethon 1.x at 1.45 or later and python-socks,
    through the one module that may import them. The sentence names the
    version when installed and the extra when not."""
    from noctornal_api import telegram_wire

    version = telegram_wire.library_version()
    if version is None:
        return False, CLIENT_MISSING
    return True, f"Telethon {version} with python-socks is installed."


# ---------------------------------------------------------------------------
# Typed ids and references
# ---------------------------------------------------------------------------

class UntypedPeer(ValueError):
    """A peer this build cannot turn into a typed durable id."""


_PREFIX = {"user": "u:", "channel": "c:", "chat": "g:"}


def durable_peer(kind: str, peer_id) -> str:
    """THE producer of every Telegram id the adapter stores: u:, c: or g:
    through the ontology's own normaliser, and the typed pattern checked
    after it, so a normaliser that ever returned something else is refused
    here rather than by the database."""
    from noctornal_ontology import normalise

    prefix = _PREFIX.get(kind)
    if (prefix is None or isinstance(peer_id, bool)
            or not isinstance(peer_id, int) or peer_id <= 0):
        raise UntypedPeer(f"a {kind!r} peer this build cannot type")
    value = normalise("TELEGRAM_ID", prefix + str(peer_id))
    if not _PEER.match(value):
        raise UntypedPeer(f"a {kind!r} peer this build cannot type")
    return value


def is_typed_uid(value) -> bool:
    return isinstance(value, str) and bool(_UID.match(value))


def is_typed_chat(value) -> bool:
    return isinstance(value, str) and bool(_CHAT.match(value))


def is_typed_peer(value) -> bool:
    return isinstance(value, str) and bool(_PEER.match(value))


def in_dc_networks(address) -> bool:
    """Whether an address is inside Telegram's published IPv4 networks."""
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    return any(ip in net for net in _DC_NETWORKS if net.version == ip.version)


class ReferenceRefused(CollectionError):
    """A chat reference this build will not look up, with the sentence."""


@dataclass(frozen=True)
class ChatRef:
    """A chat as an analyst named it: a public username, or a typed id."""

    username: str | None = None
    durable_id: str | None = None

    @property
    def by_username(self) -> bool:
        return self.username is not None


_USERNAME = re.compile(r"^[A-Za-z0-9_]{5,32}$")
_TME = re.compile(r"^(?:https?://)?(?:t\.me|telegram\.me)/(.*)$", re.I)
_TYPED_REF = re.compile(r"^([cgu]):([1-9][0-9]{0,19})$", re.I)
_SIGNED = re.compile(r"^-([1-9][0-9]{0,19})$")
_BARE_DIGITS = re.compile(r"^\+?[0-9][0-9 ]*$")


def parse_chat_reference(ref) -> ChatRef:
    """@name, https://t.me/name, t.me/name, c:<id>, g:<id> and the Bot API
    forms -100<id> (a channel or supergroup) and -<id> (a basic group).
    Hostile input is refused with a sentence and never normalised into
    something else: the id forms are matched strictly BEFORE the ontology
    decodes them, because telegram_id_norm drops every non-digit after a
    prefix and would read 'c:12' a newline '34' as c:1234
    (2026-09-24)."""
    from noctornal_ontology import normalise, refusal

    if not isinstance(ref, str):
        raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
    if len(ref) > MAX_REF_CHARS:
        raise ReferenceRefused(
            f"A chat reference is at most {MAX_REF_CHARS} characters.")
    text = ref.strip()
    if _BARE_DIGITS.match(text):
        # A bare positive is a user id or a channel id and nothing says
        # which: the ontology's own sentence, as at every other door.
        raise ReferenceRefused(refusal("TELEGRAM_ID", text))
    if not text or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127
                       for ch in text):
        raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
    link = _TME.match(text)
    if link is not None:
        path = link.group(1)
        if path.startswith("+") or path.lower().startswith("joinchat"):
            raise ReferenceRefused(INVITE_SENTENCE)
        if not _USERNAME.match(path):
            raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
        return ChatRef(username=path.lower())
    if "t.me/" in text.lower() or "telegram.me/" in text.lower():
        # t.me on another host, or a link with a query or a fragment.
        raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
    if text.startswith("@"):
        if not _USERNAME.match(text[1:]):
            raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
        return ChatRef(username=text[1:].lower())
    typed = _TYPED_REF.match(text)
    if typed is not None:
        if typed.group(1).lower() == "u":
            raise ReferenceRefused(USER_REF_SENTENCE)
        value = normalise("TELEGRAM_ID", f"{typed.group(1).lower()}:{typed.group(2)}")
        if not is_typed_chat(value):
            raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
        return ChatRef(durable_id=value)
    if _SIGNED.match(text):
        value = normalise("TELEGRAM_ID", text)
        if not is_typed_chat(value):
            raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)
        return ChatRef(durable_id=value)
    raise ReferenceRefused(REFERENCE_SHAPE_SENTENCE)


def scope_for(access_mode: str) -> str:
    """The authority scope a chat's reading needs: provenance follows the
    access mode."""
    return "MEMBER_READ" if access_mode == "MEMBER" else "PUBLIC_READ"


_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
#: Bidirectional controls: a display name carrying one reorders the text
#: around it wherever it is shown.
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")


def clean_text(value, cap: int) -> str | None:
    """U+0000 and lone surrogates replaced by U+FFFD; a text over `cap` cut
    to `cap` minus the marker's length and the marker appended, so the
    output, marker included, is at most `cap` characters."""
    if value is None:
        return None
    text = _LONE_SURROGATE.sub("\ufffd", str(value).replace("\x00", "\ufffd"))
    if len(text) > cap:
        text = text[:max(0, cap - len(TRUNCATION_MARK))] + TRUNCATION_MARK
    return text


def clean_name(value) -> str | None:
    """A display name, handle or title: clean_text at MAX_NAME_CHARS, with
    bidirectional controls replaced as well."""
    if value is None:
        return None
    text = clean_text(_BIDI.sub("\ufffd", str(value)), MAX_NAME_CHARS)
    return text or None


def device_problems(fingerprint: dict) -> list[str]:
    """TelegramAdapter.validate_persona's sentences: the five device fields,
    each printable ASCII within its length."""
    problems = []
    for key, (low, high) in DEVICE_FIELDS.items():
        value = fingerprint.get(key) if isinstance(fingerprint, dict) else None
        words = _DEVICE_WORDS[key]
        if not isinstance(value, str) or not low <= len(value) <= high:
            problems.append(f"A Telegram persona records its {words}, "
                            f"{low} to {high} characters.")
        elif not _PRINTABLE.match(value):
            problems.append(f"The {words} is printable ASCII on one line.")
    return problems


# ---------------------------------------------------------------------------
# The sealed secret
# ---------------------------------------------------------------------------

_API_HASH = re.compile(r"^[0-9a-f]{32}$")


class TelegramSecretInvalid(SourceBlocked):
    """The sealed credential is not a Telegram session this build can read.
    The sentence never quotes it."""


@dataclass(frozen=True)
class SessionAddress:
    dc_id: int
    ip: str
    port: int


def session_address(session: str) -> SessionAddress:
    """The data centre a StringSession points at, decoded without the
    library: version '1', then base64url of >B{4|16}sH256s (dc id, address,
    port, auth key). Raises TelegramSecretInvalid on anything else."""
    bad = TelegramSecretInvalid(
        "This persona's stored Telegram login cannot be read. Log it out "
        "and enrol it again.")
    if not isinstance(session, str) or len(session) not in (353, 369) \
            or session[0] != "1":
        raise bad
    try:
        raw = base64.urlsafe_b64decode(session[1:])
    except (binascii.Error, ValueError):
        raise bad from None
    ip_len = 4 if len(raw) == 263 else 16 if len(raw) == 275 else 0
    if not ip_len:
        raise bad
    dc_id, ip, port, _key = struct.unpack(f">B{ip_len}sH256s", raw)
    return SessionAddress(dc_id, ipaddress.ip_address(ip).compressed, port)


class TelegramSecret:
    """{"kind": "telegram-mtproto", "v": 1, "api_id", "api_hash", "session"}
    as the persona's one sealed string. No field ever appears in a repr, a
    log or an error."""

    __slots__ = ("api_id", "api_hash", "session")

    KIND = "telegram-mtproto"

    def __init__(self, api_id: int, api_hash: str, session: str):
        object.__setattr__(self, "api_id", api_id)
        object.__setattr__(self, "api_hash", api_hash)
        object.__setattr__(self, "session", session)

    def __setattr__(self, _name, _value):
        raise AttributeError("a TelegramSecret is immutable")

    def __repr__(self) -> str:
        return "TelegramSecret([REDACTED])"

    __str__ = __repr__

    @classmethod
    def fresh(cls, api_id, api_hash) -> TelegramSecret:
        """The credential an enrolment starts from: no session yet."""
        if isinstance(api_id, bool) or not isinstance(api_id, int) or api_id <= 0:
            raise TelegramSecretInvalid("An api_id is a positive whole number.")
        if not isinstance(api_hash, str) or not _API_HASH.match(api_hash):
            raise TelegramSecretInvalid(
                "An api_hash is 32 lowercase hexadecimal characters.")
        return cls(api_id, api_hash, "")

    @classmethod
    def parse(cls, text: str) -> TelegramSecret:
        bad = TelegramSecretInvalid(
            "This persona's stored Telegram login cannot be read. Log it "
            "out and enrol it again.")
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            raise bad from None
        if (not isinstance(data, dict) or data.get("kind") != cls.KIND
                or data.get("v") != 1):
            raise bad
        base = cls.fresh(data.get("api_id"), data.get("api_hash"))
        session = data.get("session")
        session_address(session)
        return cls(base.api_id, base.api_hash, session)

    def with_session(self, session: str) -> TelegramSecret:
        session_address(session)
        return TelegramSecret(self.api_id, self.api_hash, session)

    def dump(self) -> str:
        session_address(self.session)
        return json.dumps({"kind": self.KIND, "v": 1, "api_id": self.api_id,
                           "api_hash": self.api_hash, "session": self.session},
                          separators=(",", ":"))

    def secrets(self) -> tuple[str, ...]:
        """What redact() must remove exactly while this is in use."""
        return tuple(v for v in (self.api_hash, self.session) if v)


# ---------------------------------------------------------------------------
# Outcomes
# ---------------------------------------------------------------------------

class TelegramFloodWait(RateLimited):
    """FLOOD_WAIT. Carries Telegram's own seconds UNCHANGED: the collection
    foundation adds the margin once, on the persona's hold and on the next
    due time, and never twice."""

    def __init__(self, seconds: float):
        seconds = max(0.0, float(seconds or 0))
        super().__init__(seconds, (
            f"Telegram asked this persona to wait "
            f"{count_of(int(round(seconds)), 'second', 'seconds')}."))


class TelegramSessionRevoked(PersonaSuspended):
    def __init__(self):
        super().__init__(
            "Telegram no longer accepts this persona's login: it was revoked or has "
            "expired. Log it out and enrol it again.",
            lock_code="CREDENTIAL_REVOKED")


class TelegramAccountBanned(PersonaSuspended):
    def __init__(self):
        super().__init__(
            "Telegram refused this persona's account: it is banned or "
            "deactivated.", lock_code="ACCOUNT_BANNED")


class TelegramWrongAccount(PersonaSuspended):
    def __init__(self):
        super().__init__(
            "This persona's login belongs to another Telegram account than "
            "the one it was enrolled as. Log it out and enrol it again.",
            lock_code="WRONG_ACCOUNT")


class TelegramSessionDuplicated(PersonaSuspended):
    """AUTH_KEY_DUPLICATED: how a stolen session shows itself, hence the
    officers' alert."""

    def __init__(self):
        super().__init__(
            "Telegram refused this persona's login: it was used from two "
            "places at once. Log it out and enrol it again.",
            lock_code="CREDENTIAL_DUPLICATED", alert_officers=True)


class TelegramChatUnreachable(SourceBlocked):
    def __init__(self, sentence: str | None = None):
        super().__init__(sentence or (
            "Telegram says this persona cannot read this chat: it is private, "
            "the persona was removed, or the chat no longer exists."))


class TelegramNameMoved(SourceBlocked):
    def __init__(self):
        super().__init__(
            "This chat's public name now belongs to another chat. Names are "
            "recycled, so it is not followed: add the chat again by its id.")


class TelegramChatMigrated(SourceBlocked):
    def __init__(self, migrated_to: str):
        self.migrated_to = migrated_to
        super().__init__(
            f"This group became a supergroup ({migrated_to}). Add the "
            f"supergroup as a new chat; its authority target is confirmed "
            f"again.")


class TelegramRefused(SourceBlocked):
    """A reason not to read that this build decided, with its sentence."""


class TelegramEgressRefused(EgressUnavailable):
    """The route is not the proxy's, or the proxy refused the tunnel
    (SOCKS5 REP 0x02, or the RFC 1929 authentication). BLOCKED: a route,
    an authority or a policy, never parser health."""

    def __init__(self, sentence: str = EGRESS_REFUSED_SENTENCE):
        super().__init__(sentence)


class TelegramProxyBusy(EgressUnavailable):
    """REP 0x01: the proxy is busy, the route is at its limit, or the proxy
    could not record the connection. The proxy's condition, not the
    chat's."""

    def __init__(self):
        super().__init__(
            "The egress proxy could not open a connection to Telegram right "
            "now: it is busy or at its limit. The next poll tries again.")


class TelegramTransportFailed(CollectionError):
    """Telegram, or the path to it, did not work. FAILED through the
    foundation's failure count; an act answers 502. Carries a class name at
    most, never a library's text."""

    def __init__(self, what: str | None = None):
        super().__init__(
            "Telegram could not be reached, or answered with an error this "
            "build does not handle"
            + (f" ({what})." if what else "."))


class TelegramSessionTimedOut(TelegramTransportFailed):
    """The session's own budget ran out (asyncio.wait_for), distinct from
    the backstop: the connection was closed by the session itself."""

    def __init__(self):
        CollectionError.__init__(
            self, "Telegram did not answer within the time this allows, so "
                  "the connection was closed and nothing from it was kept.")


class TelegramSessionAbandoned(WorkAbandoned):
    """The session thread outlived its budget and its backstop and may still
    hold a connection: the persona rests, so no second connection with the
    same key starts beside it (AUTH_KEY_DUPLICATED, a false alarm)."""

    def __init__(self):
        super().__init__(
            "Telegram did not answer in time and the connection may still be "
            "open. The persona rests so no second connection starts beside it.")


class TelegramPasswordNeeded(CollectionError):
    """The account has a two-step password (enrolment only)."""


# ---------------------------------------------------------------------------
# What the transport speaks
# ---------------------------------------------------------------------------

PEER_TYPES = ("CHANNEL", "MEGAGROUP", "GIGAGROUP", "CHAT")


@dataclass(frozen=True)
class SelfInfo:
    uid: str


@dataclass(frozen=True)
class ChatInfo:
    peer_type: str
    peer_id: int
    durable_id: str
    access_hash: int | None = field(default=None, repr=False)
    username: str | None = None
    title: str | None = None
    is_member: bool | None = None
    is_forum: bool = False
    noforwards: bool = False
    migrated_to: str | None = None


@dataclass(frozen=True)
class TgMessage:
    """One message as the transport mapped it. Every id typed; every string
    cleaned and capped. `problem` is set, and the ids are None, when a peer
    could not be typed: the adapter then skips it by id and moves past it."""

    chat_durable_id: str
    message_id: int
    date: datetime | None = None
    edit_date: datetime | None = None
    text: str = ""
    sender_uid: str | None = None
    sender_handle: str | None = None
    post_author: str | None = None
    fwd_from_uid: str | None = None
    fwd_from_name: str | None = None
    fwd_from_message_id: int | None = None
    reply_to_message_id: int | None = None
    topic_id: int | None = None
    grouped_id: int | None = None
    via_bot_uid: str | None = None
    is_service: bool = False
    service_action: str | None = None
    media_kind: str | None = None
    noforwards: bool = False
    views: int | None = None
    forwards: int | None = None
    problem: str | None = None


class TelegramTransport(Protocol):
    """What the adapter and the attended acts need of Telegram. The real one
    is telegram_wire.TelethonTransport; the tests use a fake. Every method
    raises only this module's exceptions."""

    async def open(self) -> SelfInfo: ...
    async def resolve_username(self, name: str) -> ChatInfo: ...
    async def find_dialog(self, durable_id: str) -> ChatInfo | None: ...
    async def lookup(self, chat: ChatInfo) -> ChatInfo: ...
    async def history(self, chat: ChatInfo, *, min_id: int = 0, max_id: int = 0,
                      limit: int, newest_first: bool) -> list[TgMessage]: ...
    async def messages_by_id(self, chat: ChatInfo, ids: list[int]
                             ) -> list[TgMessage | None]: ...
    async def join(self, chat: ChatInfo) -> ChatInfo: ...
    async def log_out(self) -> bool: ...
    def session_string(self) -> str: ...
    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Running a session off the calling thread
# ---------------------------------------------------------------------------

def run_blocking(coro_factory, budget_s: float, *,
                 backstop_s: float = BACKSTOP_SECONDS):
    """Run `coro_factory()` in asyncio.run on a DAEMON thread and wait for it.

    The coroutine is wrapped in asyncio.wait_for(budget_s), whose
    cancellation runs the transport's close() in the coroutine's finally.
    The caller waits budget_s + backstop_s; if even that expires, the thread
    is abandoned with its connection possibly alive and the call raises
    TelegramSessionAbandoned, which the persona gate records as the
    ABANDONED machine hold BEFORE the persona lock is released. A daemon
    thread, never a ThreadPoolExecutor, whose worker is joined at
    interpreter exit.

    The thread runs in a COPY of the caller's context (2026-09-24): a
    new thread starts with an empty context, so
    the secrets the lease registered for redact() would otherwise be out of
    scope exactly where the library runs."""
    import contextvars
    import queue

    box: queue.SimpleQueue = queue.SimpleQueue()
    context = contextvars.copy_context()

    async def bounded():
        return await asyncio.wait_for(coro_factory(), timeout=budget_s)

    def target():
        try:
            box.put((True, context.run(asyncio.run, bounded())))
        except BaseException as exc:  # noqa: BLE001 - carried to the caller
            box.put((False, exc))

    thread = threading.Thread(target=target, name="telegram-session", daemon=True)
    thread.start()
    try:
        ok, value = box.get(timeout=budget_s + backstop_s)
    except queue.Empty:
        raise TelegramSessionAbandoned() from None
    if ok:
        return value
    if isinstance(value, CollectionError):
        raise value
    if isinstance(value, (asyncio.TimeoutError, TimeoutError)):
        raise TelegramSessionTimedOut() from None
    # Anything else is outside every table: the class name at most, never
    # its text (translate's catch-all).
    raise TelegramTransportFailed(type(value).__name__) from None


class _OutOfTime(Exception):
    """Internal: the next RPC would not finish inside the session."""


class _Session:
    """The RPCs of one session: the gap between them, the budget before
    each, and one custody entry per call, which the caller replays through
    RunContext.record_request on its own thread. An entry names the RPC and
    what it asked for in ids and counts, never a username, a title or a
    message's text."""

    def __init__(self, *, sleep, rng, clock, deadline_at: float, gap_s: float):
        self.sleep = sleep
        self.rng = rng
        self.clock = clock
        self.deadline_at = deadline_at
        self.gap_s = gap_s
        self.log: list[dict] = []
        self.calls = 0

    async def call(self, target: str, make, *, size=None):
        # The first call always starts: the session's own wait_for bounds
        # it, and a session that cannot make one call has nothing to keep.
        if self.calls:
            pause = self.gap_s * self.rng.uniform(0.8, 1.4)
            if self.clock() + pause + RPC_TIMEOUT_SECONDS > self.deadline_at:
                raise _OutOfTime()
            await self.sleep(pause)
        self.calls += 1
        try:
            result = await make()
        except BaseException:
            self.log.append({"target": target, "status": None, "nbytes": 0})
            raise
        nbytes = 0
        if size is not None:
            try:
                nbytes = int(size(result))
            except Exception:  # noqa: BLE001 - a count is never worth a failure
                nbytes = 0
        self.log.append({"target": target, "status": 200, "nbytes": nbytes})
        return result


def _text_bytes(messages) -> int:
    return sum(len((m.text or "").encode("utf-8")) for m in messages if m)


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TelegramPlan:
    """What plan() read before any network: the chat row, the persona's
    account id and the recheck set. Handed to fetch by source id (below)."""

    source_id: UUID
    chat: ChatInfo
    access_mode: str
    username_at_resolve: str | None
    access_hash_account_id: UUID | None
    member_since_observed: datetime | None
    persona_id: UUID | None
    persona_uid: str | None
    recheck: tuple[tuple[int, datetime | None], ...] = ()


@dataclass
class TelegramFetchResult(FetchResult):
    """FetchResult plus what commit() writes onto the chat row."""

    chat_update: dict | None = None


def _aware(moment):
    if isinstance(moment, datetime) and moment.tzinfo is not None:
        return moment.astimezone(timezone.utc)
    return None


class TelegramAdapter(Adapter):
    """Reads one Telegram chat per source, as its persona, through the
    persona's route on the egress proxy, under a confirmed authority.

    ## plan to fetch

    The collection foundation's run_once calls plan() and keeps nothing it
    returns, and its RunContext has no field for a plan (an adapter
    builds on the frozen collection contract and adds nothing to it,
    docs/00 decision 69). plan() therefore hands its result to fetch()
    through `prime()`, keyed by source id, and fetch() takes it:
    run_once holds the source's advisory lock from before plan() until
    after fetch(), so exactly one poll of a source is between the two at
    any moment, and plan() always runs again before the next fetch()
    (2026-09-24)."""

    key = "telegram"
    version = "1"
    source_kinds = frozenset({"TELEGRAM"})
    requires_authority = True
    persona_platform = "TELEGRAM"
    persona_http = False
    retention_clock = True
    default_category = "CHAT_EXPORT"
    keeps_raw = False
    run_seconds = TELEGRAM_RUN_SECONDS + BACKSTOP_SECONDS + PERSONA_MIN_GAP_S
    max_pages = 1
    min_interval_s = MIN_POLL_INTERVAL_S
    max_rps_cap = 1.0
    persona_min_gap_s = PERSONA_MIN_GAP_S
    abandon_cooldown_s = ABANDONED_COOLDOWN_S

    def __init__(self, transport_factory=None, *, sleep=asyncio.sleep,
                 rng: random.Random | None = None, clock=time.monotonic,
                 session_seconds: float = TELEGRAM_RUN_SECONDS,
                 backstop_seconds: float = BACKSTOP_SECONDS):
        self._factory = transport_factory
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._clock = clock
        self._session_seconds = float(session_seconds)
        self._backstop_seconds = float(backstop_seconds)
        self._lock = threading.Lock()
        self._plans: dict[UUID, TelegramPlan] = {}
        self._settle: dict[UUID, dict] = {}

    # -- the contract ------------------------------------------------------

    def validate_source(self, base_url, parser_config) -> list[str]:
        if base_url:
            return ["A Telegram chat has no address: add it from the Telegram "
                    "chats list, which looks it up first."]
        return []

    def validate_config(self, parser_config: dict) -> list[str]:
        extra = set(parser_config or {}) - {"access_mode"}
        mode = (parser_config or {}).get("access_mode", "PUBLIC_READ")
        if extra or mode not in ("PUBLIC_READ", "MEMBER"):
            return ["A Telegram chat's settings name its access mode only: "
                    "PUBLIC_READ or MEMBER."]
        return []

    def validate_persona(self, fingerprint: dict) -> list[str]:
        return device_problems(fingerprint or {})

    def authority_need(self, source: SourceRow) -> str:
        """MEMBER_READ unless the source says exactly PUBLIC_READ: a
        missing or unknown mode asks the stricter scope. plan() refuses a
        source whose mode disagrees with its chat row."""
        mode = (source.parser_config or {}).get("access_mode")
        return "PUBLIC_READ" if mode == "PUBLIC_READ" else "MEMBER_READ"

    def refusal(self, conn, source: SourceRow) -> str | None:
        """Cheap, no network: the library, the chat row, a migration, the
        persona's enrolment and the proxy, in that order."""
        from noctornal_api import egress

        available, sentence = client_available()
        if not available:
            return sentence
        chat = conn.execute(
            "SELECT migrated_to FROM collect.telegram_chat WHERE source_id = %s",
            (source.id,)).fetchone()
        if chat is None:
            return ("This Telegram source has no chat record. Add it from the "
                    "Telegram chats list, which looks it up first.")
        if chat[0]:
            return (f"This group became a supergroup ({chat[0]}). Add the "
                    f"supergroup as a new chat.")
        if source.collection_account_id is not None:
            row = conn.execute(
                "SELECT platform::text, session_enrolled_at "
                "FROM collect.collection_account WHERE id = %s",
                (source.collection_account_id,)).fetchone()
            if row is None or row[0] != "TELEGRAM" or row[1] is None:
                return ("The persona that reads this chat has no enrolled "
                        "Telegram login. An operator enrols one on the "
                        "server.")
        if not egress.boundary().in_force:
            return NO_PROXY_SENTENCE
        return None

    def prime(self, plan: TelegramPlan) -> None:
        """Hand a plan to the next fetch of its source (see the class
        docstring)."""
        with self._lock:
            self._plans[plan.source_id] = plan

    def _take_plan(self, source_id: UUID) -> TelegramPlan:
        with self._lock:
            plan = self._plans.pop(source_id, None)
        if plan is None:
            raise CollectionError("The Telegram poll carried no plan.")
        return plan

    def plan(self, conn, source: SourceRow, persona) -> TelegramPlan:
        """The chat row, the persona's account id and the recheck set, read
        before any network; refusals raised as TelegramRefused, BLOCKED with
        no request made."""
        row = conn.execute(
            """SELECT peer_type, peer_id, durable_id, access_mode,
                      username_at_resolve, title_at_resolve, access_hash,
                      access_hash_account_id, member_since_observed, is_forum,
                      noforwards, migrated_to
                 FROM collect.telegram_chat WHERE source_id = %s""",
            (source.id,)).fetchone()
        if row is None:
            raise TelegramRefused(
                "This Telegram source has no chat record. Add it from the "
                "Telegram chats list, which looks it up first.")
        mode = row[3]
        if (source.parser_config or {}).get("access_mode") != mode:
            raise TelegramRefused(
                "This source's recorded access mode disagrees with its chat "
                "record, so it is not read. Mark it again from the Telegram "
                "chats list.")
        chat = ChatInfo(peer_type=row[0], peer_id=int(row[1]), durable_id=row[2],
                        access_hash=row[6], username=row[4], title=row[5],
                        is_forum=bool(row[9]), noforwards=bool(row[10]),
                        migrated_to=row[11])
        if mode == "MEMBER" and row[8] is None:
            if chat.peer_type != "CHAT" and row[4]:
                raise TelegramRefused(
                    "This chat is read as a member and the persona has not "
                    "joined it. Join it from the Telegram chats list, or use "
                    "Check membership if the persona joined on its own device.")
            raise TelegramRefused(
                "This chat is read as a member and the persona's membership "
                "has not been seen. Join it from the persona's own device, "
                "then use Check membership in the Telegram chats list.")
        persona_id = persona.get("id") if isinstance(persona, dict) else None
        persona_uid = persona.get("platform_uid") if isinstance(persona, dict) else None
        recheck = ()
        if persona_uid:
            recheck = tuple(
                (int(r[0]), r[1]) for r in conn.execute(
                    """SELECT m.message_id, max(m.edit_date)
                         FROM collect.telegram_message m
                         JOIN collect.document d ON d.id = m.document_id
                        WHERE m.source_id = %s AND m.seen_via_uid = %s
                          AND NOT m.is_service
                          AND m.captured_at > now() - make_interval(hours => %s)
                        GROUP BY m.message_id
                       HAVING bool_and(m.deleted_seen_at IS NULL)
                          AND bool_and(d.purged_at IS NULL)
                        ORDER BY max(m.captured_at) DESC
                        LIMIT %s""",
                    (source.id, persona_uid, RECHECK_HOURS,
                     RECHECK_MAX_IDS)).fetchall())
        plan = TelegramPlan(
            source_id=source.id, chat=chat, access_mode=mode,
            username_at_resolve=row[4], access_hash_account_id=row[7],
            member_since_observed=row[8], persona_id=persona_id,
            persona_uid=persona_uid, recheck=recheck)
        self.prime(plan)
        return plan

    # -- the poll ------------------------------------------------------------

    def _transport(self, secret: TelegramSecret, route, fingerprint: dict):
        from noctornal_api import telegram_wire

        proxy = telegram_wire.proxy_for(route)
        factory = self._factory or telegram_wire.TelethonTransport
        return factory(secret, route, fingerprint, proxy=proxy)

    def fetch(self, *, base_url=None, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None,
              context=None, route=None) -> FetchResult:
        """One session, oldest first from the cursor, then the recheck; the
        chat reached by its stored access hash, or re-resolved (a recycled
        name is refused, never followed). Items are mapped here, on the
        calling thread; nothing Telegram sent reaches a row but through the
        Item, the cursor and commit_item's typed columns."""
        from noctornal_api import telegram_wire

        if context is None or context.persona is None:
            raise CollectionError("A Telegram poll reads through a persona.")
        route = context.route if context.route is not None else route
        plan = self._take_plan(context.source.id)
        lease = context.persona.lease
        if lease is None:
            raise CollectionError("A Telegram poll needs the persona's session.")
        leased = TelegramSecret.parse(lease.value)
        telegram_wire.proxy_for(route)  # DIRECT refused before anything else
        persona_uid = context.persona.platform_uid
        if not is_typed_uid(persona_uid):
            raise TelegramRefused(
                "The persona that reads this chat has no enrolled Telegram "
                "account id. An operator enrols it on the server.")
        context.pace()
        max_rps = float(getattr(context.source, "max_rps", 0) or 0)
        gap = max(1.0 / max_rps if max_rps > 0 else 1.0, 1.0)
        start = self._clock()
        session = _Session(sleep=self._sleep, rng=self._rng, clock=self._clock,
                           deadline_at=start + max(0.0, self._session_seconds - 5.0),
                           gap_s=gap)
        last_id = _resume_from(cursor, plan, persona_uid)
        transport = self._transport(leased, route, dict(context.persona.fingerprint or {}))

        async def run():
            with secret_in_scope(*leased.secrets()):
                try:
                    return await self._session(transport, session, plan,
                                               persona_uid, last_id)
                finally:
                    try:
                        await transport.close()
                    except Exception:  # noqa: BLE001 - closing never masks the answer
                        pass

        try:
            outcome = run_blocking(run, self._session_seconds,
                                   backstop_s=self._backstop_seconds)
        except TelegramChatMigrated as exc:
            self._remember(context.source.id, migrated_to=exc.migrated_to)
            raise
        except TelegramRefused as exc:
            if getattr(exc, "membership_lost", False):
                self._remember(context.source.id, membership_lost=True)
            raise
        finally:
            for entry in session.log:
                context.record_request(target=entry["target"],
                                       status=entry["status"],
                                       nbytes=entry["nbytes"], sha256_hex=None)
        return self._result(outcome, plan, persona_uid, last_id, leased)

    async def _reach(self, transport, session: _Session, plan: TelegramPlan
                     ) -> ChatInfo:
        chat = plan.chat
        # An access hash is valid only for the account it was given to; a
        # basic group needs none (its id is enough to an account in it).
        own_hash = (chat.access_hash is not None and plan.persona_id is not None
                    and plan.access_hash_account_id == plan.persona_id)
        if chat.peer_type == "CHAT" or own_hash:
            found = await session.call(f"channels.getChannels {chat.durable_id}"
                                       if chat.peer_type != "CHAT" else
                                       f"messages.getChats {chat.durable_id}",
                                       lambda: transport.lookup(chat))
        elif plan.username_at_resolve:
            found = await session.call("contacts.resolveUsername",
                                       lambda: transport.resolve_username(
                                           plan.username_at_resolve))
            if found.durable_id != chat.durable_id:
                raise TelegramNameMoved()
        else:
            found = await session.call(
                f"messages.getDialogs up to {RESOLVE_DIALOG_LIMIT}",
                lambda: transport.find_dialog(chat.durable_id))
            if found is None:
                raise TelegramChatUnreachable()
        if found.durable_id != chat.durable_id:
            raise TelegramChatUnreachable()
        return found

    async def _session(self, transport, session: _Session, plan: TelegramPlan,
                       persona_uid: str, last_id: int | None) -> dict:
        try:
            me = await session.call("connect and users.getUsers self", transport.open)
            if me.uid != persona_uid:
                raise TelegramWrongAccount()
            chat = await self._reach(transport, session, plan)
        except _OutOfTime:
            # Not even the chat was reached: nothing to keep.
            raise TelegramSessionTimedOut() from None
        if chat.migrated_to:
            raise TelegramChatMigrated(chat.migrated_to)
        if plan.access_mode == "PUBLIC_READ" and chat.is_member:
            raise TelegramRefused(
                "The persona is now a member of this chat, which was added for "
                "reading without joining. Mark it as a member chat; a member "
                "authority must cover it before it is read again.")
        if plan.access_mode == "MEMBER" and chat.is_member is False:
            refused = TelegramRefused(
                "The persona is no longer a member of this chat, so it is not "
                "read as one. Join it again, or stop reading it.")
            refused.membership_lost = True
            raise refused
        messages: list[TgMessage] = []
        budget_note = None
        seen_max = last_id
        try:
            if last_id is None:
                max_id = 0
                while len(messages) < FIRST_POLL_MESSAGES:
                    want = min(PAGE_SIZE, FIRST_POLL_MESSAGES - len(messages))
                    page = await session.call(
                        f"messages.getHistory {chat.durable_id} newest "
                        f"max_id={max_id} limit={want}",
                        lambda m=max_id, w=want: transport.history(
                            chat, max_id=m, limit=w, newest_first=True),
                        size=_text_bytes)
                    page = [m for m in page if m is not None][:want]
                    messages.extend(page)
                    if len(page) < want:
                        break
                    max_id = min(m.message_id for m in page)
            else:
                cursor_id = last_id
                while len(messages) < MAX_MESSAGES_PER_RUN:
                    want = min(PAGE_SIZE, MAX_MESSAGES_PER_RUN - len(messages))
                    page = await session.call(
                        f"messages.getHistory {chat.durable_id} oldest "
                        f"min_id={cursor_id} limit={want}",
                        lambda c=cursor_id, w=want: transport.history(
                            chat, min_id=c, limit=w, newest_first=False),
                        size=_text_bytes)
                    page = sorted((m for m in page
                                   if m is not None and m.message_id > cursor_id),
                                  key=lambda m: m.message_id)[:want]
                    messages.extend(page)
                    if len(page) < want:
                        break
                    cursor_id = page[-1].message_id
        except _OutOfTime:
            budget_note = "its wall clock ran out before the history was read"
        # Oldest first whichever way the window was read, so the documents
        # land in the order they were posted.
        messages.sort(key=lambda m: m.message_id if isinstance(m.message_id, int) else 0)
        rechecked: list[TgMessage] = []
        deleted: list[int] = []
        ids = [mid for mid, _edit in plan.recheck]
        if ids and budget_note is None:
            try:
                answers = await session.call(
                    f"messages.getMessages {chat.durable_id} "
                    f"{count_of(len(ids), 'id', 'ids')} from {min(ids)} to {max(ids)}",
                    lambda: transport.messages_by_id(chat, ids),
                    size=_text_bytes)
                stored = dict(plan.recheck)
                answers = list(answers or [])
                # An answer that does not line up with the ids asked for is
                # not read as deletions: a malformed reply must never mark
                # a message gone.
                if len(answers) != len(ids):
                    answers = []
                    ids = []
                for mid, answer in zip(ids, answers, strict=True):
                    if answer is None:
                        deleted.append(mid)
                        continue
                    if answer.message_id != mid:
                        continue
                    edited = _aware(answer.edit_date)
                    before = _aware(stored.get(mid))
                    if edited is not None and (before is None or edited > before):
                        rechecked.append(answer)
            except _OutOfTime:
                budget_note = "its wall clock ran out before the recheck"
        for m in messages:
            if isinstance(m.message_id, int) and (seen_max is None
                                                  or m.message_id > seen_max):
                seen_max = m.message_id
        return {"chat": chat, "messages": messages, "rechecked": rechecked,
                "deleted": deleted, "seen_max": seen_max,
                "session": transport.session_string(), "budget": budget_note}

    def _result(self, outcome: dict, plan: TelegramPlan, persona_uid: str,
                last_id: int | None, leased: TelegramSecret) -> TelegramFetchResult:
        chat: ChatInfo = outcome["chat"]
        by_id: dict[str, Item] = {}
        skipped: list[int] = []
        # History first, then the recheck: one item per message, and a
        # recheck's edited version wins over the same message read again.
        for message in list(outcome["messages"]) + list(outcome["rechecked"]):
            item = self._item(message, chat, persona_uid)
            if item is None:
                if isinstance(message.message_id, int):
                    skipped.append(message.message_id)
                continue
            by_id[item.external_id] = item
        items = list(by_id.values())
        warnings: list[RunWarning] = []
        if skipped:
            n = len(skipped)
            shown = ", ".join(str(i) for i in sorted(set(skipped))[:20])
            warnings.append(RunWarning(ITEM_SKIPPED, (
                f"{count_of(n, 'message', 'messages')} could not be stored and "
                f"{agree(n, 'was', 'were')} skipped: {agree(n, 'message', 'messages')} "
                f"{shown}, whose sender or chat id this build cannot type.")))
        if outcome.get("budget"):
            warnings.append(RunWarning(BUDGET_SPENT, (
                f"This poll stopped at its budget: {outcome['budget']}.")))
        seen_max = outcome.get("seen_max")
        cursor = ({"v": 1, "last_message_id": int(seen_max), "read_as": persona_uid}
                  if isinstance(seen_max, int) and seen_max > 0 else {})
        deleted_ids = [self._external_id(chat, mid, persona_uid)
                       for mid in outcome.get("deleted", [])]
        update = {"access_hash": chat.access_hash, "is_forum": bool(chat.is_forum),
                  "noforwards": bool(chat.noforwards), "is_member": chat.is_member,
                  "persona_id": plan.persona_id}
        new_session = outcome.get("session")
        secret_update = None
        if new_session and new_session != leased.session:
            try:
                secret_update = leased.with_session(new_session).dump()
            except TelegramSecretInvalid:
                secret_update = None
        return TelegramFetchResult(
            items=items, cursor=cursor, warnings=warnings,
            deleted_external_ids=deleted_ids, secret_update=secret_update,
            chat_update=update)

    @staticmethod
    def _external_id(chat: ChatInfo, message_id: int, persona_uid: str) -> str:
        """c:<id>/<msg> for channels and supergroups; basic-group message
        ids are per account, so g:<id>/<msg>@u:<persona>."""
        if chat.peer_type == "CHAT":
            return f"{chat.durable_id}/{message_id}@{persona_uid}"
        return f"{chat.durable_id}/{message_id}"

    def _item(self, m: TgMessage, chat: ChatInfo, persona_uid: str) -> Item | None:
        """The Item for one message, or None when it cannot be stored
        (an untyped peer, an id that is not a positive number)."""
        if m.problem or not isinstance(m.message_id, int) or m.message_id <= 0:
            return None
        if m.chat_durable_id != chat.durable_id:
            return None
        for value in (m.sender_uid, m.fwd_from_uid):
            if value is not None and not is_typed_peer(value):
                return None
        if m.via_bot_uid is not None and not is_typed_uid(m.via_bot_uid):
            return None
        if m.is_service and (not m.service_action
                             or not _SERVICE_ACTION.match(m.service_action)):
            return None
        if m.media_kind is not None and not _MEDIA_KIND.match(m.media_kind):
            return None
        external = self._external_id(chat, m.message_id, persona_uid)
        url = None
        if chat.peer_type != "CHAT":
            url = (f"https://t.me/c/{chat.peer_id}/{m.topic_id}/{m.message_id}"
                   if chat.is_forum and m.topic_id else
                   f"https://t.me/c/{chat.peer_id}/{m.message_id}")
        thread = (f"{chat.durable_id}/t:{m.topic_id}" if chat.is_forum and m.topic_id
                  else chat.durable_id)
        parent = (f"{chat.durable_id}/{m.reply_to_message_id}"
                  if m.reply_to_message_id else None)
        handle = clean_name(m.sender_handle)
        body = clean_text(m.text or "", MAX_MESSAGE_CHARS) or ""
        match_ids = {}
        if m.fwd_from_uid:
            match_ids["forwarded_from"] = m.fwd_from_uid
        if m.via_bot_uid:
            match_ids["via_bot"] = m.via_bot_uid
        meta = {
            "telegram_message": {
                "chat_durable_id": chat.durable_id, "message_id": m.message_id,
                "seen_via_uid": persona_uid, "sender_uid": m.sender_uid,
                "sender_handle_at_capture": handle,
                "post_author": clean_name(m.post_author),
                "fwd_from_uid": m.fwd_from_uid,
                "fwd_from_name": clean_name(m.fwd_from_name),
                "fwd_from_message_id": _positive(m.fwd_from_message_id),
                "reply_to_message_id": _positive(m.reply_to_message_id),
                "topic_id": _positive(m.topic_id),
                "grouped_id": _positive(m.grouped_id),
                "via_bot_uid": m.via_bot_uid, "is_service": bool(m.is_service),
                "service_action": m.service_action if m.is_service else None,
                "is_self": bool(m.sender_uid and m.sender_uid == persona_uid),
                "media_kind": m.media_kind, "noforwards": bool(m.noforwards),
                "edit_date": _aware(m.edit_date),
                "views_at_capture": _small(m.views),
                "forwards_at_capture": _small(m.forwards),
            },
            "match_ids": match_ids,
        }
        return Item(external_id=external, url=url, title=None, body=body,
                    author_handle=handle, posted_at=_aware(m.date),
                    thread_ref=thread, parent_ref=parent,
                    author_uid=m.sender_uid, category="CHAT_EXPORT", meta=meta)

    # -- the commit hooks ----------------------------------------------------

    def commit_item(self, conn, *, source_id, run_id, persona_id, item: Item,
                    document_id, inserted: bool) -> None:
        """INSIDE the item's savepoint: the capture record of a message whose
        document this run inserted. A CHECK the row fails rolls back the
        message AND its document together (ITEM_SKIPPED), and the cursor
        still moves past it."""
        if not inserted:
            return
        record = (item.meta or {}).get("telegram_message") if isinstance(
            item.meta, dict) else None
        if not isinstance(record, dict):
            return
        conn.execute(
            """INSERT INTO collect.telegram_message
                   (document_id, source_id, chat_durable_id, message_id,
                    seen_via_uid, sender_uid, sender_handle_at_capture,
                    post_author, fwd_from_uid, fwd_from_name,
                    fwd_from_message_id, reply_to_message_id, topic_id,
                    grouped_id, via_bot_uid, is_service, service_action,
                    is_self, media_kind, noforwards, edit_date,
                    views_at_capture, forwards_at_capture)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (document_id, source_id, record["chat_durable_id"],
             record["message_id"], record["seen_via_uid"], record["sender_uid"],
             record["sender_handle_at_capture"], record["post_author"],
             record["fwd_from_uid"], record["fwd_from_name"],
             record["fwd_from_message_id"], record["reply_to_message_id"],
             record["topic_id"], record["grouped_id"], record["via_bot_uid"],
             record["is_service"], record["service_action"], record["is_self"],
             record["media_kind"], record["noforwards"], record["edit_date"],
             record["views_at_capture"], record["forwards_at_capture"]))

    def commit(self, conn, *, source_id, run_id, persona_id, stored, existing,
               fetched) -> None:
        """Per run, in the persist transaction: a deletion marked once (and
        never cleared automatically: Telegram deletions are permanent), and
        what this session learnt about the chat."""
        deleted = list(getattr(fetched, "deleted_external_ids", None) or [])
        if deleted:
            conn.execute(
                """UPDATE collect.telegram_message m
                      SET deleted_seen_at = now()
                    WHERE m.deleted_seen_at IS NULL
                      AND m.document_id IN (
                        SELECT DISTINCT ON (d.external_id) d.id
                          FROM collect.document d
                         WHERE d.source_id = %s AND d.external_id = ANY(%s)
                         ORDER BY d.external_id, d.version DESC)""",
                (source_id, deleted[:5000]))
        update = getattr(fetched, "chat_update", None)
        if not isinstance(update, dict):
            return
        conn.execute(
            """UPDATE collect.telegram_chat
                  SET access_hash = coalesce(%(hash)s, access_hash),
                      access_hash_account_id = CASE WHEN %(hash)s::bigint IS NULL
                          THEN access_hash_account_id ELSE %(persona)s END,
                      is_forum = %(forum)s, noforwards = %(nofwd)s,
                      member_since_observed = CASE
                          WHEN access_mode = 'MEMBER' AND %(member)s::boolean IS TRUE
                               AND member_since_observed IS NULL THEN now()
                          ELSE member_since_observed END
                WHERE source_id = %(source)s""",
            {"hash": update.get("access_hash"), "persona": persona_id,
             "forum": bool(update.get("is_forum")),
             "nofwd": bool(update.get("noforwards")),
             "member": update.get("is_member"), "source": source_id})

    def _remember(self, source_id: UUID, **facts) -> None:
        with self._lock:
            self._settle.setdefault(source_id, {}).update(facts)

    def settle(self, conn, *, source_id, persona_id, run_id, status, error) -> None:
        """After the run is final, in its own transaction, while the persona
        lock is still held: the chat's own facts (a migration, a membership
        seen to be lost) and the persona's and source's request clocks,
        advanced to the session's end so the next session of this account
        waits its gap from there. Every hold, lock, notification and audit
        of an outcome is the foundation's record_outcome."""
        with self._lock:
            facts = self._settle.pop(source_id, {})
        if persona_id is not None:
            conn.execute(
                "UPDATE collect.collection_account SET last_request_at = "
                "clock_timestamp() WHERE id = %s", (persona_id,))
        conn.execute(
            "UPDATE collect.source SET last_request_at = clock_timestamp() "
            "WHERE id = %s", (source_id,))
        migrated = facts.get("migrated_to")
        if migrated and re.match(CHANNEL_PATTERN, migrated):
            changed = conn.execute(
                """UPDATE collect.telegram_chat SET migrated_to = %s
                    WHERE source_id = %s AND migrated_to IS NULL""",
                (migrated, source_id)).rowcount
            conn.execute("UPDATE collect.source SET is_active = false WHERE id = %s",
                         (source_id,))
            if changed:
                conn.execute(
                    """INSERT INTO audit.event
                           (actor_id, actor_kind, action, object_type,
                            object_id, detail)
                       VALUES (NULL, 'SYSTEM', 'TELEGRAM_CHAT_MIGRATED',
                               'source', %s, jsonb_build_object('migrated_to', %s::text,
                                                                'run_id', %s::text))""",
                    (source_id, migrated, str(run_id)))
        if facts.get("membership_lost"):
            conn.execute(
                """UPDATE collect.telegram_chat
                      SET member_since_observed = NULL, joined_by = NULL,
                          joined_at = NULL
                    WHERE source_id = %s""", (source_id,))


def _positive(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value if value < 2 ** 63 else None


def _small(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value if value < 2 ** 31 else None


def _resume_from(cursor, plan: TelegramPlan, persona_uid: str) -> int | None:
    """The last message id to read after, or None for a first poll. A basic
    group's ids are per account, so a cursor another account wrote is
    ignored there and the first-poll window is taken instead: a rebind needs
    no reset write."""
    if not isinstance(cursor, dict) or cursor.get("v") != 1:
        return None
    last = cursor.get("last_message_id")
    if isinstance(last, bool) or not isinstance(last, int) or last <= 0:
        return None
    if plan.chat.peer_type == "CHAT" and cursor.get("read_as") != persona_uid:
        return None
    return last
