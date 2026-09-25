"""The one module that speaks to Telethon (roadmap F5.2 and F5.3, telegram,
2026-09-24; docs/20 sections 4.2, 8.4 and 9).

Telethon is imported ONLY inside the functions below, so this module, and
telegram.py above it, import on a build without the optional `telegram`
extra; `library_version()` says whether it is there.

## The only way out

`proxy_for(route)` is the ONE place a route is read. A DIRECT route (no
egress proxy configured) is refused in EVERY environment, the stricter
reading docs/20 section 10, point 1, allows a consumer: a direct
connection would show Telegram this server's own address, and a persona
seen once from the unit's address is burnt. Otherwise it returns
`route.telethon_proxy()`: SOCKS5 to the one listener, with the route's wire
username (persona.<profile>~run.<id>, ~act.<id> or ~stop.<id>) and token as
RFC 1929 credentials. Nothing here builds a username or appends a suffix.

`CheckedConnection` is the connection class Telethon is given. Before any
socket exists it refuses: no proxy, a proxy other than the one build_client
set for this client, a local address, an address the egress classifier
refuses, one outside Telegram's published networks, or a port that is not
443, 80 or 5222. The proxy applies the profile's policy too; this is the
client's half of the same rule, so a mis-set policy fails closed on both
sides.

## Reading the proxy's refusal

Telethon replaces python-socks' ProxyError with a ConnectionError of its
own, and its connect loop swallows every IOError and raises a bare
ConnectionError, so the SOCKS5 reply byte never reaches a caller
(reproduced 2026-09-24). CheckedConnection records the reply byte, or the
authentication stage's failure, on the client's wire state BEFORE
Telethon sees it, the client is built with connection_retries
0 (one attempt, one tunnel per connect), and translate() reads that record
first. The reply's text is never read into an error.

## Logging

Telethon logs on per-module child loggers, with request reprs, proxy
addresses and exception text. A scrubbing handler on the 'telethon' logger,
with propagation off, re-logs only 'telethon LEVEL in LOGGER', with no
message, no arguments and no exc_info (a Filter on the parent would not
reach the children's records).
"""
from __future__ import annotations

import contextvars
import dataclasses
import ipaddress
import logging
import re
from dataclasses import dataclass, field

from noctornal_api import telegram
from noctornal_api.collection import CollectionError
from noctornal_api.egress_policy import is_blocked
from noctornal_api.telegram import (
    NO_PROXY_SENTENCE,
    RESOLVE_DIALOG_LIMIT,
    TELEGRAM_DC_PORTS,
    ChatInfo,
    SelfInfo,
    TelegramAccountBanned,
    TelegramChatUnreachable,
    TelegramEgressRefused,
    TelegramFloodWait,
    TelegramPasswordNeeded,
    TelegramProxyBusy,
    TelegramRefused,
    TelegramSessionDuplicated,
    TelegramSessionRevoked,
    TelegramTransportFailed,
    TgMessage,
    UntypedPeer,
    clean_name,
    clean_text,
    device_problems,
    durable_peer,
    in_dc_networks,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# The library and the route
# ---------------------------------------------------------------------------


def library_version() -> str | None:
    """Telethon's version when Telethon 1.x at 1.45 or later and python-socks
    are importable, else None."""
    try:
        import python_socks  # noqa: F401
        import telethon
    except Exception:  # noqa: BLE001 - any failure is "not installed"
        return None
    version = str(getattr(telethon, "__version__", ""))
    parts = re.match(r"^(\d+)\.(\d+)", version)
    if not parts or int(parts.group(1)) != 1 or int(parts.group(2)) < 45:
        return None
    return version


def proxy_for(route) -> dict:
    """The proxy dict Telethon is given, from the route alone; a route that
    is not the proxy's is TelegramEgressRefused in every environment."""
    if route is None or not getattr(route, "proxied", False):
        raise TelegramEgressRefused(NO_PROXY_SENTENCE)
    proxy = route.telethon_proxy()
    if not proxy:
        raise TelegramEgressRefused(NO_PROXY_SENTENCE)
    return dict(proxy)


@dataclass
class WireState:
    """One client's facts, in a ContextVar the connection reads: the proxy
    build_client set (nothing may substitute another), the first failure of
    the proxy stage, and how many tunnels were opened."""

    expected_proxy: dict = field(repr=False)
    failure: str | None = None
    tunnels: int = 0


_WIRE: contextvars.ContextVar[WireState | None] = contextvars.ContextVar(
    "noctornal_telegram_wire", default=None)

#: python-socks 3.1.1's fixed sentences for a refusal at the authentication
#: stage (python_socks/_protocols/socks5.py). A test pins them against the
#: installed library, so an upgrade that rewords them fails there.
AUTH_STAGE_MESSAGES = frozenset({
    "Username and password authentication failure",
    "No acceptable authentication methods were offered",
})


def endpoint_refusal(ip, port, proxy, local_addr,
                     state: WireState | None) -> str | None:
    """Why CheckedConnection refuses to exist, or None."""
    if state is None:
        return "no Telegram client built by build_client is in scope"
    if proxy is None:
        return "a direct connection to Telegram"
    if dict(proxy) != state.expected_proxy:
        return "a proxy other than the persona's route"
    if local_addr is not None:
        return "a local address"
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return "an address that is not an address"
    if is_blocked(address):
        return "an address the egress classifier refuses"
    if not in_dc_networks(address):
        return "an address outside Telegram's published networks"
    if isinstance(port, bool) or port not in TELEGRAM_DC_PORTS:
        return "a port other than 443, 80 or 5222"
    return None


def classify_proxy_failure(exc: BaseException) -> str:
    """'rep:<byte>', 'auth', 'protocol', 'timeout' or 'unreachable', read
    from the exception chain by class and code, never from text a proxy
    sent (the two auth-stage sentences are python-socks' own constants)."""
    chain = []
    seen = exc
    for _ in range(6):
        if seen is None:
            break
        chain.append(seen)
        seen = seen.__cause__ or seen.__context__
    for item in chain:
        code = getattr(item, "error_code", None)
        if isinstance(code, int) and not isinstance(code, bool):
            return f"rep:{code}"
    for item in chain:
        if type(item).__name__ == "ReplyError":
            text = str(item.args[0]) if item.args else ""
            return "auth" if text in AUTH_STAGE_MESSAGES else "protocol"
    for item in chain:
        if type(item).__name__ == "IncompleteReadError":
            return "protocol"
    for item in chain:
        if isinstance(item, TimeoutError) or type(item).__name__ in (
                "ProxyTimeoutError", "TimeoutError"):
            return "timeout"
    return "unreachable"


_CHECKED = None


def checked_connection_class():
    """CheckedConnection, built on first use (it subclasses Telethon's
    ConnectionTcpFull, which is imported only here)."""
    global _CHECKED
    if _CHECKED is not None:
        return _CHECKED
    from telethon.network.connection import ConnectionTcpFull

    class CheckedConnection(ConnectionTcpFull):
        def __init__(self, ip, port, dc_id, *, loggers, proxy=None,
                     local_addr=None):
            state = _WIRE.get()
            refused = endpoint_refusal(ip, port, proxy, local_addr, state)
            if refused is not None:
                if state is not None and state.failure is None:
                    state.failure = "endpoint"
                raise ConnectionRefusedError(refused)
            super().__init__(ip, port, dc_id, loggers=loggers, proxy=proxy,
                             local_addr=local_addr)

        async def _proxy_connect(self, timeout=None, local_addr=None):
            state = _WIRE.get()
            if state is not None:
                state.tunnels += 1
            try:
                return await super()._proxy_connect(timeout=timeout,
                                                    local_addr=local_addr)
            except BaseException as exc:
                if state is not None and state.failure is None:
                    state.failure = classify_proxy_failure(exc)
                raise

    _CHECKED = CheckedConnection
    return _CHECKED


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

class _ScrubbingHandler(logging.Handler):
    """Every Telethon record, from any child logger, becomes one line with
    the level and the logger's name and nothing else."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            logging.getLogger("noctornal_api.telegram_wire").log(
                max(record.levelno, logging.WARNING),
                "telethon %s in %s", record.levelname, record.name)
        except Exception:  # noqa: BLE001 - a log line never fails a session
            pass


def install_log_scrub() -> None:
    """Idempotent: 'telethon' at WARNING, propagation off, exactly one
    handler, the scrubbing one."""
    root = logging.getLogger("telethon")
    handlers = [h for h in root.handlers if isinstance(h, _ScrubbingHandler)]
    if handlers and len(root.handlers) == 1 and not root.propagate:
        return
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(handlers[0] if handlers else _ScrubbingHandler())
    root.setLevel(logging.WARNING)
    root.propagate = False


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

_ENDPOINT_SENTENCE = (
    "This Telegram login points at an address outside Telegram's published "
    "data-centre networks, or at a port this build does not use, so no "
    "connection was made.")
_PROTOCOL_WORDS = "the egress proxy's reply was not understood"


def translate(exc: BaseException, state: WireState | None = None
              ) -> CollectionError:
    """One of telegram.py's outcomes for anything Telethon or python-socks
    raised. The proxy stage's record is read first; then Telethon's error
    classes, most specific first; anything else is TelegramTransportFailed
    carrying the class name only (a ValueError quoting
    a username must never reach a row or a response)."""
    if isinstance(exc, CollectionError):
        return exc
    failure = state.failure if state is not None else None
    if failure == "endpoint":
        return TelegramEgressRefused(_ENDPOINT_SENTENCE)
    if failure in ("rep:2", "auth"):
        return TelegramEgressRefused()
    if failure == "rep:1":
        return TelegramProxyBusy()
    if failure in ("rep:7", "rep:8", "protocol"):
        return TelegramTransportFailed(_PROTOCOL_WORDS)
    if failure is not None:
        return TelegramTransportFailed("the egress proxy could not reach Telegram")
    try:
        from telethon import errors
    except Exception:  # noqa: BLE001 - no library, no mapping
        return TelegramTransportFailed(type(exc).__name__)

    def of(*names):
        return tuple(c for c in (getattr(errors, n, None) for n in names) if c)

    if isinstance(exc, of("FloodWaitError", "FloodPremiumWaitError")):
        return TelegramFloodWait(getattr(exc, "seconds", 0) or 0)
    if isinstance(exc, of("AuthKeyDuplicatedError")):
        return TelegramSessionDuplicated()
    if isinstance(exc, of("SessionPasswordNeededError")):
        return TelegramPasswordNeeded(
            "This account has a two-step password.")
    if isinstance(exc, of("UserDeactivatedBanError", "UserDeactivatedError",
                          "PhoneNumberBannedError")):
        return TelegramAccountBanned()
    if isinstance(exc, of("AuthKeyUnregisteredError", "SessionRevokedError",
                          "SessionExpiredError", "AuthKeyInvalidError",
                          "UnauthorizedError")):
        return TelegramSessionRevoked()
    if isinstance(exc, of("ChannelPrivateError", "ChatForbiddenError",
                          "UserBannedInChannelError", "ChannelInvalidError",
                          "PeerIdInvalidError", "UsernameNotOccupiedError",
                          "UsernameInvalidError", "ChatIdInvalidError",
                          "ChannelBannedError")):
        return TelegramChatUnreachable()
    if isinstance(exc, of("PhoneCodeInvalidError", "PhoneCodeExpiredError")):
        return TelegramRefused("Telegram did not accept the login code.")
    if isinstance(exc, of("PasswordHashInvalidError")):
        return TelegramRefused("Telegram did not accept the two-step password.")
    if isinstance(exc, of("PhoneNumberInvalidError", "PhoneNumberUnoccupiedError")):
        return TelegramRefused(
            "Telegram did not accept the phone number as an account's.")
    return TelegramTransportFailed(type(exc).__name__)


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------

def build_client(secret, proxy: dict, fingerprint: dict):
    """(TelegramClient, WireState). Called only inside a running coroutine,
    always with a StringSession instance (so no session file is written),
    no update loop, no automatic flood sleep, one attempt per connect, and
    the persona's device in place of the server's platform string."""
    from telethon import TelegramClient
    from telethon.sessions import StringSession

    problems = device_problems(fingerprint or {})
    if problems:
        raise TelegramRefused(
            "This persona has no complete device recorded, so Telegram would "
            "be told this server's platform. " + " ".join(problems))
    install_log_scrub()
    state = WireState(expected_proxy=dict(proxy))
    _WIRE.set(state)
    client = TelegramClient(
        StringSession(secret.session or None), secret.api_id, secret.api_hash,
        connection=checked_connection_class(), use_ipv6=False,
        proxy=dict(proxy),
        device_model=fingerprint["device_model"],
        system_version=fingerprint["system_version"],
        app_version=fingerprint["app_version"],
        lang_code=fingerprint["lang_code"],
        system_lang_code=fingerprint["system_lang_code"],
        flood_sleep_threshold=0, receive_updates=False, catch_up=False,
        request_retries=1, connection_retries=0, retry_delay=2, timeout=10,
        auto_reconnect=False, base_logger="telethon")
    return client, state


def _typed(peer) -> str:
    """A Telethon Peer as a typed durable id."""
    name = type(peer).__name__
    if name == "PeerUser":
        return durable_peer("user", getattr(peer, "user_id", None))
    if name == "PeerChannel":
        return durable_peer("channel", getattr(peer, "channel_id", None))
    if name == "PeerChat":
        return durable_peer("chat", getattr(peer, "chat_id", None))
    raise UntypedPeer(f"a {name} peer")


def chat_info(entity, *, is_member: bool | None = None) -> ChatInfo:
    """A Telethon Channel or Chat as ChatInfo; anything else (a user, a
    forbidden chat) is TelegramChatUnreachable."""
    name = type(entity).__name__
    if name == "Channel":
        peer_type = ("GIGAGROUP" if getattr(entity, "gigagroup", False)
                     else "MEGAGROUP" if getattr(entity, "megagroup", False)
                     else "CHANNEL")
        left = getattr(entity, "left", None)
        return ChatInfo(
            peer_type=peer_type, peer_id=int(entity.id),
            durable_id=durable_peer("channel", entity.id),
            access_hash=getattr(entity, "access_hash", None),
            username=(clean_text(entity.username, 32)
                      if getattr(entity, "username", None) else None),
            title=clean_name(getattr(entity, "title", None)),
            is_member=is_member if is_member is not None else (
                None if left is None else not left),
            is_forum=bool(getattr(entity, "forum", False)),
            noforwards=bool(getattr(entity, "noforwards", False)))
    if name == "Chat":
        migrated = getattr(entity, "migrated_to", None)
        migrated_to = None
        if migrated is not None and getattr(migrated, "channel_id", None):
            migrated_to = durable_peer("channel", migrated.channel_id)
        left = getattr(entity, "left", None)
        return ChatInfo(
            peer_type="CHAT", peer_id=int(entity.id),
            durable_id=durable_peer("chat", entity.id),
            title=clean_name(getattr(entity, "title", None)),
            is_member=is_member if is_member is not None else (
                None if left is None else not left),
            noforwards=bool(getattr(entity, "noforwards", False)),
            migrated_to=migrated_to)
    raise TelegramChatUnreachable()


_MEDIA = re.compile(r"(?<!^)(?=[A-Z])")


def _media_kind(media) -> str | None:
    if media is None:
        return None
    name = type(media).__name__
    if name.startswith("MessageMedia"):
        name = name[len("MessageMedia"):] or "unknown"
    kind = _MEDIA.sub("_", name).lower()
    return kind[:32] if re.match(r"^[a-z_]{1,32}$", kind[:32]) else "other"


def _sender_name(entity) -> str | None:
    if entity is None:
        return None
    username = getattr(entity, "username", None)
    if username:
        return "@" + str(username)
    first = getattr(entity, "first_name", None) or ""
    last = getattr(entity, "last_name", None) or ""
    title = getattr(entity, "title", None) or ""
    name = (f"{first} {last}".strip() or title).strip()
    return name or None


def _service_sentence(action, actor: str | None) -> str:
    """A fixed English sentence for a service message; ids typed, titles
    cleaned. The action's class name goes into service_action, never an
    id."""
    who = actor or "someone"
    name = type(action).__name__
    if name == "MessageActionChatJoinedByLink":
        return f"{who} joined the group by invite link"
    if name == "MessageActionChatJoinedByRequest":
        return f"{who} joined the group after a join request"
    if name == "MessageActionChatAddUser":
        users = [durable_peer("user", u) for u in (getattr(action, "users", None) or [])
                 if isinstance(u, int) and u > 0][:50]
        if users == [actor]:
            return f"{who} joined the group"
        return f"{who} added {', '.join(users) or 'a member'}"
    if name == "MessageActionChatDeleteUser":
        user = getattr(action, "user_id", None)
        target = durable_peer("user", user) if isinstance(user, int) and user > 0 else None
        if target == actor:
            return f"{who} left the group"
        return f"{who} removed {target or 'a member'}"
    if name in ("MessageActionChatCreate", "MessageActionChannelCreate"):
        return f"{who} created the chat"
    if name == "MessageActionChatEditTitle":
        title = clean_name(getattr(action, "title", None))
        return f"{who} changed the chat title to {title}" if title else \
            f"{who} changed the chat title"
    if name == "MessageActionPinMessage":
        return f"{who} pinned a message"
    if name == "MessageActionChatMigrateTo":
        return "The group became a supergroup"
    if name == "MessageActionChannelMigrateFrom":
        return "The supergroup was created from a basic group"
    return f"Service message: {name}"


def to_message(message, chat: ChatInfo) -> TgMessage:
    """A Telethon Message (or MessageService) as a TgMessage: every peer
    through durable_peer, every string through clean_text. A peer that
    cannot be typed yields a TgMessage whose `problem` says so and whose ids
    are empty: the adapter skips it by id and moves past it."""
    mid = getattr(message, "id", None)
    if isinstance(mid, bool) or not isinstance(mid, int):
        mid = 0
    try:
        from_id = getattr(message, "from_id", None)
        if from_id is not None:
            sender = _typed(from_id)
        elif chat.peer_type != "CHAT":
            # A channel post, or an anonymous admin: the chat speaks.
            sender = chat.durable_id
        else:
            sender = None
        fwd = getattr(message, "fwd_from", None)
        fwd_uid = _typed(fwd.from_id) if fwd is not None and getattr(
            fwd, "from_id", None) is not None else None
        bot = getattr(message, "via_bot_id", None)
        via_bot = durable_peer("user", bot) if bot else None
        action = getattr(message, "action", None)
        is_service = type(message).__name__ == "MessageService" or action is not None
        reply = getattr(message, "reply_to", None)
        reply_id = getattr(reply, "reply_to_msg_id", None) if reply is not None else None
        topic = None
        if reply is not None and getattr(reply, "forum_topic", False):
            topic = getattr(reply, "reply_to_top_id", None) or reply_id
        if is_service:
            text = _service_sentence(action, sender)
        else:
            text = getattr(message, "message", None) or ""
        date = getattr(message, "date", None)
        return TgMessage(
            chat_durable_id=chat.durable_id, message_id=mid, date=date,
            edit_date=getattr(message, "edit_date", None),
            text=clean_text(text, telegram.MAX_MESSAGE_CHARS) or "",
            sender_uid=sender,
            sender_handle=clean_name(_sender_name(getattr(message, "sender", None))),
            post_author=clean_name(getattr(message, "post_author", None)),
            fwd_from_uid=fwd_uid,
            fwd_from_name=clean_name(getattr(fwd, "from_name", None)) if fwd else None,
            fwd_from_message_id=getattr(fwd, "channel_post", None) if fwd else None,
            reply_to_message_id=reply_id, topic_id=topic,
            grouped_id=getattr(message, "grouped_id", None), via_bot_uid=via_bot,
            is_service=is_service,
            service_action=type(action).__name__ if is_service and action is not None
            else ("MessageService" if is_service else None),
            media_kind=_media_kind(getattr(message, "media", None)),
            noforwards=bool(getattr(message, "noforwards", False)),
            views=getattr(message, "views", None),
            forwards=getattr(message, "forwards", None))
    except UntypedPeer:
        return TgMessage(chat_durable_id=chat.durable_id, message_id=mid,
                         problem="a peer this build cannot type")


class TelethonTransport:
    """telegram.TelegramTransport over one TelegramClient. Every method runs
    inside the session's coroutine and raises only telegram.py's outcomes.
    It never searches, never marks anything read, never sends, never
    downloads media and never calls UpdateStatus; join is reachable only
    from the attended join act."""

    def __init__(self, secret, route, fingerprint: dict, *, proxy: dict):
        self._secret = secret
        self._route = route
        self._fingerprint = dict(fingerprint or {})
        self._proxy = dict(proxy)
        self._client = None
        self._state: WireState | None = None

    def __repr__(self) -> str:
        return "TelethonTransport([REDACTED])"

    async def _ensure(self):
        if self._client is None:
            self._client, self._state = build_client(
                self._secret, self._proxy, self._fingerprint)
        return self._client

    async def _run(self, make):
        try:
            client = await self._ensure()
            return await make(client)
        except CollectionError:
            raise
        except BaseException as exc:
            import asyncio

            if isinstance(exc, asyncio.CancelledError):
                raise
            raise translate(exc, self._state) from None

    # -- the session ---------------------------------------------------------

    async def connect(self) -> None:
        """Connect only: an enrolment's first step, before any account."""
        async def go(client):
            await client.connect()
        await self._run(go)

    async def open(self) -> SelfInfo:
        async def go(client):
            await client.connect()
            if not await client.is_user_authorized():
                raise TelegramSessionRevoked()
            me = await client.get_me()
            return SelfInfo(uid=durable_peer("user", getattr(me, "id", None)))
        return await self._run(go)

    async def is_authorized(self) -> bool:
        async def go(client):
            await client.connect()
            return bool(await client.is_user_authorized())
        return await self._run(go)

    async def me(self) -> SelfInfo:
        async def go(client):
            me = await client.get_me()
            return SelfInfo(uid=durable_peer("user", getattr(me, "id", None)))
        return await self._run(go)

    async def send_code(self, phone: str) -> str:
        async def go(client):
            sent = await client.send_code_request(phone)
            return str(getattr(sent, "phone_code_hash", "") or "")
        return await self._run(go)

    async def sign_in(self, phone: str, code: str, phone_code_hash: str) -> None:
        async def go(client):
            await client.sign_in(phone=phone, code=code,
                                 phone_code_hash=phone_code_hash)
        await self._run(go)

    async def sign_in_password(self, password: str) -> None:
        async def go(client):
            await client.sign_in(password=password)
        await self._run(go)

    async def log_out(self) -> bool:
        async def go(client):
            await client.connect()
            return bool(await client.log_out())
        return await self._run(go)

    def session_string(self) -> str:
        if self._client is None:
            return self._secret.session or ""
        return self._client.session.save() or ""

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:  # noqa: BLE001 - closing never masks the answer
                pass

    @property
    def tunnels(self) -> int:
        return self._state.tunnels if self._state is not None else 0

    # -- chats ---------------------------------------------------------------

    @staticmethod
    def _input_peer(chat: ChatInfo):
        from telethon.tl import types

        if chat.peer_type == "CHAT":
            return types.InputPeerChat(chat_id=chat.peer_id)
        return types.InputPeerChannel(channel_id=chat.peer_id,
                                      access_hash=chat.access_hash or 0)

    async def resolve_username(self, name: str) -> ChatInfo:
        from telethon.tl import functions

        async def go(client):
            found = await client(functions.contacts.ResolveUsernameRequest(
                username=name))
            peer = getattr(found, "peer", None)
            if type(peer).__name__ != "PeerChannel":
                raise TelegramChatUnreachable(
                    "That name belongs to a user or a bot, not a chat.")
            for entity in getattr(found, "chats", None) or []:
                if getattr(entity, "id", None) == peer.channel_id:
                    return chat_info(entity)
            raise TelegramChatUnreachable()
        return await self._run(go)

    async def find_dialog(self, durable_id: str) -> ChatInfo | None:
        """The persona's own conversation list, up to RESOLVE_DIALOG_LIMIT
        entries: everything but the matched chat is dropped here, in
        memory, and never logged or stored (docs/16 L4)."""
        async def go(client):
            async for dialog in client.iter_dialogs(limit=RESOLVE_DIALOG_LIMIT):
                entity = getattr(dialog, "entity", None)
                if type(entity).__name__ not in ("Channel", "Chat"):
                    continue
                try:
                    info = chat_info(entity, is_member=True)
                except (UntypedPeer, TelegramChatUnreachable):
                    continue
                if info.durable_id == durable_id:
                    return info
            return None
        return await self._run(go)

    async def lookup(self, chat: ChatInfo) -> ChatInfo:
        from telethon.tl import functions, types

        async def go(client):
            if chat.peer_type == "CHAT":
                found = await client(functions.messages.GetChatsRequest(
                    id=[chat.peer_id]))
            else:
                found = await client(functions.channels.GetChannelsRequest(
                    id=[types.InputChannel(channel_id=chat.peer_id,
                                           access_hash=chat.access_hash or 0)]))
            for entity in getattr(found, "chats", None) or []:
                if getattr(entity, "id", None) == chat.peer_id:
                    return chat_info(entity)
            raise TelegramChatUnreachable()
        return await self._run(go)

    async def history(self, chat: ChatInfo, *, min_id: int = 0, max_id: int = 0,
                      limit: int, newest_first: bool) -> list[TgMessage]:
        async def go(client):
            peer = self._input_peer(chat)
            if newest_first:
                found = await client.get_messages(peer, limit=limit, max_id=max_id)
            else:
                found = await client.get_messages(peer, limit=limit, min_id=min_id,
                                                  reverse=True)
            return [to_message(m, chat) for m in (found or []) if m is not None]
        return await self._run(go)

    async def messages_by_id(self, chat: ChatInfo, ids: list[int]
                             ) -> list[TgMessage | None]:
        async def go(client):
            found = await client.get_messages(self._input_peer(chat), ids=list(ids))
            found = list(found or [])
            return [to_message(m, chat) if m is not None and type(m).__name__ != "MessageEmpty"
                    else None for m in found]
        return await self._run(go)

    async def join(self, chat: ChatInfo) -> ChatInfo:
        from telethon.tl import functions, types

        async def go(client):
            await client(functions.channels.JoinChannelRequest(
                channel=types.InputChannel(channel_id=chat.peer_id,
                                           access_hash=chat.access_hash or 0)))
        await self._run(go)
        found = await self.lookup(chat)
        return dataclasses.replace(found, is_member=True)
