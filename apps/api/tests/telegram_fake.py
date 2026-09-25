"""The Telegram suite's fakes (roadmap F5.3, 2026-09-24).

Importable, no test functions. No Telegram test touches the network:
`guard_sockets` refuses every connection that is not loopback, Telegram's
data centres first, and FakeTransport stands in for Telethon. Routes are
PROXY routes built the way the egress proxy's contract builds them
(egress_contract_cases), so the wire username and the token are the real
grammar; `patch_routes` makes the collection foundation's route_for return
them without a proxy or a provider in the test process.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import socket
import struct
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from noctornal_api import egress_policy
from noctornal_api.egress_policy import EgressRoute, RoutePolicy

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "telegram"
STUB_KEY = b"k" * 32


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def make_session(dc: int = 2, ip: str = "149.154.167.51", port: int = 443,
                 key: bytes = b"\x07" * 256) -> str:
    """A StringSession string, built as Telethon 1.45 saves one."""
    packed = ipaddress.ip_address(ip).packed
    raw = struct.pack(f">B{len(packed)}sH256s", dc, packed, port, key)
    return "1" + base64.urlsafe_b64encode(raw).decode("ascii")


def secret_json(*, api_id: int = 1234567, api_hash: str = "0123456789abcdef0123456789abcdef",
                session: str | None = None) -> str:
    return json.dumps({"kind": "telegram-mtproto", "v": 1, "api_id": api_id,
                       "api_hash": api_hash, "session": session or make_session()})


DEVICE = {"device_model": "Pixel 7", "system_version": "Android 14",
          "app_version": "10.14.5", "lang_code": "en", "system_lang_code": "en-GB"}


def guard_sockets(monkeypatch) -> list:
    """Every outbound connection but loopback raises, and is recorded."""
    real = socket.socket.connect
    refused: list = []

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, str) and (host.startswith("127.") or host in ("::1", "localhost")):
            return real(self, address)
        refused.append(host)
        raise OSError("a Telegram test refused a connection off this host")

    monkeypatch.setattr(socket.socket, "connect", guarded)
    return refused


def route_token(route_part: str, key: bytes = STUB_KEY) -> str:
    import hashlib
    import hmac

    mac = hmac.new(key, b"noctornal-egress-route-v1\x00" + route_part.encode("ascii"),
                   hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def proxy_route(name: str, context: str, *, port: int = 9,
                host: str = "127.0.0.1") -> EgressRoute:
    """A PROXY persona route with the wire username and token of docs/20
    section 8.3."""
    policy = RoutePolicy("persona", admission="proxy")
    route_part = egress_policy.wire_username("persona", name)
    return EgressRoute("persona", name, "PROXY", policy, context, host, port,
                       route_token(route_part))


def patch_routes(monkeypatch, *, port: int = 9, direct: bool = False) -> list:
    """egress.route_for returns proxy_route (or a DIRECT route), and
    egress.boundary reports the boundary in force. Returns the list of
    (kind, name, context) asked for."""
    from noctornal_api import egress

    asked: list = []

    def route_for(kind, name, *, conn, context=None, declared=()):
        asked.append((kind, name, context))
        if direct:
            return EgressRoute.direct(kind, name, egress_policy.PUBLIC_POLICY)
        return proxy_route(name, context, port=port)

    monkeypatch.setattr(egress, "route_for", route_for)
    monkeypatch.setattr(egress, "boundary", lambda env=None: egress.Boundary(
        "PROXY", f"127.0.0.1:{port}", not direct, ""))
    return asked


# ---------------------------------------------------------------------------
# The fake transport
# ---------------------------------------------------------------------------

_KIND = {"user": "user", "channel": "channel", "chat": "chat"}


def _time(text):
    return datetime.fromisoformat(text) if text else None


def chat_info(spec: dict):
    from noctornal_api import telegram

    kind = "chat" if spec["peer_type"] == "CHAT" else "channel"
    migrated = spec.get("migrated_to")
    return telegram.ChatInfo(
        peer_type=spec["peer_type"], peer_id=int(spec["peer_id"]),
        durable_id=telegram.durable_peer(kind, int(spec["peer_id"])),
        access_hash=spec.get("access_hash"), username=spec.get("username"),
        title=spec.get("title"), is_member=spec.get("is_member"),
        is_forum=bool(spec.get("is_forum")), noforwards=bool(spec.get("noforwards")),
        migrated_to=migrated)


def _peer(spec):
    from noctornal_api import telegram

    if spec is None:
        return None
    return telegram.durable_peer(_KIND.get(spec.get("type"), spec.get("type")),
                                 spec.get("id"))


def to_message(spec: dict, chat):
    """A fixture message as the wire's to_message would give it: every peer
    through durable_peer, every string through clean_text; an untyped peer
    is a message with `problem` set."""
    from noctornal_api import telegram

    text = spec.get("text", "")
    if "text_repeat" in spec:
        text = spec["text_repeat"]["char"] * spec["text_repeat"]["count"]
    handle = spec.get("sender_handle")
    if "sender_handle_repeat" in spec:
        handle = spec["sender_handle_repeat"]["char"] * spec["sender_handle_repeat"]["count"]
    try:
        sender = _peer(spec.get("from")) if spec.get("from") is not None else (
            chat.durable_id if chat.peer_type != "CHAT" else None)
        fwd = spec.get("fwd") or None
        fwd_uid = _peer(fwd.get("from")) if fwd and fwd.get("from") else None
        via = telegram.durable_peer("user", spec["via_bot"]) if spec.get("via_bot") else None
    except telegram.UntypedPeer:
        return telegram.TgMessage(chat_durable_id=chat.durable_id,
                                  message_id=int(spec["id"]),
                                  problem="a peer this build cannot type")
    return telegram.TgMessage(
        chat_durable_id=chat.durable_id, message_id=int(spec["id"]),
        date=_time(spec.get("date")), edit_date=_time(spec.get("edit_date")),
        text=telegram.clean_text(text, telegram.MAX_MESSAGE_CHARS) or "",
        sender_uid=sender, sender_handle=handle,
        post_author=spec.get("post_author"), fwd_from_uid=fwd_uid,
        fwd_from_name=(fwd or {}).get("name"),
        fwd_from_message_id=(fwd or {}).get("channel_post"),
        reply_to_message_id=spec.get("reply_to"), topic_id=spec.get("topic"),
        grouped_id=spec.get("grouped_id"), via_bot_uid=via,
        is_service=bool(spec.get("service")), service_action=spec.get("service"),
        media_kind=spec.get("media"), noforwards=bool(spec.get("noforwards")),
        views=spec.get("views"), forwards=spec.get("forwards"))


def messages_of(fx: dict) -> list[dict]:
    out = list(fx.get("messages") or [])
    gen = fx.get("generate")
    if gen:
        from datetime import timedelta

        start = _time(gen.get("start"))
        for i in range(gen["first"], gen["first"] + gen["count"]):
            out.append({"id": i,
                        "date": (start + timedelta(minutes=i)).isoformat() if start else None,
                        "text": gen["text"].format(id=i), "from": gen.get("from")})
    return out


ALLOWED_FOR_POLL = {"open", "resolve_username", "find_dialog", "lookup", "history",
                    "messages_by_id", "session_string", "close"}


class FakeTransport:
    """telegram.TelegramTransport over a fixture. Records (method, kwargs)."""

    def __init__(self, fx: dict, *, errors: dict | None = None,
                 session_after: str | None = None, allow_join: bool = False,
                 secret=None, proxy=None, hang: bool = False, code: str = "12345",
                 password: str | None = None):
        self.fx = fx
        self.errors = dict(errors or {})
        self.session_after = session_after
        self.allow_join = allow_join
        self.secret = secret
        self.proxy = proxy
        self.hang = hang
        self.code = code
        self.password = password
        self.calls: list[tuple[str, dict]] = []
        self.chat = chat_info(fx["chat"])
        self.signed_in = False

    def _call(self, _method: str, **kw):
        self.calls.append((_method, kw))
        err = self.errors.get(_method)
        if err is not None:
            raise err() if isinstance(err, type) else err

    async def _maybe_hang(self):
        if self.hang:
            import asyncio
            await asyncio.sleep(3600)

    async def open(self):
        from noctornal_api import telegram

        self._call("open")
        await self._maybe_hang()
        return telegram.SelfInfo(uid=self.fx["me"])

    async def connect(self):
        self._call("connect")

    async def send_code(self, phone):
        self._call("send_code", phone=phone)
        return "phone-code-hash-1"

    async def sign_in(self, phone, code, phone_code_hash):
        from noctornal_api import telegram

        self._call("sign_in", phone=phone, phone_code_hash=phone_code_hash)
        if code != self.code:
            raise telegram.TelegramRefused("Telegram did not accept the login code.")
        if self.password:
            raise telegram.TelegramPasswordNeeded("This account has a two-step password.")
        self.signed_in = True

    async def sign_in_password(self, password):
        from noctornal_api import telegram

        self._call("sign_in_password")
        if password != self.password:
            raise telegram.TelegramRefused("Telegram did not accept the two-step password.")
        self.signed_in = True

    async def me(self):
        from noctornal_api import telegram

        self._call("me")
        return telegram.SelfInfo(uid=self.fx["me"])

    async def resolve_username(self, name):
        from noctornal_api import telegram

        self._call("resolve_username", name=name)
        for spec in [self.fx["chat"], *self.fx.get("other_chats", [])]:
            if (spec.get("username") or "").lower() == name.lower():
                return chat_info(spec)
        raise telegram.TelegramChatUnreachable()

    async def find_dialog(self, durable_id):
        self._call("find_dialog", durable_id=durable_id)
        for spec in [self.fx["chat"], *self.fx.get("dialogs", [])]:
            info = chat_info(spec)
            if info.durable_id == durable_id:
                return info
        return None

    async def lookup(self, chat):
        self._call("lookup", durable_id=chat.durable_id)
        return self.chat

    async def history(self, chat, *, min_id=0, max_id=0, limit, newest_first):
        self._call("history", min_id=min_id, max_id=max_id, limit=limit,
                   newest_first=newest_first)
        specs = messages_of(self.fx)
        if newest_first:
            chosen = sorted((s for s in specs if not max_id or s["id"] < max_id),
                            key=lambda s: -s["id"])[:limit]
        else:
            chosen = sorted((s for s in specs if s["id"] > min_id),
                            key=lambda s: s["id"])[:limit]
        return [to_message(s, self.chat) for s in chosen]

    async def messages_by_id(self, chat, ids):
        self._call("messages_by_id", ids=list(ids))
        recheck = self.fx.get("recheck") or {}
        specs = {s["id"]: s for s in messages_of(self.fx)}
        out = []
        for i in ids:
            if str(i) in recheck:
                spec = recheck[str(i)]
            else:
                spec = specs.get(i)
            out.append(to_message(spec, self.chat) if spec else None)
        return out

    async def join(self, chat):
        self._call("join", durable_id=chat.durable_id)
        if not self.allow_join:
            raise AssertionError("a join the test did not allow")
        import dataclasses
        return dataclasses.replace(self.chat, is_member=True)

    async def log_out(self):
        self._call("log_out")
        return True

    def session_string(self):
        # A connection always has an auth key, so a client that started
        # with no session has one now.
        return self.session_after or (
            self.secret.session if self.secret and self.secret.session else make_session())

    async def close(self):
        self.calls.append(("close", {}))


class FakeFactory:
    """transport_factory(secret, route, fingerprint, *, proxy): a
    FakeTransport per session, each kept for the test to read."""

    def __init__(self, fx: dict, **kw):
        self.fx = fx
        self.kw = kw
        self.transports: list[FakeTransport] = []
        self.proxies: list[dict] = []
        self.fingerprints: list[dict] = []
        self.secrets: list = []

    def __call__(self, secret, route, fingerprint, *, proxy):
        self.proxies.append(dict(proxy))
        self.fingerprints.append(dict(fingerprint))
        self.secrets.append(secret)
        t = FakeTransport(self.fx, secret=secret, proxy=proxy, **self.kw)
        self.transports.append(t)
        return t

    @property
    def calls(self) -> list[tuple[str, dict]]:
        return [c for t in self.transports for c in t.calls]

    def methods(self) -> list[str]:
        return [name for name, _kw in self.calls]


# ---------------------------------------------------------------------------
# A RunContext for the adapter's own tests (no database)
# ---------------------------------------------------------------------------

class FakeLease:
    def __init__(self, value: str):
        self.value = value
        self.resealed_to = None

    def reseal(self, new):
        self.resealed_to = new


class FakeRunContext:
    """What the adapter reads of the foundation's RunContext."""

    def __init__(self, source, *, persona_id=None, platform_uid="u:700000001",
                 secret: str | None = None, route=None, fingerprint=None):
        from noctornal_api.collection import PersonaContext

        self.source = source
        self.run_id = uuid4()
        self.route = route or proxy_route(str(uuid4()), f"run:{self.run_id}")
        self.persona = PersonaContext(
            persona_id=persona_id or uuid4(), handle="ghost", platform="TELEGRAM",
            platform_uid=platform_uid, fingerprint=dict(fingerprint or DEVICE),
            authority=None, route=self.route, lease=FakeLease(secret or secret_json()))
        self.requests: list[dict] = []
        self.paced = 0

    def pace(self):
        self.paced += 1

    def record_request(self, *, target, status, nbytes, sha256_hex):
        self.requests.append({"target": target, "status": status, "bytes": nbytes})


def source_row(*, access_mode: str = "PUBLIC_READ", max_rps: float = 1.0,
               source_id=None):
    from noctornal_api.collection import SourceRow

    return SourceRow(source_id or uuid4(), "TELEGRAM", "tg-test", None, "telegram",
                     "AMBER", "F", max_rps, True, uuid4(), None,
                     {"access_mode": access_mode}, None, None)


def plan_for(fx: dict, source, *, persona_id=None, persona_uid="u:700000001",
             access_mode: str | None = None, own_hash: bool = True,
             member_since=None, recheck=(), username: str | None | bool = True):
    from noctornal_api import telegram

    chat = chat_info(fx["chat"])
    mode = access_mode or (source.parser_config or {}).get("access_mode", "PUBLIC_READ")
    pid = persona_id or source.collection_account_id
    return telegram.TelegramPlan(
        source_id=source.id, chat=chat, access_mode=mode,
        username_at_resolve=(chat.username if username is True else username or None),
        access_hash_account_id=pid if own_hash and chat.access_hash else None,
        member_since_observed=member_since, persona_id=pid,
        persona_uid=persona_uid, recheck=tuple(recheck))


async def _no_sleep(_seconds):
    return None


class FakeClock:
    """A clock the adapter's sleeps move."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.now += float(seconds)
