"""The Telethon wire: the checked connection, the proxy on the persona's
route, the reply byte read before Telethon hides it, the error table and
the log scrub (roadmap F5.2 and F5.3, 2026-09-24).

Needs the optional `telegram` extra; without it every test here skips and
says so, which is the gap the telegram_collection readiness row names. No
test reaches Telegram: the SOCKS5 tests talk to the egress contract's stub
proxy on loopback, and the stub's dial to a data centre is refused by the
socket guard, which is what a REP 0x05 is.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest

import telegram_fake as tf

pytest.importorskip(
    "telethon", reason="the telegram extra is not installed: Telegram collection "
                       "is a gap in this build and these tests do not run")

API_SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    tf.guard_sockets(monkeypatch)


def _loggers():
    return defaultdict(lambda: logging.getLogger("telethon.test"))


def _state(proxy):
    from noctornal_api import telegram_wire

    state = telegram_wire.WireState(expected_proxy=dict(proxy))
    telegram_wire._WIRE.set(state)
    return state


# --- mapping ----------------------------------------------------------------

def test_telethon_messages_map_to_records():
    from telethon.tl import types

    from noctornal_api import telegram_wire
    from noctornal_api.telegram import ChatInfo

    chat = ChatInfo("MEGAGROUP", 1300000003, "c:1300000003", is_forum=True)
    when = datetime(2026, 9, 21, 9, 0, tzinfo=timezone.utc)
    message = types.Message(
        id=11, peer_id=types.PeerChannel(1300000003), date=when, message="hello",
        from_id=types.PeerUser(1300000001),
        fwd_from=types.MessageFwdHeader(date=when, from_id=types.PeerChannel(1300000002),
                                        channel_post=44),
        reply_to=types.MessageReplyHeader(reply_to_msg_id=10, forum_topic=True,
                                          reply_to_top_id=10),
        via_bot_id=93372553, post_author="Admin", grouped_id=7, views=5, forwards=1,
        media=types.MessageMediaPhoto())
    got = telegram_wire.to_message(message, chat)
    assert got.problem is None
    assert (got.sender_uid, got.fwd_from_uid, got.via_bot_uid) == (
        "u:1300000001", "c:1300000002", "u:93372553")
    assert (got.reply_to_message_id, got.topic_id, got.fwd_from_message_id) == (10, 10, 44)
    assert got.media_kind == "photo" and got.text == "hello"
    service = types.MessageService(
        id=12, peer_id=types.PeerChannel(1300000003), date=when,
        from_id=types.PeerUser(700000009),
        action=types.MessageActionChatJoinedByLink(inviter_id=1))
    got = telegram_wire.to_message(service, chat)
    assert got.is_service and got.service_action == "MessageActionChatJoinedByLink"
    assert got.text == "u:700000009 joined the group by invite link"
    post = types.Message(id=13, peer_id=types.PeerChannel(1300000003), date=when,
                         message="from the admins")
    assert telegram_wire.to_message(post, chat).sender_uid == "c:1300000003"


def test_a_message_whose_peer_cannot_be_typed_is_named_not_mapped():
    from telethon.tl import types

    from noctornal_api import telegram_wire
    from noctornal_api.telegram import ChatInfo

    chat = ChatInfo("MEGAGROUP", 1300000003, "c:1300000003")
    bad = types.Message(id=25, peer_id=types.PeerChannel(1300000003),
                        message="x", from_id=types.PeerUser(0))
    got = telegram_wire.to_message(bad, chat)
    assert got.problem and got.message_id == 25 and got.sender_uid is None


def test_chat_entities_map_with_membership_and_migration():
    from telethon.tl import types

    from noctornal_api import telegram_wire

    channel = types.Channel(id=1300000001, title="News", photo=types.ChatPhotoEmpty(),
                            date=None, access_hash=77, username="examplenews",
                            left=True, broadcast=True)
    info = telegram_wire.chat_info(channel)
    assert (info.peer_type, info.durable_id, info.is_member, info.access_hash) == (
        "CHANNEL", "c:1300000001", False, 77)
    group = types.Chat(id=4000001, title="Small", photo=types.ChatPhotoEmpty(),
                       participants_count=3, date=None, version=1,
                       migrated_to=types.InputChannel(1300000009, 5))
    info = telegram_wire.chat_info(group)
    assert info.durable_id == "g:4000001" and info.migrated_to == "c:1300000009"


# --- the checked connection ---------------------------------------------------

def _proxy():
    return tf.proxy_route("11111111-1111-4111-8111-111111111111",
                          "run:22222222-2222-4222-8222-222222222222").telethon_proxy()


def test_the_checked_connection_refuses_a_direct_connection():
    from noctornal_api import telegram_wire

    async def go():
        _state(_proxy())
        cls = telegram_wire.checked_connection_class()
        with pytest.raises(ConnectionRefusedError, match="direct"):
            cls("149.154.167.51", 443, 2, loggers=_loggers(), proxy=None)

    asyncio.run(go())


def test_the_checked_connection_refuses_a_substituted_proxy():
    from noctornal_api import telegram_wire

    async def go():
        _state(_proxy())
        cls = telegram_wire.checked_connection_class()
        other = dict(_proxy(), addr="198.51.100.9")
        with pytest.raises(ConnectionRefusedError, match="other than the persona"):
            cls("149.154.167.51", 443, 2, loggers=_loggers(), proxy=other)
        with pytest.raises(ConnectionRefusedError, match="local address"):
            cls("149.154.167.51", 443, 2, loggers=_loggers(), proxy=_proxy(),
                local_addr=("0.0.0.0", 0))

    asyncio.run(go())


@pytest.mark.parametrize("ip, port, words", [
    ("10.0.0.5", 443, "classifier"), ("127.0.0.1", 443, "classifier"),
    ("169.254.169.254", 443, "classifier"), ("8.8.8.8", 443, "outside"),
    ("149.154.167.51", 22, "port"), ("149.154.167.51", 8443, "port")])
def test_the_checked_connection_refuses_a_private_non_telegram_or_odd_port_address(
        ip, port, words):
    from noctornal_api import telegram_wire

    async def go():
        state = _state(_proxy())
        cls = telegram_wire.checked_connection_class()
        with pytest.raises(ConnectionRefusedError, match=words):
            cls(ip, port, 2, loggers=_loggers(), proxy=_proxy())
        assert state.failure == "endpoint"

    asyncio.run(go())


def test_the_checked_connection_admits_a_data_centre_through_the_route():
    from noctornal_api import telegram_wire

    async def go():
        _state(_proxy())
        cls = telegram_wire.checked_connection_class()
        conn = cls("149.154.167.51", 443, 2, loggers=_loggers(), proxy=_proxy())
        assert conn._proxy == _proxy()

    asyncio.run(go())


def test_a_route_that_is_not_proxied_is_refused():
    from noctornal_api import telegram_wire
    from noctornal_api.egress_policy import PUBLIC_POLICY, EgressRoute
    from noctornal_api.telegram import TelegramEgressRefused

    with pytest.raises(TelegramEgressRefused, match="only through the egress proxy"):
        telegram_wire.proxy_for(EgressRoute.direct("persona", "passive", PUBLIC_POLICY))
    with pytest.raises(TelegramEgressRefused):
        telegram_wire.proxy_for(None)


# --- the proxy on the wire ------------------------------------------------------

def _open_through(stub, context: str, *, key: bytes = tf.STUB_KEY):
    """TelethonTransport.open() through the stub on a route with `context`;
    returns (exception, route)."""
    from noctornal_api import telegram_wire
    from noctornal_api.telegram import TelegramSecret

    route = tf.proxy_route("11111111-1111-4111-8111-111111111111", context,
                           port=stub.port)
    if key != tf.STUB_KEY:
        route = type(route)(route.kind, route.name, route.mode, route.policy,
                            route.context, route.proxy_host, route.proxy_port,
                            tf.route_token(route.wire_username.split("~")[0], key))
    secret = TelegramSecret.parse(tf.secret_json())
    transport = telegram_wire.TelethonTransport(
        secret, route, tf.DEVICE, proxy=telegram_wire.proxy_for(route))

    async def go():
        try:
            await transport.open()
        except Exception as exc:  # noqa: BLE001 - the answer under test
            return exc
        finally:
            await transport.close()
        return None

    return asyncio.run(go()), route, transport


@pytest.mark.parametrize("kind", ["run", "act", "stop"])
def test_the_wire_speaks_socks5_with_the_route_credentials(kind):
    """docs/20 section 8.4: RFC 1929 carries the route's wire username, context
    included, and its token; the destination is the data centre's address
    on 443; one tunnel per connect; the stub's dial to Telegram is refused
    here (REP 0x05), which is a transport failure and never a proxy
    refusal."""
    import uuid

    from egress_contract_cases import StubProxy

    from noctornal_api.telegram import TelegramTransportFailed

    with StubProxy() as stub:
        context = f"{kind}:{uuid.uuid4()}"
        exc, route, transport = _open_through(stub, context)
    assert isinstance(exc, TelegramTransportFailed), exc
    socks = [r for r in stub.records if r["protocol"] == "SOCKS5"]
    assert len(socks) == 1, "connection_retries 0: one attempt, one tunnel"
    assert socks[0]["username"] == route.wire_username
    assert socks[0]["username"].endswith(f"~{kind}.{context.split(':')[1]}")
    assert socks[0]["target"] == "149.154.167.51:443"
    assert transport.tunnels == 1


@pytest.mark.parametrize("code, expected", [
    ("authority_missing", "TelegramEgressRefused"),
    ("destination_not_in_source", "TelegramEgressRefused"),
    ("proxy_busy", "TelegramProxyBusy"),
    ("route_busy", "TelegramProxyBusy"),
    ("upstream_timeout", "TelegramTransportFailed"),
])
def test_a_proxy_refusal_is_read_from_the_reply_byte(code, expected):
    """Through Telethon the reply byte never reaches a caller; the checked
    connection records it first."""
    import uuid

    from egress_contract_cases import StubProxy

    with StubProxy() as stub:
        stub.refuse_code = code
        exc, _route, _t = _open_through(stub, f"run:{uuid.uuid4()}")
    assert type(exc).__name__ == expected, (code, exc)
    assert "127.0.0.1" not in str(exc) and str(stub.port) not in str(exc)


def test_a_bad_token_is_an_egress_refusal_not_a_transport_failure():
    import uuid

    from egress_contract_cases import StubProxy

    from noctornal_api.telegram import TelegramEgressRefused

    with StubProxy() as stub:
        exc, _route, _t = _open_through(stub, f"act:{uuid.uuid4()}", key=b"z" * 32)
    assert isinstance(exc, TelegramEgressRefused), exc


def test_the_auth_stage_messages_are_the_installed_python_socks_constants():
    import python_socks

    from noctornal_api.telegram_wire import AUTH_STAGE_MESSAGES

    source = (Path(python_socks.__file__).parent / "_protocols" / "socks5.py").read_text()
    for message in AUTH_STAGE_MESSAGES:
        assert f'"{message}"' in source, message


def test_the_proxy_failure_is_read_from_codes_not_text():
    from noctornal_api.telegram_wire import classify_proxy_failure

    class ReplyError(Exception):
        def __init__(self, message, error_code=None):
            super().__init__(message)
            self.error_code = error_code

    outer = ConnectionError("Connection to Telegram failed 1 time(s)")
    outer.__cause__ = ReplyError("anything the proxy said", error_code=2)
    assert classify_proxy_failure(outer) == "rep:2"
    assert classify_proxy_failure(
        ReplyError("Username and password authentication failure")) == "auth"
    assert classify_proxy_failure(ReplyError("Malformed connect reply")) == "protocol"
    assert classify_proxy_failure(TimeoutError()) == "timeout"
    assert classify_proxy_failure(OSError("refused")) == "unreachable"


# --- the client -------------------------------------------------------------------

def test_the_client_is_built_with_a_string_session_no_update_loop_and_no_automatic_flood_sleep(
        tmp_path, monkeypatch):
    from telethon.sessions import StringSession

    from noctornal_api import telegram_wire
    from noctornal_api.telegram import TelegramSecret

    monkeypatch.chdir(tmp_path)
    secret = TelegramSecret.parse(tf.secret_json())

    async def go():
        client, state = telegram_wire.build_client(secret, _proxy(), tf.DEVICE)
        try:
            assert isinstance(client.session, StringSession)
            assert client.flood_sleep_threshold == 0
            assert client._no_updates is True
            assert client._request_retries == 1 and client._connection_retries == 0
            assert client._auto_reconnect is False
            assert client._proxy == _proxy() and state.expected_proxy == _proxy()
            assert client._init_request.device_model == "Pixel 7"
            assert client._init_request.system_version == "Android 14"
            assert client._init_request.app_version == "10.14.5"
            assert client._connection is telegram_wire.checked_connection_class()
        finally:
            await client.disconnect()

    asyncio.run(go())
    assert not list(tmp_path.glob("*.session")), "no session file is written"


def test_a_persona_without_its_device_is_refused_before_a_client_exists():
    from noctornal_api import telegram_wire
    from noctornal_api.telegram import TelegramRefused, TelegramSecret

    secret = TelegramSecret.parse(tf.secret_json())

    async def go():
        telegram_wire.build_client(secret, _proxy(), {})

    with pytest.raises(TelegramRefused, match="device"):
        asyncio.run(go())


def _error(name, **kw):
    from telethon import errors

    cls = getattr(errors, name)
    try:
        return cls(request=None, **kw)
    except TypeError:
        return cls(request=None, message="X", **kw)


@pytest.mark.parametrize("name, expected", [
    ("AuthKeyDuplicatedError", "TelegramSessionDuplicated"),
    ("SessionRevokedError", "TelegramSessionRevoked"),
    ("AuthKeyUnregisteredError", "TelegramSessionRevoked"),
    ("SessionExpiredError", "TelegramSessionRevoked"),
    ("UserDeactivatedBanError", "TelegramAccountBanned"),
    ("PhoneNumberBannedError", "TelegramAccountBanned"),
    ("ChannelPrivateError", "TelegramChatUnreachable"),
    ("UsernameNotOccupiedError", "TelegramChatUnreachable"),
    ("SessionPasswordNeededError", "TelegramPasswordNeeded"),
    ("TimedOutError", "TelegramTransportFailed"),
    ("ServerError", "TelegramTransportFailed"),
])
def test_telethon_errors_map_to_our_errors(name, expected):
    from noctornal_api.telegram_wire import translate

    got = translate(_error(name))
    assert type(got).__name__ == expected


def test_a_flood_wait_carries_telegrams_seconds():
    from noctornal_api.telegram import TelegramFloodWait
    from noctornal_api.telegram_wire import translate

    got = translate(_error("FloodWaitError", capture=37))
    assert isinstance(got, TelegramFloodWait) and got.retry_after_s == 37.0


def test_the_proxy_record_wins_over_the_library_error():
    from noctornal_api import telegram_wire
    from noctornal_api.telegram import (
        TelegramEgressRefused,
        TelegramProxyBusy,
        TelegramTransportFailed,
    )

    for failure, cls in (("rep:2", TelegramEgressRefused), ("auth", TelegramEgressRefused),
                         ("endpoint", TelegramEgressRefused), ("rep:1", TelegramProxyBusy),
                         ("rep:5", TelegramTransportFailed),
                         ("protocol", TelegramTransportFailed)):
        state = telegram_wire.WireState(expected_proxy={}, failure=failure)
        assert isinstance(telegram_wire.translate(ConnectionError("x"), state), cls)


def test_no_telethon_message_reaches_our_error_text():
    from noctornal_api.telegram_wire import translate

    for exc in (_error("ChannelPrivateError"), _error("FloodWaitError", capture=9),
                ValueError("Cannot find any entity corresponding to @secretname"),
                ConnectionError("Could not connect to proxy 10.9.8.7:1080"),
                _error("RPCError")):
        text = str(translate(exc))
        assert "caused by" not in text and "(s)" not in text
        assert "secretname" not in text and "10.9.8.7" not in text
        assert "—" not in text and "–" not in text


def test_telethon_logging_is_scrubbed_including_child_loggers(caplog, capsys):
    from noctornal_api import telegram_wire

    telegram_wire.install_log_scrub()
    telegram_wire.install_log_scrub()
    root = logging.getLogger("telethon")
    assert len(root.handlers) == 1 and root.propagate is False
    caplog.set_level(logging.DEBUG)
    try:
        raise ConnectionError("proxy 10.9.8.7:1080 refused persona.abc~run.def")
    except ConnectionError:
        logging.getLogger("telethon.network.mtprotosender").error(
            "Attempt %d at connecting failed: %s to %s", 1, "persona.abc~run.def",
            "10.9.8.7:1080", exc_info=True)
    out = capsys.readouterr()
    everything = caplog.text + out.out + out.err
    assert "telethon ERROR in telethon.network.mtprotosender" in caplog.text
    assert "10.9.8.7" not in everything and "persona.abc" not in everything


def test_the_wire_never_searches_marks_read_or_sends():
    from noctornal_api import telegram_wire
    from noctornal_api.telegram import ChatInfo, TelegramSecret

    source = (API_SRC / "noctornal_api" / "telegram_wire.py").read_text()
    for forbidden in ("SearchRequest", "ReadHistoryRequest", "GetMessagesViewsRequest",
                      "UpdateStatusRequest", "SendMessageRequest",
                      "ImportChatInviteRequest", "download_media", "send_message",
                      "send_read_acknowledge", "telethon.sync"):
        assert forbidden not in source, forbidden

    class Spy:
        def __init__(self):
            self.calls = []

        async def get_messages(self, peer, **kw):
            self.calls.append(kw)
            return []

    transport = telegram_wire.TelethonTransport(
        TelegramSecret.parse(tf.secret_json()), None, tf.DEVICE, proxy=_proxy())
    spy = Spy()
    transport._client = spy
    chat = ChatInfo("CHANNEL", 1300000001, "c:1300000001", access_hash=5)

    async def go():
        await transport.history(chat, min_id=5, limit=100, newest_first=False)
        await transport.history(chat, max_id=50, limit=100, newest_first=True)
        await transport.messages_by_id(chat, [1, 2])

    asyncio.run(go())
    for kw in spy.calls:
        assert not {"search", "filter", "from_user"} & set(kw), kw


def test_telethon_sync_is_never_imported():
    code = (
        "import sys, asyncio\n"
        "sys.path.insert(0, r'%s')\n"
        "from noctornal_api import telegram_wire, telegram\n"
        "telegram.client_available()\n"
        "telegram_wire.checked_connection_class()\n"
        "assert 'telethon' in sys.modules\n"
        "assert 'telethon.sync' not in sys.modules, 'telethon.sync imported'\n"
        % API_SRC)
    env = dict(os.environ)
    done = subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, env=env, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
