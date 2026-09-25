"""Telegram's typed ids, chat references, the sealed secret's shape and the
data-centre list (roadmap F5.2 and F5.3, telegram, 2026-09-24).

Pure: no database, no network, no Telethon.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

import telegram_fake as tf

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"


def _migration(name: str):
    path = next(VERSIONS.glob(f"*_{name}.py"))
    spec = importlib.util.spec_from_file_location(f"m_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_peer_becomes_a_typed_durable_id():
    from noctornal_api.telegram import durable_peer

    assert durable_peer("user", 700000001) == "u:700000001"
    assert durable_peer("channel", 1300000001) == "c:1300000001"
    assert durable_peer("chat", 4000001) == "g:4000001"


@pytest.mark.parametrize("kind, value", [
    ("user", 0), ("user", -5), ("channel", True), ("chat", "12"), ("martian", 5),
    ("user", None)])
def test_a_peer_this_build_cannot_type_is_refused(kind, value):
    from noctornal_api.telegram import UntypedPeer, durable_peer

    with pytest.raises(UntypedPeer):
        durable_peer(kind, value)


def test_a_user_and_a_channel_with_the_same_number_stay_two_ids():
    from noctornal_api.telegram import durable_peer

    assert durable_peer("user", 1300000001) != durable_peer("channel", 1300000001)


@pytest.mark.parametrize("ref, durable", [
    ("-1001234567890", "c:1234567890"),
    ("-1000123456789", "c:123456789"),   # a nine-digit channel id
    ("-1012345678901", "c:12345678901"),  # an eleven-digit one
    ("-4000001", "g:4000001"),
    ("c:55", "c:55"), ("G:4000001", "g:4000001")])
def test_the_bot_api_form_decodes_to_the_channel(ref, durable):
    from noctornal_api.telegram import parse_chat_reference

    assert parse_chat_reference(ref).durable_id == durable


@pytest.mark.parametrize("ref, name", [
    ("@ExampleNews", "examplenews"), ("https://t.me/examplenews", "examplenews"),
    ("t.me/example_news", "example_news"), ("http://telegram.me/examplenews", "examplenews")])
def test_public_names_are_accepted(ref, name):
    from noctornal_api.telegram import parse_chat_reference

    assert parse_chat_reference(ref).username == name


def test_a_bare_positive_reference_is_refused_with_the_ontology_sentence():
    from noctornal_ontology import refusal

    from noctornal_api.telegram import ReferenceRefused, parse_chat_reference

    with pytest.raises(ReferenceRefused) as caught:
        parse_chat_reference("1300000001")
    assert str(caught.value) == refusal("TELEGRAM_ID", "1300000001")


@pytest.mark.parametrize("ref", ["https://t.me/+AbCdEf123", "t.me/joinchat/AAAAAE",
                                 "https://telegram.me/+xyz12345"])
def test_an_invite_link_is_refused_with_the_manual_join_sentence(ref):
    from noctornal_api.telegram import INVITE_SENTENCE, ReferenceRefused, parse_chat_reference

    with pytest.raises(ReferenceRefused) as caught:
        parse_chat_reference(ref)
    assert str(caught.value) == INVITE_SENTENCE


@pytest.mark.parametrize("ref", [
    "x" * 201, "@abc", "@bad-name!", "c:12\n34", "c:1 2", "c:0", "c:0012",
    "https://evil.example/t.me/examplenews", "t.me/examplenews?start=1",
    "t.me/examplenews/12", "-0", "--100123", "examplenews", "", "   ",
    "c:12345678901234567890123", "\u202e@examplenews"])
def test_hostile_references_are_refused(ref):
    from noctornal_api.telegram import ReferenceRefused, parse_chat_reference

    with pytest.raises(ReferenceRefused):
        parse_chat_reference(ref)


def test_a_user_reference_is_refused_as_a_conversation():
    from noctornal_api.telegram import USER_REF_SENTENCE, ReferenceRefused, parse_chat_reference

    with pytest.raises(ReferenceRefused) as caught:
        parse_chat_reference("u:700000001")
    assert str(caught.value) == USER_REF_SENTENCE


def test_the_adapter_regexes_equal_the_migration_checks():
    from noctornal_api import telegram

    persona = _migration("telegram_persona")
    chat = _migration("telegram_chat_and_message")
    assert persona.UID_PATTERN == telegram.UID_PATTERN
    assert chat.UID_PATTERN == telegram.UID_PATTERN
    assert chat.CHAT_PATTERN == telegram.CHAT_PATTERN
    assert chat.CHANNEL_PATTERN == telegram.CHANNEL_PATTERN
    assert chat.PEER_PATTERN == telegram.PEER_PATTERN
    assert chat.SERVICE_ACTION_PATTERN == telegram.SERVICE_ACTION_PATTERN
    assert tuple(persona.DEVICE_FIELDS) == tuple(telegram.DEVICE_FIELDS)
    text = (VERSIONS / next(VERSIONS.glob("*_telegram_chat_and_message.py")).name).read_text()
    for name in ("CHAT_PATTERN", "UID_PATTERN", "PEER_PATTERN", "CHANNEL_PATTERN"):
        assert "{" + name + "}" in text, f"the migration's CHECKs use {name}"


def test_clean_text_output_is_within_its_cap_marker_included():
    from noctornal_api.telegram import MAX_NAME_CHARS, TRUNCATION_MARK, clean_name, clean_text

    for n in (255, 256, 257, 300, 10000):
        out = clean_text("n" * n, MAX_NAME_CHARS)
        assert len(out) <= MAX_NAME_CHARS
        assert (n > MAX_NAME_CHARS) == out.endswith(TRUNCATION_MARK)
    assert clean_text("a\x00b\ud800c", 100) == "a\ufffdb\ufffdc"
    assert "\u202e" not in clean_name("evil\u202etxt.exe")
    assert len(clean_name("\u202e" * 400)) <= MAX_NAME_CHARS


def test_a_telegram_secret_never_shows_itself():
    from noctornal_api.telegram import TelegramSecret

    secret = TelegramSecret.parse(tf.secret_json())
    assert "0123456789abcdef" not in repr(secret) and "0123456789abcdef" not in str(secret)
    assert repr(secret) == "TelegramSecret([REDACTED])"
    with pytest.raises(AttributeError):
        secret.session = "x"
    again = TelegramSecret.parse(secret.dump())
    assert again.api_id == 1234567 and again.session == secret.session


@pytest.mark.parametrize("mangle", [
    lambda d: d.update(kind="other"), lambda d: d.update(v=2),
    lambda d: d.update(api_id=0), lambda d: d.update(api_id="12"),
    lambda d: d.update(api_hash="ABCDEF"), lambda d: d.update(session=""),
    lambda d: d.update(session="1" + "A" * 352), lambda d: d.pop("session")])
def test_a_malformed_secret_is_refused_without_quoting_it(mangle):
    from noctornal_api.telegram import TelegramSecret, TelegramSecretInvalid

    data = json.loads(tf.secret_json())
    mangle(data)
    with pytest.raises(TelegramSecretInvalid) as caught:
        TelegramSecret.parse(json.dumps(data))
    assert "0123456789abcdef" not in str(caught.value)


def test_a_string_session_is_read_without_the_library():
    from noctornal_api.telegram import session_address

    where = session_address(tf.make_session(dc=4, ip="149.154.167.91", port=443))
    assert (where.dc_id, where.ip, where.port) == (4, "149.154.167.91", 443)
    six = session_address(tf.make_session(ip="2001:b28:f23d:f001::a"))
    assert six.ip == "2001:b28:f23d:f001::a"


def test_the_device_fields_are_required_and_printable():
    from noctornal_api.telegram import device_problems

    assert device_problems(tf.DEVICE) == []
    assert len(device_problems({})) == 5
    bad = dict(tf.DEVICE, device_model="Pixel\r\nX-Evil: 1")
    assert device_problems(bad) == ["The device model is printable ASCII on one line."]


def test_the_access_mode_decides_the_scope():
    from noctornal_api.telegram import scope_for

    assert scope_for("PUBLIC_READ") == "PUBLIC_READ"
    assert scope_for("MEMBER") == "MEMBER_READ"


def test_the_data_centre_list_is_ipv4_and_passes_the_contracts_rule_check():
    """The IPv6 blocks are wider than egress_policy's
    /64 rule cap; the preset the egress proxy builds from this list must
    save."""
    import ipaddress

    from noctornal_api import egress_policy, egress_routes
    from noctornal_api.egress_policy import Rule
    from noctornal_api.telegram import TELEGRAM_DC_NETWORKS, TELEGRAM_DC_PORTS

    assert all(ipaddress.ip_network(n).version == 4 for n in TELEGRAM_DC_NETWORKS)
    preset = egress_routes.presets()["telegram"]
    assert preset["cidrs"] == list(TELEGRAM_DC_NETWORKS)
    assert tuple(preset["ports"]) == TELEGRAM_DC_PORTS
    for cidr in TELEGRAM_DC_NETWORKS:
        rule = Rule(frozenset(TELEGRAM_DC_PORTS), network=cidr)
        assert egress_policy.validate_rule(
            rule, kind="persona", production=True,
            internal=tuple(ipaddress.ip_network(n) for n in
                           egress_policy.DEFAULT_INTERNAL_NETWORKS)) == [], cidr


def test_the_adapter_is_registered_and_requires_authority():
    from noctornal_api.collection import default_adapters
    from noctornal_api.telegram import TelegramAdapter

    adapter = default_adapters()["telegram"]
    assert isinstance(adapter, TelegramAdapter)
    assert adapter.requires_authority and adapter.persona_platform == "TELEGRAM"
    assert adapter.retention_clock and adapter.default_category == "CHAT_EXPORT"
    assert adapter.run_seconds == 120.0
    assert adapter.source_kinds == frozenset({"TELEGRAM"})


def test_every_outcome_sentence_survives_the_redactor_unchanged():
    """A stored run carries its outcome through redact(), which masks a
    credential word followed by a separator ("session: it", "session's"):
    every sentence here is worded so the reader gets it whole."""
    from noctornal_api import telegram, telegram_wire
    from noctornal_api.collection import redact

    outcomes = [telegram.TelegramFloodWait(37), telegram.TelegramSessionRevoked(),
                telegram.TelegramAccountBanned(), telegram.TelegramWrongAccount(),
                telegram.TelegramSessionDuplicated(), telegram.TelegramChatUnreachable(),
                telegram.TelegramNameMoved(), telegram.TelegramChatMigrated("c:1300000009"),
                telegram.TelegramEgressRefused(), telegram.TelegramProxyBusy(),
                telegram.TelegramTransportFailed("TimedOutError"),
                telegram.TelegramSessionTimedOut(), telegram.TelegramSessionAbandoned(),
                telegram.TelegramEgressRefused(telegram_wire._ENDPOINT_SENTENCE),
                telegram.TelegramSecretInvalid("x")]
    try:
        telegram.TelegramSecret.parse("{}")
    except telegram.TelegramSecretInvalid as exc:
        outcomes.append(exc)
    for exc in outcomes:
        text = str(exc)
        assert redact(text) == text, text
        assert "—" not in text and "–" not in text and "(s)" not in text
    for sentence in (telegram.NO_PROXY_SENTENCE, telegram.CLIENT_MISSING,
                     telegram.INVITE_SENTENCE, telegram.USER_REF_SENTENCE,
                     telegram.REFERENCE_SHAPE_SENTENCE):
        assert redact(sentence) == sentence, sentence
