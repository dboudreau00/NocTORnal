"""F28 (docs/17, 2026-10-02): a versioned, opt-in webhook signature with a
timestamp.

v1 is `X-NocTORnal-Signature: sha256=<hex>` over the exact body and carries no
time, so a delivery captured and posted again is indistinguishable from the
first. v2 is `X-NocTORnal-Signature-V2: t=<unix seconds>,v2=<hex>` over
`<t>.<body>`, selected by NOCTORNAL_WEBHOOK_SIGNATURE=v2 on the destination.

What these tests hold:

- v1 is untouched: with the setting unset or `v1` the delivery carries the
  same single header with the same value it always did, and no v2 header;
- v2 carries ONLY the v2 header. A delivery that carried both could be posted
  again forever with the v2 header cut off, so there is nothing to downgrade
  to (the argument is in docs/07 and `send_webhook`'s docstring);
- the signed string, the header's shape and the receiver's replay rules are
  the ones docs/07 states, proved by running the verifier printed there;
- a setting that cannot be used (a value that is neither v1 nor v2, or v2 with
  no secret) is never read as v1: the channel is HELD, the API refuses to
  start in production, and a direct send refuses.

The first half is pure. The drain half is env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from pathlib import Path

import pytest

from outbound_support import DATABASE_URL, FakeRoute, make_user, route_for_factory, teardown

SECRET = "hook-signing-secret-for-tests"
URL = "https://hooks.example.org/T0/x"
DOCS = Path(__file__).resolve().parents[3] / "docs" / "07-integrations.md"
V1, V2 = "X-NocTORnal-Signature", "X-NocTORnal-Signature-V2"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("NOCTORNAL_WEBHOOK_SIGNATURE", "NOCTORNAL_WEBHOOK_SECRET",
                 "NOCTORNAL_WEBHOOK_URL", "NOCTORNAL_ENV"):
        monkeypatch.delenv(name, raising=False)


def _route():
    return FakeRoute("webhook", frozenset({("hooks.example.org", 443)}))


def _post(monkeypatch, *, secret=SECRET, payload=None, clock=None, setting=None):
    """Send one webhook through a recorder and return (headers, body)."""
    from noctornal_api import pinned_http
    from noctornal_api.transports import send_webhook

    if setting is not None:
        monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", setting)
    seen = []
    monkeypatch.setattr(pinned_http, "fetch_response",
                        lambda url, **kw: seen.append(kw) or None)
    send_webhook(URL, payload or {"event": "notification", "notification_id": "n-1"},
                 secret, route=_route(), clock=clock)
    assert len(seen) == 1
    return seen[0]["headers"], seen[0]["body"]


def _mac(key: str, message: bytes) -> str:
    return hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


# --- the setting ---------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    (None, "v1"), ("", "v1"), ("  ", "v1"), ("v1", "v1"), ("V1", "v1"),
    ("v2", "v2"), (" V2 ", "v2"),
])
def test_the_setting_reads_v1_unless_it_says_v2(value, expected):
    from noctornal_api.transports import webhook_signature_version

    env = {} if value is None else {"NOCTORNAL_WEBHOOK_SIGNATURE": value}
    assert webhook_signature_version(env) == (expected, None)


@pytest.mark.parametrize("value", ["v3", "2", "sha256", "v1,v2", "true", "v 2"])
def test_a_value_that_is_neither_is_a_refusal_and_never_v1(value):
    from noctornal_api.transports import webhook_signature_version

    version, problem = webhook_signature_version({"NOCTORNAL_WEBHOOK_SIGNATURE": value})
    assert version is None
    assert "NOCTORNAL_WEBHOOK_SIGNATURE is not v1 or v2" in problem


def test_v2_with_no_secret_is_a_problem_and_v1_with_none_is_not():
    from noctornal_api.transports import webhook_signature_problem

    assert webhook_signature_problem({}) is None
    assert webhook_signature_problem({"NOCTORNAL_WEBHOOK_SIGNATURE": "v1"}) is None
    problem = webhook_signature_problem({"NOCTORNAL_WEBHOOK_SIGNATURE": "v2"})
    assert "v2" in problem and "NOCTORNAL_WEBHOOK_SECRET is not set" in problem
    assert webhook_signature_problem({"NOCTORNAL_WEBHOOK_SIGNATURE": "v2",
                                      "NOCTORNAL_WEBHOOK_SECRET": SECRET}) is None


# --- v1 is untouched -------------------------------------------------------------------

@pytest.mark.parametrize("setting", [None, "", "v1"])
def test_v1_sends_exactly_the_one_header_it_always_did(monkeypatch, setting):
    headers, body = _post(monkeypatch, setting=setting)
    assert headers == {"Content-Type": "application/json",
                       V1: "sha256=" + _mac(SECRET, body)}
    assert not any(name.lower() == V2.lower() for name in headers)


def test_v1_with_no_secret_sends_no_signature_at_all(monkeypatch):
    headers, _body = _post(monkeypatch, secret=None)
    assert headers == {"Content-Type": "application/json"}


def test_the_v1_function_is_the_one_it_was():
    from noctornal_api.transports import sign

    assert sign(b'{"a":1}', "s3cret") == "sha256=" + _mac("s3cret", b'{"a":1}')


# --- v2 --------------------------------------------------------------------------------

def test_v2_signs_the_timestamp_a_full_stop_and_the_body(monkeypatch):
    headers, body = _post(monkeypatch, setting="v2", clock=lambda: 1_700_000_000.9)
    value = headers[V2]
    assert re.fullmatch(r"t=[0-9]+,v2=[0-9a-f]{64}", value), value
    assert value == f"t=1700000000,v2={_mac(SECRET, b'1700000000.' + body)}"


def test_the_clock_defaults_to_now(monkeypatch):
    before = int(time.time())
    headers, _ = _post(monkeypatch, setting="v2")
    stamp = int(headers[V2].split(",")[0].removeprefix("t="))
    assert before <= stamp <= int(time.time())


def test_v2_carries_no_v1_header_so_there_is_nothing_to_downgrade_to(monkeypatch):
    headers, body = _post(monkeypatch, setting="v2", clock=lambda: 1_700_000_000)
    assert set(headers) == {"Content-Type", V2}
    assert not any(name.lower() == V1.lower() for name in headers)
    # And no value in it is a v1 signature of this body.
    assert ("sha256=" + _mac(SECRET, body)) not in "".join(headers.values())
    assert _mac(SECRET, body) not in "".join(headers.values())


def test_a_v1_signature_cannot_be_read_as_a_v2_one(monkeypatch):
    """A v1 signature is over a body that begins with a brace, and a v2 one is
    over digits first, so they are over different strings for every body and
    every timestamp."""
    from noctornal_api.transports import sign, sign_v2

    for payload in ({"event": "notification", "notification_id": "n-1", "redacted": True},
                    {"event": "notification", "notification_id": "n-2", "redacted": False}):
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        assert body.startswith(b"{")
        for stamp in (0, 1, 1_700_000_000):
            v2_mac = sign_v2(body, SECRET, stamp).split("v2=")[1]
            assert v2_mac != sign(body, SECRET).removeprefix("sha256=")


def test_every_attempt_is_signed_afresh_so_a_retry_carries_a_new_time(monkeypatch):
    clock = iter([1_700_000_000, 1_700_000_120])
    first, body_a = _post(monkeypatch, setting="v2", clock=lambda: next(clock))
    second, body_b = _post(monkeypatch, setting="v2", clock=lambda: next(clock))
    assert body_a == body_b, "the notification is the same"
    assert first[V2] != second[V2]
    assert first[V2].startswith("t=1700000000,") and second[V2].startswith("t=1700000120,")


def test_the_body_signed_is_the_body_sent(monkeypatch):
    headers, body = _post(monkeypatch, setting="v2", clock=lambda: 5,
                          payload={"event": "notification", "notification_id": "n-9",
                                   "summary": "café — not ascii"})
    assert headers[V2].endswith(_mac(SECRET, b"5." + body))
    assert json.loads(body)["summary"] == "café — not ascii"


def test_v2_with_no_secret_refuses_and_sends_nothing(monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import TransportError, send_webhook

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", "v2")
    posted = []
    monkeypatch.setattr(pinned_http, "fetch_response", lambda *a, **k: posted.append(a))
    for secret in (None, ""):
        with pytest.raises(TransportError, match="nothing was signed and nothing was sent"):
            send_webhook(URL, {"a": 1}, secret, route=_route())
    assert not posted


@pytest.mark.parametrize("setting", ["v3", "2", "sha256"])
def test_an_unknown_setting_refuses_and_never_falls_back_to_v1(monkeypatch, setting):
    from noctornal_api import pinned_http
    from noctornal_api.transports import TransportError, send_webhook

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", setting)
    posted = []
    monkeypatch.setattr(pinned_http, "fetch_response", lambda *a, **k: posted.append(a))
    with pytest.raises(TransportError, match="is not v1 or v2"):
        send_webhook(URL, {"a": 1}, SECRET, route=_route())
    assert not posted


# --- the receiver, as docs/07 prints it -------------------------------------------------

@pytest.fixture(scope="module")
def verify():
    """The verifier from docs/07, run as printed. If the docs and the sender
    disagree, this is where it shows."""
    text = DOCS.read_text(encoding="utf-8")
    blocks = [b for b in re.findall(r"```python\n(.*?)```", text, re.S)
              if "def verify_noctornal_v2" in b]
    assert len(blocks) == 1, "docs/07 prints exactly one v2 verifier"
    namespace: dict = {}
    exec(compile(blocks[0], "docs/07-integrations.md", "exec"), namespace)  # noqa: S102
    return namespace["verify_noctornal_v2"]


def _delivery(monkeypatch, stamp=None, payload=None, secret=SECRET):
    headers, body = _post(monkeypatch, setting="v2", secret=secret,
                          payload=payload or {"event": "notification",
                                              "notification_id": "n-77"},
                          clock=(lambda: stamp) if stamp is not None else None)
    return headers[V2], body


def test_the_documented_verifier_accepts_what_the_sender_sends(monkeypatch, verify):
    header, body = _delivery(monkeypatch)
    seen: set = set()
    assert verify(SECRET.encode(), header, body, seen)["notification_id"] == "n-77"
    assert seen == {"n-77"}


def test_the_documented_verifier_refuses_a_capture_posted_again(monkeypatch, verify):
    header, body = _delivery(monkeypatch)
    seen: set = set()
    verify(SECRET.encode(), header, body, seen)
    with pytest.raises(ValueError, match="already handled"):
        verify(SECRET.encode(), header, body, seen)


def test_the_documented_verifier_refuses_a_stale_or_a_future_timestamp(monkeypatch, verify):
    now = int(time.time())
    for stamp in (now - 301 - 3600, now - 400, now + 400, now + 86400):
        header, body = _delivery(monkeypatch, stamp=stamp)
        with pytest.raises(ValueError, match="replay window"):
            verify(SECRET.encode(), header, body, set())
    for stamp in (now - 250, now + 250):
        header, body = _delivery(monkeypatch, stamp=stamp)
        assert verify(SECRET.encode(), header, body, set())


def test_a_timestamp_changed_in_the_header_breaks_the_signature(monkeypatch, verify):
    """The reason for signing the time: a capture cannot be freshened by
    editing `t`."""
    now = int(time.time())
    header, body = _delivery(monkeypatch, stamp=now - 3600)
    mac = header.split("v2=")[1]
    with pytest.raises(ValueError, match="signature does not match"):
        verify(SECRET.encode(), f"t={now},v2={mac}", body, set())


def test_the_documented_verifier_refuses_a_body_or_a_key_that_is_not_the_one(monkeypatch, verify):
    header, body = _delivery(monkeypatch)
    with pytest.raises(ValueError, match="signature does not match"):
        verify(SECRET.encode(), header, body + b" ", set())
    with pytest.raises(ValueError, match="signature does not match"):
        verify(b"another-secret", header, body, set())


@pytest.mark.parametrize("header", [
    "", "t=1", "v2=ab", "garbage", "t=,v2=", "t=+123,v2=" + "0" * 64,
    "t=１２３,v2=" + "0" * 64, "t=1.5,v2=" + "0" * 64, "t=-1,v2=" + "0" * 64,
    "t=1700000000,v2=é" + "0" * 63,
])
def test_the_documented_verifier_refuses_a_malformed_header(verify, header):
    with pytest.raises(ValueError):
        verify(SECRET.encode(), header, b'{"notification_id": "n"}', set())


def test_a_v1_header_is_not_accepted_by_the_v2_verifier(monkeypatch, verify):
    from noctornal_api.transports import sign

    body = b'{"event":"notification","notification_id":"n-1"}'
    with pytest.raises(ValueError):
        verify(SECRET.encode(), sign(body, SECRET), body, set())


def test_the_docs_state_the_format_the_sender_uses():
    flat = " ".join(DOCS.read_text(encoding="utf-8").split())
    for needle in ("X-NocTORnal-Signature-V2", "t=<unix seconds>,v2=<hex>",
                   "NOCTORNAL_WEBHOOK_SIGNATURE", "300 seconds", "notification_id",
                   "carries no `X-NocTORnal-Signature` header", "at least 24 hours",
                   "the request body exactly as it arrived"):
        assert needle in flat, needle


def test_a_signature_that_is_not_ascii_is_a_refusal_and_not_a_crash(verify):
    header = f"t={int(time.time())},v2=é" + "0" * 63
    with pytest.raises(ValueError, match="signature does not match"):
        verify(SECRET.encode(), header, b'{"notification_id": "n"}', set())


# --- configuration: the start check and the channel's route -------------------------------

def _problems(**extra):
    from noctornal_api import config

    return config.verify_environment({config.ENV_VAR: config.PRODUCTION, **extra})


def test_production_refuses_a_setting_that_is_neither_v1_nor_v2():
    assert any("NOCTORNAL_WEBHOOK_SIGNATURE is not v1 or v2" in p
               for p in _problems(NOCTORNAL_WEBHOOK_SIGNATURE="v3"))
    assert any("NOCTORNAL_WEBHOOK_SIGNATURE is not v1 or v2" in p
               for p in _problems(NOCTORNAL_WEBHOOK_SIGNATURE="v3",
                                  NOCTORNAL_WEBHOOK_URL=URL))


def test_production_refuses_v2_with_a_webhook_and_no_secret_only():
    assert any("NOCTORNAL_WEBHOOK_SECRET is not set" in p
               for p in _problems(NOCTORNAL_WEBHOOK_SIGNATURE="v2",
                                  NOCTORNAL_WEBHOOK_URL=URL))
    assert not any("NOCTORNAL_WEBHOOK_SIGNATURE" in p
                   for p in _problems(NOCTORNAL_WEBHOOK_SIGNATURE="v2",
                                      NOCTORNAL_WEBHOOK_URL=URL,
                                      NOCTORNAL_WEBHOOK_SECRET=SECRET))
    assert not any("NOCTORNAL_WEBHOOK_SIGNATURE" in p
                   for p in _problems(NOCTORNAL_WEBHOOK_SIGNATURE="v2")), (
        "no webhook is configured, so there is nothing to sign")
    assert not any("NOCTORNAL_WEBHOOK_SIGNATURE" in p for p in _problems())


def test_the_channel_is_held_not_failed_when_the_signature_cannot_be_used(monkeypatch):
    from noctornal_api import transports

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", URL)
    route_for = route_for_factory({"webhook": _route()})
    ok = transports.route_state(transports.WEBHOOK, None, route_for=route_for)
    assert ok.ok, ok.why
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", "v2")
    held = transports.route_state(transports.WEBHOOK, None, route_for=route_for)
    assert not held.ok and "NOCTORNAL_WEBHOOK_SECRET is not set" in held.why
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", SECRET)
    assert transports.route_state(transports.WEBHOOK, None, route_for=route_for).ok
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", "v3")
    held = transports.route_state(transports.WEBHOOK, None, route_for=route_for)
    assert not held.ok and "is not v1 or v2" in held.why


def test_nothing_the_feature_says_uses_a_dash_the_copy_rule_forbids():
    from noctornal_api import transports

    sentences = [
        transports.webhook_signature_version({"NOCTORNAL_WEBHOOK_SIGNATURE": "x"})[1],
        transports.webhook_signature_problem({"NOCTORNAL_WEBHOOK_SIGNATURE": "v2"}),
    ]
    text = DOCS.read_text(encoding="utf-8")
    start = text.index("### Webhook signatures: v1 and v2")
    sentences.append(text[start:text.index("## Sandbox", start)])
    for sentence in sentences:
        assert "—" not in sentence and "–" not in sentence
        assert " -- " not in sentence and "(s)" not in sentence


# --- the drain ----------------------------------------------------------------------------

needs_db = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
PREFIX = "wsig-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _queued(conn):
    from noctornal_api.notifications import NotificationService

    uid, _ = make_user(conn, PREFIX)
    NotificationService(conn).set_preference(uid, "WEBHOOK", enabled=True, min_priority=1)
    n = NotificationService(conn).notify(
        recipient_id=uid, kind="EVIDENCE_INTEGRITY_ALARM", subject="OP-X: y",
        summary="y", body="y", classification="GREEN", priority=1)
    conn.execute("UPDATE notify.delivery SET deliver_after = now() + interval '1 day' "
                 "WHERE state = 'PENDING' AND notification_id <> %s", (n.id,))
    return n


def _row(conn, n):
    return conn.execute("SELECT state, attempts, cause, detail FROM notify.delivery "
                        "WHERE notification_id = %s AND channel = 'WEBHOOK'",
                        (n.id,)).fetchone()


@needs_db
def test_the_drain_posts_v2_with_the_v2_header_only_and_the_receiver_accepts_it(
        conn, monkeypatch, verify):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    from outbound_support import fetched

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", URL)
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", "v2")
    calls = []
    monkeypatch.setattr(pinned_http, "fetch_response",
                        lambda url, **kw: calls.append(kw) or fetched(204, b""))
    n = _queued(conn)
    dispatch_due(conn, send_mail=lambda m: None,
                 route_for=route_for_factory({"webhook": _route()}))
    assert calls, "nothing was posted"
    headers, body = calls[0]["headers"], calls[0]["body"]
    assert V2 in headers and not any(k.lower() == V1.lower() for k in headers)
    assert verify(SECRET.encode(), headers[V2], body, set())["notification_id"] == str(n.id)
    assert _row(conn, n)[0] == "SENT"


@needs_db
def test_the_drain_holds_a_bad_signature_setting_and_spends_no_attempt(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", URL)
    posted = []
    monkeypatch.setattr(pinned_http, "fetch_response", lambda *a, **k: posted.append(a))
    for setting, secret in (("v3", SECRET), ("v2", None)):
        monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", setting)
        if secret:
            monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", secret)
        else:
            monkeypatch.delenv("NOCTORNAL_WEBHOOK_SECRET", raising=False)
        n = _queued(conn)
        counters = dispatch_due(conn, send_mail=lambda m: None,
                                route_for=route_for_factory({"webhook": _route()}))
        state, attempts, _cause, _detail = _row(conn, n)
        assert (state, attempts) == ("PENDING", 0), "held, not failed"
        assert counters["held"] >= 1 and counters["failed"] == 0
    assert not posted


@needs_db
def test_the_drain_still_posts_v1_when_nothing_is_set(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    from outbound_support import fetched

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", URL)
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", SECRET)
    calls = []
    monkeypatch.setattr(pinned_http, "fetch_response",
                        lambda url, **kw: calls.append(kw) or fetched(204, b""))
    n = _queued(conn)
    dispatch_due(conn, send_mail=lambda m: None,
                 route_for=route_for_factory({"webhook": _route()}))
    headers, body = calls[0]["headers"], calls[0]["body"]
    assert headers[V1] == "sha256=" + _mac(SECRET, body) and V2 not in headers
    assert _row(conn, n)[0] == "SENT"


@needs_db
def test_the_integrations_overview_names_the_scheme_and_still_no_secret(conn, monkeypatch):
    from outbound_support import client as make_client
    from outbound_support import session

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", URL)
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", SECRET)
    _uid, email = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    api = make_client()
    seen = {}
    for setting in (None, "v2", "v3"):
        if setting is None:
            monkeypatch.delenv("NOCTORNAL_WEBHOOK_SIGNATURE", raising=False)
        else:
            monkeypatch.setenv("NOCTORNAL_WEBHOOK_SIGNATURE", setting)
        r = api.get("/api/v1/integrations", headers=session(conn, email))
        assert r.status_code == 200, r.text
        assert SECRET not in r.text
        seen[setting] = r.json()["webhook"]
    assert seen[None]["signature"] == "v1" and seen["v2"]["signature"] == "v2"
    assert seen["v3"]["signature"] is None
    assert seen["v3"]["route"]["ok"] is False and "is not v1 or v2" in seen["v3"]["route"]["why"]
