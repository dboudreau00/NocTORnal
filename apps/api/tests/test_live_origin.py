"""The live socket's two ORIGIN refusals, driven rather than read.

Both stand between a page this server does not serve and a case's activity stream, and neither has anything
to do with the credential the socket would go on to check.

**Cross-site.** `_cross_site_upgrade` is the control that does not depend on a word: `__Host-session` is
`SameSite=strict`, so a compliant browser will not attach it to a cross-site upgrade at all. This check
holds when that sentence is wrong (an old browser, a proxy, a future relaxation of the attribute), and it is
load-bearing because `_handshake` accepts that cookie.

**The sample origin.** Invariant 10 says the process serving hostile bytes serves nothing else, and
`_allowed_on_sample_origin` (`http/app.py`) makes that true of the process rather than of a proxy
allow-list. It is an `@app.middleware("http")`, and Starlette hands a `websocket` scope to the router without
running http middleware, so that gate never sees an upgrade: without the check in `live()`, a sample-origin
process would accept a socket, authenticate it and stream one case's changes out of the one process that is
supposed to hold no session at all. The tests drive both scopes through one assembled app, because "the http
gate does not see this" is the reason the second check is not redundant.

Pure, deliberately. The behavioural tests for the cookie are in `test_live_cookie_pg.py`, which needs
Postgres and is skipped on a laptop with no database, which would leave the newest security controls in the
socket unchecked. Nothing below opens a database connection or a socket: both refusals are decided from two
headers and the environment, before `accept()` and before any handshake, so a synthetic ASGI scope and a
recording `send` are enough. What this file cannot prove is that a browser always sends `Origin` on an
upgrade and cannot be made to omit it, which the no-Origin allowance rests on.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from starlette.websockets import WebSocket

from noctornal_api.http.routers import live as module
from noctornal_api.http.routers.live import (
    _CLOSE_BUSY,
    _CLOSE_POLICY,
    _cross_site_upgrade,
)

#: The application origin every test below configures. Long enough that
#: the refusal reason interpolating it is a real measurement of RFC 6455's
#: 123-byte budget rather than a comfortable one.
APP = "https://noctornal-console.police.example"

#: The separate origin invariant 10 puts hostile bytes on.
SAMPLE = "https://samples.police.example"

#: An origin this deployment is not and never was -- the attacker's page.
#: A sibling of the console's own registrable domain on purpose: SameSite
#: is same-SITE, so a compliant browser DOES attach `__Host-session` to an
#: upgrade from here, and the comparison is the whole defence.
FOREIGN = "https://evil.police.example"

LIVE = "/api/v1/live"

#: RFC 6455 leaves 123 bytes for a close reason: 125 in a control frame,
#: less the two-byte code. A reason over it is a frame the server cannot
#: send, so the refusal would arrive as a crash rather than a refusal.
_MAX_CLOSE_REASON = 123

LIVE_PY = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
           / "http" / "routers" / "live.py")


def _upgrade(*, cookie: str | None = None, origin: str | None = None,
             host: str | None = "noctornal-console.police.example",
             scheme: str = "wss",
             sent: list[dict] | None = None,
             inbound: tuple[dict, ...] = ()) -> WebSocket:
    """One upgrade, as Starlette sees it.

    Half the rule compares `Origin` with `Host` deliberately (`_request_origin`), so on the default upgrade
    the two agree and an `Origin` of `APP` is accepted whatever the configuration says. Every test about the
    configured comparison therefore passes its own `host=` that matches neither side. `host=None` omits the
    header, the only way to reach the branch where this process cannot name its own origin at all.

    `scheme` is the scope's own: `wss` by default, as a deployed console is. A test comparing against an
    `http` origin must say `scheme="ws"`, since `_request_origin` maps the socket's scheme onto the
    http/https pair an `Origin` header is written with, and a plain socket claiming an https origin is a
    mismatch.

    `sent` and `inbound` are for the tests that drive `live()` itself: recording every ASGI message is the
    only way to see whether a refusal came before or after `accept()`, which is the difference between a
    dropped transport and ten seconds of uvicorn's close timeout (`_PendingBudget`). A `TestClient`
    completes the close handshake in process and cannot show it.
    """
    headers = [] if host is None else [(b"host", host.encode())]
    if cookie is not None:
        headers.append((b"cookie", cookie.encode()))
    if origin is not None:
        headers.append((b"origin", origin.encode()))

    pending = iter(inbound)

    async def _receive() -> dict:
        try:
            return next(pending)
        except StopIteration:                  # pragma: no cover - a read
            await asyncio.sleep(3600)          # past the last one is a bug

    async def _send(message: dict) -> None:
        if sent is not None:
            sent.append(message)

    return WebSocket({"type": "websocket", "path": LIVE,
                      "query_string": b"", "scheme": scheme,
                      "client": ("198.51.100.7", 51234), "headers": headers},
                     _receive, _send)


def _sent_by_live(**upgrade) -> list[dict]:
    """Run the endpoint over one synthetic upgrade; return what it sent.

    The peer disconnects immediately after connecting, so a socket that gets past the pre-accept refusals
    accepts and then closes "no credentials" without reaching a database: `_handshake` needs a hello frame
    it never gets. That makes the admitted case assertable with no Postgres; the interesting message is the
    first one either way.
    """
    sent: list[dict] = []
    ws = _upgrade(sent=sent,
                  inbound=({"type": "websocket.connect"},
                           {"type": "websocket.disconnect", "code": 1006}),
                  **upgrade)
    asyncio.run(asyncio.wait_for(module.live(ws), timeout=10))
    return sent


def _configured(monkeypatch, *, app: str = APP, this: str | None = None,
                sample: str = SAMPLE) -> None:
    # The off switch shares `_CLOSE_BUSY` with the sample-origin refusal
    # and sits one line above it, so an ambient NOCTORNAL_LIVE=0 would
    # pass the assertions below for the wrong reason.
    monkeypatch.delenv("NOCTORNAL_LIVE", raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", app)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", sample)
    if this is None:
        monkeypatch.delenv("NOCTORNAL_PUBLIC_ORIGIN", raising=False)
    else:
        monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", this)


def test_a_caller_with_no_session_cookie_is_never_refused_here(monkeypatch):
    """The check fires on the cookie being present, and on nothing else.

    A caller with no cookie must prove itself with a token in the first frame, a credential a page on
    another origin cannot obtain by making a browser connect. Refusing it on its origin would break
    `scripts/bootstrap.py session` (a shell, no cookie jar, no `Origin`) and protect nothing, so a hostile
    origin with no cookie goes through to the token path.
    """
    _configured(monkeypatch)
    assert _cross_site_upgrade(_upgrade(origin="https://evil.example")) is None
    assert _cross_site_upgrade(_upgrade()) is None
    # An EMPTY cookie is not a cookie. It matters that the two agree,
    # because `_handshake` reads the same value with `or`: an empty string
    # falls through to the frame token there, so a check that treated it
    # as present would refuse an upgrade whose credential is the frame.
    assert _cross_site_upgrade(
        _upgrade(cookie="__Host-session=", origin="https://evil.example")) is None


def test_the_consoles_own_upgrade_is_admitted_however_it_is_spelled(monkeypatch):
    """Both sides go through `normalise_origin`, so the comparison is of
    origins and not of strings. A refusal here is not a security failure
    but it is a total outage of the live channel for every analyst, and it
    would arrive as a browser reporting 1006 with the answer only in the
    server log -- so the spellings a browser or a proxy may legitimately
    produce are pinned.
    """
    _configured(monkeypatch)
    for spelling in (APP, APP.upper(), APP + ":443"):
        assert _cross_site_upgrade(
            _upgrade(cookie="__Host-session=abc", origin=spelling)) is None, spelling
    # Among other cookies, in any position: this is a parse, not a prefix
    # match on the header.
    assert _cross_site_upgrade(_upgrade(
        cookie="theme=dark; __Host-session=abc; __Host-csrf=xyz",
        origin=APP)) is None


def test_a_cookie_bearing_upgrade_from_anywhere_else_is_refused(monkeypatch):
    """The attack in one line: a page on any origin may open a socket to this one, the upgrade is not a
    `fetch` so there is no preflight to withhold, and every cookie the browser holds for this host rides
    along.

    Each case below is a way an `Origin` can fail to be ours, and each must fail closed. `null` is the
    opaque origin a sandboxed frame or a redirected navigation sends; a scheme downgrade is a different
    origin; a subdomain is a different host; an `Origin` carrying a path is not an origin at all, which is
    why `allow_path` is passed for our value and never for theirs.
    """
    _configured(monkeypatch)
    for origin in ("https://evil.example",
                   "null",
                   "http://noctornal-console.police.example",
                   "https://x.noctornal-console.police.example",
                   "https://noctornal-console.police.example/live",
                   "https://noctornal-console.police.example:8443",
                   "https://user:pass@noctornal-console.police.example",
                   ""):
        reason = _cross_site_upgrade(
            _upgrade(cookie="__Host-session=abc", origin=origin))
        assert reason is not None, origin
        # OURS, never an echo of theirs. RFC 6455 leaves 123 bytes for a
        # close reason and the caller chooses the length of anything
        # interpolated into it, so an echo is both a disclosure and a way
        # to make this server build a frame it cannot send.
        assert origin == "" or origin not in reason, origin
        assert len(reason.encode("utf-8")) <= _MAX_CLOSE_REASON, (
            origin, len(reason))


def test_an_upgrade_with_no_origin_header_is_deliberately_allowed(monkeypatch):
    """Pinned because it is the one hole, and a hole nobody wrote down gets closed or widened by accident.

    A browser always sends `Origin` on an upgrade and cannot be made to omit it, so its absence means the
    caller is not a browser, and such a caller holds the cookie's value only because it was given it, the
    same string it could put in the first frame. Refusing it would protect nothing and break the token path.
    """
    _configured(monkeypatch)
    assert _cross_site_upgrade(_upgrade(cookie="__Host-session=abc")) is None


def test_a_process_that_cannot_name_its_own_origin_refuses_every_cookie(monkeypatch):
    """Fails closed, the direction a misconfiguration usually gets wrong.

    `NOCTORNAL_BASE_URL` set to something that is not an origin, or to the empty string (which
    `os.environ.get` returns in preference to the default), leaves this process unable to say what "the same
    origin" means. The answer is to refuse, not to skip the check: a comparison against nothing that returned
    None would turn one typo into the silent removal of this control.
    """
    for broken in ("not-an-origin", "", "ftp://console.example",
                   "https://"):
        _configured(monkeypatch, app=broken)
        # No Host either, so there is no arrival origin to fall back on
        # and the process genuinely cannot say what "here" means. With
        # a Host present the second half of the rule answers instead,
        # which is the next case.
        reason = _cross_site_upgrade(
            _upgrade(cookie="__Host-session=abc", origin=APP, host=None))
        assert reason is not None, broken
        assert "no valid origin" in reason, (broken, reason)

        # A broken configuration does NOT switch the check off while a
        # Host is present: an origin matching neither is still refused.
        assert _cross_site_upgrade(_upgrade(
            cookie="__Host-session=abc", origin=FOREIGN,
            host="noctornal-console.police.example")) is not None, broken


def test_the_sample_process_compares_against_the_origin_it_serves(monkeypatch):
    """`public_origin()`, not `app_origin()`, and the difference is only visible here.

    `http/app.py` 404s everything but the download on a process configured as the sample origin, but in an
    `@app.middleware("http")`, which never runs for a `websocket` scope, so `/live` is routable on such a
    process. Comparing against `app_origin()` there would admit an `Origin` naming a host this process does
    not serve and refuse the one it does.

    `live()` refuses that process its socket outright before this predicate is consulted, so the two are
    tested apart: a predicate that is only correct while a check in another function holds goes wrong
    silently the day that check moves.
    """
    _configured(monkeypatch, this=SAMPLE)
    # `host=` is the sample host, so the arrival origin is SAMPLE too
    # and BOTH halves of the rule agree here. Without that the default
    # Host would make the arrival origin the APP's, and this test would
    # be reading the second half while claiming to read the first.
    sample_host = "samples.police.example"
    assert _cross_site_upgrade(_upgrade(
        cookie="__Host-session=abc", origin=APP,
        host=sample_host)) is not None
    assert _cross_site_upgrade(_upgrade(
        cookie="__Host-session=abc", origin=SAMPLE,
        host=sample_host)) is None


def test_the_refusal_is_sent_before_a_pending_slot_is_taken(monkeypatch):
    """Read from the source, because the order is the property and no synthetic scope can show it.

    The call is ahead of `_pending.reserve`, so a cross-site flood cannot spend the budget analysts need on
    its way to being refused: the check reads two headers and one environment variable, which the budget does
    not exist to protect. It is ahead of `accept()` with the other credential-free refusals: a close sent
    after `accept()` leaves the transport up for the backend's ten-second close timeout, so a refusal a
    hostile page can cause at will would be one any visited site could aim at this server.
    """
    src = LIVE_PY.read_text(encoding="utf-8")
    call = src.index("cross_site = _cross_site_upgrade(ws)")
    reserve = src.index("_pending.reserve(ip)")
    accept = src.index("await ws.accept()")
    assert call < reserve < accept, (call, reserve, accept)
    refusal = src[call:reserve]
    assert f"code={_CLOSE_POLICY!s}" in refusal or "code=_CLOSE_POLICY" in refusal, (
        "the cross-site refusal no longer closes with the policy code, which "
        "is the one code the console stops reconnecting on")
    # The caller's origin goes to the LOG, escaped and bounded: it is text
    # the caller chose, and an unescaped newline in a log line forges a
    # second one.
    assert re.search(r"ws\.headers\.get\('origin'\)\s*or\s*''\)\[:\d+\]!r", refusal), (
        "the refused origin is no longer repr-escaped and length-bounded "
        "before it reaches the log")


# --- invariant 10: the sample-origin process opens no socket at all ------

def test_the_sample_origin_process_is_refused_its_socket_before_accept(
        monkeypatch):
    """The process that serves hostile bytes gets no live channel, and is told so before the handshake
    completes.

    Invariant 10: no page carrying an analyst's session ever runs beside the bytes a suspect uploaded.
    `_allowed_on_sample_origin` (`http/app.py`) makes that a property of the process, but it is an
    `@app.middleware("http")`, which Starlette does not run for a `websocket` scope; without this refusal a
    sample-origin process would authenticate the socket against the cookie and stream one case's activity out
    of the one process meant to hold no session at all.

    Driven rather than read, because the order is the property: the whole message stream is one close, with
    no `websocket.accept` in front of it. Under uvicorn's `websockets` backend a pre-accept close is an HTTP
    403 and an immediate `transport.close()`, while a post-accept one holds the transport for ten seconds
    waiting for an echo the peer need never send (`_PendingBudget`).
    """
    _configured(monkeypatch, this=SAMPLE)

    sent = _sent_by_live()
    assert [m["type"] for m in sent] == ["websocket.close"], (
        f"the refusal was not the first and only message; the endpoint sent "
        f"{[m['type'] for m in sent]}")
    assert sent[0]["code"] == _CLOSE_BUSY, sent[0]
    reason = sent[0]["reason"]
    assert "sample origin" in reason, reason
    assert len(reason.encode("utf-8")) <= _MAX_CLOSE_REASON, len(reason)
    # Nothing was reserved on the way out. The check sits with the other
    # configuration refusals, above `_pending.reserve`, so a client that
    # keeps reconnecting to the wrong process cannot fill a budget on it.
    assert module._pending.count == 0

    # A cookie changes nothing: this refusal is about which process this is, never the caller, so it lands
    # identically on the console's own upgrade and a hostile one. Folding it into `_cross_site_upgrade`,
    # which fires only when a cookie is present, would let a socket with no cookie through to the token path
    # on the sample origin.
    for extra in ({"cookie": "__Host-session=abc", "origin": SAMPLE},
                  {"cookie": "__Host-session=abc", "origin": APP},
                  {"origin": "https://evil.example"}):
        again = _sent_by_live(**extra)
        assert [m["type"] for m in again] == ["websocket.close"], extra
        assert (again[0]["code"], again[0]["reason"]) == (
            _CLOSE_BUSY, reason), extra


def test_every_deployment_that_is_not_the_sample_origin_keeps_its_socket(
        monkeypatch):
    """The fail direction, which for this check costs an outage rather than a breach.

    `origin_split()` has five verdicts and only one means "this process serves the bytes". The other four
    are a deployment with no split configured, one whose `NOCTORNAL_SAMPLE_ORIGIN` is not an origin, one
    that names the application origin, and the application process itself, and each still runs the console.
    A check written as "is a sample origin configured" rather than "am I it" would read three of those the
    same way and take the live channel down for every analyst, silently: a pre-accept close reaches a
    browser as 1006 with neither code nor reason.

    Getting past the refusal is the whole assertion, and all this file can watch without a database: with no
    hello frame the socket accepts and then closes "no credentials" one step into `_handshake`.
    """
    from noctornal_api.samples import origin_split
    for role, config in (("unconfigured", {"sample": ""}),
                         ("invalid", {"sample": f"{SAMPLE}/bytes"}),
                         ("same_origin", {"sample": APP}),
                         ("app", {})):
        _configured(monkeypatch, **config)
        assert origin_split().role == role, (role, origin_split().role)
        sent = _sent_by_live()
        assert sent[0]["type"] == "websocket.accept", (role, sent)
    assert module._pending.count == 0


def _asgi(app, scope: dict, inbound: tuple[dict, ...]) -> list[dict]:
    """Hand one assembled app one scope; return every message it sent.

    Called directly rather than through a `TestClient` because the point
    of the test below is which SCOPE TYPE reaches what, and a test client
    that speaks HTTP or WebSocket cannot put both through one object.
    """
    sent: list[dict] = []
    pending = iter(inbound)

    async def receive() -> dict:
        try:
            return next(pending)
        except StopIteration:                  # pragma: no cover - a read
            await asyncio.sleep(3600)          # past the last one is a bug

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=10))
    return sent


def _scope(kind: str, path: str) -> dict:
    """An `http` or a `websocket` scope, identical but for the type.

    `Host` names the console on both, on a process configured as the
    sample origin, because neither gate may read it -- `samples.py`
    records what happened when an origin check was derived from a value
    the caller sends.
    """
    scope = {
        "type": kind, "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "https" if kind == "http" else "wss", "path": path,
        "raw_path": path.encode(), "root_path": "", "query_string": b"",
        "client": ("198.51.100.7", 51234), "server": ("host.invalid", 443),
        "state": {},
        "headers": [(b"host", b"noctornal-console.police.example")],
    }
    scope.update({"method": "GET"} if kind == "http" else {"subprotocols": []})
    return scope


def test_the_http_gate_never_sees_the_upgrade_the_socket_refuses(monkeypatch):
    """Why the check in `live()` is not a duplicate, measured on one assembled app.

    Both scopes go to the same `create_app()` under the same configuration. On the sample-origin process the
    http scope is refused by `_allowed_on_sample_origin`'s 404 and the websocket scope reaches the endpoint
    untouched, because Starlette runs an `@app.middleware("http")` for an `http` scope only. Anyone who
    deletes the socket's check as redundant with that middleware fails the websocket half.

    The two answers are then held to agree across every verdict `origin_split()` produces. An edit that
    gives either file a comparison of its own (against `sample_origin()` alone, or `app_origin()`) makes them
    disagree for at least one of the five deployments, and this names which.

    `/api/v1/no-such-route` deliberately routes nowhere, so every configuration answers 404 and the
    sample-origin refusal is told apart by its detail rather than its status. An unrouted path also touches
    no database.
    """
    from noctornal_api.http.app import create_app
    from noctornal_api.samples import origin_split

    for role, config in (("unconfigured", {"sample": ""}),
                         ("invalid", {"sample": f"{SAMPLE}/bytes"}),
                         ("same_origin", {"sample": APP}),
                         ("app", {}),
                         ("sample", {"this": SAMPLE})):
        _configured(monkeypatch, **config)
        assert origin_split().role == role, (role, origin_split().role)
        app = create_app()

        http = _asgi(app, _scope("http", "/api/v1/no-such-route"),
                     ({"type": "http.request", "body": b"",
                       "more_body": False},))
        body = b"".join(m.get("body", b"") for m in http
                        if m["type"] == "http.response.body").decode()
        gated = "this process is the sample origin" in body

        socket = _asgi(app, _scope("websocket", LIVE),
                       ({"type": "websocket.connect"},
                        {"type": "websocket.disconnect", "code": 1006}))
        refused = (socket[0]["type"] == "websocket.close"
                   and socket[0]["code"] == _CLOSE_BUSY)

        assert gated is refused is (role == "sample"), (
            f"{role}: the http gate {'refused' if gated else 'admitted'} and "
            f"the socket {'refused' if refused else 'admitted'}; the two read "
            f"one verdict, or invariant 10 holds on one transport only")


def test_the_origin_the_request_arrived_on_is_accepted(monkeypatch):
    """The origin the request arrived on is accepted, not only the configured one.

    On the shipped laptop configuration `scripts/launch.ps1` binds `127.0.0.1:8000` and leaves
    `NOCTORNAL_BASE_URL` at its matching default, while the console is opened at `localhost:8000`. Those are
    two origins and no browser treats them as one, so comparing against configuration alone would refuse
    every live socket before `accept()`, which reaches the browser with neither code nor reason.
    """
    _configured(monkeypatch, app="http://127.0.0.1:8000")
    assert _cross_site_upgrade(_upgrade(
        cookie="__Host-session=abc", origin="http://localhost:8000",
        host="localhost:8000", scheme="ws")) is None

    # And the reverse pairing, which is the same deployment approached the
    # other way round.
    _configured(monkeypatch, app="http://localhost:8000")
    assert _cross_site_upgrade(_upgrade(
        cookie="__Host-session=abc", origin="http://127.0.0.1:8000",
        host="127.0.0.1:8000", scheme="ws")) is None


def test_a_foreign_origin_is_refused_even_when_the_host_is_ours(monkeypatch):
    """The attack the whole check exists for, against the new half.

    This is the shape that matters: an attacker's page reaches OUR host,
    so `Host` is ours, and the browser writes the attacker's own origin
    into `Origin`. Script can set neither header on an upgrade, so the two
    cannot be made to agree -- which is exactly why comparing them is a
    real control and not a Host-trust defect.
    """
    _configured(monkeypatch, app=APP)
    for host in ("noctornal-console.police.example", "localhost:8000"):
        assert _cross_site_upgrade(_upgrade(
            cookie="__Host-session=abc", origin=FOREIGN,
            host=host)) is not None, host


def test_a_terminator_forwarding_plain_ws_is_not_refused(monkeypatch):
    """Behind the production Caddy the browser speaks `wss` and uvicorn is
    handed a plain socket, so the scope's own scheme is the wrong thing to
    compare an `https` Origin against. `x-forwarded-proto` is read first
    for that reason -- without it every socket the terminator forwards
    would be refused, which is Wave 1's deployment refusing Wave 2's
    feature."""
    _configured(monkeypatch, app=APP)
    ws = _upgrade(cookie="__Host-session=abc", origin=APP,
                  host="noctornal-console.police.example")
    ws.scope["scheme"] = "ws"
    ws.scope["headers"] = list(ws.scope["headers"]) + [
        (b"x-forwarded-proto", b"https")]
    assert _cross_site_upgrade(WebSocket(ws.scope, ws._receive, ws._send)) is None
