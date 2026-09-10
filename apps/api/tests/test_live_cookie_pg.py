"""The live socket's COOKIE credential, and the origin check that had to
arrive with it.

Until this change `routers/live.py` read no cookie at all: the socket took
a session token from its first frame and nothing else, so the console had
to keep the login-body token in page memory for the life of the tab. That
token is the thing Wave 2 deletes, and it cannot be deleted while the one
credential that survives a reload -- `__Host-session` -- is the one
credential the live channel refuses. A websocket upgrade is an ordinary
HTTP request until the server switches protocols, the browser attaches
cookies to it, and `starlette.websockets.WebSocket` is an
`HTTPConnection`, so `ws.cookies` was readable here the whole time.

Two halves, and the second is not optional:

* **The cookie is preferred, the first frame remains the fallback.** The
  frame is what `scripts/bootstrap.py session` has to use -- it mints
  through `SessionService` in a shell, for a browser it has never met, and
  a shell has no cookie jar. That recovery path is now the only reason the
  hello frame has a token field at all, and these tests hold both paths to
  the same outcomes so removing the wrong one is a visible failure.
* **A cookie-authenticated socket checks `Origin` before `accept()`.** Any
  page on any origin may open a WebSocket to this one: no preflight, no
  CORS answer to withhold, no same-origin rule on the handshake. Before,
  such a socket carried a cookie this file never read and gained nothing
  by it; now it carries one that authenticates, which is
  cross-site WebSocket hijacking with a case's activity stream on the
  other end. `SameSite=strict` stops that from a cross-SITE page, and
  nothing else does: SameSite's unit is the registrable domain, so a page
  on a sibling subdomain is same-site and a compliant browser attaches
  the host-only `__Host-session` to its upgrade. There the origin check
  is the only control, which is why the refusals below are asserted as
  hard as the acceptances.

Three properties these tests pin that a reasonable-looking edit would
break:

1. the refusal is the FIRST message the app sends -- no `websocket.accept`
   in front of it, for the reason `test_live_handshake_pg` documents at
   length (a post-accept close arms uvicorn's ten-second linger);
2. it takes no pending-budget slot, so a hostile page cannot spend the
   budget analysts need by pointing a visitor's browser at this server;
3. the origin it is compared against is CONFIGURATION -- `public_origin()`
   -- and never the request's own `Host`. `samples.py` records what
   happened on 2026-09-09 when an origin check was derived from a header
   the client sends, so one test here sends a lying `Host`.

One refusal that is not about the cookie is tested here too, because a
session is what makes it worth asserting: a process configured as the
SAMPLE ORIGIN opens no socket at all. `_allowed_on_sample_origin`
(`http/app.py`) holds invariant 10 for HTTP from inside an
`@app.middleware("http")`, and Starlette runs no http middleware for a
`websocket` scope, so the check in `live()` is the only copy of that rule
an upgrade ever meets. `test_live_origin` proves the middleware is blind
here without a database; what needs one is the part below -- that a live
analyst session, the very one that reaches "ready" above, buys nothing on
such a process.

Env-gated on DATABASE_URL: the app comes from `create_app()` and every
test mints a session. Email prefix `lck-`, unique to this file.
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import date
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "lck-%@noctornal.test"
LIVE = "/api/v1/live"
# TEST-NET (RFC 5737) and .test hostnames, so a leaked fixture value can
# never be a real peer or a real origin.
PEER = "203.0.113.41"
ORIGIN = "https://console.lck.noctornal.test"
FOREIGN = "https://evil.lck.noctornal.test"
#: The separate origin invariant 10 puts hostile bytes on. A process
#: configured as this one gets no live socket at all, whatever session it
#: is shown.
SAMPLE = "https://samples.lck.noctornal.test"
SESSION_COOKIE = "__Host-session"
STRICT = "NOCTORNAL_SESSION_STRICT_BINDING"
LOGGER = "noctornal.live"
#: RFC 6455 leaves 123 bytes for a close reason (125 in a control frame,
#: less the two-byte code). Asserted below because the obvious "helpful"
#: edit to the refusal -- echoing the Origin the caller sent -- would put
#: a caller-chosen string of any length into that budget.
_MAX_CLOSE_REASON = 123


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        # A session row references its user, so it goes first.
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub}")
    c.close()


@pytest.fixture
def live(monkeypatch):
    """The router module with this process's origin declared, and every
    environment switch that would otherwise decide these tests cleared.

    `NOCTORNAL_PUBLIC_ORIGIN` rather than `NOCTORNAL_BASE_URL`, because
    `public_origin()` is what the check reads and the point of these tests
    is which one that is. `NOCTORNAL_SAMPLE_ORIGIN` is cleared so
    `origin_split()` stays `unconfigured` and this app does not turn into
    the sample process mid-test. Strict binding is off: every session here
    is minted the way `bootstrap.py` mints one, with no address and no
    User-Agent recorded, and strict mode refuses exactly that (correctly --
    `test_session_binding_pg` owns that contract).
    """
    from noctornal_api.http.routers import live as module
    monkeypatch.delenv(STRICT, raising=False)
    monkeypatch.delenv("NOCTORNAL_LIVE", raising=False)
    monkeypatch.delenv("NOCTORNAL_SAMPLE_ORIGIN", raising=False)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", ORIGIN)
    return module


def _app():
    """The real app with the limiter swapped for an in-process one, the
    shape `test_live_pg._app` uses, so two tests do not share a meter."""
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return app


def _client(app):
    """A client whose sockets arrive from `PEER`, opened as a context
    manager so all of them run on one portal (one event loop)."""
    from fastapi.testclient import TestClient
    return TestClient(app, client=(PEER, 40000))


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"lck-{uuid4().hex[:8]}@noctornal.test", "Live cookie", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-LCK-{uuid4().hex[:6]}", title="Live cookie",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification="GREEN", compartments=[])


def _session(conn, user_id):
    """A session minted directly, the way `bootstrap.py session` does:
    unbound, so it is the SAME credential on either transport and the two
    paths are being compared and not two different sessions."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), user_id, mfa_satisfied=True)
    return record, token


def _cookie(token: str, **extra: str) -> dict[str, str]:
    """Upgrade headers carrying the session cookie, as a browser sends it.
    The CSRF cookie is deliberately absent: the double-submit needs a
    request header, a browser cannot set one on an upgrade, and this
    socket therefore does not ask for it -- `SameSite=strict` and the
    origin check are what stand in its place."""
    return {"Cookie": f"{SESSION_COOKIE}={token}", **extra}


def _sent_by(app, headers: dict[str, str]) -> list[dict]:
    """Hand `app` one websocket scope and return every ASGI message it
    sent, in order. The shape `test_live_handshake_pg` uses, and for the
    same reason: a `TestClient` completes the close handshake in process,
    so it cannot tell a refusal sent before `accept()` from one sent
    after, and that difference is what a close costs under uvicorn.
    """
    sent: list[dict] = []
    inbound = iter([{"type": "websocket.connect"},
                    {"type": "websocket.disconnect", "code": 1006}])

    async def receive():
        try:
            return next(inbound)
        except StopIteration:  # pragma: no cover -- reading after the
            await asyncio.sleep(3600)  # disconnect is itself a bug

    async def send(message):
        sent.append(message)

    raw = {"host": "testserver", **{k.lower(): v for k, v in headers.items()}}
    scope = {
        "type": "websocket", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "scheme": "ws", "path": LIVE, "raw_path": LIVE.encode(), "root_path": "",
        "query_string": b"", "client": (PEER, 40000), "subprotocols": [],
        "server": ("testserver", 80), "state": {},
        "headers": [(k.encode(), v.encode()) for k, v in raw.items()],
    }
    asyncio.run(asyncio.wait_for(app(scope, receive, send), timeout=10))
    return sent


# --- the cookie is a credential this socket accepts ----------------------

def test_a_cookie_alone_reaches_ready(conn, live):
    """The point of the change. No token in the hello frame, no
    `Authorization` header, nothing in page memory: the browser's own
    session cookie authenticates the socket, and the case gate downstream
    is untouched -- the cookie value IS a session token, so `_authenticate`
    sees exactly what it always saw.

    The hello frame is still REQUIRED, and still carries the case id;
    what it no longer has to carry is the credential.
    """
    owner = _user(conn)
    case_id = _case(conn, owner)
    _, token = _session(conn, owner)

    with _client(_app()) as client:
        with client.websocket_connect(LIVE, headers=_cookie(token)) as ws:
            ws.send_json({"case_id": str(case_id)})
            ready = ws.receive_json()
    assert ready == {"type": "ready", "case_id": str(case_id)}


def test_the_first_frame_token_still_works_with_no_cookie(conn, live):
    """The fallback, which is the whole reason the frame protocol keeps a
    token field. `scripts/bootstrap.py session` mints in a shell for a
    browser it has never met; a shell has no cookie jar, and this is its
    only way onto the live channel. Deleting the login-body token must not
    delete this."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    _, token = _session(conn, owner)

    with _client(_app()) as client:
        with client.websocket_connect(LIVE) as ws:
            ws.send_json({"token": token, "case_id": str(case_id)})
            ready = ws.receive_json()
    assert ready == {"type": "ready", "case_id": str(case_id)}


def test_the_cookie_wins_when_both_are_sent(conn, live):
    """Order, asserted rather than assumed, because the origin check
    depends on it: that check fires on the cookie being PRESENT, and it is
    only sound to treat presence as use because the cookie is what
    `_handshake` picks. Here the frame carries a token for a DIFFERENT
    user, and the socket comes up as the cookie's."""
    cookie_user, frame_user = _user(conn), _user(conn)
    case_id = _case(conn, cookie_user)
    _, cookie_token = _session(conn, cookie_user)
    _, frame_token = _session(conn, frame_user)

    with _client(_app()) as client:
        with client.websocket_connect(LIVE,
                                      headers=_cookie(cookie_token)) as ws:
            # The frame user is not on this case, so a socket that took
            # the frame token would be refused "no such case" here.
            ws.send_json({"token": frame_token, "case_id": str(case_id)})
            ready = ws.receive_json()
    assert ready == {"type": "ready", "case_id": str(case_id)}


# --- the origin check ----------------------------------------------------

def test_a_matching_origin_is_accepted(conn, live):
    """The console's own upgrade: same origin, cookie attached, and the
    comparison is against `NOCTORNAL_PUBLIC_ORIGIN`, normalised the way
    `samples.normalise_origin` normalises the sample origin and the CSP
    source -- so a default port and a capitalised host are the same
    origin and not a refusal an analyst would report as "live is broken"."""
    owner = _user(conn)
    _, token = _session(conn, owner)

    with _client(_app()) as client:
        for sent in (ORIGIN, ORIGIN.replace("https://", "HTTPS://"),
                     f"{ORIGIN}:443"):
            with client.websocket_connect(
                    LIVE, headers=_cookie(token, Origin=sent)) as ws:
                ws.send_json({})
                assert ws.receive_json()["type"] == "ready", sent


def test_a_foreign_origin_with_a_cookie_is_refused_before_accept(conn, live):
    """Cross-site WebSocket hijacking, refused. The cookie is VALID -- the
    same one that reaches "ready" in the test above -- so what is being
    refused is a live credential presented from a page this server does not
    serve, which is precisely the attack: the browser attaches the cookie,
    the handshake has no preflight to fail, and the socket would otherwise
    stream case activity to script on `evil`.

    Refused BEFORE `accept()`, asserted on the ASGI send stream because
    that is the only place the difference is visible: a `TestClient`
    completes the close handshake itself, while under uvicorn a
    post-accept close writes a frame and then holds the transport for ten
    seconds waiting for an echo the attacker's page need never send. A
    refusal a hostile page can cause is the last one that should linger.

    The lying `Host` header is deliberate: `samples.py` records what
    happened on 2026-09-09 when an origin check was derived from
    `request.url`, which Starlette builds from the header the client sends.
    This check reads configuration, so a caller claiming to be the console
    gets nowhere.
    """
    from starlette.websockets import WebSocketDisconnect
    owner = _user(conn)
    _, token = _session(conn, owner)
    app = _app()

    sent = _sent_by(app, _cookie(token, Origin=FOREIGN,
                                Host="console.lck.noctornal.test"))
    assert [m["type"] for m in sent] == ["websocket.close"], (
        f"the refusal was not the first message; the app sent "
        f"{[m['type'] for m in sent]}")
    assert sent[0]["code"] == 1008, (
        "a cross-site upgrade must close with the policy code the console "
        "stops reconnecting on, not one it backs off and retries on")
    reason = sent[0]["reason"]
    assert reason.startswith("cross-origin upgrade refused")
    # Names OUR origin, so a developer reading it can tell a
    # misconfiguration from an attack; not theirs, which they already have
    # and which would be a caller-chosen string in a 123-byte budget.
    assert ORIGIN in reason and FOREIGN not in reason
    assert len(reason.encode()) <= _MAX_CLOSE_REASON

    # No pending slot was spent. The check sits BEFORE the reservation so
    # that a hostile page cannot exhaust the budget analysts need simply by
    # being visited.
    assert live._pending.count == 0

    # And through a client, the refusal an attacker's page would actually
    # observe: connect, then nothing.
    with _client(app) as client:
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect(
                    LIVE, headers=_cookie(token, Origin=FOREIGN)) as ws:
                ws.receive_json()
    assert refused.value.code == 1008
    assert refused.value.reason == reason


def test_no_origin_at_all_is_allowed_through(conn, live):
    """A browser always sends `Origin` on an upgrade and cannot be made to
    omit it, so a socket without one is not a browser: a shell, a curl, an
    integration test. Refusing it would break the token path this file
    still needs and would protect nothing -- such a caller holds the cookie
    value only because it was handed to it, and that value IS the session
    token it could have put in the first frame instead.

    Asserted next to the refusal it is so easily confused with: the same
    process, the same cookie, one with a foreign `Origin` and one with
    none.
    """
    from starlette.websockets import WebSocketDisconnect
    owner = _user(conn)
    _, token = _session(conn, owner)

    with _client(_app()) as client:
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect(
                    LIVE, headers=_cookie(token, Origin=FOREIGN)) as hostile:
                hostile.receive_json()
        assert refused.value.code == 1008

        with client.websocket_connect(LIVE, headers=_cookie(token)) as ws:
            ws.send_json({})
            assert ws.receive_json()["type"] == "ready"


def test_a_foreign_origin_without_a_cookie_still_reaches_the_token_path(
        conn, live):
    """The check is about the COOKIE, not about the origin on its own. A
    caller that sends no cookie has nothing the browser attached for it, so
    there is nothing to hijack: it presents a token in the frame or it gets
    "no credentials", exactly as before this change. Narrowing the rule
    this way is what keeps a non-browser client with an odd `Origin` --
    an Electron shell, a test harness -- working."""
    owner = _user(conn)
    _, token = _session(conn, owner)

    with _client(_app()) as client:
        with client.websocket_connect(
                LIVE, headers={"Origin": FOREIGN}) as ws:
            ws.send_json({"token": token})
            assert ws.receive_json()["type"] == "ready"


def test_the_refusal_is_logged_with_the_origin_escaped(conn, live, monkeypatch,
                                                       caplog):
    """The security officer chasing a hijack attempt needs the origin that
    tried it, and the log line is the ONLY place it exists: a pre-accept
    refusal reaches the browser as a 403, which carries neither the close
    code nor the reason, so nothing the page sees names anything. Through
    the same sampler as every other pre-accept refusal -- a refusal any
    visited page can cause must not let that page choose the log volume --
    and through `repr` so a header carrying a newline cannot forge a second
    line in it -- a log line naming a caller-chosen string is an injection
    site, and this one is reachable from any page an analyst visits.

    A FRESH sampler, because a refusal written by an earlier test in this
    process would otherwise swallow this one's line.
    """
    monkeypatch.setattr(live, "_refusals", live._SampledWarning())
    owner = _user(conn)
    _, token = _session(conn, owner)
    app = _app()
    injected = FOREIGN + "\nWARNING:noctornal.live:all clear"

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        for _ in range(5):
            _sent_by(app, _cookie(token, Origin=injected))
    lines = [r.getMessage() for r in caplog.records
             if r.name == LOGGER and "refused" in r.getMessage()]
    assert len(lines) == 1, (
        f"{len(lines)} warning lines for 5 refusals; one page chose the "
        f"log volume")
    assert "cross-origin upgrade from" in lines[0]
    assert FOREIGN in lines[0]
    assert "\n" not in lines[0], "the origin was logged unescaped"


def test_the_sample_origin_process_refuses_a_valid_session_its_socket(
        conn, live, monkeypatch):
    """Invariant 10 over the transport the http gate cannot see.

    The credential here is not a near miss: it is the same cookie that
    reaches "ready" at the top of this file, on the same app object, and
    the `Origin` it arrives with is the one this process is configured to
    serve -- so `_cross_site_upgrade` would admit it, and every other
    refusal in `live()` is about a budget rather than about a caller. The
    only thing between that valid session and a subscription is the
    sample-origin check, which is exactly the point: reconfiguring this
    process as the sample origin must take the live channel away from
    everyone, including the analyst whose session it is.

    Why the check has to exist in `live()` at all is the middleware.
    `_allowed_on_sample_origin` (`http/app.py`) 404s everything but the
    download on such a process, but it runs inside an
    `@app.middleware("http")` and Starlette hands a `websocket` scope
    straight to the router -- so before this check, a sample-origin
    process authenticated sockets and streamed a case's changes out of
    the one process that is supposed to hold no session at all.
    `test_live_origin` puts both scopes through one app to show that the
    http gate really is blind here; what this test adds is the part that
    needs a database, which is that a LIVE session buys nothing.

    Refused before `accept()`, on the ASGI stream, for the reason the
    cross-site refusal is: a post-accept close holds the transport for
    uvicorn's ten-second close timeout, and a refusal every misdirected
    client will keep retrying is the last one that should linger.
    """
    from starlette.websockets import WebSocketDisconnect
    owner = _user(conn)
    case_id = _case(conn, owner)
    _, token = _session(conn, owner)
    app = _app()

    # Alive first, on this app, so the refusal below is the configuration
    # and not a fixture that never worked.
    with _client(app) as client:
        with client.websocket_connect(LIVE, headers=_cookie(token)) as ws:
            ws.send_json({"case_id": str(case_id)})
            assert ws.receive_json()["type"] == "ready"

    # The same process, now deployed as the sample origin. `NOCTORNAL_BASE_URL`
    # is pinned as well as the other two: `origin_split()` reads all three,
    # and an ambient application origin that happened to equal SAMPLE would
    # make this "same_origin" -- a different verdict, refusing for a
    # different reason.
    monkeypatch.setenv("NOCTORNAL_BASE_URL", ORIGIN)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLE)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLE)

    sent = _sent_by(app, _cookie(token, Origin=SAMPLE))
    assert [m["type"] for m in sent] == ["websocket.close"], (
        f"the refusal was not the first message; the app sent "
        f"{[m['type'] for m in sent]}")
    assert sent[0]["code"] == 1013, sent[0]
    reason = sent[0]["reason"]
    # The reason is asserted rather than the code alone because 1013 is
    # also what a full hub and the off switch send: it is the reason that
    # says WHICH refusal this was.
    assert "sample origin" in reason, reason
    assert len(reason.encode()) <= _MAX_CLOSE_REASON

    with _client(app) as client:
        with pytest.raises(WebSocketDisconnect) as refused:
            with client.websocket_connect(
                    LIVE, headers=_cookie(token, Origin=SAMPLE)) as ws:
                ws.receive_json()
    assert (refused.value.code, refused.value.reason) == (1013, reason)


# --- the session behind either transport ---------------------------------

def test_a_revoked_session_is_refused_on_either_transport(conn, live):
    """The cookie is a transport for the session token, not a second kind
    of credential, and the point of preferring it is that NOTHING
    downstream changes. So revocation must land on both paths identically:
    same code, same reason, and a reason that is no more specific than an
    unknown case gets -- a close that distinguished "real token, revoked"
    from "no such case" would be the oracle the 401 wording is careful not
    to be.
    """
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    from starlette.websockets import WebSocketDisconnect
    owner = _user(conn)
    case_id = _case(conn, owner)
    record, token = _session(conn, owner)

    with _client(_app()) as client:
        # Alive on both transports first, so the refusals below are the
        # revocation and not a fixture that never worked.
        with client.websocket_connect(LIVE, headers=_cookie(token)) as ws:
            ws.send_json({"case_id": str(case_id)})
            assert ws.receive_json()["type"] == "ready"

        SessionService(PgSessionStore(conn)).revoke(record.id, "test")

        refusals = []
        for headers, hello in ((_cookie(token), {}),
                               ({}, {"token": token})):
            with pytest.raises(WebSocketDisconnect) as refused:
                with client.websocket_connect(LIVE, headers=headers) as ws:
                    ws.send_json({**hello, "case_id": str(case_id)})
                    ws.receive_json()
            refusals.append((refused.value.code, refused.value.reason))
    assert refusals[0] == refusals[1], (
        f"the two transports refuse a revoked session differently: "
        f"{refusals}")
    assert refusals[0][0] == 1008
