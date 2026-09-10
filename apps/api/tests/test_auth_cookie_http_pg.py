"""The cookie session over HTTP: set as designed, guarded by the CSRF
double-submit, deleted in a form a browser will honour, and reachable from
a bearer hand-off.

`POST /auth/login` has set `__Host-session` (HttpOnly) and `__Host-csrf`
on every success since the CSRF work, and `deps.session_token` has
demanded the `x-csrf-token` header for a cookie-authenticated unsafe
method. Two things were wrong around that, found by the Alpha 4 product
review on 2026-09-09:

- **Logout could not delete the cookies.** `delete_cookie(name, path="/")`
  emits `Max-Age=0` with NO `Secure` attribute, and a browser matches a
  deletion against the cookie's attributes -- a `__Host-` cookie without
  `Secure` is refused outright -- so the revoked token kept being
  presented on every request until the tab closed. The server said 204
  and the browser kept the credential: a failure reported as success.
  The set and the delete now share one attribute declaration
  (`deps.COOKIE_ATTRS`), and one test here reads both headers.

- **Nothing used the cookie.** The console kept the bearer token in
  `sessionStorage`. It now runs on the cookie pair, and the `#token=`
  hand-off from `scripts/bootstrap.py session` is exchanged for the pair
  through `POST /auth/cookie`, which is tested here from the bearer side.

- **The exchange could swap the session under every open tab.** Found by
  the second review pass the same day: `session_token` prefers the bearer,
  so a `#token=` link carrying ANOTHER account's token, opened by a
  signed-in analyst, replaced the browser-wide cookie with that account's
  session while every open tab kept showing the analyst. `adopt_cookie`
  now refuses that with 409 and an audit row; the same account may still
  re-mint its pair (that is how a tab left with the session cookie and no
  readable half recovers).

Since 2026-09-10 the pair is the WHOLE of a successful login: `POST
/auth/login` answers 204 and returns no token in a body, because the two
paths that could not read the cookie -- the live websocket and the
cross-origin Lab download -- now take the cookie and a one-shot ticket
instead. This file is where that is asserted, and it is the reason the
"the cookie IS the token" claim below is now made against `iam.session`
rather than against a second field of the same response.

Cookies are passed as an explicit `cookie` header rather than through the
client's jar: httpx will not send a `Secure` cookie over the test client's
plain-http base URL, and a test that silently sent no cookie would pass
the CSRF check for the wrong reason.

Env-gated on DATABASE_URL. Email prefix `ck-`, unique to this file.
"""
from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; cookie-session e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ck-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ck-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"ck-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Cookie Exemplar", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    return uid, email, secret


def _login(client, email, secret):
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    # 204 since 2026-09-10: the pair IS the response. Asserted on the
    # status alone here and on the body itself below, because a handler
    # that answered 204 and set no cookie would be a login that signed
    # nobody in and said nothing about it.
    assert r.status_code == 204, r.text
    return r


def _set_cookies(r) -> dict[str, tuple[str, dict[str, str | None]]]:
    """name -> (value, {attribute (lower-cased): value or None})."""
    out: dict[str, tuple[str, dict[str, str | None]]] = {}
    for raw in r.headers.get_list("set-cookie"):
        first, *rest = [part.strip() for part in raw.split(";")]
        name, _, value = first.partition("=")
        attrs: dict[str, str | None] = {}
        for part in rest:
            key, has_value, val = part.partition("=")
            attrs[key.strip().lower()] = val.strip() if has_value else None
        out[name.strip()] = (value.strip().strip('"'), attrs)
    return out


def _cookie_header(session: str, csrf: str | None = None) -> str:
    from noctornal_api.http.deps import CSRF_COOKIE, SESSION_COOKIE
    parts = [f"{SESSION_COOKIE}={session}"]
    if csrf is not None:
        parts.append(f"{CSRF_COOKIE}={csrf}")
    return "; ".join(parts)


def test_login_sets_both_host_cookies_as_designed(conn, client):
    """The session cookie is unreadable from script and the CSRF cookie is
    readable on purpose; both carry what the `__Host-` prefix demands
    (Secure, Path=/, no Domain) and SameSite=strict. The cookie IS the
    bearer token -- one session, two transports -- which is what lets the
    console adopt a bearer hand-off as a cookie without a second login.

    "The cookie IS the token" was asserted against the login body until
    2026-09-10, when the body went (Wave 2). The claim did not go with
    it, so it is now asserted against the row: the cookie's value,
    hashed, is the `token_hash` of this analyst's live session. That is
    the stronger reading of the same fact -- the old one only ever proved
    that two halves of one response agreed with each other, and would
    have passed just as well if BOTH had been some other string.
    """
    from noctornal_api.http.deps import CSRF_COOKIE, SESSION_COOKIE
    from noctornal_api.security.tokens import hash_token
    from noctornal_api.stores import PgSessionStore
    uid, email, secret = _make_user(conn)
    r = _login(client, email, secret)
    assert not r.content, f"a 204 login answered with a body: {r.content!r}"
    cookies = _set_cookies(r)
    assert {SESSION_COOKIE, CSRF_COOKIE} <= set(cookies), cookies

    value, attrs = cookies[SESSION_COOKIE]
    record = PgSessionStore(conn).get_by_token_hash(hash_token(value))
    assert record is not None, (
        "the session cookie does not resolve to a session; whatever it "
        "carries, it is not the token this login minted")
    assert record.user_id == uid
    assert "secure" in attrs and "httponly" in attrs
    assert attrs.get("samesite", "").lower() == "strict"
    assert attrs.get("path") == "/"
    assert "domain" not in attrs, "__Host- forbids a Domain attribute"

    value, attrs = cookies[CSRF_COOKIE]
    assert value, "the CSRF cookie is empty"
    assert "secure" in attrs
    assert "httponly" not in attrs, (
        "the CSRF cookie must be readable by the page: it is the half the "
        "script copies into the header")
    assert attrs.get("samesite", "").lower() == "strict"
    assert attrs.get("path") == "/"


def test_a_cookie_session_reads_freely_and_writes_only_with_the_csrf_header(conn, client):
    """The double-submit as a browser would exercise it: the cookie alone
    authenticates a GET; an unsafe method with the cookie and no header is
    refused with 403 and leaves the session alive (a refused CSRF attempt
    must not log the victim out); the header that matches the readable
    cookie lets the same request through."""
    from noctornal_api.http.deps import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
    _, email, secret = _make_user(conn)
    cookies = _set_cookies(_login(client, email, secret))
    session, csrf = cookies[SESSION_COOKIE][0], cookies[CSRF_COOKIE][0]

    r = client.get("/api/v1/auth/me", headers={"cookie": _cookie_header(session, csrf)})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == email

    r = client.post("/api/v1/auth/logout",
                    headers={"cookie": _cookie_header(session, csrf)})
    assert r.status_code == 403, r.text
    assert "CSRF" in r.json()["detail"]
    # Still signed in: the refusal must not be a logout by another name.
    assert client.get("/api/v1/auth/me",
                      headers={"cookie": _cookie_header(session, csrf)}).status_code == 200

    # A header that does not match the cookie is the same refusal.
    r = client.post("/api/v1/auth/logout",
                    headers={"cookie": _cookie_header(session, csrf),
                             CSRF_HEADER: "not-the-cookie"})
    assert r.status_code == 403, r.text

    r = client.post("/api/v1/auth/logout",
                    headers={"cookie": _cookie_header(session, csrf),
                             CSRF_HEADER: csrf})
    assert r.status_code == 204, r.text
    assert client.get("/api/v1/auth/me",
                      headers={"cookie": _cookie_header(session, csrf)}).status_code == 401


def test_logout_deletes_the_cookies_with_the_attributes_they_were_set_with(conn, client):
    """Asserted on the raw Set-Cookie header, both sides at once.

    Before 2026-09-09 logout emitted `__Host-session=""; Max-Age=0;
    Path=/; SameSite=lax` -- no Secure. A browser refuses a `__Host-`
    cookie without Secure and matches a deletion against the attributes
    the cookie was stored with, so the deletion was dropped on the floor
    and the dead token rode along on every later request. The server
    returned 204 either way.
    """
    from noctornal_api.http.deps import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
    _, email, secret = _make_user(conn)
    set_at_login = _set_cookies(_login(client, email, secret))
    session, csrf = set_at_login[SESSION_COOKIE][0], set_at_login[CSRF_COOKIE][0]

    r = client.post("/api/v1/auth/logout",
                    headers={"cookie": _cookie_header(session, csrf),
                             CSRF_HEADER: csrf})
    assert r.status_code == 204, r.text
    cleared = _set_cookies(r)
    assert {SESSION_COOKIE, CSRF_COOKIE} <= set(cleared), (
        f"logout did not clear both cookies: {r.headers.get_list('set-cookie')}")

    for name in (SESSION_COOKIE, CSRF_COOKIE):
        value, attrs = cleared[name]
        assert value == "", (name, value)
        assert attrs.get("max-age") == "0", (name, attrs)
        assert "secure" in attrs, (
            f"the deletion of {name} carries no Secure attribute; a browser "
            f"refuses it and keeps presenting the revoked cookie: "
            f"{r.headers.get_list('set-cookie')}")
        # The attributes a browser matches the deletion against must be
        # the ones the cookie was set with. Read from the login response,
        # not restated here.
        _, as_set = set_at_login[name]
        for attribute in ("path", "samesite", "domain"):
            assert attrs.get(attribute) == as_set.get(attribute), (
                f"{name}: set with {attribute}={as_set.get(attribute)!r}, "
                f"deleted with {attribute}={attrs.get(attribute)!r}")
        assert ("httponly" in attrs) == ("httponly" in as_set), name


def test_a_bearer_session_can_be_adopted_as_the_cookie_pair(conn, client):
    """`scripts/bootstrap.py session` mints a token from a shell and hands
    it to the browser in the URL fragment. The console exchanges it once
    for the cookie pair so the session survives a reload without the token
    ever being written to storage. The cookie set is the SAME session --
    no new row, no second AUTH_SUCCEEDED -- and it then works over both
    transports."""
    from noctornal_api.http.deps import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid, _, _ = _make_user(conn)
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)

    r = client.post("/api/v1/auth/cookie",
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 204, r.text
    cookies = _set_cookies(r)
    assert cookies[SESSION_COOKIE][0] == token
    assert "httponly" in cookies[SESSION_COOKIE][1]
    assert "secure" in cookies[SESSION_COOKIE][1]
    csrf = cookies[CSRF_COOKIE][0]
    assert csrf and "httponly" not in cookies[CSRF_COOKIE][1]

    # The cookie alone now authenticates, as the same session.
    me = client.get("/api/v1/auth/me",
                    headers={"cookie": _cookie_header(token, csrf)})
    assert me.status_code == 200, me.text
    assert me.json()["user_id"] == str(uid)
    rows = conn.execute(
        "SELECT count(*) FROM iam.session WHERE user_id = %s", (uid,)).fetchone()[0]
    assert rows == 1, "adoption minted a second session"

    # And the pair carries a write.
    r = client.post("/api/v1/auth/logout",
                    headers={"cookie": _cookie_header(token, csrf),
                             CSRF_HEADER: csrf})
    assert r.status_code == 204, r.text
    revoked = conn.execute(
        "SELECT revoked_at FROM iam.session WHERE id = %s", (record.id,)).fetchone()
    assert revoked and revoked[0] is not None


def test_adopting_a_cookie_needs_a_live_session(conn, client):
    """A bogus bearer gets the same generic 401 every other endpoint gives
    and sets nothing: the exchange must not be a way to plant a cookie.

    Extended 2026-09-09 with the browser's real situation: a stale
    hand-off link opened in a tab that already holds a live cookie pair.
    The bearer wins in `session_token`, so the 401 judges the BEARER and
    nothing else -- no Set-Cookie, and the cookie session is untouched.
    This pins what the server already did; the defect was on the
    console, which routed that 401 through `endSession` and deleted the
    readable CSRF cookie for a session the server kept
    (`test_ui_invariants` holds the console's 401 exemptions to this
    route).
    """
    from noctornal_api.http.deps import CSRF_COOKIE, SESSION_COOKIE
    r = client.post("/api/v1/auth/cookie",
                    headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401, r.text
    assert not r.headers.get_list("set-cookie")

    _, email, secret = _make_user(conn)
    cookies = _set_cookies(_login(client, email, secret))
    session, csrf = cookies[SESSION_COOKIE][0], cookies[CSRF_COOKIE][0]
    r = client.post("/api/v1/auth/cookie",
                    headers={"Authorization": "Bearer not-a-real-token",
                             "cookie": _cookie_header(session, csrf)})
    assert r.status_code == 401, r.text
    assert not r.headers.get_list("set-cookie"), (
        "a refused bearer must not touch the cookie the browser holds")
    me = client.get("/api/v1/auth/me",
                    headers={"cookie": _cookie_header(session, csrf)})
    assert me.status_code == 200, "the tab's own session was ended by a 401 about a different credential"
    assert me.json()["email"] == email


def test_a_hand_off_cannot_replace_another_accounts_cookie_session(conn, client):
    """Two accounts. The victim is signed in (cookie pair in the browser);
    a link carries the attacker's token in its fragment. Until 2026-09-09
    the exchange returned 204 with `Set-Cookie: __Host-session=<attacker's
    token>`: every tab the victim had open kept rendering the victim,
    `authHeaders()` in each read the fresh CSRF cookie live, and every
    write from them was attributed to the attacker's user_id in the
    hash-chained audit log -- SameSite=Strict does not help, because the
    page's own same-origin fetches carry the cookies after a cross-site
    top-level navigation.

    Now: 409, no Set-Cookie, the victim's session untouched and still the
    victim's, an audit row under the attacker's id naming both sessions,
    and the attacker's own session refused rather than revoked (an
    attacker holding a token must not be able to make the server act on
    it either way). The same account IS allowed, because that is how a
    tab stranded with the session cookie and no readable half recovers
    through its own `bootstrap.py session` link.
    """
    from noctornal_api.http.deps import CSRF_COOKIE, SESSION_COOKIE
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    victim_id, v_email, v_secret = _make_user(conn)
    attacker_id, _, _ = _make_user(conn)
    cookies = _set_cookies(_login(client, v_email, v_secret))
    session, csrf = cookies[SESSION_COOKIE][0], cookies[CSRF_COOKIE][0]
    sessions = SessionService(PgSessionStore(conn))
    attacker_record, attacker_token = sessions.create(
        uuid4(), attacker_id, mfa_satisfied=True)

    r = client.post("/api/v1/auth/cookie",
                    headers={"Authorization": f"Bearer {attacker_token}",
                             "cookie": _cookie_header(session, csrf)})
    assert r.status_code == 409, r.text
    assert not r.headers.get_list("set-cookie"), (
        f"the refusal still set a cookie: {r.headers.get_list('set-cookie')}")

    me = client.get("/api/v1/auth/me",
                    headers={"cookie": _cookie_header(session, csrf)})
    assert me.status_code == 200, me.text
    assert me.json()["user_id"] == str(victim_id)

    row = conn.execute(
        """SELECT actor_id, detail FROM audit.event
            WHERE action = 'AUTH_COOKIE_ADOPT_REFUSED' AND actor_id = %s
            ORDER BY seq DESC LIMIT 1""", (attacker_id,)).fetchone()
    assert row, "the refusal left no audit row"
    assert row[1]["cookie_user_id"] == str(victim_id)
    assert row[1]["bearer_session_id"] == str(attacker_record.id)

    # Refused, not revoked.
    still = client.get("/api/v1/auth/me",
                       headers={"Authorization": f"Bearer {attacker_token}"})
    assert still.status_code == 200 and still.json()["user_id"] == str(attacker_id)

    # The same account, presenting the session cookie WITHOUT its readable
    # half (the stranded tab): a fresh pair for the new token.
    _, own_token = sessions.create(uuid4(), victim_id, mfa_satisfied=True)
    r = client.post("/api/v1/auth/cookie",
                    headers={"Authorization": f"Bearer {own_token}",
                             "cookie": _cookie_header(session)})
    assert r.status_code == 204, r.text
    fresh = _set_cookies(r)
    assert fresh[SESSION_COOKIE][0] == own_token
    assert fresh[CSRF_COOKIE][0]


def test_the_login_audit_names_the_address_the_session_is_bound_to(
        conn, client, monkeypatch):
    """Behind a declared proxy `client_ip` is the address the session is
    bound to (0058) and the limiter meters. Until 2026-09-09 the login
    audit hashed `request.client.host` instead, so AUTH_SUCCEEDED named
    the proxy for every analyst behind it -- a split between what the
    audit said and what the session knew. One address, both places."""
    import hashlib
    import time

    from noctornal_api.security import totp

    monkeypatch.setenv("NOCTORNAL_TRUSTED_PROXY_HOPS", "1")
    uid, email, secret = _make_user(conn)
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))},
        headers={"x-forwarded-for": "203.0.113.77"})
    assert r.status_code == 204, r.text

    rows = conn.execute(
        "SELECT ip_hash FROM audit.event WHERE actor_id = %s "
        "AND action = 'AUTH_SUCCEEDED'", (uid,)).fetchall()
    assert len(rows) == 1
    audited = bytes(rows[0][0])
    bound = conn.execute(
        "SELECT host(ip) FROM iam.session WHERE user_id = %s", (uid,)).fetchone()[0]
    assert bound == "203.0.113.77"
    assert audited == hashlib.sha256(bound.encode()).digest()
    assert audited != hashlib.sha256(b"testclient").digest(), (
        "the audit named the test client's peer address, i.e. the proxy")
