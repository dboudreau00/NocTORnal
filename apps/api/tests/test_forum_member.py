"""The authenticated forum path: XenForo and MyBB read as a signed-in
member, through the real adapters, the real pinned client and the egress
contract's stub proxy on loopback (ROADMAP-REMAINING "the authenticated
forum path", docs/16 L3, 2026-10-02).

Each test stands up a loopback forum that imitates the platform's sign-in
form, its session cookie, its member-only pages and its failure modes
(a wrong password, a CAPTCHA, a second factor, a sign-in that wants
JavaScript, a forced password change, a session the board ends mid-run, a
hostile sign-in page), and polls it through `run_once` with the shipped
member adapter: every request leaves through the contract stub as the
persona's run, the credential is posted once and never stored, the
session is sealed in the vault's storage and reused, the posts land as
MEMBER documents naming the persona and the authority, and a sign-out on
stop clears the session. The read is refused without a MEMBER_READ
authority, and the module posts nothing but the two forms.

DATABASE_URL-gated. Nothing contacts a forum: the stub proxy dials the
loopback server by number, and the socket guard refuses anything else.
"""
from __future__ import annotations

import dataclasses
import http.server
import inspect
import os
import re
import socketserver
import threading
import urllib.parse
from uuid import UUID, uuid4

import pytest
from psycopg.types.json import Jsonb

import collection_helpers as h
import forum_helpers as fh
from egress_contract_cases import StubHarness, StubProxy

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-fmbr-"
PASSWORD = "correct-horse-battery-staple-91"
XF_TOKEN = "1789139000,9f0e3c1b2a7d6e5f4a3b2c1d0e9f8a7b"
MB_KEY = "3b4c5d6e7f8091a2b3c4d5e6f7081920"
# Onion names: a member read signs the persona in over https or to an onion
# address only (g40 verify major 6, 2026-10-03), and this loopback board
# speaks plain http through the stub proxy, which is exactly what an onion
# hop is. The board's pages still name their canonical https origin.
XF_HOST = "xfboardtest.onion"
MB_HOST = "mbforumtest.onion"

MYBB_LOGIN = """<!DOCTYPE html><html><head><title>Login</title></head><body>
<div id="container"><div id="content">{error}
<form action="member.php" method="post">
<input type="hidden" name="action" value="do_login" />
<input type="hidden" name="url" value="" />
<input type="hidden" name="my_post_key" value="{key}" />
<input type="text" name="username" /><input type="password" name="password" />
</form>{extra}</div></div></body></html>"""
XF_2FA = ('<!DOCTYPE html><html id="XF" data-template="login_2fa" data-logged-in="false">'
          '<body data-template="login_2fa"><form action="/login/two-step" method="post">'
          'Enter the code from your authenticator app<input type="text" name="code" />'
          '<input type="hidden" name="_xfToken" value="x" /></form></body></html>')
XF_PASSWORD_CHANGE = ('<!DOCTYPE html><html id="XF" data-logged-in="false">'
                      '<body><div class="blockMessage">You must change your '
                      'password before continuing.</div><form action="/account/'
                      'security" method="post"><input type="password" name="password" />'
                      '</form></body></html>')
XF_JS = ('<!DOCTYPE html><html id="XF" data-logged-in="false"><body>'
         '<div class="blockMessage">Please enable JavaScript to sign in.</div>'
         '</body></html>')
XF_CAPTCHA_FORM = ('<form action="/login/login" method="post">'
                   '<input type="text" name="login" /><input type="password" name="password" />'
                   '<div class="g-recaptcha" data-sitekey="6Ld"></div>'
                   '<input type="hidden" name="_xfToken" value="' + XF_TOKEN + '" /></form>')


class MemberForum(http.server.HTTPServer):
    """A loopback board. `platform` is xenforo or mybb; `mode` scripts the
    failure (ok, wrong_password, captcha, two_factor, js, password_change,
    hostile); `expire_after` ends a session after that many member reads."""

    def __init__(self, platform: str, *, handle: str, mode: str = "ok",
                 expire_after: int | None = None):
        self.platform = platform
        self.handle = handle
        self.mode = mode
        self.expire_after = expire_after
        self.sessions: dict[str, int] = {}
        self.logins = 0
        self.logouts = 0
        self.posts: list[tuple[str, dict]] = []
        self.seen: list[tuple[str, str, bool]] = []
        super().__init__(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def close(self) -> None:
        self.shutdown()
        self.server_close()

    @property
    def host(self) -> str:
        return XF_HOST if self.platform == "xenforo" else MB_HOST

    @property
    def base_url(self) -> str:
        if self.platform == "xenforo":
            return f"http://{self.host}:{self.server_port}/threads/wts-fresh-dumps.1234/"
        return f"http://{self.host}:{self.server_port}/community/showthread.php?tid=12"


def _member_page(platform: str, name: str) -> bytes:
    body = fh.page(name)
    if platform == "xenforo":
        return body.replace(b'data-logged-in="false"', b'data-logged-in="true"').replace(
            b"p-navgroup--guest", b"p-navgroup--member")
    return body.replace(
        b"<div id=\"content\">",
        b"<div id=\"content\"><a href=\"member.php?action=logout&amp;logoutkey="
        + MB_KEY.encode() + b"\">Log out</a>", 1)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _cookie(self) -> str | None:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name in ("xf_session", "mybbuser"):
                return value
        return None

    def _signed_in(self) -> bool:
        value = self._cookie()
        if value is None or value not in self.server.sessions:
            return False
        if self.server.expire_after is not None:
            self.server.sessions[value] += 1
            if self.server.sessions[value] > self.server.expire_after:
                del self.server.sessions[value]
                return False
        return True

    def _send(self, status: int, body: bytes, *, headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _login_page(self, *, error: bool = False) -> bytes:
        s = self.server
        if s.platform == "xenforo":
            # The saved page names the board's canonical https origin; this
            # board answers on a loopback port, so its form posts there.
            body = fh.page("xenforo/login.html").replace(
                b'action="https://board.example.test/login/login"', b'action="/login/login"')
            if s.mode == "captcha":
                body = re.sub(rb"<form action=\"/login/login\".*?</form>",
                              XF_CAPTCHA_FORM.encode(), body, count=1, flags=re.S)
            elif s.mode == "js":
                body = XF_JS.encode()
            elif s.mode == "hostile":
                body = b"<html><body>" + b"<form><input type='text' name='x' /></form>" * 8000 \
                    + b"</body></html>"
            elif s.mode == "popup_only":
                body = (b"<html><body><div class='modal'><form action='/login/login' "
                        b"method='post'><input type='password' name='password' /></form>"
                        b"</div></body></html>")
            return body
        extra = ""
        if s.mode == "captcha":
            extra = '<div class="h-captcha" data-sitekey="x"></div>'
        if s.mode == "js":
            return XF_JS.encode()
        return MYBB_LOGIN.format(
            error='<div class="error">You have entered an invalid username/password '
                  'combination.</div>' if error else "",
            key=MB_KEY, extra=extra).encode()

    def _issue(self) -> str:
        token = f"S{self.server.logins}-{uuid4().hex[:12]}"
        self.server.sessions[token] = 0
        return token

    def do_GET(self):  # noqa: N802 - the stdlib's naming
        s = self.server
        path = urllib.parse.urlsplit(self.path)
        signed = self._signed_in()
        s.seen.append(("GET", self.path, self._cookie() is not None))
        if s.platform == "xenforo":
            if path.path == "/login/":
                return self._send(200, self._login_page())
            pages = {"/threads/wts-fresh-dumps.1234/": "xenforo/thread_page1.html",
                     "/threads/wts-fresh-dumps.1234/page-2": "xenforo/thread_page2.html",
                     "/threads/wts-fresh-dumps.1234/page-3": "xenforo/thread_page3.html"}
            if path.path in pages:
                if not signed:
                    return self._send(403, self._login_page())
                return self._send(200, _member_page("xenforo", pages[path.path]))
            return self._send(404, b"<html><body>Not found</body></html>")
        query = urllib.parse.parse_qs(path.query)
        if path.path == "/community/member.php":
            if query.get("action") == ["login"]:
                return self._send(200, self._login_page())
            if query.get("action") == ["logout"]:
                if query.get("logoutkey") == [MB_KEY] and self._cookie() in s.sessions:
                    del s.sessions[self._cookie()]
                    s.logouts += 1
                return self._send(302, b"", headers={"Location": "/community/index.php"})
        if path.path == "/community/showthread.php" and query.get("tid") == ["12"]:
            if not signed:
                return self._send(403, self._login_page())
            name = ("mybb/showthread_page2.html" if query.get("page") == ["2"]
                    else "mybb/showthread_linear.html")
            return self._send(200, _member_page("mybb", name))
        return self._send(404, b"<html><body>Not found</body></html>")

    def do_POST(self):  # noqa: N802 - the stdlib's naming
        s = self.server
        length = int(self.headers.get("Content-Length") or 0)
        fields = {k: v[0] for k, v in urllib.parse.parse_qs(
            self.rfile.read(length).decode("utf-8")).items()}
        path = urllib.parse.urlsplit(self.path).path
        s.posts.append((path, fields))
        s.seen.append(("POST", self.path, self._cookie() is not None))
        if s.platform == "xenforo":
            if path == "/logout/":
                if fields.get("_xfToken") == XF_TOKEN and self._cookie() in s.sessions:
                    del s.sessions[self._cookie()]
                    s.logouts += 1
                return self._send(303, b"", headers={"Location": "/"})
            if path != "/login/login":
                return self._send(404, b"")
            ok = (fields.get("login") == s.handle and fields.get("password") == PASSWORD
                  and fields.get("_xfToken") == XF_TOKEN and s.mode != "wrong_password")
            if s.mode == "two_factor" and ok:
                return self._send(200, XF_2FA.encode())
            if s.mode == "password_change" and ok:
                return self._send(200, XF_PASSWORD_CHANGE.encode())
            if not ok:
                return self._send(200, self._login_page(error=True))
            s.logins += 1
            token = self._issue()
            return self._send(303, b"", headers={
                "Location": "/threads/wts-fresh-dumps.1234/",
                "Set-Cookie": f"xf_session={token}; path=/; HttpOnly"})
        if path != "/community/member.php" or fields.get("action") != "do_login":
            return self._send(404, b"")
        ok = (fields.get("username") == s.handle and fields.get("password") == PASSWORD
              and fields.get("my_post_key") == MB_KEY and s.mode != "wrong_password")
        if not ok:
            return self._send(200, self._login_page(error=True))
        s.logins += 1
        token = self._issue()
        return self._send(302, b"", headers={
            "Location": "/community/showthread.php?tid=12&mode=linear",
            "Set-Cookie": f"mybbuser={token}; path=/; HttpOnly"})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.delenv("NOCTORNAL_FORUM_ALLOW_DIRECT", raising=False)
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def stub(monkeypatch):
    """The egress contract's stub proxy, and every persona route of this
    test built on it: the pinned client speaks CONNECT to it, it dials the
    loopback board by number, and it records who the connection was."""
    from noctornal_api import collection, egress

    with StubProxy() as proxy:
        harness = StubHarness(proxy)
        monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{proxy.port}")

        def onion_route(profile, context):
            # The persona's exit reaches onion services (a Tor exit does):
            # the boards of this test are named as onion hosts.
            route = harness.route("persona", str(profile), context=context)
            return dataclasses.replace(
                route, policy=dataclasses.replace(route.policy, onion=True))

        def for_source(conn, source, persona, *, adapter, run_id):
            return onion_route(persona["egress_profile_id"], f"run:{run_id}")

        def for_persona(conn, persona, *, context):
            return onion_route(persona["egress_profile_id"], context)

        monkeypatch.setattr(collection, "_route_for_source", for_source)
        monkeypatch.setattr(collection, "_route_for_persona", for_persona)
        yield harness


def registry():
    from noctornal_api.collection import RssAdapter
    from noctornal_api.forum_adapters import parse_in_process
    from noctornal_api.forum_member import MyBBMemberAdapter, XenForoMemberAdapter

    kw = {"parse": parse_in_process, "sleep": lambda _s: None}
    return {"rss": RssAdapter(), "xenforo_member": XenForoMemberAdapter(**kw),
            "mybb_member": MyBBMemberAdapter(**kw)}


def _world(conn, stub, platform: str, *, mode="ok", expire_after=None,
           scope="MEMBER_READ", board_class=None):
    """Two people, a persona on its own exit with a credential and a
    browser identity, a board, a source bound to the persona, and a
    confirmed authority over it."""
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    egress = h.egress_profile(conn, P)
    persona = h.persona(conn, P, platform=platform.upper(), egress=egress,
                        secret=PASSWORD,
                        fingerprint={"user_agent": "Mozilla/5.0 (member test)"})
    handle = conn.execute("SELECT handle FROM collect.collection_account WHERE id = %s",
                          (persona,)).fetchone()[0]
    board = (board_class or MemberForum)(platform, handle=handle, mode=mode,
                                         expire_after=expire_after)
    stub.origin(board.host, board.server_port)
    source = h.source(conn, P, kind=platform.upper(), parser=f"{platform}_member",
                      base_url=board.base_url, persona=persona)
    if platform == "mybb":
        conn.execute("UPDATE collect.source SET parser_config = %s WHERE id = %s",
                     (Jsonb(dict(fh.MB_CONFIG)), source))
    view = h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=persona,
                       source_ids=[source], scope=scope,
                       member_ref="MEMBER-ACCESS-2026-0042" if scope == "MEMBER_READ" else None,
                       adapters=registry())
    return {"recorder": recorder, "confirmer": confirmer, "egress": egress,
            "persona": persona, "handle": handle, "board": board, "source": source,
            "authority": UUID(view["id"])}


def _svc(conn):
    from noctornal_api.collection import CollectionService
    from noctornal_api.rawstore import InMemoryDocumentRawStorage
    return CollectionService(conn, registry(), raw_store=InMemoryDocumentRawStorage(),
                             sleep=lambda _s: None)


def _run(conn, run_id):
    return conn.execute(
        """SELECT status::text, error_class, error_detail, authority_id,
                  collection_account_id, requests, notes
             FROM collect.collection_run WHERE id = %s""", (run_id,)).fetchone()


def _side_rows(conn, source):
    return conn.execute(
        """SELECT d.external_id, fp.provenance, fp.collection_account_id, fp.authority_id
             FROM collect.document d JOIN collect.forum_post fp ON fp.document_id = d.id
            WHERE d.source_id = %s ORDER BY d.external_id""", (source,)).fetchall()


def _session_row(conn, persona):
    return conn.execute(
        """SELECT session_ciphertext IS NOT NULL, session_key_id, session_sealed_at
             FROM collect.collection_account WHERE id = %s""", (persona,)).fetchone()


# ---------------------------------------------------------------------------
# The member read, end to end
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("platform", ["xenforo", "mybb"])
def test_a_member_read_signs_in_once_reads_the_members_pages_and_seals_the_session(
        conn, stub, platform):
    w = _world(conn, stub, platform)
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "OK", run
        assert run[3] == w["authority"] and run[4] == w["persona"]
        # The posts are MEMBER documents naming the persona and the authority.
        rows = _side_rows(conn, w["source"])
        assert rows and all(r[1] == "MEMBER" and r[2] == w["persona"]
                            and r[3] == w["authority"] for r in rows)
        # Every request left as the persona's run, through the stub.
        connects = [r for r in stub.records if r["protocol"] == "CONNECT"]
        assert connects, "nothing went through the proxy"
        assert all(r["username"] == f"persona.{w['egress']}~run.{result.run_id}"
                   for r in connects)
        assert all(r["target"] == f"{board.host}:{board.server_port}" for r in connects)
        # The credential was posted exactly once, to the board's own form,
        # as the persona, and no page was read as a guest afterwards.
        assert board.logins == 1
        posted = [p for p in board.posts if p[1].get("password")]
        assert len(posted) == 1 and posted[0][1]["password"] == PASSWORD
        assert all(cookie for method, _path, cookie in board.seen
                   if method == "GET" and "login" not in _path)
        # Nothing of the credential or the session reached the run row.
        text = " ".join(str(x) for x in run)
        assert PASSWORD not in text
        assert all(v not in text for v in board.sessions)
        assert "password" not in str(run[5]), "the custody log never carries a form"
        # The session is sealed beside the credential.
        sealed, key_id, at = _session_row(conn, w["persona"])
        assert sealed and key_id and at is not None
        # A second poll reads as the member without signing in again.
        again = _svc(conn).run_once(w["source"], actor_id=None)
        assert again.status == "OK", _run(conn, again.run_id)
        assert board.logins == 1
    finally:
        board.close()


def test_a_member_read_is_refused_without_a_member_scope_and_touches_nothing(conn, stub):
    w = _world(conn, stub, "xenforo", scope="PUBLIC_READ")
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "BLOCKED" and run[1] == "AuthorityMissing"
        assert "read as a member" in run[2] and "public only" in run[2]
        assert board.seen == [] and stub.records == []
        assert _side_rows(conn, w["source"]) == []
        # The scope is held in the code, not only in the data: a confirmed
        # authority cannot be MEMBER_READ without its member-access reference.
        import psycopg
        with pytest.raises((psycopg.errors.CheckViolation, psycopg.errors.RaiseException)):
            with conn.transaction():
                conn.execute("UPDATE collect.collection_authority SET scope = 'MEMBER_READ' "
                             "WHERE id = %s", (w["authority"],))
    finally:
        board.close()


def test_a_refused_credential_locks_the_persona_and_stores_nothing(conn, stub):
    w = _world(conn, stub, "xenforo", mode="wrong_password")
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "BLOCKED" and run[1] == "PersonaSuspended"
        assert "did not accept this persona's sign-in" in run[2]
        assert PASSWORD not in run[2] and "[REDACTED]" not in run[2]
        lock = conn.execute("SELECT machine_lock_code FROM collect.collection_account "
                            "WHERE id = %s", (w["persona"],)).fetchone()[0]
        assert lock == "CREDENTIAL_REVOKED"
        assert _side_rows(conn, w["source"]) == []
        assert _session_row(conn, w["persona"])[0] is False
    finally:
        board.close()


@pytest.mark.parametrize("mode, words", [
    ("captcha", "CAPTCHA or a bot challenge"),
    ("two_factor", "second factor"),
    ("js", "wants JavaScript"),
    ("password_change", "demands a change"),
    ("hostile", "no form this adapter can fill in"),
    ("popup_only", "no form this adapter can fill in"),
])
def test_what_the_board_asks_for_at_sign_in_is_refused_by_name(conn, stub, mode, words):
    w = _world(conn, stub, "xenforo", mode=mode)
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "BLOCKED", run
        assert words in run[2], run[2]
        assert "nothing was read" in run[2]
        # A CAPTCHA, a form that is not one, or a page that wants JavaScript
        # is never answered: no form is posted at all.
        if mode in ("captcha", "js", "hostile", "popup_only"):
            assert board.posts == []
        assert _side_rows(conn, w["source"]) == []
    finally:
        board.close()


@pytest.mark.parametrize("platform", ["xenforo", "mybb"])
def test_a_captcha_on_the_mybb_and_xenforo_pages_is_never_solved(conn, stub, platform):
    w = _world(conn, stub, platform, mode="captcha")
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        assert result.status == "BLOCKED"
        assert board.posts == []
    finally:
        board.close()


def test_a_session_the_board_ends_mid_run_is_signed_in_again_once(conn, stub):
    w = _world(conn, stub, "xenforo", expire_after=3)
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "OK", run
        assert board.logins == 2, "signed in once more when the session ended"
        assert len(_side_rows(conn, w["source"])) >= 3
    finally:
        board.close()


def test_a_session_the_board_keeps_ending_stops_the_run_where_it_was(conn, stub):
    w = _world(conn, stub, "xenforo", expire_after=1)
    board = w["board"]
    try:
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "FAILED" and run[1] == "LoginWall", run
        assert "signed the persona out" in run[2]
        assert board.logins == 2, "once more, and never a third time"
    finally:
        board.close()


@pytest.mark.parametrize("platform", ["xenforo", "mybb"])
def test_a_stop_signs_the_persona_out_through_its_route_and_clears_the_session(
        conn, stub, platform):
    from noctornal_api.forum_member import sign_out_persona

    w = _world(conn, stub, platform)
    board = w["board"]
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert _session_row(conn, w["persona"])[0] is True
        before = len(stub.records)
        out = sign_out_persona(conn, w["persona"], actor_id=w["recorder"],
                               clearance="RED")
        assert out["cleared"] is True
        assert out["signed_out"] and out["signed_out"][0]["reached"] is True
        assert board.logouts == 1 and board.sessions == {}
        assert _session_row(conn, w["persona"]) == (False, None, None)
        stops = [r for r in stub.records[before:] if r["protocol"] == "CONNECT"]
        assert stops and all(r["username"] == f"persona.{w['egress']}~stop.{w['persona']}"
                             for r in stops)
        audited = conn.execute(
            "SELECT detail FROM audit.event WHERE action = 'PERSONA_FORUM_SIGNED_OUT' "
            "AND object_id = %s", (w["persona"],)).fetchone()
        assert audited and audited[0]["cleared"] is True
        # A second stop with no session finds nothing to do and still records.
        again = sign_out_persona(conn, w["persona"], actor_id=w["recorder"],
                                 clearance="RED")
        assert again["signed_out"] == [] and board.logouts == 1
    finally:
        board.close()


def test_a_sign_out_that_fails_with_the_cookie_in_its_error_does_not_audit_it(
        conn, stub, monkeypatch):
    """The failed sign-out's note is written to the audit log, which no label
    gates, after the scope that made the jar's cookies live has ended: an
    error that quotes a cookie (a redirect to a URL carrying it) was audited
    as it stood (beta 1 gate 6, 2026-10-07)."""
    from noctornal_api import forum_member, forum_session
    from noctornal_api.collection import CollectionError

    w = _world(conn, stub, "xenforo")
    board = w["board"]
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        jars = forum_session.open_sessions(conn, w["persona"])
        cookies = [v for jar in jars.values() for v in jar.values() if len(v) >= 6]
        assert cookies

        def refusing(self):
            raise CollectionError(f"redirect to https://elsewhere.example/?s={cookies[0]} "
                                  f"was refused")

        monkeypatch.setattr(forum_member.MemberSession, "sign_out", refusing)
        out = forum_member.sign_out_persona(conn, w["persona"], actor_id=w["recorder"],
                                            clearance="RED")
        assert out["notes"] and out["cleared"] is True
        audited = conn.execute(
            "SELECT detail::text FROM audit.event WHERE action = 'PERSONA_FORUM_SIGNED_OUT' "
            "AND object_id = %s", (w["persona"],)).fetchone()[0]
        assert "was refused" in audited
        assert all(c not in audited for c in cookies)
    finally:
        board.close()


def test_the_forum_detail_route_says_the_post_was_read_as_a_member(conn, stub):
    from noctornal_api.forum_adapters import forum_details

    w = _world(conn, stub, "xenforo")
    board = w["board"]
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        doc = conn.execute("SELECT id FROM collect.document WHERE source_id = %s LIMIT 1",
                           (w["source"],)).fetchone()[0]
        detail = forum_details(conn, doc, clearance="RED")
        assert detail["provenance"] == "MEMBER"
        assert detail["persona_id"] == str(w["persona"])
        assert detail["authority_id"] == str(w["authority"])
    finally:
        board.close()


# ---------------------------------------------------------------------------
# What the module may never do
# ---------------------------------------------------------------------------

def test_the_module_posts_the_sign_in_and_sign_out_forms_and_nothing_else():
    import ast

    from noctornal_api import forum_member, forum_parse

    source = inspect.getsource(forum_member)
    posts = [m.start() for m in re.finditer(r'method="POST"', source)]
    assert len(posts) == 2, "exactly the sign-in POST and XenForo's sign-out POST"
    for at in posts:
        head = source[:at]
        owner = re.findall(r"\n    def (\w+)\(", head)[-1]
        assert owner in ("sign_in", "sign_out"), owner
    # No string the module could send names a page that posts, replies,
    # reacts, messages, joins or buys (the prose above may name them).
    literals = [n.value for n in ast.walk(ast.parse(source))
                if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for forbidden in ("add-reply", "/react", "conversations", "post-reply", "newreply",
                      "purchase", "private.php", "sendmessage", "/join", "cart"):
        assert not any(forbidden in lit.lower() for lit in literals), forbidden
    # The URL builders know a thread, a board, a member, the sign-in and the
    # sign-out, and no other page.
    builders = [n for n in dir(forum_parse)
                if n.endswith("_url") and not n.startswith("_")]
    # login_url is the wall detector (a predicate), not a builder.
    assert sorted(builders) == ["board_page_url", "login_page_url", "login_url",
                                "logout_url", "member_page_url", "post_url",
                                "thread_page_url"]


def test_every_refusal_sentence_survives_the_credential_redactor():
    from noctornal_api import forum_member
    from noctornal_api.pinned_http import redact

    from noctornal_api import forum_adapters

    # The module's own sentences: not the public adapter's, which it
    # imports and which are held by their own suite.
    sentences = {name: getattr(forum_member, name) for name in dir(forum_member)
                 if name.isupper() and isinstance(getattr(forum_member, name), str)
                 and name not in ("PROVENANCE_MEMBER", "PROVENANCE_PUBLIC",
                                  "FORM_CONTENT_TYPE")
                 and getattr(forum_adapters, name, None) != getattr(forum_member, name)}
    assert len(sentences) >= 12
    for name, text in sentences.items():
        assert redact(text) == text, (name, redact(text))
        assert "\u2014" not in text and "\u2013" not in text and " -- " not in text
        assert "(s)" not in text


def test_the_member_adapters_are_registered_and_ask_for_the_member_scope():
    from noctornal_api.collection import default_adapters
    from noctornal_api.collection_authority import MEMBER_READ

    adapters = default_adapters()
    for key, platform in (("xenforo_member", "XENFORO"), ("mybb_member", "MYBB")):
        a = adapters[key]
        assert a.requires_authority and a.persona_platform == platform
        assert a.persona_http is True
        assert a.authority_need(None) == MEMBER_READ
        assert a.validate_persona({}) and not a.validate_persona(
            {"user_agent": "Mozilla/5.0"})


# ---------------------------------------------------------------------------
# g40 verify round, 2026-10-03: whose session is whose, and what a stop clears
# ---------------------------------------------------------------------------

class _OtherBoard(MemberForum):
    """A second board, on another host, read by the SAME persona."""

    host = property(lambda self: "other-board-test.onion")


class _ClearnetBoard(MemberForum):
    """A board whose address is plain http to an ordinary host name."""

    host = property(lambda self: "board.example.test")


def _second_board(conn, stub, w):
    board = _OtherBoard("xenforo", handle=w["handle"])
    stub.origin(board.host, board.server_port)
    source = h.source(conn, P, kind="XENFORO", parser="xenforo_member",
                      base_url=board.base_url, persona=w["persona"])
    h.authority(conn, recorder=w["recorder"], confirmer=w["confirmer"],
                persona_id=w["persona"], source_ids=[source], scope="MEMBER_READ",
                member_ref="MEMBER-ACCESS-2026-0043", adapters=registry())
    return board, source


def test_a_persona_with_two_boards_never_sends_one_boards_session_to_the_other(
        conn, stub):
    """Blocker 2: the jar was keyed by persona alone, so the first board's
    live session went to the second board's operator."""
    from noctornal_api import forum_session

    w = _world(conn, stub, "xenforo")
    board_a = w["board"]
    board_b, source_b = _second_board(conn, stub, w)
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        a_session = next(iter(board_a.sessions))
        second = _svc(conn).run_once(source_b, actor_id=None)
        assert second.status == "OK", _run(conn, second.run_id)
        # Board B's first request carried no cookie at all, and none of its
        # requests carried board A's value.
        assert board_b.seen[0][2] is False, "board A's session reached board B"
        assert a_session not in board_b.sessions
        # Each board holds its own session, sealed under its own origin.
        origin_a = forum_session.origin_key(board_a.base_url)
        origin_b = forum_session.origin_key(board_b.base_url)
        assert origin_a != origin_b
        jars = forum_session.open_sessions(conn, w["persona"])
        assert set(jars) == {origin_a, origin_b}
        assert jars[origin_a]["xf_session"] == a_session
        assert jars[origin_b]["xf_session"] == next(iter(board_b.sessions))
        assert jars[origin_a]["xf_session"] != jars[origin_b]["xf_session"]
        # A later poll of each reads with its own and signs in no more.
        logins = (board_a.logins, board_b.logins)
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert _svc(conn).run_once(source_b, actor_id=None).status == "OK"
        assert (board_a.logins, board_b.logins) == logins
        assert forum_session.open_session(conn, w["persona"], origin_b) == jars[origin_b]
        assert forum_session.open_session(conn, w["persona"], "https://nowhere:443") == {}
        # A stop signs out of each board with that board's own cookies.
        from noctornal_api.forum_member import sign_out_persona
        out = sign_out_persona(conn, w["persona"], actor_id=w["recorder"],
                               clearance="RED")
        assert len(out["signed_out"]) == 2 and out["cleared"] is True
        assert board_a.logouts == 1 and board_b.logouts == 1
        assert board_a.sessions == {} and board_b.sessions == {}
    finally:
        board_a.close()
        board_b.close()


def test_a_sealed_session_in_the_earlier_one_jar_shape_is_discarded(conn, stub):
    """A blob keyed by persona alone cannot be attributed to a board, so it
    is signed in again rather than carried to whichever board asks."""
    import json

    from noctornal_api import forum_session
    from noctornal_api.security import envelope

    w = _world(conn, stub, "xenforo")
    try:
        blob, key_id = envelope.encrypt(json.dumps({"xf_session": "S9-flat"}))
        conn.execute(
            """UPDATE collect.collection_account
                  SET session_ciphertext = %s, session_key_id = %s,
                      session_sealed_at = now() WHERE id = %s""",
            (blob, key_id, w["persona"]))
        origin = forum_session.origin_key(w["board"].base_url)
        assert forum_session.open_session(conn, w["persona"], origin) == {}
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert w["board"].logins == 1 and "S9-flat" not in str(w["board"].seen)
    finally:
        w["board"].close()


@pytest.mark.parametrize("how", ["destroy", "burn", "lock", "machine_lock"])
def test_every_stop_of_a_persona_clears_its_sealed_session(conn, stub, how):
    """Major 1: a destroyed credential and a burn left the session sealed."""
    from noctornal_api.collection import PersonaVault

    w = _world(conn, stub, "xenforo")
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert _session_row(conn, w["persona"])[0] is True
        vault = PersonaVault(conn)
        if how == "destroy":
            vault.destroy_secret(w["persona"], actor_id=None, reason="stopping")
        elif how == "burn":
            vault.set_status(w["persona"], "BURNED", actor_id=w["recorder"],
                             reason="seen by an administrator")
        elif how == "lock":
            vault.set_status(w["persona"], "LOCKED", actor_id=w["recorder"],
                             reason="paused by a person")
        else:
            vault.signal(w["persona"], reason="the board banned it",
                         lock_code="ACCOUNT_BANNED")
        assert _session_row(conn, w["persona"]) == (False, None, None)
        audited = conn.execute(
            "SELECT count(*) FROM audit.event WHERE action = "
            "'PERSONA_FORUM_SESSION_CLEARED' AND object_id = %s",
            (w["persona"],)).fetchone()[0]
        assert audited == 1
    finally:
        w["board"].close()


def test_a_run_that_stops_the_persona_seals_no_session_for_it(conn, stub):
    w = _world(conn, stub, "xenforo", mode="wrong_password")
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "BLOCKED"
        assert _session_row(conn, w["persona"])[0] is False
    finally:
        w["board"].close()


def test_the_stop_route_signs_a_forum_persona_out_of_its_board(conn, stub, monkeypatch):
    from noctornal_api.http.routers import collection as router

    monkeypatch.setattr(router, "blocking_failures", lambda _c: [])
    w = _world(conn, stub, "xenforo")
    client, _app = h.client()
    uid, email = h.user(conn, P, roles=("COLLECTOR",))
    try:
        assert _svc(conn).run_once(w["source"], actor_id=None).status == "OK"
        assert w["board"].sessions and w["board"].logouts == 0
        answer = client.post(
            f"/api/v1/collection/personas/{w['persona']}/status",
            headers=h.auth(h.session(conn, email)),
            json={"status": "LOCKED", "reason": "a person stops this persona"})
        assert answer.status_code == 200, answer.text
        assert answer.json()["status"] == "LOCKED"
        assert "signed out of its forum" in answer.json()["forum_sign_out"]
        assert w["board"].logouts == 1 and w["board"].sessions == {}
        assert _session_row(conn, w["persona"]) == (False, None, None)
        assert uid
    finally:
        w["board"].close()


def test_a_member_read_over_plain_http_to_a_clearnet_host_is_refused_before_a_request(
        conn, stub):
    """Major 6: the password and the cookie were posted and replayed over
    plain http to any address."""
    w = _world(conn, stub, "xenforo", board_class=_ClearnetBoard)
    board = w["board"]
    try:
        assert board.base_url.startswith("http://board.example.test:")
        result = _svc(conn).run_once(w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "BLOCKED", run
        from noctornal_api.forum_member import PLAIN_HTTP
        assert run[2] == PLAIN_HTTP
        assert board.seen == [] and board.posts == [] and stub.records == []
        assert _session_row(conn, w["persona"])[0] is False
    finally:
        board.close()


@pytest.mark.parametrize("platform", ["xenforo", "mybb"])
def test_a_board_that_reflects_the_personas_secrets_gets_none_of_them_stored(
        conn, stub, monkeypatch, platform):
    """Beta 1 verification, group F4: a board that echoed the persona's
    password and session cookie into a post (a debug echo, or a hostile
    board) had both stored as the post's text, in its side rows and in the
    raw markup store, contrary to this module's own account of the vault. The
    secrets are removed from every item while they are still live; the post
    itself is kept, with the place of the echo marked."""
    from noctornal_api.collection import CollectionService
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    anchors = {"xenforo": b'class="bbWrapper">Fresh batch in. ',
               "mybb": b'<div class="post_body scaleimages" id="pid_120">'}
    anchor = anchors[platform]
    real_send = _Handler._send
    echoed: list[str] = []

    def echoing(self, status, body, *, headers=None):
        if status == 200 and anchor in body:
            session = self._cookie()
            echoed.append(session)
            echo = (f"debug echo password {PASSWORD} form "
                    f"{urllib.parse.quote_plus(PASSWORD)} cookie {session} ")
            body = body.replace(anchor, anchor + echo.encode(), 1)
        return real_send(self, status, body, headers=headers)

    monkeypatch.setattr(_Handler, "_send", echoing)
    w = _world(conn, stub, platform)
    board = w["board"]
    raw = InMemoryDocumentRawStorage()
    svc = CollectionService(conn, registry(), raw_store=raw, sleep=lambda _s: None)
    try:
        result = svc.run_once(w["source"], actor_id=None)
        assert result.status == "OK", _run(conn, result.run_id)
        assert echoed and all(echoed), "the board never reflected anything: no proof"
        session = next(iter(board.sessions))
        secrets = (PASSWORD, urllib.parse.quote_plus(PASSWORD), session)
        docs = conn.execute(
            """SELECT external_id, external_url, thread_ref, author_handle, title,
                      body_text FROM collect.document WHERE source_id = %s""",
            (w["source"],)).fetchall()
        assert docs
        text = " ".join(str(c) for row in docs for c in row)
        side = conn.execute(
            """SELECT fp.signature_text, fp.quoted_post_refs::text, fp.reactions::text
                 FROM collect.forum_post fp JOIN collect.document d
                   ON d.id = fp.document_id WHERE d.source_id = %s""",
            (w["source"],)).fetchall()
        text += " " + " ".join(str(c) for row in side for c in row)
        assert side, "the posts have side rows"
        for value in secrets:
            assert value not in text, "a reflected secret was stored"
        assert "debug echo" in text and "[REDACTED]" in text, \
            "the post is kept, the echo's place is marked"
        # The raw markup store holds the fragment of the post the echo was in.
        assert raw._objects, "no raw markup was stored, so nothing was shown"
        for data in raw._objects.values():
            for value in secrets:
                assert value.encode() not in data, "a reflected secret was stored as markup"
        assert any(b"[REDACTED]" in data for data in raw._objects.values())
        # Nothing of it in the run row either.
        assert all(value not in " ".join(str(x) for x in _run(conn, result.run_id))
                   for value in secrets)
    finally:
        board.close()


def test_the_transport_rule_allows_https_and_onion_hosts_only():
    from noctornal_api.forum_member import PLAIN_HTTP, transport_problem

    for ok in ("https://board.example.com/threads/x.1/", "HTTPS://Board.Example.com/",
               "http://abcdefghijklmnop.onion/threads/x.1/",
               "http://abcdefghijklmnop.onion:8080/", "http://x.ONION./"):
        assert transport_problem(ok) is None, ok
    for bad in ("http://board.example.com/", "http://onion/", "ftp://x.onion/",
                "http://x.onion.example.com/", "https:///no-host", "", None,
                "javascript:alert(1)", "//board.example.com/", "http://[::1]/"):
        assert transport_problem(bad) == PLAIN_HTTP, bad
