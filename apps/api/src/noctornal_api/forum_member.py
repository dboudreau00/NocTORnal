"""The authenticated forum path: XenForo and MyBB boards read as a signed-in
member (ROADMAP-REMAINING "the authenticated forum path", docs/16 L3,
2026-10-02).

## What a member read is

The public adapters (`forum_adapters`) read what a board shows anyone.
These two read what it shows a member: the same walk over the same pages,
after the persona bound to the source has signed in. Everything the
collection foundation enforces for a public read holds here unchanged and
more is asked:

- the source is bound to a persona on the adapter's platform, with a
  browser identity recorded (`persona_http`), read through the persona's
  own egress profile and the egress proxy only (`_route_for_source`, docs/00
  decision 130: no forum read ever leaves from this server's own address);
- the read runs only under a confirmed collection authority whose scope is
  MEMBER_READ, which the database refuses to record without a member-access
  reference (0083): `authority_need` asks for it, `run_once` requires it,
  and `fetch` refuses again at the last step (docs/16 L3 holds in the code
  exactly as for the public path);
- the credential is taken from `PersonaVault.use()` through the run's
  lease, held only inside `fetch`, posted once to the board's own sign-in
  form, and registered for redaction; the adapter never keeps it;
- the session cookies the board answers with are a credential too: sealed
  in the vault's storage between runs (`forum_session`) as one jar PER
  ORIGIN, so a persona that reads two boards never carries the first
  board's session to the second (g40 verify blocker 2, 2026-10-03), in
  memory only for the run, registered for redaction, never in a run row, a
  warning, a document or a response; cleared by a sign-out, and by every
  stop of the persona (`PersonaVault`);
- the sign-in and the session travel over https, or over plain http to an
  onion address only (Tor encrypts that hop): a clearnet address that
  would carry the persona's password and cookie in clear is refused by
  name before a request is made (g40 verify major 6, 2026-10-03);
- the pages read are the authority's targets' own (the source's thread or
  board and what its walk reaches), under the source's pacing and the
  persona's gap;
- every post and profile read is stored as a collected document whose
  side row says MEMBER, names the persona and the authority (0162).

## What it refuses, by name, and never does

A CAPTCHA or bot challenge at sign-in stops the run and records it: this
product never solves or bypasses one. A second factor is never entered. A
sign-in that wants JavaScript is not run. A forced password change is a
person's act. A credential the board refuses locks the persona by the
machine until a new one is enrolled (`PersonaSuspended`). A session the
board ends mid-run is signed in again once; a second loss ends the run
where it was. Nothing here posts, replies, reacts, messages, joins or
buys: the two POSTs this module makes are the board's own sign-in and
sign-out forms, and `test_forum_member.py` holds the module to that.

## Where it runs (the vault split, decision 174, merged 2026-10-03)

Nothing here opens a credential: the lease is the run's, from the persona
gate. These adapters run inside the collector as every persona adapter does
(a scheduled poll is the collector's own child, and a Poll now of a member
source is a persona act it runs), and `forum_session` seals and opens the
sessions under the persona ring, never the TOTP ring, so the jars are
opened only in the collector's process. The board's own sign-out on a stop
is the persona act `FORUM_SIGN_OUT` (`persona_acts.py`), which calls
`sign_out_persona` there.
"""
from __future__ import annotations

import contextlib
import logging
import urllib.parse
from datetime import datetime, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from noctornal_api import analysis_runner, forum_parse, forum_session
from noctornal_api.collection import (
    CollectionError,
    FetchResult,
    LoginWall,
    PersonaSuspended,
    SourceBlocked,
    header_text_problem,
)
from noctornal_api.collection_authority import MEMBER_READ
from noctornal_api.forum_adapters import (
    ACCEPT,
    CHALLENGE,
    DIRECT_REFUSED,
    NO_CONTEXT,
    PARSE_WALL_S,
    SECRET_REFUSED,
    AnalysisUnavailable,
    ForumAdapter,
    MyBBAdapter,
    ParseAbandoned,
    XenForoAdapter,
    _Walk,
    direct_reads_allowed,
    sandbox_sentence,
)
from noctornal_api.pinned_http import REDIRECT_CODES, secret_in_scope

log = logging.getLogger("noctornal.forum_member")

PROVENANCE_PUBLIC = "PUBLIC"
PROVENANCE_MEMBER = "MEMBER"
#: A member's requests are spaced further apart than a guest's: a member
#: reading at a crawler's pace is a member a board notices.
MEMBER_GAP_S = 2.0
#: How many times one run signs the persona in: once, and once more when
#: the board ends the session mid-run.
MAX_SIGN_INS = 2
#: The requests one sign-in costs (the form, the POST, the landing page):
#: room the walk is given on top of its page budget, because a sign-in
#: reads no page of the source.
SIGN_IN_PAGES = 3

NO_PERSONA = ("A member read needs the persona bound to this source, and "
              "none was leased for this poll, so nothing was read.")
NOT_MEMBER_SCOPE = ("This source is read as a member, and the authority "
                    "covering it does not carry the member scope, so nothing "
                    "was read.")
NO_BROWSER_IDENTITY = ("A persona that reads a forum as a member needs a "
                       "browser identity recorded.")
LOGIN_FORM_MISSING = ("The forum's sign-in page carries no form this adapter "
                      "can fill in, so the persona did not sign in and nothing "
                      "was read.")
LOGIN_TOKEN_MISSING = ("The forum's sign-in form carries no form token, so the "
                       "persona did not sign in and nothing was read.")
LOGIN_BY_GET = ("The forum's sign-in form sends what the persona typed in the "
                "address line, which a persona never does, so nothing was read.")
CAPTCHA = ("The forum asked for a CAPTCHA or a bot challenge at sign-in. This "
           "product never solves or bypasses one: the persona did not sign in "
           "and nothing was read.")
TWO_FACTOR = ("The forum asked for a second factor at sign-in. A persona's "
              "second factor is never entered by this product: the persona did "
              "not sign in and nothing was read.")
JS_REQUIRED = ("The forum's sign-in wants JavaScript, which this adapter does "
               "not run: the persona did not sign in and nothing was read.")
# Worded around the credential redactor's shapes (decision 136's rule for
# outcome sentences): none of these may put "password", "credential",
# "session", "token" or "cookie" before a space and a word, or the stored
# run detail reads [REDACTED]; test_forum_member holds each to redact().
PASSWORD_CHANGE = ("The forum will not let this persona in until a person renews "
                   "its sign-in, because the board demands a change. A person "
                   "makes the change and enrols the persona again: nothing was "
                   "read.")
WRONG_PASSWORD = ("The forum did not accept this persona's sign-in. The persona is "
                  "locked until it is enrolled again, and nothing was read.")
SESSION_LOST = ("The forum signed the persona out during this poll and would not "
                "keep it signed in, so the poll stopped where it was.")
SIGN_IN_UNREADABLE = ("The forum's answer to the sign-in could not be read, so "
                      "the persona was not signed in and nothing was read.")
OFF_ORIGIN_FORM = ("The forum's sign-in form posts to another site, which a "
                   "persona never does, so nothing was read.")
NO_FORUM_SOURCE = ("This persona reads no forum source, so there is no board "
                   "to sign out of; whatever it held sealed was cleared.")
PLAIN_HTTP = ("This source's address is plain http to a site that is not an "
              "onion address, so the persona's sign-in would travel unencrypted "
              "past its exit. The persona did not sign in and nothing was "
              "read. A member read needs an https address.")
PLAIN_HTTP_SIGN_OUT = ("the address is plain http to a site that is not an "
                       "onion address, so the board's own sign-out was not "
                       "attempted; what was sealed here was cleared")

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


# ---------------------------------------------------------------------------
# The session of one run
# ---------------------------------------------------------------------------

class _SessionLost(Exception):
    """The board answered a page with a sign-in wall while the persona was
    thought to be signed in."""


class MemberSession:
    """The persona's cookies for one run: opened from the vault's storage
    by `plan`, carried on every request, grown from every answer,
    registered for redaction as long as they are held, and handed back to
    `settle` to be sealed. `sign_in` is the one place the credential is
    used, and `sign_out` the one place a sign-out form is posted."""

    def __init__(self, adapter, context, loc: forum_parse.Located, jar: dict):
        self.adapter = adapter
        self.ctx = context
        self.loc = loc
        self.jar = dict(jar)
        self.changed = False
        self.sign_ins = 0
        self.resigned = False
        self._stack = contextlib.ExitStack()

    def __enter__(self) -> MemberSession:
        self._stack.__enter__()
        self._guard(self.jar.values())
        return self

    def __exit__(self, *exc) -> None:
        self._stack.__exit__(*exc)

    def _guard(self, values) -> None:
        live = [v for v in values if isinstance(v, str) and v]
        if live:
            self._stack.enter_context(secret_in_scope(*live))

    def headers(self, extra: dict | None = None) -> dict | None:
        out = dict(extra or {})
        cookie = forum_session.cookie_header(self.jar)
        if cookie:
            out["Cookie"] = cookie
        return out or None

    def absorb(self, fetched) -> None:
        values = []
        try:
            values = fetched.headers.get_all("Set-Cookie") or [] if fetched.headers else []
        except (AttributeError, TypeError):
            values = []
        new = forum_session.take_cookies(self.jar, values)
        if new != self.jar:
            self._guard(v for k, v in new.items() if self.jar.get(k) != v)
            self.jar = new
            self.changed = True

    def forget(self) -> None:
        if self.jar:
            self.changed = True
        self.jar = {}

    # -- reading a page's verdict -------------------------------------------

    def _parse(self, kind: str, fetched) -> dict:
        now = datetime.now(timezone.utc)
        wall = max(1.0, min(PARSE_WALL_S, self.ctx.remaining()))
        try:
            return self.adapter.parse(kind, fetched, dict(self.ctx.source.parser_config or {}),
                                      now, wall)
        except ParseAbandoned as exc:
            if exc.reason in analysis_runner.SANDBOX_FAILURES:
                # The sandbox, not the board (the isolated analysis worker,
                # F42, merged 2026-10-03): the run is BLOCKED with no failure
                # counted and nothing stored, and the sign-in is not read as
                # one the board answered in a way nobody could read.
                raise AnalysisUnavailable(sandbox_sentence(exc.reason)) from None
            raise SourceBlocked(SIGN_IN_UNREADABLE) from None

    def state_of(self, fetched) -> dict:
        parsed = self._parse("session", fetched)
        if parsed.get("state") == "challenge":
            raise SourceBlocked(CHALLENGE)
        return parsed

    def probe(self) -> bool:
        """Whether the sealed session still signs the persona in, asked of
        the source's own first page."""
        url = (forum_parse.board_page_url(self.loc, 1) if self.loc.kind == "board"
               else forum_parse.thread_page_url(self.loc, self.loc.id, 1, self.loc.slug))
        fetched = self.ctx.fetch(url, accept_status=ACCEPT, headers=self.headers())
        self.absorb(fetched)
        return self.state_of(fetched).get("state") == "signed_in"

    def ensure_signed_in(self) -> None:
        if self.jar and self.probe():
            return
        self.forget()
        self.sign_in()

    # -- the sign-in -----------------------------------------------------------

    def sign_in(self) -> None:
        """One sign-in through the board's own form: the page, the form
        and its token, the POST with the leased credential, the answer's
        verdict. Every refusal is a sentence that names what the board
        asked for and says nothing was read."""
        persona = self.ctx.persona
        if persona is None or persona.lease is None:
            raise SourceBlocked(NO_PERSONA)
        self.sign_ins += 1
        login_url = forum_parse.login_page_url(self.loc)
        page = self.ctx.fetch(login_url, accept_status=ACCEPT, headers=self.headers())
        self.absorb(page)
        parsed = self._parse("login", page)
        if parsed.get("state") == "challenge":
            raise SourceBlocked(CHALLENGE)
        self._refuse_blocks(parsed)
        form = parsed.get("form")
        if not isinstance(form, dict):
            raise SourceBlocked(JS_REQUIRED if parsed.get("js_required")
                                else LOGIN_FORM_MISSING)
        if not form.get("token_present"):
            raise SourceBlocked(LOGIN_TOKEN_MISSING)
        if (form.get("method") or "get") != "post":
            raise SourceBlocked(LOGIN_BY_GET)
        action = urllib.parse.urljoin(login_url, form.get("action") or login_url)
        if _origin(action) != _origin(login_url):
            raise SourceBlocked(OFF_ORIGIN_FORM)
        fields = {str(k): str(v) for k, v in (form.get("fields") or {}).items()}
        fields[str(form.get("login_field") or "login")] = persona.handle
        fields[str(form.get("password_field") or "password")] = persona.lease.value
        body = urllib.parse.urlencode(fields).encode("utf-8")
        answer = self.ctx.fetch(
            action, method="POST", body=body,
            headers=self.headers({"Content-Type": FORM_CONTENT_TYPE}),
            accept_status=ACCEPT | REDIRECT_CODES)
        del body, fields
        self.absorb(answer)
        if answer.status in REDIRECT_CODES and answer.location:
            if _origin(answer.location) != _origin(login_url):
                raise SourceBlocked(OFF_ORIGIN_FORM)
            # A board answers a sign-in with a redirect to where the
            # member was going; the landing page says whether it worked.
            answer = self.ctx.fetch(answer.location, accept_status=ACCEPT,
                                    headers=self.headers())
            self.absorb(answer)
        verdict = self.state_of(answer)
        state = verdict.get("state")
        if state == "signed_in":
            return
        if state == "login":
            raise PersonaSuspended(WRONG_PASSWORD, lock_code="CREDENTIAL_REVOKED")
        self._refuse_blocks({"captcha": state == "captcha",
                             "two_factor": state == "two_factor",
                             "password_change": state == "password_change",
                             "js_required": state == "js_required"})
        raise SourceBlocked(SIGN_IN_UNREADABLE)

    @staticmethod
    def _refuse_blocks(parsed: dict) -> None:
        if parsed.get("captcha"):
            raise SourceBlocked(CAPTCHA)
        if parsed.get("two_factor"):
            raise SourceBlocked(TWO_FACTOR)
        if parsed.get("password_change"):
            raise SourceBlocked(PASSWORD_CHANGE)
        if parsed.get("js_required"):
            raise SourceBlocked(JS_REQUIRED)

    # -- the sign-out ------------------------------------------------------------

    def sign_out(self) -> bool:
        """Sign the persona out of the board with the session held, then
        forget the session whatever the board answered. True when the
        board's own sign-out was reached."""
        if not self.jar:
            return False
        reached = False
        try:
            url = (forum_parse.board_page_url(self.loc, 1) if self.loc.kind == "board"
                   else forum_parse.thread_page_url(self.loc, self.loc.id, 1, self.loc.slug))
            page = self.ctx.fetch(url, accept_status=ACCEPT, headers=self.headers())
            self.absorb(page)
            verdict = self.state_of(page)
            token = verdict.get("logout_token")
            if verdict.get("state") == "signed_in":
                if self.loc.platform == "xenforo":
                    body = urllib.parse.urlencode(
                        {"_xfToken": token or ""}).encode("utf-8")
                    answer = self.ctx.fetch(
                        forum_parse.logout_url(self.loc), method="POST", body=body,
                        headers=self.headers({"Content-Type": FORM_CONTENT_TYPE}),
                        accept_status=ACCEPT | REDIRECT_CODES)
                else:
                    answer = self.ctx.fetch(
                        forum_parse.logout_url(self.loc, token), accept_status=ACCEPT
                        | REDIRECT_CODES, headers=self.headers())
                self.absorb(answer)
                reached = True
        finally:
            self.forget()
        return reached


def transport_problem(url: str | None) -> str | None:
    """Why a member read may not use this address, or None. The password
    and the session cookie are posted and replayed to it, so the hop must
    be encrypted: https, or http to an onion host (Tor's own hop). Anything
    else is refused, and so is an address that does not parse (fail
    closed)."""
    try:
        parts = urllib.parse.urlsplit(url or "")
        scheme = (parts.scheme or "").lower()
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return PLAIN_HTTP
    if scheme == "https" and host:
        return None
    if scheme == "http" and host.endswith(".onion"):
        return None
    return PLAIN_HTTP


def _persona_stopped(conn: psycopg.Connection, persona_id: UUID) -> bool:
    """Whether the persona is LOCKED, BURNED or machine-locked now."""
    row = conn.execute(
        """SELECT status::text IN ('LOCKED', 'BURNED')
                  OR machine_lock_code IS NOT NULL
             FROM collect.collection_account WHERE id = %s""",
        (persona_id,)).fetchone()
    return bool(row and row[0])


def _origin(url: str) -> tuple | None:
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return parts.scheme, parts.hostname.lower(), port
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# The walk, with the session on every request
# ---------------------------------------------------------------------------

class _WithCookies:
    """The run context as the walk sees it, with the session's cookies on
    every request and every answer's cookies taken."""

    def __init__(self, context, session: MemberSession):
        self._ctx = context
        self._session = session

    def fetch(self, url, **kw):
        headers = self._session.headers(kw.pop("headers", None))
        fetched = self._ctx.fetch(url, headers=headers, **kw)
        self._session.absorb(fetched)
        return fetched

    def __getattr__(self, name: str):
        return getattr(self._ctx, name)


class _MemberWalk(_Walk):
    """The public walk over the member's view. A sign-in wall met during
    the walk is the board ending the session: the persona signs in once
    more and the page is read again; a second loss ends the run (a
    primary page) or skips the page (a thread on a board)."""

    def __init__(self, adapter, context, loc, cursor: dict, config: dict,
                 session: MemberSession):
        super().__init__(adapter, context, loc, cursor, config)
        self.session = session
        self.ctx = _WithCookies(context, session)
        # The sign-ins' own requests are not pages of the source: the walk
        # and the run's context both get that much more room, and no more.
        room = SIGN_IN_PAGES * MAX_SIGN_INS
        self.budget += room
        context.page_budget += room

    def _walled(self, primary: bool, what: str):
        raise _SessionLost(what)

    def _page(self, url: str, page_kind: str, *, primary: bool, what: str):
        try:
            return super()._page(url, page_kind, primary=primary, what=what)
        except _SessionLost:
            if self.session.resigned or self.session.sign_ins >= MAX_SIGN_INS:
                if primary:
                    raise LoginWall(SESSION_LOST) from None
                return self._skip(what, "the forum ended the persona's session")
            self.session.resigned = True
            self.session.forget()
            self.session.sign_in()
            try:
                return super()._page(url, page_kind, primary=primary, what=what)
            except _SessionLost:
                if primary:
                    raise LoginWall(SESSION_LOST) from None
                return self._skip(what, "the forum ended the persona's session")

    def _result(self) -> FetchResult:
        result = super()._result()
        persona = self.session.ctx.persona
        authority = getattr(persona, "authority", None)
        for item in result.items:
            forum = item.meta.setdefault("forum", {})
            forum["provenance"] = PROVENANCE_MEMBER
            forum["persona_id"] = str(persona.persona_id)
            forum["authority_id"] = str(authority.authority_id)
        return result


# ---------------------------------------------------------------------------
# The adapters
# ---------------------------------------------------------------------------

class MemberForumAdapter(ForumAdapter):
    """What the two member adapters share."""

    persona_http = True
    persona_min_gap_s = MEMBER_GAP_S
    provenance = PROVENANCE_MEMBER

    def __init__(self, *, parse=None, sleep=None):
        import time as _time
        super().__init__(parse=parse, sleep=sleep or _time.sleep)
        #: source id -> the run's jar between plan, fetch and settle, and
        #: the origin it belongs to (the jar is that origin's, no other's).
        self._jars: dict[UUID, dict] = {}
        self._origins: dict[UUID, str | None] = {}
        self._changed: dict[UUID, bool] = {}

    def authority_need(self, source) -> str:
        return MEMBER_READ

    def validate_persona(self, fingerprint: dict) -> list[str]:
        problem = header_text_problem("browser identity",
                                      (fingerprint or {}).get("user_agent"),
                                      low=1, high=400)
        return [NO_BROWSER_IDENTITY] if problem else []

    def plan(self, conn: psycopg.Connection, source, persona):
        super().plan(conn, source, persona)
        if persona is not None:
            origin = forum_session.origin_key(source.base_url)
            self._origins[source.id] = origin
            self._jars[source.id] = forum_session.open_session(
                conn, persona["id"], origin)
            self._changed[source.id] = False
        return None

    def fetch(self, *, base_url: str, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None,
              context=None, route=None) -> FetchResult:
        if secret is not None:
            raise CollectionError(SECRET_REFUSED)
        if context is None:
            raise CollectionError(NO_CONTEXT)
        if not context.route.proxied and not direct_reads_allowed():
            raise SourceBlocked(DIRECT_REFUSED)
        persona = context.persona
        if persona is None or persona.lease is None:
            raise SourceBlocked(NO_PERSONA)
        authority = persona.authority
        if authority is None or getattr(authority, "scope", None) != MEMBER_READ:
            # docs/16 L3, held at the last step as run_once holds it first.
            raise SourceBlocked(NOT_MEMBER_SCOPE)
        problem = transport_problem(base_url)
        if problem is not None:
            raise SourceBlocked(problem)
        loc = forum_parse.locate(self.platform, base_url)
        if loc is None:
            raise SourceBlocked(self.shape_sentence)
        session = MemberSession(self, context, loc,
                                self._jars.get(context.source.id) or {})
        try:
            with session:
                walk = _MemberWalk(self, context, loc, cursor or {},
                                   dict(context.source.parser_config or {}),
                                   session)
                session.ensure_signed_in()
                result = walk.run()
        finally:
            self._jars[context.source.id] = session.jar
            self._changed[context.source.id] = session.changed
        return result

    def settle(self, conn: psycopg.Connection, *, source_id: UUID,
               persona_id: UUID | None, run_id: UUID, status: str,
               error: str | None) -> None:
        """Seal what the run learnt of the session, then drop it from
        memory, before the public adapter's settle (the lock and the
        backoff ladder)."""
        jar = self._jars.pop(source_id, None)
        origin = self._origins.pop(source_id, None)
        changed = self._changed.pop(source_id, False)
        try:
            if (persona_id is not None and jar is not None and changed
                    and origin is not None):
                if _persona_stopped(conn, persona_id):
                    # The run's own outcome stopped the persona (a credential
                    # the board refused locks it): nothing is sealed for a
                    # stopped persona, whatever cookies the board handed out
                    # on its way to refusing it (g40 verify major 1).
                    forum_session.clear_session(conn, persona_id)
                else:
                    forum_session.seal_session(conn, persona_id, origin, jar)
        finally:
            super().settle(conn, source_id=source_id, persona_id=persona_id,
                           run_id=run_id, status=status, error=error)

    def commit_item(self, conn: psycopg.Connection, *, source_id: UUID,
                    run_id: UUID, persona_id: UUID | None, item, document_id: UUID,
                    inserted: bool) -> None:
        """The side row of a post or a member, as the public adapter writes
        it, saying MEMBER and naming the persona and the authority (0162)."""
        forum = (item.meta or {}).get("forum") or {}
        authority = forum.get("authority_id")
        try:
            authority_id = UUID(str(authority)) if authority else None
        except ValueError:
            authority_id = None
        provenance = PROVENANCE_MEMBER if (persona_id and authority_id) else PROVENANCE_PUBLIC
        persona = persona_id if provenance == PROVENANCE_MEMBER else None
        auth = authority_id if provenance == PROVENANCE_MEMBER else None
        if forum.get("kind") == "member":
            conn.execute(
                """INSERT INTO collect.forum_member
                       (document_id, profile, provenance, collection_account_id,
                        authority_id)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (document_id) DO UPDATE
                      SET profile = EXCLUDED.profile, observed_at = now(),
                          provenance = EXCLUDED.provenance,
                          collection_account_id = EXCLUDED.collection_account_id,
                          authority_id = EXCLUDED.authority_id""",
                (document_id, Jsonb(forum.get("profile") or {}), provenance,
                 persona, auth))
            return
        conn.execute(
            """INSERT INTO collect.forum_post
                   (document_id, signature_text, quoted_post_refs, reactions,
                    provenance, collection_account_id, authority_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (document_id) DO UPDATE
                  SET signature_text = EXCLUDED.signature_text,
                      quoted_post_refs = EXCLUDED.quoted_post_refs,
                      reactions = EXCLUDED.reactions, observed_at = now(),
                      provenance = EXCLUDED.provenance,
                      collection_account_id = EXCLUDED.collection_account_id,
                      authority_id = EXCLUDED.authority_id""",
            (document_id, forum.get("signature"),
             list(forum.get("quoted") or [])[:forum_parse.MAX_QUOTED],
             Jsonb(forum.get("reactions") or {}), provenance, persona, auth))


class XenForoMemberAdapter(MemberForumAdapter, XenForoAdapter):
    """A XenForo board or thread read as a signed-in member."""

    key = "xenforo_member"
    persona_platform = "XENFORO"


class MyBBMemberAdapter(MemberForumAdapter, MyBBAdapter):
    """A MyBB board or thread read as a signed-in member."""

    key = "mybb_member"
    persona_platform = "MYBB"


def member_registry() -> dict:
    """The two entries forum_adapters.forum_registry() adds."""
    return {"xenforo_member": XenForoMemberAdapter(),
            "mybb_member": MyBBMemberAdapter()}


# ---------------------------------------------------------------------------
# Signing out on stop
# ---------------------------------------------------------------------------

def sign_out_persona(conn: psycopg.Connection, persona_id: UUID, *,
                     actor_id: UUID | None, clearance: str | None,
                     compartments=None, fetcher=None, sleep=None) -> dict:
    """Sign a forum persona out of every board it holds a session on and
    clear its sealed sessions: a STOP, so it is always allowed (the persona
    gate's stopping path: visible, on a forum platform, with an exit; no
    authority, no hours, no usability), through the persona's own route
    in a `stop` context. Each board is signed out with that board's OWN
    cookies, once per origin (g40 verify blocker 2, 2026-10-03). The
    sessions are cleared whatever the boards answer: a cookie this product
    no longer holds is not one it can present again.

    Called in the collector, by the `FORUM_SIGN_OUT` persona act that the
    persona's stop route (`POST /collection/personas/{id}/status` to LOCKED
    or BURNED) queues and waits for; `PersonaVault` clears the sealed
    sessions itself on every stop, so a stop that does not reach a board
    still leaves nothing sealed (g40 verify major 1). The notes name no
    source: the caller's labels are the persona's gate, not each source's."""
    from noctornal_api.collection import PersonaContext, PersonaGate, _source_row
    from noctornal_api.collection_context import RunContext

    gate = PersonaGate(conn, persona_id, actor_id=actor_id, clearance=clearance,
                       compartments=compartments,
                       purpose="sign out of a forum", source_id=None, need=None,
                       platform=None, stopping=True, needs_secret=False,
                       sleep=sleep or (lambda _s: None))
    row = gate.check()
    if row["platform"] not in ("XENFORO", "MYBB"):
        raise CollectionError("This persona is not a forum account.")
    gate.lock()
    out = {"persona_id": str(persona_id), "signed_out": [], "cleared": False,
           "notes": []}
    try:
        registry = member_registry()
        sources = conn.execute(
            """SELECT id FROM collect.source
                WHERE collection_account_id = %s AND kind IN ('XENFORO', 'MYBB')
                  AND base_url IS NOT NULL
                ORDER BY is_active DESC, name""", (persona_id,)).fetchall()
        jars = forum_session.open_sessions(conn, persona_id)
        if jars and sources:
            route = gate.route()
            done: set[str] = set()
            for (sid,) in sources:
                source = _source_row(conn, sid, None)
                origin = forum_session.origin_key(source.base_url)
                jar = jars.get(origin) if origin else None
                if not jar or origin in done:
                    continue
                done.add(origin)
                if transport_problem(source.base_url) is not None:
                    out["notes"].append(f"source {sid}: {PLAIN_HTTP_SIGN_OUT}")
                    continue
                adapter = registry.get("xenforo_member" if source.kind == "XENFORO"
                                       else "mybb_member")
                loc = forum_parse.locate(adapter.platform, source.base_url)
                if loc is None:
                    continue
                persona = PersonaContext(
                    persona_id=persona_id, handle=row["handle"],
                    platform=row["platform"], platform_uid=row["platform_uid"],
                    fingerprint=dict(row["fingerprint"] or {}),
                    authority=None, route=route, lease=None)
                context = RunContext(source=source, run_id=None, adapter=adapter,
                                     route=route, persona=persona, fetcher=fetcher)
                session = MemberSession(adapter, context, loc, jar)
                try:
                    with secret_in_scope(*[v for v in jar.values() if v]):
                        with context, session:
                            reached = session.sign_out()
                except CollectionError as exc:
                    out["notes"].append(f"source {sid}: {exc}")
                    continue
                out["signed_out"].append({"source_id": str(sid),
                                          "reached": reached})
            if set(jars) - done:
                out["notes"].append(
                    "a session on a board no source reads any more was "
                    "cleared without signing out")
        elif jars:
            out["notes"].append(NO_FORUM_SOURCE)
        out["cleared"] = forum_session.clear_session(conn, persona_id)
        conn.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action, object_type,
                                        object_id, outcome, detail)
               VALUES (%s, %s, 'PERSONA_FORUM_SIGNED_OUT', 'collection_account',
                       %s, 'SUCCESS', %s)""",
            (actor_id, "USER" if actor_id else "SYSTEM", persona_id,
             Jsonb({"signed_out": out["signed_out"], "cleared": out["cleared"],
                    "notes": out["notes"]})))
    finally:
        gate.release()
    return out


__all__ = [
    "CAPTCHA", "JS_REQUIRED", "MAX_SIGN_INS", "MEMBER_GAP_S", "MemberForumAdapter",
    "MemberSession", "MyBBMemberAdapter", "NOT_MEMBER_SCOPE", "NO_PERSONA",
    "PASSWORD_CHANGE", "PLAIN_HTTP", "PROVENANCE_MEMBER", "PROVENANCE_PUBLIC",
    "SESSION_LOST", "TWO_FACTOR", "WRONG_PASSWORD", "XenForoMemberAdapter",
    "member_registry", "sign_out_persona", "transport_problem",
]
