"""Authentication endpoints: password + TOTP login, logout, whoami.

Every outcome is audited (docs/05 requires authentication success AND
failure): a brute-force campaign or a successful credential-stuffing login
must leave a trace in a system whose premise is that "who did what" is
answerable.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from uuid import uuid4

import psycopg
from fastapi import APIRouter, Depends, Request, Response
from psycopg.types.json import Json
from pydantic import BaseModel

from noctornal_api.http.deps import (
    COOKIE_ATTRS,
    CSRF_COOKIE,
    SESSION_COOKIE,
    CurrentUser,
    current_user,
    get_conn,
    session_token,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import (
    client_ip,
    consume_on_failure,
    rate_limit,
    rate_limit_peek,
)
from noctornal_api.iam_admin import change_password, new_password_problem
from noctornal_api.security.auth import AuthOutcome, AuthService
from noctornal_api.security.sessions import (
    IDLE_TIMEOUT,
    STEP_UP_FRESHNESS,
    SessionService,
)
from noctornal_api.stores import PgSessionStore, PgUserStore

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str
    totp_code: str | None = None
    # The password the person chooses, sent only when the server has said
    # it must be changed (0066; gap-password-reset, 2026-09-23). Absent
    # on every ordinary sign-in.
    new_password: str | None = None


def _ip_hash(request: Request) -> bytes | None:
    """The address the audit row names is the one the session is bound to.

    `client_ip` is the peer, or the outermost trusted proxy's client when
    `NOCTORNAL_TRUSTED_PROXY_HOPS` says so. Until 2026-09-09 this hashed
    `request.client.host` while the binding (0058) and the rate limiter
    read `client_ip`, so behind a proxy every sign-in was audited from
    the proxy's own address: the log said who signed in from where, and
    the where was the load balancer.
    """
    ip = client_ip(request)
    if ip is None:
        return None
    return hashlib.sha256(ip.encode()).digest()


def _audit(conn, action: str, actor_id, detail: dict, request: Request) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail, ip_hash)
           VALUES (%s, %s, %s, 'auth', NULL, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, Json(detail),
         _ip_hash(request)),
    )


#: Says what happened and what to do, and nothing about which key: the
#: register names that, to somebody who may read it.
SECOND_FACTOR_UNAVAILABLE = (
    "the second factor for this account cannot be checked: the key that "
    "sealed its authenticator secret is not available to this deployment. "
    "Nothing about the credentials was wrong. An operator must read the "
    "readiness register (kek_ring_opens_stored_secrets) and restore or "
    "retire that key."
)


#: The problem `type` of the refusal that asks for a new password. A URN
#: rather than a sentence the console would have to pattern-match: the
#: detail is prose for a person, and prose gets reworded.
PASSWORD_CHANGE_REQUIRED_TYPE = "urn:noctornal:problem:password-change-required"

PASSWORD_CHANGE_REQUIRED = (
    "an administrator issued this password, so it has to be replaced "
    "before it opens a session. Choose a new password and sign in again "
    "with it and a fresh code from your authenticator."
)


@router.post("/login", status_code=204,
             dependencies=[Depends(rate_limit("auth.login")),
                           Depends(rate_limit_peek("auth.login_failed"))])
def login(body: LoginBody, request: Request,
          conn: psycopg.Connection = Depends(get_conn)) -> Response:
    """204 and the cookie pair; since 2026-09-10 there is no body at all.

    The credential leaves here as `__Host-session` and nowhere else. What
    that closed, what it did not, and why it could not be done sooner are
    at the set itself, below.

    Metered twice, both IP-scoped, and both checked before the Argon2id
    verify.

    The order is the point: password hashing is deliberately expensive, so
    an unlimited login endpoint is a CPU amplifier — one cheap HTTP request
    buys ~100ms of server work. `auth.login` caps that draw per source.

    `auth.login_failed` is the anti-guessing control, and it is PEEKED
    here and consumed below only when authentication actually fails. That
    asymmetry is what lets an IP-scoped control coexist with the customer
    for this product: two hundred analysts behind one corporate egress
    address, all signing on within ten minutes of 09:00, never move the
    failure meter at all. A password sprayer moves nothing else.

    Neither is email-scoped: anyone can send a given address, so an
    email-keyed limit would be a remotely triggerable lockout of a named
    analyst. Targeted guessing against one account is the (decaying)
    account lockout's job.
    """
    # A chosen password is judged BEFORE the credentials are, so a rule
    # failure spends no lockout attempt and no authenticator code, and
    # says nothing about the account (it depends on nothing stored).
    if body.new_password is not None:
        problem = new_password_problem(body.new_password, email=body.email,
                                       current=body.password)
        if problem:
            raise Problem(422, "Invalid field", problem)
    # A recovery code is checked here and spent only once the sign-in is
    # known to go ahead (`spend`, below): the must-change and
    # no-change-pending refusals come first, and until 2026-09-24 each of
    # them cost the person a single-use code (final review u4).
    service = AuthService(PgUserStore(conn))
    result = service.authenticate(
        body.email, body.password, body.totp_code, spend_recovery=False
    )
    if result.outcome is AuthOutcome.SECOND_FACTOR_UNAVAILABLE:
        # The password verified; the stored second factor could not be
        # opened under any key this process holds. Not a credential
        # failure, so the failure meter is not consumed and no lockout
        # attempt was burnt; audited under its own reason; answered as
        # the server fault it is, naming the readiness check that
        # explains it. Until 2026-09-11 this was an InvalidTag out of the
        # store and a 500 to the analyst.
        _audit(conn, "AUTH_FAILED", result.user_id,
               {"reason": result.audit_reason, "email": body.email}, request)
        raise Problem(503, "Service unavailable", SECOND_FACTOR_UNAVAILABLE)
    if not result.ok:
        consume_on_failure(request, "auth.login_failed")
        # The specific cause is audited server-side and NEVER returned —
        # a distinct response would confirm which factor was right.
        _audit(conn, "AUTH_FAILED", result.user_id,
               {"reason": result.audit_reason, "email": body.email}, request)
        raise Problem(401, "Unauthenticated", "invalid credentials")
    must_change = _password_change_due(conn, result.user_id, body, request)
    if not service.spend(result):
        # The recovery code verified above was spent by a concurrent
        # sign-in before this one could spend it. The same answer and the
        # same trace as a spent code gets inside `authenticate`; nothing
        # has been changed yet, the new password included.
        consume_on_failure(request, "auth.login_failed")
        _audit(conn, "AUTH_FAILED", None,
               {"reason": "bad_recovery_code", "email": body.email}, request)
        raise Problem(401, "Unauthenticated", "invalid credentials")
    if must_change:
        change_password(conn, result.user_id, body.new_password,
                        keep_session=None, via="sign-in after a reset")
    # Where the session was minted (0058). `client_ip` is the rate
    # limiter's view of the peer -- the outermost trusted proxy's client
    # when NOCTORNAL_TRUSTED_PROXY_HOPS says so -- because a binding to the
    # proxy's own address would match every replay that came through the
    # same proxy, which is every replay.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), result.user_id, mfa_satisfied=True,
        ip=client_ip(request), user_agent=request.headers.get("user-agent"),
    )
    # The Admin card's "last password sign-in", stamped here, where a
    # session exists, and nowhere else (final review u22, 2026-09-24).
    PgUserStore(conn).record_sign_in(result.user_id, datetime.now(timezone.utc))
    _audit(conn, "AUTH_SUCCEEDED", result.user_id, {}, request)
    response = Response(status_code=204)
    # The pair is the WHOLE of a successful login now: the HttpOnly
    # session cookie, and the readable CSRF cookie that is the
    # double-submit half docs/05 requires (`deps.session_token` demands
    # the matching header on a cookie-authenticated unsafe method).
    #
    # The same token was returned in the body as well, to every client,
    # until 2026-09-10. It had to be: two console paths could not read the
    # cookie -- the live websocket authenticated from a token in its first
    # frame, and the Lab download is cross-origin, so no `__Host-` cookie
    # can reach it. Both are closed (`routers/live.py` `_handshake` now
    # prefers `__Host-session` off the upgrade; the download crosses on a
    # one-shot ticket minted under the cookie session, 0061), and a body
    # token nothing needs is a session credential that any script on this
    # origin can read -- the exact property HttpOnly exists to deny. The
    # order was load-bearing: deleting it first would have taken the
    # console's live pane and every Lab download with it.
    #
    # This is not the end of bearer tokens, and reading it that way is the
    # mistake to avoid. `deps.session_token` still prefers `Authorization:
    # Bearer`; `scripts/bootstrap.py session` still mints one through
    # `SessionService` directly, never through here, and the `#token=`
    # link it prints is still exchanged at `POST /auth/cookie`. What went
    # away is LOGIN handing one out.
    #
    # Nor is the token withheld from the client that just signed in: the
    # cookie value IS the raw session token, so a script client reads it
    # off `Set-Cookie` and may send it as either transport. The property
    # gained is narrower and is the one that matters here -- script in the
    # analyst's browser cannot read an HttpOnly cookie, so after this
    # there is nowhere in a browser that the session token is legible.
    _set_session_cookies(response, token)
    return response


def _password_change_due(conn, user_id, body: LoginBody,
                         request: Request) -> bool:
    """The must-change rule, at the one door a session comes through.

    gap-password-reset (2026-09-23). An administrator-issued password is
    known to whoever issued it, so it must never open a session: a reset
    password, and since 2026-09-24 the password an administrator issues
    with a new account (final review c8). Reached only AFTER both factors
    verified, so the refusals below tell nobody anything a guesser did not
    already have to know. Three outcomes:

    - the flag is set and no new password came: 403 with
      `PASSWORD_CHANGE_REQUIRED_TYPE`, and NO session. A TOTP code this
      request carried has been spent (replay protection), so the console
      asks for a fresh one with the new password. A recovery code has
      not: `login` spends it only after this answers (final review u4);
    - the flag is set and a new password came: True, and `login` stores
      it and clears the flag in one statement (`iam_admin.change_password`)
      once the second factor is spent, then mints the session with it;
    - no flag, but a new password came: 409. Nothing asked for a change,
      and quietly ignoring the field would leave the person believing
      they had changed a password that is still the old one.

    This is the ONLY check of the flag in the API, and that is enough:
    `reset_password` revokes every live session, and no session can be
    minted here while the flag stands. (`scripts/bootstrap.py session`
    mints from the server's shell, whose operator holds the database.)
    """
    row = conn.execute(
        "SELECT must_change_password FROM iam.app_user WHERE id = %s",
        (user_id,)).fetchone()
    must = bool(row and row[0])
    if must and body.new_password is None:
        _audit(conn, "AUTH_PASSWORD_CHANGE_REQUIRED", user_id, {}, request)
        raise Problem(403, "Password change required",
                      PASSWORD_CHANGE_REQUIRED,
                      type_=PASSWORD_CHANGE_REQUIRED_TYPE)
    if body.new_password is None:
        return False
    if not must:
        raise Problem(409, "Conflict",
                      "no password change is pending for this account, so "
                      "nothing was changed. Sign in without a new password, "
                      "then change it from Account")
    return True


@router.post("/logout", status_code=204)
def logout(request: Request,
           user: CurrentUser = Depends(current_user),
           conn: psycopg.Connection = Depends(get_conn)) -> Response:
    """Revoke ONLY the presenting session. Revoking every session for the
    user would evict their other devices; that is a separate, deliberate
    capability (password change, admin kill-all)."""
    SessionService(PgSessionStore(conn)).revoke(user.session_id, "logout")
    _audit(conn, "AUTH_LOGOUT", user.user_id, {"session_id": str(user.session_id)},
           request)
    response = Response(status_code=204)
    # Clear the cookies so the browser stops presenting a dead token. With
    # the attributes they were SET with: until 2026-09-09 this was
    # `delete_cookie(name, path="/")`, whose defaults emit no Secure and
    # `SameSite=lax`, and a browser refuses a `__Host-` cookie without
    # Secure -- so the deletion was ignored and the revoked token rode
    # along on every later request while this endpoint said 204.
    _clear_session_cookies(response)
    return response


@router.post("/cookie", status_code=204)
def adopt_cookie(request: Request,
                 raw: str = Depends(session_token),
                 user: CurrentUser = Depends(current_user),
                 conn: psycopg.Connection = Depends(get_conn)) -> Response:
    """Set the cookie pair for the session the caller is already presenting.

    Kept deliberately after login stopped returning a token (2026-09-10),
    because the hand-off it serves does not come from login and never
    did. A browser can no longer be handed a bearer by signing in, but
    `scripts/bootstrap.py session` still mints one through
    `SessionService` directly -- the recovery path for a host whose clock
    TOTP cannot live with -- and this route is the only way that token
    becomes a session the browser keeps across a reload. Without it that
    hand-off would either die or have to write the token into web
    storage, which is what the cookie pair replaced. What did change is
    the population: nothing arrives here holding a login-body token,
    because there is no longer any such thing.

    For the `#token=` hand-off: `scripts/bootstrap.py session` mints a
    session from a shell and hands the token to the browser in the URL
    fragment, and the console exchanges it here ONCE so the session
    survives a reload without the token ever being written to web
    storage. The cookie carries the same token, so no session is minted,
    no login event is written and nothing about the session changes but
    its transport -- which is why a successful adoption is not audited as
    an authentication outcome: `current_user` has already validated the
    session (and, under `NOCTORNAL_SESSION_STRICT_BINDING`, checked its
    binding), and a bogus token gets the same generic 401 as everywhere
    else with no cookie set.

    Reachable with a cookie too, in which case the CSRF double-submit in
    `session_token` applies and the effect is a fresh CSRF cookie for the
    same session.

    A bearer that arrives alongside a live cookie session for a DIFFERENT
    account is refused with 409 and audited (2026-09-09). `session_token`
    prefers the bearer, so until then a link of the documented deep-link
    shape `#case=<id>&tab=feeds&token=<attacker's token>` opened by a
    signed-in analyst replaced the browser's cookie with the attacker's
    session: every tab the analyst already had open kept showing the
    analyst, `authHeaders()` in each of them read the new CSRF cookie
    live, and every write from those tabs landed in the hash-chained
    audit log under the attacker's user_id. The console now checks for an
    existing session before it exchanges; this refusal is what holds when
    the console gets that wrong. The SAME account is allowed on purpose: a
    tab left with the session cookie and no readable half recovers through
    its own `bootstrap.py session` link, and the effect is a fresh pair
    for the same user. A cookie the server no longer honours is replaced
    freely -- there is no session there to protect.
    """
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie and cookie != raw:
        holder = SessionService(PgSessionStore(conn)).validate(cookie, touch=False)
        if holder.ok and holder.session.user_id != user.user_id:
            _audit(conn, "AUTH_COOKIE_ADOPT_REFUSED", user.user_id,
                   {"reason": "cookie_session_belongs_to_another_account",
                    "bearer_session_id": str(user.session_id),
                    "cookie_session_id": str(holder.session.id),
                    "cookie_user_id": str(holder.session.user_id)},
                   request)
            raise Problem(409, "Conflict",
                          "this browser already holds a session for a "
                          "different account; sign out of it before "
                          "adopting another")
    response = Response(status_code=204)
    _set_session_cookies(response, raw)
    return response


def _set_session_cookies(response: Response, token: str) -> None:
    """The pair, from ONE attribute declaration shared with the delete
    (`deps.COOKIE_ATTRS`): HttpOnly on the session cookie because script
    must never read it, readable on the CSRF cookie because script must
    copy it into the header."""
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **COOKIE_ATTRS)
    response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False,
                        **COOKIE_ATTRS)


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, httponly=True, **COOKIE_ATTRS)
    response.delete_cookie(CSRF_COOKIE, httponly=False, **COOKIE_ATTRS)


class Me(BaseModel):
    user_id: str
    # Who you are, not just which row you are. Until 2026-09-02 the model
    # carried the id and the code count and nothing else, and the analyst
    # UI put `me.user_id` straight into the app bar, so every signed-in
    # analyst was greeted by their own UUID.
    display_name: str
    email: str
    recovery_codes_remaining: int
    # The session's two limits, so the console can warn before either
    # instead of discovering them on a Save (expiry-drops-context,
    # 2026-09-22). The idle window has just been slid by this very request,
    # so it is the full timeout; the absolute limit is a distance rather
    # than a timestamp because the browser's clock need not agree with
    # this one.
    idle_timeout_seconds: int
    session_expires_in_seconds: int
    # How much longer this session satisfies the step-up gate (a second
    # factor within STEP_UP_FRESHNESS), 0 when it no longer does. The
    # console asks for a fresh sign-in BEFORE a gated request instead of
    # after its 403, because each refused POST /auth/recovery-codes still
    # spends a token of that route's rate limit (2026-09-22 fix round).
    step_up_fresh_seconds: int
    # The account's own clearance, so the app bar can say what this
    # person may open ("cleared RED") beside their role on the case, in
    # place of a literal "analyst" printed for every account
    # (ux02-cases:header-says-analyst-no-permission-cues, 2026-09-23).
    tlp_clearance: str | None = None


@router.get("/me", response_model=Me)
def me(user: CurrentUser = Depends(current_user),
       conn: psycopg.Connection = Depends(get_conn)) -> Me:
    # Read live from the row rather than from anything the session
    # carries, so an administrator's correction to a name shows up on the
    # analyst's next load and not their next login.
    row = conn.execute(
        "SELECT display_name, email, tlp_clearance FROM iam.app_user "
        "WHERE id = %s",
        (user.user_id,),
    ).fetchone()
    if row is None:
        # A session that resolved a moment ago and now names no account:
        # the row went between the two reads. Say so as an auth failure,
        # not as a 500 the client would retry.
        raise Problem(401, "Unauthenticated", "session refers to no account")
    display_name, email, clearance = row
    expires = conn.execute(
        "SELECT expires_at FROM iam.session WHERE id = %s", (user.session_id,),
    ).fetchone()
    left = (expires[0] - datetime.now(timezone.utc)).total_seconds() if expires else 0
    fresh_left = 0.0
    if user.session_mfa_at is not None:
        fresh_left = (STEP_UP_FRESHNESS
                      - (datetime.now(user.session_mfa_at.tzinfo) - user.session_mfa_at)
                      ).total_seconds()
    return Me(
        user_id=str(user.user_id),
        display_name=display_name,
        email=email,
        # The COUNT only. Knowing you are down to your last code is
        # actionable; the codes themselves exist in plaintext exactly once,
        # at the moment they are issued.
        recovery_codes_remaining=PgUserStore(conn).count_recovery_codes(user.user_id),
        idle_timeout_seconds=int(IDLE_TIMEOUT.total_seconds()),
        session_expires_in_seconds=max(0, int(left)),
        step_up_fresh_seconds=max(0, int(fresh_left)),
        tlp_clearance=clearance,
    )


class RecoveryCodesOut(BaseModel):
    codes: list[str]
    note: str


@router.post("/recovery-codes", response_model=RecoveryCodesOut,
             dependencies=[Depends(rate_limit("auth.recovery_codes"))])
def issue_recovery_codes(
    request: Request,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> RecoveryCodesOut:
    """Issue a fresh SET of recovery codes, invalidating any previous set
    (docs/05: "10, single-use, Argon2id-hashed, regenerated as a set").

    Step-up protected. Anyone who can reach a live session can otherwise
    mint themselves a permanent MFA bypass, which would make the second
    factor decorative: a stolen session cookie would become ten reusable
    keys that survive the session's own expiry.

    The plaintexts are returned here and are never retrievable again.
    """
    fresh = (
        user.session_mfa_at is not None
        and (datetime.now(user.session_mfa_at.tzinfo) - user.session_mfa_at)
        < STEP_UP_FRESHNESS
    )
    if not fresh:
        _audit(conn, "RECOVERY_CODES_DENIED", user.user_id,
               {"reason": "step_up_required"}, request)
        raise Problem(403, "Forbidden",
                      "re-authenticate with your second factor before "
                      "issuing recovery codes")
    codes = PgUserStore(conn).issue_recovery_codes(user.user_id)
    _audit(conn, "RECOVERY_CODES_ISSUED", user.user_id,
           {"count": len(codes)}, request)
    return RecoveryCodesOut(
        codes=codes,
        note="Store these somewhere safe and offline. Each works once, they "
             "replace any previous set, and they cannot be shown again.",
    )


class PasswordChangeBody(BaseModel):
    current_password: str
    totp_code: str
    new_password: str


# Metered like sign-in, because it IS a credential check: the current
# password and a code are verified here with the same Argon2id work, so an
# unmetered route would be the CPU amplifier and the guessing surface that
# login's two meters exist to close, reachable by anyone holding a session.
@router.post("/password", response_model=dict,
             dependencies=[Depends(rate_limit("auth.login")),
                           Depends(rate_limit_peek("auth.login_failed"))])
def change_own_password(
    body: PasswordChangeBody,
    request: Request,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Change your own password (gap-password-reset, 2026-09-23).

    There was no way for a person to change their own password at all.
    The current password AND a code from the authenticator are required,
    in the request, rather than a step-up window: a session somebody
    walked away from must not be enough to lock its owner out by replacing
    the password, and a code typed now is the freshest proof there is.
    Verified by `AuthService.authenticate`, the sign-in's own reader, so a
    wrong current password here counts toward the account's lockout
    exactly as a wrong sign-in does, and a session thief guessing it is
    stopped by the same five failures.

    A refusal is a 403, not a 401: the session is fine and stays signed
    in, and a 401 would tell the console the session had ended. Which
    factor was wrong is not said, for the reason login does not say it.
    Every other session is signed out (`iam_admin.change_password`); the
    one making the change is kept.
    """
    row = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                       (user.user_id,)).fetchone()
    if row is None:
        raise Problem(401, "Unauthenticated", "session refers to no account")
    email = row[0]
    problem = new_password_problem(body.new_password, email=email,
                                   current=body.current_password)
    if problem:
        raise Problem(422, "Invalid field", problem)
    result = AuthService(PgUserStore(conn)).authenticate(
        email, body.current_password, body.totp_code)
    if result.outcome is AuthOutcome.SECOND_FACTOR_UNAVAILABLE:
        _audit(conn, "PASSWORD_CHANGE_FAILED", user.user_id,
               {"reason": result.audit_reason}, request)
        raise Problem(503, "Service unavailable", SECOND_FACTOR_UNAVAILABLE)
    if not result.ok or result.user_id != user.user_id:
        consume_on_failure(request, "auth.login_failed")
        _audit(conn, "PASSWORD_CHANGE_FAILED", user.user_id,
               {"reason": result.audit_reason}, request)
        raise Problem(403, "Forbidden",
                      "the current password or the code is not right. Five "
                      "failures lock the account for 15 minutes.")
    revoked = change_password(conn, user.user_id, body.new_password,
                              keep_session=user.session_id, via="account")
    return {"changed": True, "other_sessions_signed_out": revoked}
