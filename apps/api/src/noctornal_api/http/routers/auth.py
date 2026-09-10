"""Authentication endpoints: password + TOTP login, logout, whoami.

Every outcome is audited (docs/05 requires authentication success AND
failure): a brute-force campaign or a successful credential-stuffing login
must leave a trace in a system whose premise is that "who did what" is
answerable.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime
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
from noctornal_api.security.auth import AuthService
from noctornal_api.security.sessions import STEP_UP_FRESHNESS, SessionService
from noctornal_api.stores import PgSessionStore, PgUserStore

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str
    totp_code: str | None = None


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
    result = AuthService(PgUserStore(conn)).authenticate(
        body.email, body.password, body.totp_code
    )
    if not result.ok:
        consume_on_failure(request, "auth.login_failed")
        # The specific cause is audited server-side and NEVER returned —
        # a distinct response would confirm which factor was right.
        _audit(conn, "AUTH_FAILED", result.user_id,
               {"reason": result.audit_reason, "email": body.email}, request)
        raise Problem(401, "Unauthenticated", "invalid credentials")
    # Where the session was minted (0058). `client_ip` is the rate
    # limiter's view of the peer -- the outermost trusted proxy's client
    # when NOCTORNAL_TRUSTED_PROXY_HOPS says so -- because a binding to the
    # proxy's own address would match every replay that came through the
    # same proxy, which is every replay.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), result.user_id, mfa_satisfied=True,
        ip=client_ip(request), user_agent=request.headers.get("user-agent"),
    )
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


@router.get("/me", response_model=Me)
def me(user: CurrentUser = Depends(current_user),
       conn: psycopg.Connection = Depends(get_conn)) -> Me:
    # Read live from the row rather than from anything the session
    # carries, so an administrator's correction to a name shows up on the
    # analyst's next load and not their next login.
    row = conn.execute(
        "SELECT display_name, email FROM iam.app_user WHERE id = %s",
        (user.user_id,),
    ).fetchone()
    if row is None:
        # A session that resolved a moment ago and now names no account:
        # the row went between the two reads. Say so as an auth failure,
        # not as a 500 the client would retry.
        raise Problem(401, "Unauthenticated", "session refers to no account")
    display_name, email = row
    return Me(
        user_id=str(user.user_id),
        display_name=display_name,
        email=email,
        # The COUNT only. Knowing you are down to your last code is
        # actionable; the codes themselves exist in plaintext exactly once,
        # at the moment they are issued.
        recovery_codes_remaining=PgUserStore(conn).count_recovery_codes(user.user_id),
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
