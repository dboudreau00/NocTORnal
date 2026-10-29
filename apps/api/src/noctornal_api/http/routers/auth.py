"""Authentication endpoints: password + TOTP login, logout, whoami.

Every outcome is audited (docs/05 requires authentication success AND
failure): a brute-force campaign or a successful credential-stuffing login
must leave a trace in a system whose premise is that "who did what" is
answerable.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone
from uuid import uuid4

import psycopg
from fastapi import APIRouter, Depends, Request, Response
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.db import SystemContextUnavailable, SystemPurpose, system_connection
from noctornal_api.http.deps import (
    COOKIE_ATTRS,
    CSRF_COOKIE,
    SESSION_COOKIE,
    CurrentUser,
    current_user,
    get_conn,
    note_system_fallback,
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
    # Bounded: this route is unauthenticated and a failed attempt is audited. 254 is the longest
    # address SMTP carries; the passwords leave room above MAX_PASSWORD_LENGTH so the policy, not
    # the parser, words that refusal.
    email: str = Field(max_length=254)
    password: str = Field(max_length=4096)
    totp_code: str | None = Field(default=None, max_length=64)
    # The password the person chooses, sent only when the server has said it must be changed
    # (0066). Absent on every ordinary sign-in.
    new_password: str | None = Field(default=None, max_length=4096)


#: How much of a submitted address a failed sign-in records verbatim.
AUDIT_EMAIL_CHARS = 64


#: What an address looks like, and no more: one `@`, no whitespace, and a
#: dot in the domain with something on each side of it. A shape test, not
#: a validator; it exists to tell an address from something typed into the
#: wrong box.
_ADDRESS_SHAPE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


def _audit_email(email: str) -> dict:
    """The submitted address as a failed sign-in records it in the append-only log.

    Verbatim up to AUDIT_EMAIL_CHARS when shaped like an address; past that the head, the length
    and a sha256 prefix, so one unauthenticated request cannot write a huge permanent row and
    repeated submissions can still be told apart. Anything else records only its length and the
    prefix, because people type passwords into the sign-in box by mistake; an address-shaped
    password is the residual docs/17 records."""
    if not _ADDRESS_SHAPE.fullmatch(email):
        return {"email_length": len(email),
                "email_sha256": hashlib.sha256(email.encode()).hexdigest()[:16]}
    if len(email) <= AUDIT_EMAIL_CHARS:
        return {"email": email}
    return {"email": email[:AUDIT_EMAIL_CHARS], "email_length": len(email),
            "email_sha256": hashlib.sha256(email.encode()).hexdigest()[:16]}


def _ip_hash(request: Request) -> bytes | None:
    """The address the audit row names is the one the session is bound to.

    `client_ip` (the peer, or the outermost trusted proxy's client when
    `NOCTORNAL_TRUSTED_PROXY_HOPS` says so) is what the binding (0058) and the rate limiter read;
    `request.client.host` behind a proxy would be the load balancer.
    """
    ip = client_ip(request)
    if ip is None:
        return None
    return hashlib.sha256(ip.encode()).digest()


def _audit(conn, action: str, actor_id, detail: dict, request: Request,
           *, outcome: str = "SUCCESS") -> None:
    # `outcome`: a failed sign-in is DENIED, not the column's default SUCCESS.
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail,
                ip_hash, outcome)
           VALUES (%s, %s, %s, 'auth', NULL, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, Json(detail),
         _ip_hash(request), outcome),
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
    """Sign in: 204 and the cookie pair, no body; the credential leaves only as `__Host-session`.

    Two IP-scoped meters run before the Argon2id verify: `auth.login` caps the hashing work per
    source, and `auth.login_failed` is peeked here and consumed only on a failure, so many analysts
    behind one egress address never move it. Neither is keyed by email, which would let anyone lock
    out a named analyst; targeted guessing is the account lockout's job.
    """
    # Sign-in writes the IAM plane (the lockout and TOTP counters, a recovery code, the new
    # session, the sign-in stamp), which the request role may only read (0109), so it runs on a
    # system connection; in development and the suite that is this request's own connection.
    with system_connection(SystemPurpose.AUTH, reuse=conn) as sconn:
        return _login(body, request, sconn)


def _login(body: LoginBody, request: Request,
           conn: psycopg.Connection) -> Response:
    """`login`'s body, on the connection that may write the IAM plane."""
    # A chosen password is judged BEFORE the credentials are, so a rule
    # failure spends no lockout attempt and no authenticator code, and
    # says nothing about the account (it depends on nothing stored).
    if body.new_password is not None:
        problem = new_password_problem(body.new_password, email=body.email,
                                       current=body.password)
        if problem:
            raise Problem(422, "Invalid field", problem)
    # A recovery code is checked here and spent only once the sign-in is known to go ahead
    # (`spend`, below), so the must-change and no-change-pending refusals do not cost the person a
    # single-use code.
    service = AuthService(PgUserStore(conn))
    result = service.authenticate(
        body.email, body.password, body.totp_code, spend_recovery=False
    )
    if result.outcome is AuthOutcome.SECOND_FACTOR_UNAVAILABLE:
        # The password verified but the stored second factor could not be opened under any key this
        # process holds. Not a credential failure, so neither the failure meter nor the lockout is
        # touched; audited under its own reason and answered as a server fault naming the
        # readiness check that explains it.
        _audit(conn, "AUTH_FAILED", result.user_id,
               {"reason": result.audit_reason, **_audit_email(body.email)},
               request, outcome="DENIED")
        raise Problem(503, "Service unavailable", SECOND_FACTOR_UNAVAILABLE)
    if not result.ok:
        consume_on_failure(request, "auth.login_failed")
        # The specific cause is audited server-side and NEVER returned —
        # a distinct response would confirm which factor was right.
        _audit(conn, "AUTH_FAILED", result.user_id,
               {"reason": result.audit_reason, **_audit_email(body.email)},
               request, outcome="DENIED")
        raise Problem(401, "Unauthenticated", "invalid credentials")
    must_change = _password_change_due(conn, result.user_id, body, request)
    if not service.spend(result):
        # A concurrent sign-in spent the recovery code verified above first. The same answer and
        # trace as a spent code gets inside `authenticate`; nothing has changed yet, the new
        # password included.
        consume_on_failure(request, "auth.login_failed")
        _audit(conn, "AUTH_FAILED", None,
               {"reason": "bad_recovery_code", **_audit_email(body.email)},
               request, outcome="DENIED")
        raise Problem(401, "Unauthenticated", "invalid credentials")
    if must_change:
        change_password(conn, result.user_id, body.new_password,
                        keep_session=None, via="sign-in after a reset")
    # Where the session was minted (0058): `client_ip`, the outermost trusted proxy's client when
    # NOCTORNAL_TRUSTED_PROXY_HOPS says so, because a binding to the proxy's own address would
    # match every replay that came through it.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), result.user_id, mfa_satisfied=True,
        ip=client_ip(request), user_agent=request.headers.get("user-agent"),
    )
    # The Admin card's "last password sign-in" is stamped only here, where a session exists.
    PgUserStore(conn).record_sign_in(result.user_id, datetime.now(timezone.utc))
    _audit(conn, "AUTH_SUCCEEDED", result.user_id, {}, request)
    response = Response(status_code=204)
    # The whole of a successful login: the HttpOnly session cookie and the readable CSRF cookie,
    # the double-submit half docs/05 requires. No token in the body, so no script in the browser
    # can read the session token. Bearer use is unaffected: `deps.session_token` prefers
    # `Authorization: Bearer`, a script client reads the token off `Set-Cookie`, and
    # `scripts/bootstrap.py session` mints one through `SessionService`, never through here.
    _set_session_cookies(response, token)
    return response


def _password_change_due(conn, user_id, body: LoginBody,
                         request: Request) -> bool:
    """The must-change rule, at the one door a session comes through.

    A password an administrator issued (a reset, or a new account's) is known to whoever issued
    it, so it never opens a session. Reached only after both factors verified:

    - flag set, no new password: 403 `PASSWORD_CHANGE_REQUIRED_TYPE` and no session; the TOTP code
      is spent, a recovery code is not;
    - flag set and a new password: True; `login` stores it and clears the flag in one statement;
    - no flag but a new password: 409, rather than leave the person believing it changed.

    The only check of the flag in the API, which is enough: `reset_password` revokes every session.
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
    # The revoke ended this connection's binding, and the database attributes a request-role row
    # only to the user its connection is bound to (0150), so the sign-out is written by the system
    # role, as sign-in is. With none to hand the row is written here and demoted, not lost.
    try:
        with system_connection(SystemPurpose.AUTH, reuse=conn) as sconn:
            _audit(sconn, "AUTH_LOGOUT", user.user_id,
                   {"session_id": str(user.session_id)}, request)
    except SystemContextUnavailable as exc:
        note_system_fallback(exc, "AUTH_LOGOUT")
        _audit(conn, "AUTH_LOGOUT", user.user_id,
               {"session_id": str(user.session_id)}, request)
    response = Response(status_code=204)
    # Clear the cookies with the attributes they were set with: a browser ignores a `__Host-`
    # cookie deletion without Secure, and the dead token would ride along on every later request.
    _clear_session_cookies(response)
    return response


@router.post("/cookie", status_code=204)
def adopt_cookie(request: Request,
                 raw: str = Depends(session_token),
                 user: CurrentUser = Depends(current_user),
                 conn: psycopg.Connection = Depends(get_conn)) -> Response:
    """Set the cookie pair for the session the caller is already presenting.

    Serves the `#token=` hand-off from `scripts/bootstrap.py session`: the console exchanges the
    token here once, so the session survives a reload without the token in web storage. Nothing is
    minted, so a success is not audited as an authentication. A bearer arriving beside a live
    cookie session for a different account is refused with 409 and audited: a link carrying
    someone else's token would otherwise swap the analyst's open tabs onto that session. A cookie
    for the same account, or one the server does not honour, is overwritten freely.
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
                   request, outcome="DENIED")
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
    display_name: str
    email: str
    recovery_codes_remaining: int
    # The session's two limits, so the console can warn before either. This request has just
    # slid the idle window, so it is the full timeout; the absolute limit is a distance, not a
    # timestamp, because the browser's clock need not agree with this one.
    idle_timeout_seconds: int
    session_expires_in_seconds: int
    # How much longer this session satisfies the step-up gate (a second factor within
    # STEP_UP_FRESHNESS), 0 once it does not. The console asks for a fresh sign-in before a gated
    # request rather than after its 403, because each refused POST /auth/recovery-codes spends a
    # token of that route's rate limit.
    step_up_fresh_seconds: int
    # The account's own clearance, so the app bar can say what this person may open ("cleared
    # RED") beside their role on the case.
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
    # Through the definer: the request role may not read the hashes it counts. None means the
    # connection is not bound to this account any more, a session revoked while this request ran.
    remaining = PgUserStore(conn).recovery_codes_remaining(user.user_id)
    if remaining is None:
        raise Problem(401, "Unauthenticated", "invalid or expired session")
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
        recovery_codes_remaining=remaining,
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
    """Issue a fresh set of recovery codes, invalidating any previous set (docs/05).

    Step-up protected, or a stolen session could mint ten second factors that outlive it. The
    plaintexts are returned here and are never retrievable again.
    """
    fresh = (
        user.session_mfa_at is not None
        and (datetime.now(user.session_mfa_at.tzinfo) - user.session_mfa_at)
        < STEP_UP_FRESHNESS
    )
    if not fresh:
        _audit(conn, "RECOVERY_CODES_DENIED", user.user_id,
               {"reason": "step_up_required"}, request, outcome="DENIED")
        raise Problem(403, "Forbidden",
                      "re-authenticate with your second factor before "
                      "issuing recovery codes")
    # An IAM write, so on a system connection (0109).
    with system_connection(SystemPurpose.AUTH, reuse=conn) as sconn:
        codes = PgUserStore(sconn).issue_recovery_codes(user.user_id)
    _audit(conn, "RECOVERY_CODES_ISSUED", user.user_id,
           {"count": len(codes)}, request)
    return RecoveryCodesOut(
        codes=codes,
        note="Store these somewhere safe and offline. Each works once, they "
             "replace any previous set, and they cannot be shown again.",
    )


class PasswordChangeBody(BaseModel):
    # Bounded as LoginBody is.
    current_password: str = Field(max_length=4096)
    totp_code: str = Field(max_length=64)
    new_password: str = Field(max_length=4096)


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
    """Change your own password.

    Takes the current password and an authenticator code in the request, not a step-up window, so
    an abandoned session cannot lock its owner out. Checked by `AuthService.authenticate`, so a
    wrong password counts toward the lockout as at sign-in. A refusal is a 403 that does not say
    which factor was wrong; a 401 would tell the console the session had ended. Every other
    session is signed out; this one is kept.
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
    # The credential check and the change both write the IAM plane (lockout and TOTP counters, the
    # password, other sessions revoked), so they run on a system connection (0109).
    with system_connection(SystemPurpose.AUTH, reuse=conn) as sconn:
        return _change_own_password(body, request, user, conn, sconn, email)


def _change_own_password(body: PasswordChangeBody, request: Request,
                         user: CurrentUser, conn: psycopg.Connection,
                         sconn: psycopg.Connection, email: str) -> dict:
    """The rest of `change_own_password`: IAM writes on `sconn`, audits on
    `conn` as before."""
    result = AuthService(PgUserStore(sconn)).authenticate(
        email, body.current_password, body.totp_code)
    if result.outcome is AuthOutcome.SECOND_FACTOR_UNAVAILABLE:
        _audit(conn, "PASSWORD_CHANGE_FAILED", user.user_id,
               {"reason": result.audit_reason}, request, outcome="DENIED")
        raise Problem(503, "Service unavailable", SECOND_FACTOR_UNAVAILABLE)
    if not result.ok or result.user_id != user.user_id:
        consume_on_failure(request, "auth.login_failed")
        _audit(conn, "PASSWORD_CHANGE_FAILED", user.user_id,
               {"reason": result.audit_reason}, request, outcome="DENIED")
        raise Problem(403, "Forbidden",
                      "the current password or the code is not right. Five "
                      "failures lock the account for 15 minutes.")
    revoked = change_password(sconn, user.user_id, body.new_password,
                              keep_session=user.session_id, via="account")
    return {"changed": True, "other_sessions_signed_out": revoked}
