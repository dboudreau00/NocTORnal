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
    CSRF_COOKIE,
    SESSION_COOKIE,
    CurrentUser,
    current_user,
    get_conn,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import consume_on_failure, rate_limit, rate_limit_peek
from noctornal_api.security.auth import AuthService
from noctornal_api.security.sessions import STEP_UP_FRESHNESS, SessionService
from noctornal_api.stores import PgSessionStore, PgUserStore

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str
    totp_code: str | None = None


class LoginResponse(BaseModel):
    token: str  # opaque session token; send as Authorization: Bearer <token>


def _ip_hash(request: Request) -> bytes | None:
    client = request.client
    if client is None:
        return None
    return hashlib.sha256(client.host.encode()).digest()


def _audit(conn, action: str, actor_id, detail: dict, request: Request) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail, ip_hash)
           VALUES (%s, %s, %s, 'auth', NULL, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, Json(detail),
         _ip_hash(request)),
    )


@router.post("/login", response_model=LoginResponse,
             dependencies=[Depends(rate_limit("auth.login")),
                           Depends(rate_limit_peek("auth.login_failed"))])
def login(body: LoginBody, request: Request, response: Response,
          conn: psycopg.Connection = Depends(get_conn)) -> LoginResponse:
    """Metered twice, both IP-scoped, and both checked before the Argon2id
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
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), result.user_id, mfa_satisfied=True
    )
    _audit(conn, "AUTH_SUCCEEDED", result.user_id, {}, request)
    # Cookie for browser clients (HttpOnly; the __Host- prefix requires
    # Secure + Path=/ + no Domain). The paired readable CSRF cookie is the
    # double-submit half required by docs/05 — deps.session_token demands a
    # matching header for cookie-authenticated unsafe methods.
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=True,
                        samesite="strict", path="/")
    response.set_cookie(CSRF_COOKIE, secrets.token_urlsafe(32), httponly=False,
                        secure=True, samesite="strict", path="/")
    return LoginResponse(token=token)


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
    # Clear the cookies so the browser stops presenting a dead token.
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
    return response


class Me(BaseModel):
    user_id: str
    recovery_codes_remaining: int


@router.get("/me", response_model=Me)
def me(user: CurrentUser = Depends(current_user),
       conn: psycopg.Connection = Depends(get_conn)) -> Me:
    return Me(
        user_id=str(user.user_id),
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
