"""Authentication endpoints: password + TOTP login, logout, whoami."""
from __future__ import annotations

from uuid import uuid4

import psycopg
from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

from noctornal_api.http.deps import CurrentUser, current_user, get_conn
from noctornal_api.http.errors import Problem
from noctornal_api.security.auth import AuthService
from noctornal_api.security.sessions import SessionService
from noctornal_api.stores import PgSessionStore, PgUserStore

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str
    totp_code: str | None = None


class LoginResponse(BaseModel):
    token: str  # opaque session token; send as Authorization: Bearer <token>


@router.post("/login", response_model=LoginResponse)
def login(body: LoginBody, response: Response,
          conn: psycopg.Connection = Depends(get_conn)) -> LoginResponse:
    result = AuthService(PgUserStore(conn)).authenticate(
        body.email, body.password, body.totp_code
    )
    if not result.ok:
        # Single generic failure — never reveal which factor was wrong.
        raise Problem(401, "Unauthenticated", "invalid credentials")
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), result.user_id, mfa_satisfied=True
    )
    # Cookie for browser clients (HttpOnly, __Host- prefix requires Secure +
    # Path=/ + no Domain). Bearer token in the body for API clients.
    response.set_cookie("__Host-session", token, httponly=True, secure=True,
                        samesite="strict", path="/")
    return LoginResponse(token=token)


@router.post("/logout", status_code=204)
def logout(user: CurrentUser = Depends(current_user),
           conn: psycopg.Connection = Depends(get_conn)) -> Response:
    SessionService(PgSessionStore(conn)).revoke_all_for_user(user.user_id, "logout")
    return Response(status_code=204)


class Me(BaseModel):
    user_id: str


@router.get("/me", response_model=Me)
def me(user: CurrentUser = Depends(current_user)) -> Me:
    return Me(user_id=str(user.user_id))
