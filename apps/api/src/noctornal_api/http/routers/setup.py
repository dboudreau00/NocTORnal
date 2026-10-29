"""First-run setup: the one door that exists only while the house is empty.

`POST /setup/first-admin` works exactly while `iam.app_user` has no rows, active or not, and
answers 409 for ever after; production also needs the setup token (`http/setup_token.py`). The
emptiness check runs under an advisory lock in the insert's transaction, so two first-runs cannot
both win. A deployment whose accounts are all deactivated is locked out, not fresh, and is
repaired from the database shell: reopening the door would hand it to anyone on the network. Both
routes use the login limiter. The first account gets SYS_ADMIN, SECURITY_OFFICER (break-glass
grants nothing until one exists), CASE_OWNER and ANALYST; its credentials are returned once.
"""
from __future__ import annotations

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import get_conn
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit, rate_limit_peek
from noctornal_api.http.setup_token import (
    door_closed,
    require_setup_door,
    token_required,
)
from noctornal_api.iam_admin import AdminError, create_first_admin, needs_setup

router = APIRouter(prefix="/setup", tags=["setup"])


class FirstAdminBody(BaseModel):
    # Bounded: unauthenticated input.
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=200)


@router.get("/status", response_model=dict,
            dependencies=[Depends(rate_limit("auth.login"))])
def status(conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Whether the first-run door can be used, and whether it needs a token. Whether accounts
    exist is not a secret (the sign-in page says as much), and nothing else leaks.

    `needs_setup` is true only while the door can be used: a production deployment with no setup
    token has no web first-run (`http/setup_token.py`), so it never invites the card.
    `setup_token_required` tells the card to ask for the token."""
    return {"needs_setup": needs_setup(conn) and not door_closed(),
            "setup_token_required": token_required()}


@router.post("/first-admin", response_model=dict, status_code=201,
             # The token after the meters, so a guessed token is counted and, as for a password,
             # refused once the failure meter is spent, and before the body is validated, so a
             # caller without it learns nothing from a 422.
             dependencies=[Depends(rate_limit("auth.login")),
                           Depends(rate_limit_peek("auth.login_failed")),
                           Depends(require_setup_door)])
def first_admin(
    body: FirstAdminBody,
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        # Creating an account is an IAM write, which the request role may only read (migration
        # 0109), so it runs on a system connection.
        with system_connection(SystemPurpose.IAM_ADMIN, reuse=conn) as sconn:
            creds = create_first_admin(sconn, email=body.email,
                                       display_name=body.display_name)
    except AdminError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {
        "user_id": str(creds.user_id),
        "email": creds.email,
        "password": creds.password,
        "totp_secret": creds.totp_secret,
        "otpauth_uri": creds.otpauth_uri,
        # The console signs in on the card itself.
        "notice": ("Shown once and not recoverable. Put the secret in your "
                   "authenticator and keep the password safe, then sign in "
                   "with both on this page. They stay here until that "
                   "works."),
    }
