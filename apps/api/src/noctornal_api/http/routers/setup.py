"""First-run setup: the one door that exists only while the house is empty.

A fresh install used to require shelling into the server, exporting
`DATABASE_URL` and the TOTP KEK, and running `bootstrap.py create-user` —
before anyone could so much as sign in. This router replaces that first
hurdle and ONLY that hurdle: `POST /setup/first-admin` works exactly while
`iam.app_user` has zero rows, and answers 409 forever after.

## Why this is safe to leave unauthenticated

- The gate is the emptiness of the user table itself, checked under an
  advisory lock in the same transaction as the insert — two concurrent
  first-runs cannot both win, and the loser gets the 409.
- It counts EVERY row, active or not. A deployment with one deactivated
  account is locked out, not fresh; re-opening this door for it would let
  anyone on the network become its administrator. That state is repaired
  from the database shell, deliberately.
- Rate-limited with the login limiter: the status probe is cheap but not
  free, and the create endpoint is a password generator.

The first account gets SYS_ADMIN (someone must manage users),
SECURITY_OFFICER (break-glass refuses to grant until one exists), and
CASE_OWNER + ANALYST (a fresh single-operator install IS the operator).
Credentials are returned once and are not retrievable afterwards.
"""
from __future__ import annotations

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.http.deps import get_conn
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.iam_admin import AdminError, create_first_admin, needs_setup

router = APIRouter(prefix="/setup", tags=["setup"])


class FirstAdminBody(BaseModel):
    email: str = Field(min_length=3)
    display_name: str = Field(min_length=1)


@router.get("/status", response_model=dict,
            dependencies=[Depends(rate_limit("auth.login"))])
def status(conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """One boolean. Whether accounts EXIST is not a secret — the sign-in
    page's existence says as much — and nothing else leaks."""
    return {"needs_setup": needs_setup(conn)}


@router.post("/first-admin", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("auth.login"))])
def first_admin(
    body: FirstAdminBody,
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        creds = create_first_admin(conn, email=body.email,
                                   display_name=body.display_name)
    except AdminError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {
        "user_id": str(creds.user_id),
        "email": creds.email,
        "password": creds.password,
        "totp_secret": creds.totp_secret,
        "otpauth_uri": creds.otpauth_uri,
        "notice": ("Shown once and not recoverable. Put the secret in your "
                   "authenticator before leaving this page, then sign in "
                   "below."),
    }
