"""Analyst account administration over HTTP (`user.manage`, step-up).

Every route here is gated on `user.manage`, which the seed grants to
SYS_ADMIN alone and marks step-up — `require_global` enforces both, so a
stale session cannot mint accounts.

Credentials appear ONCE, in the response that generated them, and no
route returns an existing secret. The response says so, because an
administrator who believes they can fetch that password again will close
the tab.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.http.deps import CurrentUser, get_conn, require_global
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.iam_admin import AdminError, IamAdminService, OneTimeCredentials

router = APIRouter(prefix="/admin/users", tags=["admin"])


class CreateBody(BaseModel):
    email: str = Field(min_length=3)
    display_name: str = Field(min_length=1)
    clearance: str = "AMBER"
    roles: list[str] = Field(default_factory=lambda: ["ANALYST"])


class ClearanceBody(BaseModel):
    clearance: str


class RoleBody(BaseModel):
    role: str


def _refuse(exc: AdminError) -> Problem:
    """409 for a rule, 404 for a user that is not there.

    Every route used to answer 409 Conflict, so naming a user id that does
    not exist reported "Conflict" — a refusal about state, for a request
    about a thing that has no state. Only the two role routes could
    produce it, and they produced it two different wrong ways: grant let a
    raw ForeignKeyViolation reach the catch-all as a 500, and revoke
    deleted nothing and answered 200 "revoked".
    """
    detail = safe_detail(exc)
    if "no such user" in str(exc):
        return Problem(404, "Not found", detail)
    return Problem(409, "Conflict", detail)


def _credentials(c: OneTimeCredentials) -> dict:
    return {
        "user_id": str(c.user_id),
        "email": c.email,
        "password": c.password or None,
        "totp_secret": c.totp_secret,
        "otpauth_uri": c.otpauth_uri,
        "notice": ("Shown once. Neither the password nor the TOTP secret "
                   "is stored in a recoverable form, and no endpoint "
                   "returns them again — hand them over now or re-enrol."),
    }


@router.get("", response_model=dict)
def list_users(
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    users = IamAdminService(conn).list_users()
    return {"users": users, "count": len(users),
            # The caller's own id, so the UI can disable self-footguns
            # client-side. The server refuses them regardless.
            "you": str(user.user_id)}


@router.post("", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("auth.recovery_codes"))])
def create_user(
    body: CreateBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        creds = IamAdminService(conn).create_analyst(
            email=body.email, display_name=body.display_name,
            clearance=body.clearance, roles=body.roles,
            actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return _credentials(creds)


@router.post("/{user_id}/deactivate", response_model=dict)
def deactivate(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).set_active(user_id, active=False,
                                         actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "is_active": False,
            "notice": "Their sessions are revoked; the account and its "
                      "history remain."}


@router.post("/{user_id}/reactivate", response_model=dict)
def reactivate(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).set_active(user_id, active=True,
                                         actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "is_active": True}


@router.post("/{user_id}/clearance", response_model=dict)
def set_clearance(
    user_id: UUID, body: ClearanceBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).set_clearance(user_id, clearance=body.clearance,
                                            actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "tlp_clearance": body.clearance}


@router.post("/{user_id}/roles", response_model=dict)
def grant_role(
    user_id: UUID, body: RoleBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).grant_role(user_id, role=body.role,
                                         actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "granted": body.role.upper()}


@router.delete("/{user_id}/roles/{role}", response_model=dict)
def revoke_role(
    user_id: UUID, role: str,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).revoke_role(user_id, role=role,
                                          actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "revoked": role.upper()}


# Same meter as recovery codes: both mint a credential in a loop
# an impatient operator will happily click.
@router.post("/{user_id}/totp", response_model=dict,
             dependencies=[Depends(rate_limit("auth.recovery_codes"))])
def reenrol_totp(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        creds = IamAdminService(conn).reenrol_totp(user_id,
                                                   actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return _credentials(creds)


@router.post("/{user_id}/unlock", response_model=dict)
def unlock(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).unlock(user_id, actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "unlocked": True}
