"""The compartment registry over HTTP (migration 0057).

Reading the vocabulary is open to any authenticated user: it is the list
an analyst needs in order to ask for the right read-in, and a KEY is not
a secret -- a case's contents are. Writing it, and setting what a user
holds, is `user.manage` (SYS_ADMIN, step-up), like every other change to
what an account can see.

The user-side write is here rather than in `routers/admin.py` so that
the registry and the two things gated on it ship as one surface; the
refusal mapping mirrors admin's (`409` for a rule, `404` for a user that
is not there) and is deliberately the same shape, so a client that knows
one knows both.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.http.deps import CurrentUser, current_user, get_conn, require_global
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.iam_admin import AdminError, IamAdminService

router = APIRouter(prefix="/compartments", tags=["compartments"])


class RegisterBody(BaseModel):
    key: str
    label: str = Field(min_length=1)


class UserCompartmentsBody(BaseModel):
    """The COMPLETE set the user should hold afterwards. A set, not a
    delta, so a stale panel that re-submits what it last saw cannot
    silently add or remove a read-in it did not know about."""
    compartments: list[str]


def _refuse(exc: AdminError) -> Problem:
    """409 for a rule, 404 for a user that is not there -- the same split
    `routers/admin.py` makes, for the same reason: naming a user id that
    does not exist is not a conflict about state."""
    detail = safe_detail(exc)
    if "no such user" in str(exc):
        return Problem(404, "Not found", detail)
    return Problem(409, "Conflict", detail)


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def list_compartments(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    rows = IamAdminService(conn).list_compartments()
    return {"compartments": rows, "count": len(rows)}


@router.post("", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def register_compartment(
    body: RegisterBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return IamAdminService(conn).register_compartment(
            key=body.key, label=body.label, actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc


@router.put("/users/{user_id}", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def set_user_compartments(
    user_id: UUID, body: UserCompartmentsBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        held = IamAdminService(conn).set_compartments(
            user_id, body.compartments, actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "compartments": held}
