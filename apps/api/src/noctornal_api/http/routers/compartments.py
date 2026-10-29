"""The compartment registry over HTTP (migration 0057).

A key is the lock itself, so listing one tells a reader which operations exist. An ordinary account
sees only the compartments it is read into (key and label); a `user.manage` holder sees the whole
registry with its metadata, and `scope` says which answer this is. Every write is `user.manage`
(SYS_ADMIN). Rename and retire ask for step-up explicitly, as the seed flag is data, and use the
merge limit, since each locks every compartmented table while it runs.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.compartment_lifecycle import (
    CompartmentBusy,
    CompartmentError,
    CompartmentLifecycle,
    NoSuchCompartment,
)
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    current_user,
    get_conn,
    require_global,
    require_step_up,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.http.routers.admin import _refuse
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


#: What an unprivileged caller is told about a compartment it holds. The
#: key is the lock and the label is its name; `created_by` and
#: `created_at` are registry administration and belong to the account that
#: administers the registry.
_HELD_FIELDS = ("key", "label")


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def list_compartments(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The caller's own read-ins, or the whole registry for `user.manage`.

    `scope` is part of the answer, not decoration: the two callers get
    different sets from one URL, and a client that could not tell them
    apart would report "these are the compartments" about whichever it
    happened to receive. See the module docstring for why the whole
    vocabulary is not public.
    """
    svc = IamAdminService(conn)
    if svc.holds_global_permission(user.user_id, "user.manage"):
        rows = svc.list_compartments()
        scope = "all"
    else:
        rows = [{k: c[k] for k in _HELD_FIELDS}
                for c in svc.list_compartments(held_by=user.user_id)]
        scope = "held"
    return {"compartments": rows, "scope": scope, "count": len(rows)}


@router.post("", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def register_compartment(
    body: RegisterBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        # An IAM write, so on a system connection (0109).
        with system_connection(SystemPurpose.IAM_ADMIN, reuse=conn) as sconn:
            return IamAdminService(sconn).register_compartment(
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
        # An IAM write, so on a system connection (0109).
        with system_connection(SystemPurpose.IAM_ADMIN, reuse=conn) as sconn:
            held = IamAdminService(sconn).set_compartments(
                user_id, body.compartments, actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "compartments": held}


class RenameBody(BaseModel):
    new_key: str
    #: Optional: the label is kept unless a new one is given.
    label: str | None = None


def _lifecycle_refusal(exc: CompartmentError) -> Problem:
    """404 for a key that is not registered, 409 for a rule (in use, onto
    a registered key, busy). The busy refusal carries Retry-After, because
    it is the one that asking again later will fix."""
    detail = safe_detail(exc)
    if isinstance(exc, NoSuchCompartment):
        return Problem(404, "Not found", detail)
    if isinstance(exc, CompartmentBusy):
        return Problem(409, "Busy", detail, headers={"Retry-After": "30"})
    return Problem(409, "Conflict", detail)


@router.post("/{key}/rename", response_model=dict,
             dependencies=[Depends(rate_limit("merge"))])
def rename_compartment(
    key: str, body: RenameBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Rename a registered key everywhere it is used, in one transaction.
    Who holds it and what it locks do not change; see
    `compartment_lifecycle.py`."""
    try:
        # A rename must reach every row that carries the key, above the administrator's own labels
        # too, and writes the registry: a system purpose.
        with system_connection(SystemPurpose.COMPARTMENTS, reuse=conn) as sconn:
            return CompartmentLifecycle(sconn).rename(
                key, body.new_key, label=body.label, actor_id=user.user_id)
    except CompartmentError as exc:
        raise _lifecycle_refusal(exc) from exc


@router.post("/{key}/retire", response_model=dict,
             dependencies=[Depends(rate_limit("merge"))])
def retire_compartment(
    key: str,
    user: CurrentUser = Depends(require_global("user.manage")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Drop a registered key nothing carries. A key still carried is
    refused, and the refusal counts every kind of row that carries it and
    names only the accounts, cases and ingest keys the caller can already
    see: `user.manage` is not a case role, and a case code is not told to
    somebody who cannot open the case (`compartment_lifecycle.py`)."""
    try:
        # "Nothing carries it" must be true of every row, not of the rows the administrator may
        # read: a system purpose.
        with system_connection(SystemPurpose.COMPARTMENTS, reuse=conn) as sconn:
            return CompartmentLifecycle(sconn).retire(key, actor_id=user.user_id)
    except CompartmentError as exc:
        raise _lifecycle_refusal(exc) from exc
