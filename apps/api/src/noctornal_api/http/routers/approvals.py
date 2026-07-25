"""Four-eyes approval over HTTP: raise a request, decide it, withdraw it,
and set the per-case policy that makes it mandatory.

The one thing this router is really for is the check in `decide`: the
approver must independently hold the operation's own permission and have a
fresh second factor. A second human drawn from a wider pool than the actors
is a witness, not a control -- and a second human whose session has been
sitting unlocked since this morning is not even that.

That check cannot be a `require("...")` dependency, because which
permission is required depends on which operation the request is for. So it
calls `authorize_object` inside the handler, which is the same single
`evaluate()` the dependency would have used (docs/05: authorization is
decided in one place, never re-implemented).
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.approvals import (
    OPERATIONS,
    ApprovalError,
    ApprovalRequest,
    ApprovalService,
)
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    get_conn,
    require,
    require_step_up,
)
from noctornal_api.http.errors import Problem

router = APIRouter(prefix="/cases/{case_id}/approvals", tags=["approvals"])

_STATES = frozenset({"PENDING", "APPROVED", "REJECTED", "WITHDRAWN", "CONSUMED"})


class RequestBody(BaseModel):
    operation: str
    payload: dict
    justification: str = Field(min_length=1)


class DecisionBody(BaseModel):
    approve: bool
    note: str | None = None


class ApprovalOut(BaseModel):
    id: str
    case_id: str | None
    operation: str
    payload: dict
    justification: str
    requested_by: str
    requested_at: datetime
    expires_at: datetime
    state: str
    decided_by: str | None
    decided_at: datetime | None
    decision_note: str | None
    consumed_at: datetime | None
    result_ref: str | None
    #: PENDING but past its expiry. Derived, never stored -- see migration
    #: 0028 on why there is no EXPIRED state and no sweeper.
    is_expired: bool


def _out(r: ApprovalRequest) -> ApprovalOut:
    return ApprovalOut(
        id=str(r.id), case_id=str(r.case_id) if r.case_id else None,
        operation=r.operation, payload=r.payload, justification=r.justification,
        requested_by=str(r.requested_by), requested_at=r.requested_at,
        expires_at=r.expires_at, state=r.state,
        decided_by=str(r.decided_by) if r.decided_by else None,
        decided_at=r.decided_at, decision_note=r.decision_note,
        consumed_at=r.consumed_at,
        result_ref=str(r.result_ref) if r.result_ref else None,
        is_expired=r.is_expired(),
    )


@router.get("", response_model=dict)
def list_approvals(
    case_id: UUID,
    state: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every request in the case, decided ones included. A rejected request
    that vanished would hide the fact that somebody once asked."""
    if state is not None and state not in _STATES:
        raise Problem(400, "Invalid request",
                      f"unknown state {state!r}; one of {', '.join(sorted(_STATES))}")
    rows = ApprovalService(conn).list_for_case(case_id, state=state, limit=limit)
    return {"approvals": [_out(r).model_dump(mode="json") for r in rows],
            "operations": {k: {"permission": v.permission,
                               "description": v.description,
                               "ttl_seconds": int(v.ttl.total_seconds())}
                           for k, v in OPERATIONS.items()}}


@router.post("", response_model=ApprovalOut, status_code=201)
def raise_request(
    case_id: UUID, body: RequestBody,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """Ask for a second signature.

    Gated on the REQUESTER holding the operation's own permission, not just
    case.read: a request from somebody who could never perform the operation
    is noise in an approver's queue, and an approver who is used to
    dismissing noise is an approver who stops reading.
    """
    operation = OPERATIONS.get(body.operation)
    if operation is None:
        raise Problem(400, "Invalid request",
                      f"unknown operation {body.operation!r}; one of "
                      f"{', '.join(sorted(OPERATIONS))}")
    authorize_object(conn, user, case_id=case_id,
                     permission_key=operation.permission)
    try:
        return _out(ApprovalService(conn).request(
            operation=body.operation, case_id=case_id, payload=body.payload,
            justification=body.justification, requested_by=user.user_id))
    except ApprovalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@router.post("/{request_id}/decide", response_model=ApprovalOut)
def decide(
    case_id: UUID, request_id: UUID, body: DecisionBody,
    user: CurrentUser = Depends(require("case.read")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """Approve or reject somebody else's request.

    Three gates, and each one is load-bearing:

    1. `case.read` on this case, from the dependency -- the approver has to
       be on the case at all.
    2. The OPERATION's own permission, checked below. An approver who could
       not perform the action themselves cannot meaningfully judge it, and
       an approval pool wider than the actor pool quietly weakens the
       control it is meant to strengthen.
    3. A fresh second factor. Otherwise the second human is whichever
       laptop was left unlocked.

    The requester-is-not-the-approver rule is enforced in the service AND by
    a CHECK constraint (migration 0028); this endpoint just produces the
    readable error.
    """
    svc = ApprovalService(conn)
    record = svc.get(request_id)
    # Authorization before existence: an unauthorised caller gets the same
    # 404 whether or not the request is real (deps.py rule 2).
    if record is None or record.case_id != case_id:
        raise Problem(404, "Not found", "no such approval request in this case")
    operation = OPERATIONS.get(record.operation)
    if operation is None:
        # A request raised against an operation later removed from the
        # catalogue. Refuse rather than fall back to a weaker permission.
        raise Problem(409, "Conflict",
                      f"operation {record.operation!r} is no longer registered")
    authorize_object(conn, user, case_id=case_id,
                     permission_key=operation.permission)
    try:
        return _out(svc.decide(request_id, decided_by=user.user_id,
                               approve=body.approve, note=body.note))
    except ApprovalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@router.post("/{request_id}/withdraw", response_model=ApprovalOut)
def withdraw(
    case_id: UUID, request_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """The requester changing their mind. Not a decision: a withdrawn
    request never had one, and the record says so."""
    try:
        return _out(ApprovalService(conn).withdraw(request_id, actor_id=user.user_id))
    except ApprovalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


class PolicyBody(BaseModel):
    dual_control_merge: bool | None = None
    #: docs/14 U2. NONE | PRESENCE | COUNT -- see migration 0030.
    withheld_disclosure: str | None = None


class PolicyOut(BaseModel):
    dual_control_merge: bool
    withheld_disclosure: str


_DISCLOSURE = frozenset({"NONE", "PRESENCE", "COUNT"})


policy_router = APIRouter(prefix="/cases/{case_id}/policy", tags=["approvals"])


@policy_router.get("", response_model=PolicyOut)
def get_policy(
    case_id: UUID,
    _: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> PolicyOut:
    row = conn.execute(
        'SELECT dual_control_merge, withheld_disclosure '
        'FROM core."case" WHERE id = %s', (case_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    return PolicyOut(dual_control_merge=bool(row[0]), withheld_disclosure=row[1])


@policy_router.put("", response_model=PolicyOut)
def set_policy(
    case_id: UUID, body: PolicyBody,
    user: CurrentUser = Depends(require("case.update")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> PolicyOut:
    """Turn dual control on or off for this case's merges.

    Step-up gated even though `case.update` is not a step-up permission,
    because turning a control OFF is exactly the action an attacker with a
    borrowed session would want, and the composability of `require_step_up`
    exists for cases where the danger is not captured by the permission row.

    Audited both ways. "When did this case stop requiring two signatures"
    is a question somebody will eventually need answered.
    """
    from psycopg.types.json import Json

    row = conn.execute(
        'SELECT dual_control_merge, withheld_disclosure '
        'FROM core."case" WHERE id = %s', (case_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    current = {"dual_control_merge": bool(row[0]),
               "withheld_disclosure": row[1]}

    if (body.withheld_disclosure is not None
            and body.withheld_disclosure not in _DISCLOSURE):
        raise Problem(400, "Invalid request",
                      f"withheld_disclosure must be one of "
                      f"{', '.join(sorted(_DISCLOSURE))}")

    wanted = {
        "dual_control_merge": (current["dual_control_merge"]
                               if body.dual_control_merge is None
                               else body.dual_control_merge),
        "withheld_disclosure": (body.withheld_disclosure
                                or current["withheld_disclosure"]),
    }
    # One literal statement per setting. docs/05: "Parameterised queries
    # only; no string-built SQL anywhere" -- and a column name interpolated
    # from a dict this function happens to own today is exactly the shape
    # that stops being safe when somebody widens the dict tomorrow.
    _UPDATES = {
        "dual_control_merge":
            'UPDATE core."case" SET dual_control_merge = %s WHERE id = %s',
        "withheld_disclosure":
            'UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
    }
    for setting, value in wanted.items():
        if value == current[setting]:
            continue
        conn.execute(_UPDATES[setting], (value, case_id))
        conn.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', 'CASE_POLICY_CHANGED', 'case', %s, %s, %s)""",
            (user.user_id, case_id, case_id,
             Json({"setting": setting, "from": current[setting], "to": value})))
    return PolicyOut(**wanted)
