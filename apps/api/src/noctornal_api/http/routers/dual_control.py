"""The deployment's two-person policy over HTTP (F9, 2026-09-24): read
it, propose a change, apply a countersigned one.

Countersigning is not here: it is a decision on a deployment-wide approval
request, made through `/approvals/{id}/decide` like every other, so the
signer's permission, the step-up and the person-level refusals live in one
place (`routers/approvals.py`, `ApprovalService.decide`).

Both reads are open to either side (`dual_control.manage` or
`dual_control.countersign`, both step-up). Proposing and applying are the
administrator's (`dual_control.manage`); a Security officer holding
`dual_control.countersign` reads the screen and signs, and never proposes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.approvals import (
    ApprovalError,
    ApprovalService,
    countersign_block,
)
from noctornal_api.dual_control import (
    COUNTERSIGN,
    MANAGE,
    DualControlPolicyService,
    PolicyError,
)
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require_global,
    require_global_any,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.http.routers.approvals import (
    _held_globally,
    _jsonable,
    _out,
    _request_reach,
)

router = APIRouter(prefix="/admin/dual-control", tags=["admin"])


class ChangeBody(BaseModel):
    change: Literal["OPERATION_MODE", "SEPARATED_DUTY_ADD",
                    "SEPARATED_DUTY_REMOVE"]
    operation: str | None = None
    to: str | None = None
    permission_a: str | None = None
    permission_b: str | None = None
    why: str | None = None
    justification: str = Field(min_length=1)


def _jsonify(value):
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonify(v) for v in value]
    return value


@router.get("", response_model=dict)
def overview(
    user: CurrentUser = Depends(require_global_any(MANAGE, COUNTERSIGN)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Everything the Two-person controls screen draws, and what the caller
    may do there. Counts are over the caller's own cases only (the
    service's docstring says why)."""
    clearance, held = user_ceiling(conn, user.user_id)
    svc = DualControlPolicyService(conn)
    body = svc.overview(user.user_id, clearance=clearance.name,
                        compartments=held)
    mine = _held_globally(conn, user.user_id, [MANAGE, COUNTERSIGN])
    block = (countersign_block(conn, user.user_id, COUNTERSIGN)
             if COUNTERSIGN in mine else None)
    body["you"] = {
        "user_id": str(user.user_id),
        "may_propose": MANAGE in mine,
        # An account holding both is one person, so it never countersigns
        # a change (2026-09-24).
        "may_countersign": COUNTERSIGN in mine and MANAGE not in mine,
        "countersign_block": _jsonable(block),
    }
    return _jsonify(body)


@router.get("/history", response_model=dict)
def history(
    limit: int = Query(100, ge=1, le=500),
    _: CurrentUser = Depends(require_global_any(MANAGE, COUNTERSIGN)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    rows = DualControlPolicyService(conn).history(limit)
    return {"changes": _jsonify(rows)}


@router.post("/changes", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def propose(
    body: ChangeBody,
    user: CurrentUser = Depends(require_global(MANAGE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Propose a change. It raises a deployment-wide approval that a
    Security officer who is not an administrator countersigns; nothing
    changes until the proposer applies it."""
    change = body.model_dump(exclude={"justification"})
    svc = DualControlPolicyService(conn)
    try:
        record = svc.propose(change=change, justification=body.justification,
                             requested_by=user.user_id)
    except (PolicyError, ApprovalError) as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    out = _out(record, reach=_request_reach(record)).model_dump(mode="json")
    clearance, held = user_ceiling(conn, user.user_id)
    out["preview"] = _jsonify(svc.preview(
        record.payload or {}, viewer_id=user.user_id,
        clearance=clearance.name, compartments=held))
    return out


@router.post("/changes/{request_id}/apply", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def apply(
    request_id: UUID,
    user: CurrentUser = Depends(require_global(MANAGE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Put a countersigned change in force. Only its proposer may, once:
    applying spends the countersignature (approvals.py: consuming is the
    requester's job)."""
    # Applying writes the IAM plane (the policy ledger, and through it
    # the operations and separated duties), which the request role may only
    # read (0109, S1 2026-09-25). The ledger binds the approval's consume to
    # the same transaction, so all of it runs on one system connection.
    with system_connection(SystemPurpose.IAM_ADMIN, reuse=conn) as sconn:
        svc = DualControlPolicyService(sconn)
        try:
            result = svc.apply(request_id, actor_id=user.user_id)
        except PolicyError as exc:
            raise Problem(409, "Conflict", safe_detail(exc)) from exc
    approval = ApprovalService(conn).get(request_id)
    return {"change": _jsonify(result["change"]), "effect": result["effect"],
            "approval": _out(approval).model_dump(mode="json")}
