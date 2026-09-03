"""The assumptions register over HTTP (docs/08 Phase 6).

Thin: the rules are in `assumptions.py`. What this router decides is WHO:

- listing is `case.read`, because an analyst assigned to a case must be
  able to see what its findings rest on -- that is the point of writing
  them down;
- making, reviewing and withdrawing are `case.update`, because an
  assumption is a statement about the case at the case's own level, and
  the seed does not give ANALYST `case.update`. An analyst who disagrees
  with a premise raises it with the owner; they do not edit the register.

Both go through `require()`, so every request passes the five-part gate,
and a denial is a 403 that reveals nothing about which check failed.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.assumptions import STATUSES, AssumptionError, AssumptionService
from noctornal_api.http.deps import CurrentUser, get_conn, require
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/assumptions", tags=["assumptions"])


class AssumptionBody(BaseModel):
    statement: str = Field(min_length=1)
    basis: str | None = None


class ReviewBody(BaseModel):
    """`status` is any of the four; WITHDRAWN is routed to the register's
    own verb for it, so a client has one PATCH and the service keeps its
    distinction between a judgement and a retraction."""
    status: str
    note: str | None = None


def _refuse(exc: AssumptionError) -> Problem:
    """404 for an id that is not in this case, 400 for a rule."""
    detail = safe_detail(exc)
    if "no such assumption" in str(exc):
        return Problem(404, "Not found", detail)
    return Problem(400, "Invalid request", detail)


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def list_assumptions(
    case_id: UUID,
    include_withdrawn: bool = Query(False),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    rows = AssumptionService(conn).list(case_id, include_withdrawn=include_withdrawn)
    return {"assumptions": [r.as_dict() for r in rows], "count": len(rows)}


@router.post("", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def make_assumption(
    case_id: UUID, body: AssumptionBody,
    user: CurrentUser = Depends(require("case.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        assumption_id = AssumptionService(conn).create(
            case_id, statement=body.statement, basis=body.basis,
            made_by=user.user_id)
    except AssumptionError as exc:
        raise _refuse(exc) from exc
    return {"id": str(assumption_id), "status": "OPEN"}


@router.patch("/{assumption_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def review_assumption(
    case_id: UUID, assumption_id: UUID, body: ReviewBody,
    user: CurrentUser = Depends(require("case.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    if body.status not in STATUSES:
        raise Problem(400, "Invalid request",
                      f"status must be one of {', '.join(STATUSES)}")
    svc = AssumptionService(conn)
    try:
        if body.status == "WITHDRAWN":
            row = svc.withdraw(case_id, assumption_id,
                               withdrawn_by=user.user_id, note=body.note)
        else:
            row = svc.update_status(case_id, assumption_id, status=body.status,
                                    reviewed_by=user.user_id, note=body.note)
    except AssumptionError as exc:
        raise _refuse(exc) from exc
    return row.as_dict()
