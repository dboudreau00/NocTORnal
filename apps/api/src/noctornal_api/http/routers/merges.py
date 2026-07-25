"""Entity merge and its reversal over HTTP (docs/01, Phase 6).

docs/01: "Merges require `graph.merge` with step-up auth, and generate an
audit event and a case-owner notification."

The step-up is not decoration. A merge rewrites who did what across the
whole case and is the operation docs/01 names as "most likely to quietly
corrupt a case", so a session someone walked away from must not be enough
to perform one. Reversal is gated the same way for the same reason: undoing
a correct merge is just as destructive as making a wrong one.

The case-owner notification is Phase 5 work and is NOT built; the audit
event is.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require,
    require_step_up,
)
from noctornal_api.http.errors import Problem
from noctornal_api.merges import MergeError, MergeRecord, MergeService

router = APIRouter(prefix="/cases/{case_id}/merges", tags=["merges"])


class MergeBody(BaseModel):
    source_node_id: UUID
    target_node_id: UUID
    reason: str = Field(min_length=1)
    basis_selector_id: UUID | None = None


class ReversalBody(BaseModel):
    reason: str = Field(min_length=1)


class MergeOut(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    reason: str
    merged_at: str
    merged_by: str
    edges_repointed: int
    reversed_at: str | None
    reversal_reason: str | None
    is_live: bool


def _out(m: MergeRecord) -> MergeOut:
    return MergeOut(
        id=str(m.id), source_node_id=str(m.source_node_id),
        target_node_id=str(m.target_node_id), reason=m.reason,
        merged_at=m.merged_at.isoformat(), merged_by=str(m.merged_by),
        edges_repointed=m.edges_repointed,
        reversed_at=m.reversed_at.isoformat() if m.reversed_at else None,
        reversal_reason=m.reversal_reason, is_live=m.is_live,
    )


@router.get("", response_model=dict)
def history(
    case_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    _: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every merge in the case, reversed ones included — a reversed merge
    that vanished from the record would hide the fact that somebody once
    believed these were the same actor."""
    return {"merges": [_out(m) for m in MergeService(conn).history(case_id, limit)]}


@router.post("", response_model=MergeOut, status_code=201)
def merge(
    case_id: UUID, body: MergeBody,
    user: CurrentUser = Depends(require("graph.merge")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> MergeOut:
    """Fold one entity into another, reversibly."""
    try:
        return _out(MergeService(conn).merge(
            case_id=case_id, source_node_id=body.source_node_id,
            target_node_id=body.target_node_id, merged_by=user.user_id,
            reason=body.reason, basis_selector_id=body.basis_selector_id))
    except MergeError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@router.post("/{merge_id}/reverse", response_model=MergeOut)
def reverse(
    case_id: UUID, merge_id: UUID, body: ReversalBody,
    user: CurrentUser = Depends(require("graph.unmerge")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> MergeOut:
    """Restore every edge's original endpoints and clear the redirect."""
    record = MergeService(conn).get(merge_id)
    if record is None or record.case_id != case_id:
        raise Problem(404, "Not found", "no such merge in this case")
    try:
        return _out(MergeService(conn).unmerge(
            merge_id, reversed_by=user.user_id, reason=body.reason))
    except MergeError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
