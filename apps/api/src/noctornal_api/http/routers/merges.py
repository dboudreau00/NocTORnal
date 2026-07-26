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

**Dual control** (migration 0028, `approvals.py`) is a PER-CASE switch,
default off. docs/05 scopes dual control to "the genuinely irreversible",
and a merge here is the most reversible destructive-looking operation in
the system — a ledger with an exact restore. Entity resolution is also the
daily work of this tool, so a second signature on every merge in a case
with three hundred personas is a control that gets switched off in week two.
On, it is one switch for the case whose subject warrants the friction.

Reversal is deliberately NOT dual-controlled even when merging is. Undoing
a merge restores the pre-merge state; requiring two humans to correct a
mistake is how mistakes stay in a case file.
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
from noctornal_api.approvals import (
    ApprovalError,
    ApprovalService,
    case_requires_dual_control,
)
from noctornal_api.http.limits import rate_limit
from noctornal_api.merges import MergeError, MergeRecord, MergeService

router = APIRouter(prefix="/cases/{case_id}/merges", tags=["merges"])


class MergeBody(BaseModel):
    """Under dual control ONLY `approval_request_id` is read.

    The merge then executes the parameters recorded on the approval, not the
    ones in this body. That is not belt and braces, it is the whole control:
    if the body were authoritative, an analyst could get a nod for merging
    two obviously-identical spam bots and then post the ids of the two nodes
    the case actually turns on.
    """

    source_node_id: UUID | None = None
    target_node_id: UUID | None = None
    reason: str | None = Field(default=None, min_length=1)
    basis_selector_id: UUID | None = None
    approval_request_id: UUID | None = None


def merge_payload(source_node_id: UUID, target_node_id: UUID, reason: str,
                  basis_selector_id: UUID | None) -> dict:
    """The canonical parameter set an approval is taken over.

    The reason is included: it is what the approver read, and a merge whose
    recorded reason is not the one that was signed off makes the audit log
    say something nobody agreed to.
    """
    return {
        "source_node_id": str(source_node_id),
        "target_node_id": str(target_node_id),
        "reason": reason.strip(),
        "basis_selector_id": str(basis_selector_id) if basis_selector_id else None,
    }


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


@router.post("", response_model=MergeOut, status_code=201,
             dependencies=[Depends(rate_limit("merge"))])
def merge(
    case_id: UUID, body: MergeBody,
    user: CurrentUser = Depends(require("graph.merge")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> MergeOut:
    """Fold one entity into another, reversibly.

    If the case has dual control switched on (migration 0028), this needs an
    APPROVED request raised by the same analyst, and the merge runs the
    parameters recorded on it. The consume and the merge share one
    transaction: split them and a failure in between either burns an
    approval without merging, or merges without burning the approval —
    leaving a reusable signature, which is the bad direction to fail in.
    """
    if case_requires_dual_control(conn, case_id, "node.merge"):
        return _merge_under_dual_control(conn, case_id, body, user)

    if body.source_node_id is None or body.target_node_id is None or not body.reason:
        raise Problem(422, "Validation failed",
                      "source_node_id, target_node_id and reason are required")
    try:
        return _out(MergeService(conn).merge(
            case_id=case_id, source_node_id=body.source_node_id,
            target_node_id=body.target_node_id, merged_by=user.user_id,
            reason=body.reason, basis_selector_id=body.basis_selector_id))
    except MergeError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


def _merge_under_dual_control(conn, case_id: UUID, body: MergeBody,
                              user: CurrentUser) -> MergeOut:
    if body.approval_request_id is None:
        raise Problem(
            409, "Approval required",
            "this case requires dual control on merges: raise an approval "
            "request, have a second analyst approve it, then merge with its id")
    svc = ApprovalService(conn)
    approval = svc.get(body.approval_request_id)
    if approval is None or approval.case_id != case_id:
        raise Problem(404, "Not found", "no such approval request in this case")

    # Execute from the payload we are about to HASH, never from the one the
    # consume returns. They are normally the same row; they differ exactly
    # in the case that matters — someone editing `payload` between this read
    # and the update. The hash we pass is taken over `approval.payload`, so
    # that is the only version proven to match what was signed off.
    payload = approval.payload
    try:
        source_node_id = UUID(payload["source_node_id"])
        target_node_id = UUID(payload["target_node_id"])
        reason = payload["reason"]
        basis = payload.get("basis_selector_id")
        basis_selector_id = UUID(basis) if basis else None
    except (KeyError, TypeError, ValueError) as exc:
        raise Problem(409, "Conflict",
                      "that approval was not raised for a merge") from exc

    try:
        with conn.transaction():
            svc.consume(body.approval_request_id, actor_id=user.user_id,
                        operation="node.merge", case_id=case_id, payload=payload)
            record = MergeService(conn).merge(
                case_id=case_id, source_node_id=source_node_id,
                target_node_id=target_node_id, merged_by=user.user_id,
                reason=reason, basis_selector_id=basis_selector_id)
    except ApprovalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    except MergeError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc

    # Outside the transaction on purpose: this is a convenience join between
    # the approval and its consequence, and failing to record it must not
    # roll back a merge that already succeeded.
    svc.attach_result(body.approval_request_id, record.id)
    return _out(record)


@router.post("/{merge_id}/reverse", response_model=MergeOut,
             dependencies=[Depends(rate_limit("merge"))])
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
