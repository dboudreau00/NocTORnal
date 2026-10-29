"""Entity merge and its reversal over HTTP (docs/01).

Both need `graph.merge` or `graph.unmerge` with step-up: a merge rewrites who did what across
the case, and undoing a correct one is as destructive as making a wrong one. A merge writes an
audit event; the case-owner notification docs/01 asks for is not built. Dual control (migration 0028,
`approvals.py`) is a per-case switch, default off, since a merge is reversible and entity
resolution is daily work. Reversal is never dual-controlled: requiring two people to correct a
mistake is how mistakes stay in a case file.
"""
from __future__ import annotations

from dataclasses import replace
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require,
    require_step_up,
    system_conn,
    user_ceiling,
)
from noctornal_api.http.element_gate import (
    check_basis_selector,
    disclosure_mode,
    gate_element,
    visible_node_ids,
    withheld_notice,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.approvals import (
    ApprovalError,
    ApprovalService,
    case_requires_dual_control,
    policy_mode,
)
from noctornal_api.http.limits import rate_limit
from noctornal_api.merges import (
    MergeBlocked,
    MergeCollision,
    MergeError,
    MergeRecord,
    MergeService,
)
from noctornal_api.projections import DISCLOSURE_NONE

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
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every merge in the case this reader may see, reversed ones included: a reversed merge that
    vanished would hide that somebody once believed these were the same actor. A merge is visible
    when both its entities are within the reader's labels; the rest are said under `withheld` as
    the case's withheld_disclosure allows, never which."""
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    out: dict = {"merges": [_out(m) for m in MergeService(conn).history_for_reader(
        case_id, limit, clearance=clearance.name, compartments=held)]}
    mode = disclosure_mode(conn, case_id)
    hidden = 0
    if mode != DISCLOSURE_NONE:
        # Counted on a system connection: row security hides exactly these
        # merges from the reader's own (0132).
        with system_connection(SystemPurpose.WITHHELD, reuse=conn) as counter:
            hidden = MergeService(counter).count_hidden_from_reader(
                case_id, clearance=clearance.name, compartments=held)
    notice = withheld_notice(mode, hidden, noun="merges")
    if notice:
        out["withheld"] = notice
    return out


def _gate_merge_nodes(conn, user: CurrentUser, case_id: UUID, permission: str,
                      node_ids, missing_detail: str) -> None:
    """Both entities of a merge, at their own labels. The merge and its reversal run on a system
    connection that sees every node, so without this an entity the caller cannot read could be
    merged by id. One 404 for an entity that is missing, in another case or above the caller."""
    for node_id in node_ids:
        gate_element(conn, user, case_id=case_id, kind="node",
                     element_id=node_id, permission_key=permission,
                     missing_detail=missing_detail)


def _conflict(conn, user: CurrentUser, case_id: UUID, exc: MergeError) -> Problem:
    """A merge the service refused, as a 409. A duplicate tie names its third party only to a
    caller who may read that entity, and a reversal held up by a later merge names that merge only
    to a reader of it."""
    if (isinstance(exc, MergeCollision)
            and exc.third_party not in visible_node_ids(
                conn, user, case_id, [exc.third_party])):
        return Problem(409, "Conflict", exc.without_third_party())
    if isinstance(exc, MergeBlocked):
        clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
        if MergeService(conn).get_for_reader(
                exc.blocker, clearance=clearance.name,
                compartments=held) is None:
            return Problem(409, "Conflict", exc.without_blocker())
    return Problem(409, "Conflict", safe_detail(exc))


@router.post("", response_model=MergeOut, status_code=201,
             dependencies=[Depends(rate_limit("merge"))])
def merge(
    case_id: UUID, body: MergeBody,
    user: CurrentUser = Depends(require("graph.merge")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
    # A merge re-points every edge of the source node, including ties above the merging user's
    # labels, so it needs a connection that sees them or hidden edges would be left on a redirected
    # node. Under dual control the approval's consume shares the merge's transaction here.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.MERGE)),
) -> MergeOut:
    """Fold one entity into another, reversibly.

    Under dual control (migration 0028) this needs an APPROVED request raised by the same analyst,
    and runs the parameters recorded on it. The consume and the merge share one transaction, so a
    failure can neither burn an approval without merging nor leave a reusable signature.
    """
    if case_requires_dual_control(conn, case_id, "node.merge"):
        return _merge_under_dual_control(conn, case_id, body, user, sconn)

    if body.source_node_id is None or body.target_node_id is None or not body.reason:
        raise Problem(422, "Validation failed",
                      "source_node_id, target_node_id and reason are required")
    _gate_merge_nodes(conn, user, case_id, "graph.merge",
                      (body.source_node_id, body.target_node_id),
                      "no such node in this case")
    check_basis_selector(conn, user, case_id=case_id,
                         selector_id=body.basis_selector_id)
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    try:
        record = MergeService(sconn).merge(
            case_id=case_id, source_node_id=body.source_node_id,
            target_node_id=body.target_node_id, merged_by=user.user_id,
            reason=body.reason, basis_selector_id=body.basis_selector_id,
            clearance=clearance.name, compartments=held)
    except MergeError as exc:
        raise _conflict(conn, user, case_id, exc) from exc
    return _out(_as_reader(conn, record, user))


def _as_reader(conn, record: MergeRecord, user: CurrentUser) -> MergeRecord:
    """The record as its reader sees it. The merge and its reversal run on a system connection and
    re-point every tie; the counts they answer with are read back at the reader's own labels, as
    the history is (`history_for_reader`, `core.node_merge_edge` policied by migration 0123), so a
    tie the reader cannot see is not counted, even where row security does not filter. The audit
    row keeps the full count. Were the merge not theirs to see, the counts would be withheld."""
    clearance, held = user_ceiling(conn, user.user_id, case_id=record.case_id)
    seen = MergeService(conn).get_for_reader(
        record.id, clearance=clearance.name, compartments=held)
    return seen or replace(record, edges_repointed=0,
                           edges_self_loop_deleted=0)


def _merge_under_dual_control(conn, case_id: UUID, body: MergeBody,
                              user: CurrentUser, sconn=None) -> MergeOut:
    # `sconn` carries the approval read, its consume and the merge in one transaction.
    sconn = conn if sconn is None else sconn
    if body.approval_request_id is None:
        # Said by where the requirement comes from: "this case requires" is untrue of a case whose
        # own switch is off under a deployment that requires it everywhere.
        where = ("this deployment requires a second signature on every merge"
                 if policy_mode(conn, "node.merge") == "ALWAYS"
                 else "this case requires dual control on merges")
        raise Problem(
            409, "Approval required",
            f"{where}: raise an approval request, have a second analyst "
            f"approve it, then merge with its id")
    svc = ApprovalService(sconn)
    approval = svc.get(body.approval_request_id)
    if approval is None or approval.case_id != case_id:
        raise Problem(404, "Not found", "no such approval request in this case")

    # Execute from the payload about to be hashed, never the one the consume returns: they differ
    # only if someone edits `payload` between this read and the update, and only the hashed one is
    # proven to match what was signed off.
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
    # The caller must still be able to read both entities when the approval is spent, or the
    # payload's ids would run unchecked on the system connection. Before the consume, so a refusal
    # leaves it unspent, and with the missing-approval 404, so it does not say the request exists.
    _gate_merge_nodes(conn, user, case_id, "graph.merge",
                      (source_node_id, target_node_id),
                      "no such approval request in this case")
    check_basis_selector(conn, user, case_id=case_id,
                         selector_id=basis_selector_id)
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)

    try:
        with sconn.transaction():
            svc.consume(body.approval_request_id, actor_id=user.user_id,
                        operation="node.merge", case_id=case_id, payload=payload)
            record = MergeService(sconn).merge(
                case_id=case_id, source_node_id=source_node_id,
                target_node_id=target_node_id, merged_by=user.user_id,
                reason=reason, basis_selector_id=basis_selector_id,
                clearance=clearance.name, compartments=held)
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except MergeError as exc:
        raise _conflict(conn, user, case_id, exc) from exc

    # Outside the transaction on purpose: this is a convenience join between
    # the approval and its consequence, and failing to record it must not
    # roll back a merge that already succeeded.
    svc.attach_result(body.approval_request_id, record.id)
    return _out(_as_reader(conn, record, user))


@router.post("/{merge_id}/reverse", response_model=MergeOut,
             dependencies=[Depends(rate_limit("merge"))])
def reverse(
    case_id: UUID, merge_id: UUID, body: ReversalBody,
    user: CurrentUser = Depends(require("graph.unmerge")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
    # An unmerge restores every edge the merge re-pointed, hidden ones included.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.MERGE)),
) -> MergeOut:
    """Restore every edge's original endpoints and clear the redirect."""
    record = MergeService(sconn).get(merge_id)
    if record is None or record.case_id != case_id:
        raise Problem(404, "Not found", "no such merge in this case")
    # Its two entities at their own labels, so a reader below either cannot reverse a merge they
    # cannot see; the same 404 as no merge at all.
    _gate_merge_nodes(conn, user, case_id, "graph.unmerge",
                      (record.source_node_id, record.target_node_id),
                      "no such merge in this case")
    try:
        reversed_ = MergeService(sconn).unmerge(
            merge_id, reversed_by=user.user_id, reason=body.reason)
    except MergeError as exc:
        raise _conflict(conn, user, case_id, exc) from exc
    return _out(_as_reader(conn, reversed_, user))
