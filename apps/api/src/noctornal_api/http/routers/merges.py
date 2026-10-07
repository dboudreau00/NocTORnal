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
    """Every merge in the case, reversed ones included — a reversed merge
    that vanished from the record would hide the fact that somebody once
    believed these were the same actor.

    Every merge THIS READER may see (rls-1, graph-merge-ledger-and-approvals-
    leak, http_ui-001, 2026-10-03): one whose two entities are both within
    their labels. The history served every merge, with both node ids and
    the free reason, to every case reader. The rest are said as the case's
    withheld_disclosure allows, under `withheld`, never which."""
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
    """Both entities of a merge, at their own labels (graph-merge-no-element-
    label-gate, http_ui-001, 2026-10-03). The merge and its reversal run on a
    system connection that sees every node, so before this an analyst could
    merge, or reverse the merge of, an entity they cannot read, by id, and a
    hidden id answered 201 where a random one answered 409. One 404 now, for
    an entity that is missing, in another case or above the caller."""
    for node_id in node_ids:
        gate_element(conn, user, case_id=case_id, kind="node",
                     element_id=node_id, permission_key=permission,
                     missing_detail=missing_detail)


def _conflict(conn, user: CurrentUser, case_id: UUID, exc: MergeError) -> Problem:
    """A merge the service refused, as a 409. A duplicate tie names its third
    party only to a merger who may read that entity (2026-10-03): the id of
    one above them, and with it that two ties to it exist, was theirs to read
    in the refusal. A reversal held up by a later merge names that merge only
    to a reader of it (verification round three, A5, 2026-10-07)."""
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
    # A merge re-points EVERY edge of the source node, including ties
    # above the merging user's own labels, as it always has; under row-level
    # security that needs a connection that sees them, or hidden edges would
    # be left on a redirected node (S1, 2026-09-25). Under dual control the
    # approval's consume shares the merge's transaction on this connection.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.MERGE)),
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
    """The record as its reader sees it (S1, 2026-09-25). The merge and its
    reversal run on a system connection and re-point every tie; the counts
    they answer with are read back on the request connection, so a tie
    above the reader is counted nowhere they can see, exactly as the merge
    history counts it (`core.node_merge_edge` is policied since 0123). The
    audit row keeps the full count for its own readers.

    At the reader's own labels since 2026-10-03, as the history is
    (`history_for_reader`), so a development stack, whose request
    connection row security does not filter, answers the same, and a tie
    to an entity the reader cannot see is not counted either. The gate let
    the reader past both entities, so the merge is theirs to see; were it
    not, the counts are withheld rather than the system's full ones
    returned."""
    clearance, held = user_ceiling(conn, user.user_id, case_id=record.case_id)
    seen = MergeService(conn).get_for_reader(
        record.id, clearance=clearance.name, compartments=held)
    return seen or replace(record, edges_repointed=0,
                           edges_self_loop_deleted=0)


def _merge_under_dual_control(conn, case_id: UUID, body: MergeBody,
                              user: CurrentUser, sconn=None) -> MergeOut:
    # `sconn` carries the approval read, its consume and the merge in
    # one transaction (S1).
    sconn = conn if sconn is None else sconn
    if body.approval_request_id is None:
        # F9b (2026-09-24): said by where the requirement comes from,
        # because "this case requires" is untrue of a case whose own
        # switch is off under a deployment that requires it everywhere.
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
    # The merger must still be able to read both entities when the approval
    # is spent, as when it was raised (2026-10-03): the payload's ids run on
    # the system connection otherwise. Before the consume, so a refusal
    # leaves the approval unspent. The sentence is the one for an approval
    # that is not there (graph-merge-approval-hidden, 2026-10-03): a
    # request that names entities above the caller is not theirs to see, and
    # a different 404 for it than for a random id would say it exists.
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
    # An unmerge restores EVERY edge the merge re-pointed (S1).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.MERGE)),
) -> MergeOut:
    """Restore every edge's original endpoints and clear the redirect."""
    record = MergeService(sconn).get(merge_id)
    if record is None or record.case_id != case_id:
        raise Problem(404, "Not found", "no such merge in this case")
    # graph-merge-ledger-and-approvals-leak, http_ui-001 (2026-10-03): a
    # reader below either entity reversed a merge they could not see. Its
    # two entities at their own labels, the same 404 as no merge at all.
    _gate_merge_nodes(conn, user, case_id, "graph.unmerge",
                      (record.source_node_id, record.target_node_id),
                      "no such merge in this case")
    try:
        reversed_ = MergeService(sconn).unmerge(
            merge_id, reversed_by=user.user_id, reason=body.reason)
    except MergeError as exc:
        raise _conflict(conn, user, case_id, exc) from exc
    return _out(_as_reader(conn, reversed_, user))
