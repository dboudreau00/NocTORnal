"""Four-eyes approval over HTTP: raise, decide and withdraw requests, and set the per-case policy.

`decide` checks that the approver holds the operation's own signer permission and has a fresh
second factor. Which permission depends on the operation, so it calls `authorize_object`, the same
single `evaluate()` a `require()` dependency uses (docs/05). Deployment-wide operations have their
own routes under `/approvals`, and case and global routes refuse each other's requests as absent.
The service refuses a signer who also holds the requester's permission: one person is not two.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.approvals import (
    GLOBAL_GATE_PERMISSIONS,
    OPERATIONS,
    PENDING,
    ApprovalError,
    ApprovalRequest,
    ApprovalService,
    case_requires_dual_control,
    policy_mode,
    relax_seasoning_days,
)
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_global,
    authorize_object,
    get_conn,
    require,
    require_global_any,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.element_gate import (
    BASIS_SELECTOR_REFUSAL,
    check_basis_selector,
    disclosure_mode,
    gate_element,
    visible_node_ids,
    withheld_notice,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.projections import DISCLOSURE_NONE
from noctornal_api.security.access import tlp_from_name

router = APIRouter(prefix="/cases/{case_id}/approvals", tags=["approvals"])

#: The operation whose payload names two entities.
MERGE_OPERATION = "node.merge"


def _merge_pair(payload) -> tuple[UUID, UUID] | None:
    """The two entity ids a node.merge payload names, or None when it does
    not name two well-formed ids."""
    try:
        return (UUID(str((payload or {})["source_node_id"])),
                UUID(str((payload or {})["target_node_id"])))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _hidden_merge_requests(conn: psycopg.Connection, user: CurrentUser,
                           case_id: UUID, items) -> set[UUID]:
    """The node.merge requests among `items` ((id, operation, payload) triples) whose two entities
    the viewer may not both see; their payload and justification would name them. A request without
    two well-formed ids counts as hidden, failing closed."""
    pairs = {rid: _merge_pair(payload) for rid, operation, payload in items
             if operation == MERGE_OPERATION}
    if not pairs:
        return set()
    seen = visible_node_ids(conn, user, case_id,
                            {i for p in pairs.values() if p for i in p})
    return {rid for rid, p in pairs.items()
            if p is None or not (p[0] in seen and p[1] in seen)}


def _merge_request_visible(conn: psycopg.Connection, user: CurrentUser,
                           case_id: UUID, record: ApprovalRequest) -> bool:
    return not _hidden_merge_requests(
        conn, user, case_id, [(record.id, record.operation, record.payload)])


def _hidden_merge_request_count(conn: psycopg.Connection, user: CurrentUser,
                                case_id: UUID, state: str | None) -> int:
    """How many node.merge requests of the case, under the listing's state
    filter, the viewer is not shown: over the case, not one page."""
    items = conn.execute(
        """SELECT id, operation, payload FROM core.approval_request
            WHERE case_id = %s AND operation = %s
              AND (%s::text IS NULL OR state = %s)""",
        (case_id, MERGE_OPERATION, state, state)).fetchall()
    return len(_hidden_merge_requests(conn, user, case_id, items))

_STATES = frozenset({"PENDING", "APPROVED", "REJECTED", "WITHDRAWN", "CONSUMED"})

#: The operation that turns a case's merge requirement off.
RELAX = "case.policy.relax"


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
    #: Set on the response to the write (POST "" and POST /decide): `approvers_notified` 0 means
    #: nobody could be told and None that the notify write failed; `requester_notified` False means
    #: suppressed and None failed. A listing counts `approvers_notified` from the notifications the
    #: request raised and leaves `requester_notified` None (not recorded). `warnings` spells each
    #: case out, so a four-eyes request nobody was told about is never a silent 201.
    approvers_notified: int | None = None
    requester_notified: bool | None = None
    warnings: list[str] = Field(default_factory=list)


def _out(r: ApprovalRequest, *, reach: dict | None = None) -> ApprovalOut:
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
        **(reach or {}),
    )


def _request_reach(r: ApprovalRequest) -> dict:
    """The reach fields for the response to `request()`, with the warning
    that turns a silent zero into a sentence the requester will read."""
    warnings: list[str] = []
    if r.approvers_notified is None:
        warnings.append(
            "the request is recorded but the notification failed; no "
            "approver has been told, so ask one directly")
    elif r.approvers_notified == 0 and r.case_id is None:
        # A deployment-wide request has no case, so "nobody on this case" would be the wrong fact.
        op = OPERATIONS.get(r.operation)
        signer = op.signer_permission if op else "the signing permission"
        warnings.append(
            f"the change is recorded but nobody who could countersign it was "
            f"notified: no other active account holds {signer} and may sign "
            f"it, so grant the role or ask directly")
    elif r.approvers_notified == 0:
        warnings.append(
            "the request is recorded but no approver was notified: nobody "
            "else on this case both holds the operation's permission and is "
            "cleared to read the request, so assign one or ask directly")
    return {"approvers_notified": r.approvers_notified, "warnings": warnings}


def _decision_reach(r: ApprovalRequest) -> dict:
    warnings: list[str] = []
    if r.requester_notified is None:
        warnings.append(
            "the decision is recorded but the requester's notification "
            "failed; tell them yourself")
    elif not r.requester_notified:
        warnings.append(
            "the decision is recorded but the requester was not notified: "
            + ("their account may no longer be active" if r.case_id is None
               else "they may no longer be able to read this case"))
    return {"requester_notified": r.requester_notified, "warnings": warnings}


def _merge_subjects(conn: psycopg.Connection, user: CurrentUser,
                    case_id: UUID, rows: list[ApprovalRequest]) -> dict:
    """The two entities of each merge request, by label and type.

    Resolved here rather than from the console's graph, which holds only the current projection.
    An entity this approver may not see is None, and the card says so rather than naming it."""
    wanted: dict[UUID, tuple[str | None, str | None]] = {}
    ids: set[UUID] = set()
    for r in rows:
        if r.operation != "node.merge":
            continue
        pair = []
        for key in ("source_node_id", "target_node_id"):
            try:
                pair.append(UUID(str((r.payload or {}).get(key))))
            except ValueError:
                pair.append(None)
        wanted[r.id] = tuple(pair)
        ids |= {i for i in pair if i}
    if not ids:
        return {}
    clearance, held = user_ceiling(conn, user.user_id, case_id)
    found = {row[0]: {"label": row[1], "node_type": row[2]}
             for row in conn.execute(
                 """SELECT id, label, node_type FROM core.node
                     WHERE id = ANY(%s) AND case_id = %s
                       AND classification <= %s::core.tlp
                       AND compartments <@ %s::text[]""",
                 (list(ids), case_id, clearance.name, sorted(held)))}
    return {rid: {"source": found.get(src), "target": found.get(dst)}
            for rid, (src, dst) in wanted.items()}


def _approvers_reached(conn: psycopg.Connection,
                       rows: list[ApprovalRequest]) -> dict:
    """How many APPROVAL_REQUESTED notifications each request raised.

    Row-level security shows each notice to its recipient alone, so this runs as a withheld
    count on a system connection. The ids are requests the caller has already read under policy,
    and only a number comes back."""
    from noctornal_api.db import SystemPurpose, system_connection

    ids = [r.id for r in rows]
    if not ids:
        return {}
    with system_connection(SystemPurpose.WITHHELD, reuse=conn) as sconn:
        return {row[0]: row[1] for row in sconn.execute(
            """SELECT object_id, count(*) FROM notify.notification
                WHERE kind = 'APPROVAL_REQUESTED'
                  AND object_type = 'approval_request'
                  AND object_id = ANY(%s)
                GROUP BY object_id""", (ids,))}


def _names(conn: psycopg.Connection, rows: list[ApprovalRequest]) -> dict:
    ids = {r.requested_by for r in rows} | {r.decided_by for r in rows
                                            if r.decided_by}
    return {row[0]: row[1] for row in conn.execute(
        "SELECT id, display_name FROM iam.app_user WHERE id = ANY(%s)",
        (list(ids),)).fetchall()} if ids else {}


@router.get("", response_model=dict)
def list_approvals(
    case_id: UUID,
    state: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every request in the case, decided ones included. A rejected request
    that vanished would hide the fact that somebody once asked."""
    if state is not None and state not in _STATES:
        raise Problem(400, "Invalid request",
                      f"unknown state {state!r}; one of {', '.join(sorted(_STATES))}")
    # A node.merge request is listed only to a viewer who may see both its entities; the rest are
    # reported under `withheld` as the case allows, counted over the whole case (state filter
    # included), not this page. The page is cut after the filter, so hidden requests do not push
    # visible ones off it.
    rows = ApprovalService(conn).list_for_case(case_id, state=state, limit=500)
    hidden = _hidden_merge_requests(
        conn, user, case_id, [(r.id, r.operation, r.payload) for r in rows])
    rows = [r for r in rows if r.id not in hidden][:limit]
    mode = disclosure_mode(conn, case_id)
    withheld = withheld_notice(
        mode, 0 if mode == DISCLOSURE_NONE
        else _hidden_merge_request_count(conn, user, case_id, state),
        noun="requests")
    out = [_out(r).model_dump(mode="json") for r in rows]
    # Who asked and who decided, by name: the ids stay as the durable record, the names are for the
    # person deciding.
    names = _names(conn, rows)
    subjects = _merge_subjects(conn, user, case_id, rows)
    reached = _approvers_reached(conn, rows)
    svc = ApprovalService(conn)
    for item, r in zip(out, rows, strict=True):
        item["requested_by_name"] = names.get(r.requested_by)
        item["decided_by_name"] = names.get(r.decided_by) if r.decided_by else None
        item["subjects"] = subjects.get(r.id)
        # What stops this viewer approving it yet, said before they try. None when the seasoning
        # rule does not cover the request or nothing stops the viewer.
        item["signer_block"] = svc.signer_block_for(r, user.user_id)
        # Reach is not stored on the request, but its notifications are, so a listing can say
        # "nobody was told" for as long as that stays true, not only in the reply to the write.
        item["approvers_notified"] = reached.get(r.id, 0)
        op = OPERATIONS.get(r.operation)
        item["operation_description"] = op.description if op else None
    # Case operations only: this route refuses a deployment-wide one, so it is not offered.
    body = {"approvals": out,
            "operations": {k: {"permission": v.permission,
                               "signer_permission": v.signer_permission,
                               "description": v.description,
                               "ttl_seconds": int(v.ttl.total_seconds())}
                           for k, v in OPERATIONS.items()
                           if v.scope == "case"}}
    if withheld:
        body["withheld"] = withheld
    return body


def _relax_payload_problem(conn: psycopg.Connection, case_id: UUID,
                           payload: dict) -> Problem | None:
    """What refuses a `case.policy.relax` request before it is raised: only the one payload shape,
    only while the switch is on, never under a deployment that requires it, and only for the
    switch as it stands now."""
    epoch = payload.get("epoch") if isinstance(payload, dict) else None
    if (not isinstance(payload, dict)
            or set(payload) != {"setting", "from", "to", "epoch"}
            or payload.get("setting") != "dual_control_merge"
            or payload.get("from") is not True
            or payload.get("to") is not False
            or not isinstance(epoch, int) or isinstance(epoch, bool)):
        return Problem(
            400, "Invalid request",
            'a case.policy.relax request carries exactly {"setting": '
            '"dual_control_merge", "from": true, "to": false, "epoch": the '
            "case's dual_control_merge_epoch}")
    row = conn.execute(
        'SELECT dual_control_merge, dual_control_merge_epoch '
        'FROM core."case" WHERE id = %s', (case_id,)).fetchone()
    if row is None:
        return Problem(404, "Not found", "case does not exist")
    if not row[0]:
        return Problem(409, "Conflict",
                       "Merges in this case take one signature already.")
    if policy_mode(conn, "node.merge") == "ALWAYS":
        return Problem(409, "Conflict", _DEPLOYMENT_REQUIRES)
    if epoch != row[1]:
        return Problem(409, "Conflict",
                       "The switch changed after this was prepared: reload "
                       "and ask again.")
    return None


def _merge_request_labels(conn: psycopg.Connection, user: CurrentUser,
                          case_id: UUID, payload: dict) -> dict:
    """A node.merge request names two entities of this case the requester may merge, or it is not
    raised. One 404 for an entity that is missing, in another case or above the requester. The
    notice to the signers is labelled at the stricter of the two entities, as the merge's own
    notification is, so a signer below either is not sent the justification."""
    pair = _merge_pair(payload)
    if pair is None:
        raise Problem(400, "Invalid request",
                      "a node.merge request names source_node_id and "
                      "target_node_id, the two entities to merge")
    classifications, compartments = [], frozenset()
    for node_id in pair:
        cls, comp = gate_element(
            conn, user, case_id=case_id, kind="node", element_id=node_id,
            permission_key=OPERATIONS[MERGE_OPERATION].permission,
            missing_detail="no such node in this case")
        classifications.append(cls)
        compartments |= comp
    # The basis selector is checked when the request is raised, as it is when
    # it is spent, so a payload that cannot merge never reaches a signer.
    basis = (payload or {}).get("basis_selector_id")
    if basis:
        try:
            basis_id = UUID(str(basis))
        except ValueError:
            raise Problem(400, "Invalid request",
                          BASIS_SELECTOR_REFUSAL) from None
        check_basis_selector(conn, user, case_id=case_id, selector_id=basis_id)
    return {"element_classification": max(classifications, key=tlp_from_name),
            "element_compartments": compartments}


#: Per-operation checks a request's payload must pass before it is raised, after the requester's
#: own authorisation.
_CASE_PAYLOAD_CHECKS = {RELAX: _relax_payload_problem}

_DEPLOYMENT_REQUIRES = (
    "Every merge on this deployment needs a second signature (Administration, "
    "Two-person controls), so a case cannot turn it off.")


@router.post("", response_model=ApprovalOut, status_code=201)
def raise_request(
    case_id: UUID, body: RequestBody,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """Ask for a second signature.

    The requester must hold the operation's own permission, not just `case.read`: a request from
    somebody who could never perform it is noise, and an approver who is accustomed to noise stops
    reading.
    """
    operation = OPERATIONS.get(body.operation)
    if operation is None:
        raise Problem(400, "Invalid request",
                      f"unknown operation {body.operation!r}; one of "
                      f"{', '.join(sorted(k for k, v in OPERATIONS.items() if v.scope == 'case'))}")
    if operation.scope != "case":
        raise Problem(400, "Invalid request",
                      f"{operation.description} is deployment-wide: it is "
                      f"raised from Administration, Two-person controls")
    authorize_object(conn, user, case_id=case_id,
                     permission_key=operation.permission, after_case_gate=True)
    check = _CASE_PAYLOAD_CHECKS.get(body.operation)
    if check is not None:
        problem = check(conn, case_id, body.payload)
        if problem is not None:
            raise problem
    labels = (_merge_request_labels(conn, user, case_id, body.payload)
              if body.operation == MERGE_OPERATION else {})
    try:
        record = ApprovalService(conn).request(
            operation=body.operation, case_id=case_id, payload=body.payload,
            justification=body.justification, requested_by=user.user_id,
            **labels)
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return _out(record, reach=_request_reach(record))


@router.post("/{request_id}/decide", response_model=ApprovalOut)
def decide(
    case_id: UUID, request_id: UUID, body: DecisionBody,
    user: CurrentUser = Depends(require("case.read")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """Approve or reject somebody else's request.

    Needs `case.read` on the case, the operation's own signer permission (an approval pool wider
    than the actor pool weakens the control) and a fresh second factor. The service and a CHECK
    constraint (migration 0028) refuse a requester deciding their own request; this route gives the
    readable error.
    """
    svc = ApprovalService(conn)
    record = svc.get(request_id)
    # Authorization before existence: an unauthorised caller gets the same
    # 404 whether or not the request is real (deps.py rule 2).
    if (record is None or record.case_id != case_id
            # Before the signer permission check, so a merge request naming entities above the
            # caller gets the listing's 404, not a 403 that says the request exists.
            or not _merge_request_visible(conn, user, case_id, record)):
        raise Problem(404, "Not found", "no such approval request in this case")
    operation = OPERATIONS.get(record.operation)
    if operation is None:
        # A request raised against an operation later removed from the
        # catalogue. Refuse rather than fall back to a weaker permission.
        raise Problem(409, "Conflict",
                      f"operation {record.operation!r} is no longer registered")
    # After `case.read` from the dependency, so a break-glass use counts once, here and in
    # `raise_request`.
    authorize_object(conn, user, case_id=case_id,
                     permission_key=operation.signer_permission,
                     after_case_gate=True)
    try:
        record = svc.decide(request_id, decided_by=user.user_id,
                            approve=body.approve, note=body.note)
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return _out(record, reach=_decision_reach(record))


@router.post("/{request_id}/withdraw", response_model=ApprovalOut)
def withdraw(
    case_id: UUID, request_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """The requester changing their mind. Not a decision: a withdrawn request never had one.

    Bound to the path's case, so `case.read` on one case cannot withdraw a request raised in
    another, which the requester may have lost access to. The same 404 as `decide`."""
    svc = ApprovalService(conn)
    record = svc.get(request_id)
    if (record is None or record.case_id != case_id
            # The payload comes back in the response, so a merge request whose entities the
            # caller cannot both see gets the listing's 404.
            or not _merge_request_visible(conn, user, case_id, record)):
        raise Problem(404, "Not found", "no such approval request in this case")
    try:
        return _out(svc.withdraw(request_id, actor_id=user.user_id,
                                 scope="case", case_id=case_id))
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


# ---------------------------------------------------------------------------
# Deployment-wide approvals
# ---------------------------------------------------------------------------

global_router = APIRouter(prefix="/approvals", tags=["approvals"])

_GLOBAL_STATES = _STATES | {"OPEN"}


def _held_globally(conn: psycopg.Connection, user_id: UUID,
                   keys: list[str]) -> set[str]:
    return {r[0] for r in conn.execute(
        """SELECT DISTINCT rp.permission_key FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND u.is_active
              AND rp.permission_key = ANY(%s)""",
        (user_id, keys)).fetchall()}


def _global_operations(conn: psycopg.Connection, user: CurrentUser) -> list[str]:
    """The deployment-wide operations the caller holds either side of."""
    keys = sorted({p for op in OPERATIONS.values() if op.scope == "global"
                   for p in (op.permission, op.signer_permission)})
    held = _held_globally(conn, user.user_id, keys)
    return [k for k, op in OPERATIONS.items() if op.scope == "global"
            and (op.permission in held or op.signer_permission in held)]


@global_router.get("", response_model=dict)
def list_global_approvals(
    state: str | None = Query(None),
    operation: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global_any(*GLOBAL_GATE_PERMISSIONS)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Deployment-wide requests the caller may see: those of the operations
    they hold either side of. `state=OPEN` is what can still move: waiting
    for a decision, or approved and not yet applied.

    A policy change carries what the card needs: the effect, over the
    caller's own cases; whether it still applies to the policy as it
    stands; what the caller may do with it and why not; and, once decided,
    the latest takeover of the countersigner's account before they signed."""
    from noctornal_api.dual_control import OPERATION as POLICY
    from noctornal_api.dual_control import DualControlPolicyService

    if state is not None and state not in _GLOBAL_STATES:
        raise Problem(400, "Invalid request",
                      f"unknown state {state!r}; one of "
                      f"{', '.join(sorted(_GLOBAL_STATES))}")
    ops = _global_operations(conn, user)
    if operation is not None:
        known = OPERATIONS.get(operation)
        if known is None or known.scope != "global":
            raise Problem(400, "Invalid request",
                          f"unknown deployment-wide operation {operation!r}")
        ops = [o for o in ops if o == operation]
    rows = ApprovalService(conn).list_global(ops, state=state, limit=limit)
    out = [_out(r).model_dump(mode="json") for r in rows]
    names = _names(conn, rows)
    reached = _approvers_reached(conn, rows)
    policy = DualControlPolicyService(conn)
    clearance, held = user_ceiling(conn, user.user_id)
    for item, r in zip(out, rows, strict=True):
        op = OPERATIONS.get(r.operation)
        item["requested_by_name"] = names.get(r.requested_by)
        item["decided_by_name"] = names.get(r.decided_by) if r.decided_by else None
        item["approvers_notified"] = reached.get(r.id, 0)
        item["operation_description"] = op.description if op else None
        if r.operation == POLICY:
            preview = policy.preview(r.payload or {}, viewer_id=user.user_id,
                                     clearance=clearance.name,
                                     compartments=held)
            item["preview"] = preview
            item["stale"] = preview["stale"]
            item["countersign"] = _jsonable(policy.countersign_view(r, user.user_id))
            item["provenance"] = _jsonable(policy.provenance(r))
    return {"approvals": out,
            "operations": {k: {"permission": OPERATIONS[k].permission,
                               "signer_permission": OPERATIONS[k].signer_permission,
                               "description": OPERATIONS[k].description,
                               "ttl_seconds": int(OPERATIONS[k].ttl.total_seconds())}
                           for k in ops}}


def _jsonable(d: dict | None) -> dict | None:
    if d is None:
        return None
    return {k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in d.items()}


@global_router.post("/{request_id}/decide", response_model=ApprovalOut)
def decide_global(
    request_id: UUID, body: DecisionBody,
    user: CurrentUser = Depends(require_global_any(*GLOBAL_GATE_PERMISSIONS)),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """Countersign or refuse a deployment-wide request.

    The gate runs first, so a caller holding neither side is refused whether or not the id
    exists. Then 404 unless the request is deployment-wide, then the signer permission of its
    operation with a forced step-up, refused as "re-authentication required" so the console asks
    for the sign-in (not `require_step_up`, whose words differ)."""
    svc = ApprovalService(conn)
    record = svc.get(request_id)
    if record is None or record.case_id is not None:
        raise Problem(404, "Not found", "no such deployment-wide approval request")
    operation = OPERATIONS.get(record.operation)
    if operation is None:
        raise Problem(409, "Conflict",
                      f"operation {record.operation!r} is no longer registered")
    authorize_global(conn, user, operation.signer_permission, force_step_up=True)
    try:
        record = svc.decide(request_id, decided_by=user.user_id,
                            approve=body.approve, note=body.note)
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return _out(record, reach=_decision_reach(record))


@global_router.post("/{request_id}/withdraw", response_model=ApprovalOut)
def withdraw_global(
    request_id: UUID,
    user: CurrentUser = Depends(require_global_any(*GLOBAL_GATE_PERMISSIONS)),
    conn: psycopg.Connection = Depends(get_conn),
) -> ApprovalOut:
    """The requester taking back their own deployment-wide request. One answer, 404, for a request
    that is not there, not deployment-wide, not theirs or not pending, so this route tells nobody
    which."""
    svc = ApprovalService(conn)
    record = svc.get(request_id)
    if (record is None or record.case_id is not None
            or record.requested_by != user.user_id or record.state != PENDING):
        raise Problem(404, "Not found",
                      "no pending deployment-wide request of yours with that id")
    try:
        return _out(svc.withdraw(request_id, actor_id=user.user_id,
                                 scope="global"))
    except ApprovalError as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc


# ---------------------------------------------------------------------------
# The per-case policy
# ---------------------------------------------------------------------------

class PolicyBody(BaseModel):
    dual_control_merge: bool | None = None
    #: docs/14 U2. NONE | PRESENCE | COUNT -- see migration 0030.
    withheld_disclosure: str | None = None
    #: The approved `case.policy.relax` request that turns the merge requirement off. Ignored in
    #: every other direction.
    approval_request_id: UUID | None = None


class PolicyOut(BaseModel):
    dual_control_merge: bool
    withheld_disclosure: str
    #: The deployment's mode for merges, whether this case needs a second signature on them once
    #: that is applied, the switch's epoch (what a relax request is raised against), and how many
    #: other people on the case could approve turning it off.
    dual_control_merge_mode: str = "PER_CASE"
    dual_control_merge_effective: bool = False
    dual_control_merge_epoch: int = 0
    relax_signers: int = 0
    #: How many days a second person must have held `case.update` on the case (0: the rule is off),
    #: and, while nobody counted in `relax_signers` qualifies yet, when the first colleague will.
    #: None when there is no such colleague.
    relax_seasoning_days: int = 0
    relax_next_eligible: datetime | None = None


_DISCLOSURE = frozenset({"NONE", "PRESENCE", "COUNT"})


policy_router = APIRouter(prefix="/cases/{case_id}/policy", tags=["approvals"])


def _relax_signers(conn: psycopg.Connection, case_id: UUID,
                   user_id: UUID, *, days: int) -> tuple[int, datetime | None]:
    """How many colleagues could approve turning the switch off now, and when the next one can.

    Active accounts other than the caller, assigned to the case under a role carrying the relax
    operation's signer permission, whose clearance and compartments dominate the case. Only those
    assigned `days` days ago or more count, on the database's clock as in `assignment_block`; with
    `days` 0 everyone does. The second figure is None when somebody counts already or nobody else
    holds the permission."""
    row = conn.execute(
        """SELECT count(DISTINCT u.id) FILTER (WHERE seasoned),
                  min(eligible_from) FILTER (WHERE NOT seasoned)
             FROM (SELECT u.id,
                          ca.granted_at + make_interval(hours => %(days)s::int * 24)
                              AS eligible_from,
                          (%(days)s::int = 0
                           OR ca.granted_at
                              + make_interval(hours => %(days)s::int * 24)
                              <= now()) AS seasoned
                     FROM iam.case_assignment ca
                     JOIN iam.app_user u ON u.id = ca.user_id
                     JOIN iam.role_permission rp ON rp.role_key = ca.role_key
                                                AND rp.permission_key = %(perm)s
                     JOIN core."case" c ON c.id = ca.case_id
                    WHERE ca.case_id = %(case)s AND u.is_active
                      AND u.id <> %(me)s
                      AND (ca.expires_at IS NULL OR ca.expires_at > now())
                      AND c.classification <= u.tlp_clearance
                      AND c.compartments <@ u.compartments) u""",
        {"days": days, "perm": OPERATIONS[RELAX].signer_permission,
         "case": case_id, "me": user_id}).fetchone()
    counting = int(row[0])
    return counting, (None if counting else row[1])


def _policy_out(conn: psycopg.Connection, case_id: UUID,
                user_id: UUID) -> PolicyOut:
    row = conn.execute(
        'SELECT dual_control_merge, withheld_disclosure, '
        'dual_control_merge_epoch FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    days = relax_seasoning_days()
    signers, next_eligible = _relax_signers(conn, case_id, user_id, days=days)
    return PolicyOut(
        dual_control_merge=bool(row[0]), withheld_disclosure=row[1],
        dual_control_merge_mode=policy_mode(conn, "node.merge"),
        dual_control_merge_effective=case_requires_dual_control(
            conn, case_id, "node.merge"),
        dual_control_merge_epoch=int(row[2]),
        relax_signers=signers, relax_seasoning_days=days,
        relax_next_eligible=next_eligible)


@policy_router.get("", response_model=PolicyOut)
def get_policy(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> PolicyOut:
    return _policy_out(conn, case_id, user.user_id)


@policy_router.put("", response_model=PolicyOut)
def set_policy(
    case_id: UUID, body: PolicyBody,
    user: CurrentUser = Depends(require("case.update")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> PolicyOut:
    """Turn dual control on or off for this case's merges.

    Step-up gated, because turning a control off is what an attacker with a borrowed session wants.
    Turning it off also takes an approved `case.policy.relax` request raised against the switch as
    it stands, from a colleague who had held `case.update` on the case for the deployment's window
    (seven days unless declared) when they signed; the database refuses the change without one.
    Turning it on takes one signature, and a deployment that requires two on every merge cannot be
    relaxed per case. The consume is the transaction's first write (approvals.py, the out-of-band
    rule), and every setting commits with its CASE_POLICY_CHANGED row.
    """
    from psycopg.types.json import Json

    row = conn.execute(
        'SELECT dual_control_merge, withheld_disclosure, '
        'dual_control_merge_epoch FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    current = {"dual_control_merge": bool(row[0]),
               "withheld_disclosure": row[1]}
    epoch = int(row[2])

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
    relaxing = current["dual_control_merge"] and not wanted["dual_control_merge"]
    svc = ApprovalService(conn)
    approval = None
    if relaxing:
        if policy_mode(conn, "node.merge") == "ALWAYS":
            raise Problem(409, "Conflict", _DEPLOYMENT_REQUIRES)
        if body.approval_request_id is None:
            raise Problem(
                409, "Approval required",
                "Turning off the second signature on this case's merges "
                "takes a second Lead investigator: raise a request under "
                "Triage, Dual control, and use it here once it is approved.")
        approval = svc.get(body.approval_request_id)
        if approval is None or approval.case_id != case_id:
            raise Problem(404, "Not found",
                          "no such approval request in this case")
        # Was the second person seasoned when they signed? Before the transaction, so a refusal
        # recorded out of band is not rolled back with it (approvals.py, the out-of-band rule).
        try:
            svc.refuse_unseasoned_spend(approval, actor_id=user.user_id)
        except ApprovalError as exc:
            raise Problem(409, "Conflict", safe_detail(exc)) from exc

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
    try:
        with conn.transaction():
            if approval is not None:
                svc.consume(approval.id, actor_id=user.user_id,
                            operation="case.policy.relax", case_id=case_id,
                            payload=approval.payload)
            for setting, value in wanted.items():
                if value == current[setting]:
                    continue
                conn.execute(_UPDATES[setting], (value, case_id))
                detail = {"setting": setting, "from": current[setting],
                          "to": value}
                if setting == "dual_control_merge":
                    detail["epoch"] = epoch
                    if approval is not None:
                        detail["approval_request_id"] = str(approval.id)
                        detail["approved_by"] = str(approval.decided_by)
                conn.execute(
                    """INSERT INTO audit.event
                           (actor_id, actor_kind, action, object_type,
                            object_id, case_id, detail)
                       VALUES (%s, 'USER', 'CASE_POLICY_CHANGED', 'case', %s,
                               %s, %s)""",
                    (user.user_id, case_id, case_id, Json(detail)))
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except psycopg.errors.RaiseException as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    if approval is not None:
        svc.attach_result(approval.id, case_id)
    return _policy_out(conn, case_id, user.user_id)
