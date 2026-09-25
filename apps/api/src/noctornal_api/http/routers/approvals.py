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

## Deployment-wide requests (F9, 2026-09-24)

A deployment-wide operation (`Operation.scope == "global"`) has no case to
be raised in and nobody assigned to it, so it has its own routes under
`/approvals` (`global_router`): list, decide, withdraw. The case routes
refuse a global operation and the global routes refuse a case request, each
with the answer a request that is not there gets. The global decide route
checks the SIGNER's permission of the request's operation with a forced
step-up in the global gate's words, and the service refuses an account
that also holds the requester's permission, because one person holding
both roles is not two people.
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
from noctornal_api.http.errors import Problem, safe_detail

router = APIRouter(prefix="/cases/{case_id}/approvals", tags=["approvals"])

_STATES = frozenset({"PENDING", "APPROVED", "REJECTED", "WITHDRAWN", "CONSUMED"})

#: The operation that turns a case's merge requirement off (F9b).
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
    #: N1 (2026-09-02). Populated on the response to the write that
    #: produced them (POST "" and POST /decide). Since 2026-09-23 a listing
    #: also carries `approvers_notified`, counted from the notifications
    #: the request raised (ux08-triage:approval-reach-warning-dropped);
    #: `requester_notified` is still None there, meaning "not recorded",
    #: not "failed". On the write: `approvers_notified` 0 is "nobody could
    #: be told", None is "the notify write failed"; `requester_notified`
    #: False is "suppressed", None is "failed". `warnings` spells each of
    #: those out, because a 201 with a silent zero is the defect this
    #: exists to fix -- a four-eyes request nobody was told about.
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
        # F9 (2026-09-24): a deployment-wide request has no case to
        # be assigned to, so "nobody on this case" would be the wrong fact.
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

    ux08-triage:approval-row-uuids-no-requester (2026-09-23). The card
    named them through the console's own graph, which holds only what the
    current projection drew, so a merge of two entities outside it was
    still signed as two UUIDs. Resolved here instead, for the entities
    this approver may see; one they may not is None, and the card says so
    rather than naming it."""
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
    """How many APPROVAL_REQUESTED notifications each request raised."""
    ids = [r.id for r in rows]
    if not ids:
        return {}
    return {row[0]: row[1] for row in conn.execute(
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
    rows = ApprovalService(conn).list_for_case(case_id, state=state, limit=limit)
    out = [_out(r).model_dump(mode="json") for r in rows]
    # Who asked and who decided, by NAME. The card printed the payload's
    # UUIDs and nothing about either person, so dual control was a blind
    # click (ux19 raw-ids-instead-of-names, 2026-09-22). The ids stay: they
    # are the durable record, the names are for the person deciding.
    names = _names(conn, rows)
    subjects = _merge_subjects(conn, user, case_id, rows)
    reached = _approvers_reached(conn, rows)
    for item, r in zip(out, rows, strict=True):
        item["requested_by_name"] = names.get(r.requested_by)
        item["decided_by_name"] = names.get(r.decided_by) if r.decided_by else None
        item["subjects"] = subjects.get(r.id)
        # ux08-triage:approval-reach-warning-dropped (2026-09-23). Reach
        # is not stored on the request, but the notifications it raised
        # are, so a listing can say "nobody was told" for as long as that
        # stays true, not only in the reply the requester's browser threw
        # away.
        item["approvers_notified"] = reached.get(r.id, 0)
        op = OPERATIONS.get(r.operation)
        item["operation_description"] = op.description if op else None
    # Case operations only (F9, 2026-09-24): a deployment-wide one is not
    # raised here, and listing it offered an operation this route refuses.
    return {"approvals": out,
            "operations": {k: {"permission": v.permission,
                               "signer_permission": v.signer_permission,
                               "description": v.description,
                               "ttl_seconds": int(v.ttl.total_seconds())}
                           for k, v in OPERATIONS.items()
                           if v.scope == "case"}}


def _relax_payload_problem(conn: psycopg.Connection, case_id: UUID,
                           payload: dict) -> Problem | None:
    """What refuses a `case.policy.relax` request before it is raised (F9b,
    2026-09-24): only the one payload shape, only while the switch is on,
    never under a deployment that requires it, and only for the switch as
    it stands now."""
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


#: Per-operation checks a request's payload must pass before it is raised,
#: after the requester's own authorisation (F9b, 2026-09-24).
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

    Gated on the REQUESTER holding the operation's own permission, not just
    case.read: a request from somebody who could never perform the operation
    is noise in an approver's queue, and an approver who is used to
    dismissing noise is an approver who stops reading.
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
    try:
        record = ApprovalService(conn).request(
            operation=body.operation, case_id=case_id, payload=body.payload,
            justification=body.justification, requested_by=user.user_id)
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

    Three gates, and each one is load-bearing:

    1. `case.read` on this case, from the dependency -- the approver has to
       be on the case at all.
    2. The OPERATION's signer permission, checked below. An approver who
       could not perform the action themselves cannot meaningfully judge
       it, and an approval pool wider than the actor pool quietly weakens
       the control it is meant to strengthen.
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
    # After `case.read` from the dependency, so a break-glass use counts
    # once (sec-breakglass-double-count, 2026-09-23), here and in
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
    """The requester changing their mind. Not a decision: a withdrawn
    request never had one, and the record says so.

    Bound to the path's case (2026-09-24): `case.read` on
    case A no longer withdraws a request raised in case B, which its
    requester may have lost access to. The same 404 as `decide`."""
    svc = ApprovalService(conn)
    record = svc.get(request_id)
    if record is None or record.case_id != case_id:
        raise Problem(404, "Not found", "no such approval request in this case")
    try:
        return _out(svc.withdraw(request_id, actor_id=user.user_id,
                                 scope="case", case_id=case_id))
    except ApprovalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


# ---------------------------------------------------------------------------
# Deployment-wide approvals (F9, dual control, 2026-09-24)
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

    The gate runs first, so a caller holding neither side is refused
    whether or not the id exists. Then 404 unless it is a deployment-wide
    request; then the SIGNER's permission of its operation with a forced
    step-up, refused in the global gate's words ("re-authentication
    required") so the console asks for the sign-in
    (2026-09-24). No `require_step_up` dependency: its words differ."""
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
    """The requester taking back their own deployment-wide request. One
    answer, 404, for a request that is not there, not deployment-wide, not
    theirs or no longer pending, so this route tells nobody which."""
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
    #: F9b (2026-09-24): the approved `case.policy.relax` request that turns
    #: the merge requirement off. Ignored in every other direction.
    approval_request_id: UUID | None = None


class PolicyOut(BaseModel):
    dual_control_merge: bool
    withheld_disclosure: str
    #: F9b (2026-09-24). The deployment's mode for merges, whether this
    #: case needs a second signature on them once that is applied, the
    #: switch's epoch (what a relax request is raised against), and how many
    #: other people on the case could approve turning it off.
    dual_control_merge_mode: str = "PER_CASE"
    dual_control_merge_effective: bool = False
    dual_control_merge_epoch: int = 0
    relax_signers: int = 0


_DISCLOSURE = frozenset({"NONE", "PRESENCE", "COUNT"})


policy_router = APIRouter(prefix="/cases/{case_id}/policy", tags=["approvals"])


def _relax_signers(conn: psycopg.Connection, case_id: UUID,
                   user_id: UUID) -> int:
    """Active accounts other than the caller, assigned to the case under a
    role carrying the relax operation's signer permission, whose clearance
    and compartments dominate the case: the people who could read the
    request and decide it."""
    return conn.execute(
        """SELECT count(DISTINCT u.id)
             FROM iam.case_assignment ca
             JOIN iam.app_user u ON u.id = ca.user_id
             JOIN iam.role_permission rp ON rp.role_key = ca.role_key
                                        AND rp.permission_key = %s
             JOIN core."case" c ON c.id = ca.case_id
            WHERE ca.case_id = %s AND u.is_active AND u.id <> %s
              AND (ca.expires_at IS NULL OR ca.expires_at > now())
              AND c.classification <= u.tlp_clearance
              AND c.compartments <@ u.compartments""",
        (OPERATIONS[RELAX].signer_permission, case_id, user_id)).fetchone()[0]


def _policy_out(conn: psycopg.Connection, case_id: UUID,
                user_id: UUID) -> PolicyOut:
    row = conn.execute(
        'SELECT dual_control_merge, withheld_disclosure, '
        'dual_control_merge_epoch FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "case does not exist")
    return PolicyOut(
        dual_control_merge=bool(row[0]), withheld_disclosure=row[1],
        dual_control_merge_mode=policy_mode(conn, "node.merge"),
        dual_control_merge_effective=case_requires_dual_control(
            conn, case_id, "node.merge"),
        dual_control_merge_epoch=int(row[2]),
        relax_signers=_relax_signers(conn, case_id, user_id))


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

    Step-up gated even though `case.update` is not a step-up permission,
    because turning a control OFF is exactly the action an attacker with a
    borrowed session would want, and the composability of `require_step_up`
    exists for cases where the danger is not captured by the permission row.

    Turning it OFF takes a second person (F9b, 2026-09-24): an approved
    `case.policy.relax` request raised against the switch as it stands,
    consumed here in the same transaction as the change. The database
    refuses the change without one (migration case_merge_relax_two_people).
    Turning it ON stays one signature: a tightening that needs a second
    person is one nobody makes. Under a deployment that requires a second
    signature on every merge, a case cannot turn it off at all.

    Every setting and its CASE_POLICY_CHANGED row land in one transaction,
    so a change is never left without its record, and the consume is the
    transaction's first write (approvals.py, the out-of-band rule).

    Audited both ways. "When did this case stop requiring two signatures"
    is a question somebody will eventually need answered.
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
