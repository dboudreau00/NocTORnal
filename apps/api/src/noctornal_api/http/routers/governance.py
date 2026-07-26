"""Phase 6 over HTTP: retention, purge, legal hold and break-glass.

These services have existed since 2026-07-25 with no interface, which
meant the two most consequential operations in the system -- destroying
data on a schedule, and granting emergency access -- were reachable only
from a Python shell. That is not a safety property. It is an absence of
one, because a Python shell has no five-part gate, no rate limit and no
step-up.

## What this router refuses to make easy

**Purge is destruction and reads like it.** Every purge endpoint demands a
written `authority`, is step-up gated through `retention.purge`, and
`dry_run` defaults to TRUE -- an endpoint whose default is destruction
will eventually be called by a script that meant to ask a question. The
response reports `storage_locked` rather than folding it into a success
boolean, because MinIO under COMPLIANCE object lock can refuse a delete
*even to satisfy a deletion order*, and a tombstone recording a purge that
did not happen is a false record (decision 50).

**Out-of-schedule purge carries a four-eyes approval.** docs/08 requires
dual control and decision 44 registered `evidence.purge` as an
unconditional four-eyes operation, so `approval_request_id` is a required
field rather than something the router may make optional.

**A placeholder retention rule is surfaced, not hidden.** Six rules ship
with periods somebody typed rather than chose, `STEALER_LOG` at 90 days
among them, governing data about thousands of people who are not under
investigation. `GET /retention/rules` marks each one, because a
placeholder that is never surfaced becomes policy by default.

**Break-glass is easy to obtain and loud everywhere else.** docs/05 wants
it "available, loud and short". Making it hard to obtain does not stop the
emergency -- it makes people route around the system during one, which is
worse than the access. So the controls are everywhere EXCEPT the door.
There is deliberately no endpoint to extend a grant, and none to un-review
one.

## Everything here is global, and the case is checked separately

Retention rules are per-category and cross-case by design; a break-glass
grant may name no case at all, which is the shape it takes during an
incident. So these hang off `/retention` and `/break-glass` under
`require_global` -- and `_case_scoped` runs the full five-part gate
whenever a case id IS supplied, because `require_global` knows nothing
about a case and a tombstone names what was destroyed.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.break_glass import BreakGlassError, BreakGlassService, Grant
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    current_user,
    get_conn,
    require_global,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.retention import PurgeResult, RetentionError, RetentionService

router = APIRouter(prefix="/retention", tags=["governance"])
break_glass_router = APIRouter(prefix="/break-glass", tags=["governance"])


def _case_scoped(conn: psycopg.Connection, user: CurrentUser,
                 case_id: UUID, permission: str) -> None:
    """Run the full gate for one case. `case_id` is REQUIRED.

    It used to accept None and no-op, which was the hole: `require_global`
    checks the verb, the account and step-up and knows nothing about a
    case, so every route that let `case_id` default to None ran with no
    case check at all. A caller holding only the global role could purge
    every expired exhibit in the deployment, read any case's deadlines,
    and lift any exhibit's legal hold. All three were reproduced live.
    """
    authorize_object(conn, user, case_id=case_id, permission_key=permission)


def _authorised_cases(conn: psycopg.Connection, user: CurrentUser,
                      permission: str) -> list[UUID]:
    """Every case where the FULL five-part gate would allow `permission`.

    The cross-case listings here are genuinely useful -- an operator wants
    one deadline list, not one per case -- so they are SCOPED rather than
    refused.

    All four checks, matching `CaseService.list_for_user`, which exists
    for exactly this problem and says why: a listing must return exactly
    the set the gate would allow, "or the list becomes a disclosure
    channel". Assignment alone is not enough, because `assign_user`
    performs no clearance check and a case's classification can be raised
    after somebody is assigned to it.
    """
    rows = conn.execute(
        """SELECT c.id
             FROM iam.case_assignment ca
             JOIN core."case" c ON c.id = ca.case_id
             JOIN iam.app_user u ON u.id = ca.user_id
            WHERE ca.user_id = %s
              AND (ca.expires_at IS NULL OR ca.expires_at > now())
              AND u.is_active
              AND EXISTS (SELECT 1 FROM iam.role_permission rp
                           WHERE rp.role_key = ca.role_key
                             AND rp.permission_key = %s)
              AND c.classification <= u.tlp_clearance
              AND c.compartments <@ u.compartments""",
        (user.user_id, permission)).fetchall()
    return [r[0] for r in rows]


def _own_evidence(conn: psycopg.Connection, evidence_id: UUID) -> UUID:
    """The case an exhibit belongs to, or a 404 that reveals nothing.

    `evidence.py` established this pattern and this router did not adopt
    it: gate the case, then confirm the object is IN that case. Without
    it an exhibit id from anywhere was accepted on trust.
    """
    row = conn.execute(
        "SELECT case_id FROM core.evidence WHERE id = %s",
        (evidence_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such exhibit")
    return row[0]


# ---------------------------------------------------------------------------
# Retention rules
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=dict)
def rules(
    user: CurrentUser = Depends(require_global("retention.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every per-category rule, and which of them nobody has confirmed.

    The placeholder flag is the point. `Rule.is_placeholder` is true while
    `confirmed_at` is NULL, and purge WARNS on one rather than refusing --
    refusing would make the first purge the moment somebody discovers the
    question, which is when they are least able to answer it. Surfacing
    them here is what stops a guess becoming policy (docs/16 D3).
    """
    out = []
    for category, rule in sorted(RetentionService(conn).rules().items()):
        out.append({
            "category": category,
            "retain_days": rule.retain_days,
            "rationale": rule.rationale,
            "is_placeholder": rule.is_placeholder,
            "confirmed_by": str(rule.confirmed_by) if rule.confirmed_by else None,
            "confirmed_at": (rule.confirmed_at.isoformat()
                             if rule.confirmed_at else None),
        })
    unconfirmed = [r["category"] for r in out if r["is_placeholder"]]
    return {
        "rules": out,
        "unconfirmed": unconfirmed,
        "notice": (
            f"{len(unconfirmed)} rule(s) still hold a placeholder period "
            f"nobody has confirmed. These are jurisdictional and the build "
            f"cannot choose them (docs/16 D3)." if unconfirmed else
            "every rule has been confirmed, with a rationale and a name"),
    }


class ConfirmRuleBody(BaseModel):
    retain_days: int = Field(gt=0)
    rationale: str = Field(min_length=10)


@router.post("/rules/{category}", response_model=dict)
def confirm_rule(
    category: str, body: ConfirmRuleBody,
    user: CurrentUser = Depends(require_global("retention.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Replace a placeholder with a decision, and record who made it.

    The service's docstring puts it exactly right: the point of the
    confirmation is not the number, it is that somebody's id is attached
    to it. The rationale minimum is what answers "why does this category
    expire when it does" to somebody who was not in the room.
    """
    try:
        rule = RetentionService(conn).confirm_rule(
            category, retain_days=body.retain_days,
            rationale=body.rationale, confirmed_by=user.user_id)
    except RetentionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"category": rule.category, "retain_days": rule.retain_days,
            "rationale": rule.rationale, "confirmed_by": str(user.user_id),
            "is_placeholder": rule.is_placeholder}


# ---------------------------------------------------------------------------
# What is due, and what was destroyed
# ---------------------------------------------------------------------------

@router.get("/due", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def due(
    case_id: UUID | None = Query(None),
    as_of: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=1000),
    user: CurrentUser = Depends(require_global("retention.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What has passed its deadline. Destroys nothing.

    A preview exists so that "what would this purge" is a question you can
    ask before it is a thing you have done. Held items come back FLAGGED
    rather than filtered out: "nothing is due" and "eleven things are due
    and all of them are frozen by a court order" are different answers,
    and an operator needs the second one.
    """
    if case_id is not None:
        _case_scoped(conn, user, case_id, "retention.read")
        scope = [case_id]
    else:
        # NOT "every case in the deployment". A global retention role is
        # not a relationship to a case, and this returns object ids,
        # deadlines and hold reasons.
        scope = _authorised_cases(conn, user, "retention.read")
    svc = RetentionService(conn)
    items = []
    for cid in scope:
        items.extend(svc.due(case_id=cid, as_of=as_of, limit=limit))
    items = items[:limit]
    held = [i for i in items if i.held]
    return {
        "due": [
            {"object_type": i.object_type, "object_id": str(i.object_id),
             "case_id": str(i.case_id) if i.case_id else None,
             "deadline": i.deadline.isoformat(), "rule": i.rule,
             "legal_hold": i.held, "hold_reason": i.hold_reason}
            for i in items],
        "count": len(items),
        "on_legal_hold": len(held),
        "notice": ("Nothing has been destroyed. Legal hold overrides "
                   "deletion everywhere (docs/08), so held items are "
                   "listed and flagged rather than quietly omitted."),
    }


class PurgeBody(BaseModel):
    authority: str = Field(min_length=10)
    #: REQUIRED. It was optional, and a purge with no case id ran
    #: `due(case_id=None)` -- every expired exhibit in the DEPLOYMENT --
    #: for any holder of a global retention role, writing the tombstone
    #: under case_id NULL so the victim case had no record it happened.
    #: Reproduced live. A purge is destruction; it names its case.
    case_id: UUID
    #: TRUE by default. An endpoint whose default is destruction will
    #: eventually be called by a script that meant to ask a question.
    dry_run: bool = True


@router.post("/purge", response_model=dict,
             dependencies=[Depends(rate_limit("retention.destroy"))])
def purge(
    body: PurgeBody,
    user: CurrentUser = Depends(require_global("retention.purge")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Destroy what is expired and not held, under a written authority.

    `authority` is free text and mandatory: the schedule, the policy
    reference, the instruction. A destruction whose authority nobody
    recorded cannot be defended later, and "the job ran" is not one.
    """
    _case_scoped(conn, user, body.case_id, "retention.purge")
    try:
        result = RetentionService(conn).purge_due(
            actor_id=user.user_id, authority=body.authority,
            case_id=body.case_id, dry_run=body.dry_run)
    except RetentionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return _purge_response(result, dry_run=body.dry_run)


class OutOfScheduleBody(BaseModel):
    #: docs/08 requires DUAL CONTROL, and decision 44 registered
    #: `evidence.purge` as an unconditional four-eyes operation. The
    #: approval is consumed inside the same transaction as the
    #: destruction, so this is not a field the router may make optional.
    approval_request_id: UUID
    case_id: UUID
    evidence_ids: list[UUID] = Field(min_length=1)
    authority: str = Field(min_length=10)


@router.post("/purge/out-of-schedule", response_model=dict,
             dependencies=[Depends(rate_limit("retention.destroy"))])
def purge_out_of_schedule(
    body: OutOfScheduleBody,
    user: CurrentUser = Depends(require_global("retention.purge")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Destroy exhibits BEFORE their retention expires.

    Separate from the scheduled path on purpose: that one is the system
    enforcing a rule, this one is a person overriding one, and the two
    must never share an audit signature.
    """
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="retention.purge")
    # Every exhibit must be IN the approved case.
    #
    # The service constrains nothing: its legal-hold pre-check and its
    # UPDATE are both `WHERE id = ANY(%s)`. The four-eyes approval does
    # not save you either -- the payload hash covers the id LIST, so it
    # proves the approver saw those UUIDs, not that the UUIDs belong to
    # the case they approved. Mixing in another case's exhibits destroyed
    # them and wrote the tombstone under the wrong case.
    # Counted POSITIVELY: how many of the requested ids are present in
    # this case. Counting the foreign ones instead would pass a
    # nonexistent id straight through, because it matches neither side.
    ids = list(dict.fromkeys(body.evidence_ids))
    present = conn.execute(
        """SELECT count(*) FROM core.evidence
            WHERE id = ANY(%s) AND case_id = %s""",
        (ids, body.case_id)).fetchone()[0]
    if present != len(ids):
        raise Problem(
            400, "Invalid request",
            f"{len(ids) - present} of the {len(ids)} selected exhibits are "
            f"not in this case. An out-of-schedule purge destroys exactly "
            f"what its approval named, in the case it named -- and the "
            f"tombstone is written against that case, so a cross-case "
            f"destruction would leave the other case with no record that "
            f"it happened.")
    try:
        result = RetentionService(conn).purge_out_of_schedule(
            actor_id=user.user_id, authority=body.authority,
            approval_request_id=body.approval_request_id,
            case_id=body.case_id, evidence_ids=body.evidence_ids)
    except RetentionError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return _purge_response(result, dry_run=False)


def _purge_response(result: PurgeResult, *, dry_run: bool) -> dict:
    return {
        "dry_run": dry_run,
        "evidence_purged": result.evidence_purged,
        "documents_purged": result.documents_purged,
        # Ingest counted separately: an exhibit and a partner's raw record
        # are destroyed under different authority, and one total would hide
        # which of them just went (docs/17 F17(a)).
        "records_purged": result.records_purged,
        "dead_letters_purged": result.dead_letters_purged,
        "held_back": result.held_back,
        # decision 50, reported rather than folded into a boolean.
        "storage_locked": result.storage_locked,
        "tombstones": [str(t) for t in result.tombstones],
        "warnings": result.warnings,
        "notice": (
            "DRY RUN -- nothing was destroyed."
            if dry_run else
            "Destruction is irreversible. `storage_locked` counts objects "
            "the store REFUSED to delete: COMPLIANCE-mode object lock can "
            "refuse even to satisfy a deletion order, and a tombstone "
            "recording a purge that did not happen is a false record."),
    }


@router.get("/tombstones", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def tombstones(
    case_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global("retention.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What was destroyed, under what authority, by whom.

    The tombstone outlives the data on purpose (decision 50): a case file
    that simply lacks an exhibit cannot be told apart from one that never
    had it, and "destroyed lawfully on this date under this authority" is
    the answer a disclosure request needs.
    """
    svc = RetentionService(conn)
    if case_id is not None:
        _case_scoped(conn, user, case_id, "retention.read")
        rows = svc.tombstones(case_id=case_id, limit=limit)
    else:
        # A tombstone names what was destroyed, out of which case, under
        # what authority. Listing every one of them to any holder of a
        # global retention role was a disclosure channel.
        rows = []
        for cid in _authorised_cases(conn, user, "retention.read"):
            rows.extend(svc.tombstones(case_id=cid, limit=limit))
        rows = rows[:limit]
    return {"tombstones": rows, "count": len(rows)}


class LegalHoldBody(BaseModel):
    evidence_id: UUID
    on: bool = True
    reason: str | None = None


@router.post("/legal-hold", response_model=dict,
             dependencies=[Depends(rate_limit("retention.destroy"))])
def legal_hold(
    body: LegalHoldBody,
    user: CurrentUser = Depends(require_global("retention.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Freeze something against every deletion path, or release it.

    docs/08: a hold overrides all deletion, everywhere. Lifting one is as
    consequential as applying one -- it is what makes a later purge lawful
    -- so both are audited, and applying one requires a reason the service
    enforces.
    """
    # The exhibit's OWN case, resolved from the row rather than taken on
    # trust. Without this the endpoint was a blind UPDATE by id: a holder
    # of the global role could LIFT a court-ordered hold on any exhibit in
    # the deployment and then purge it. Reproduced live.
    case_id = _own_evidence(conn, body.evidence_id)
    _case_scoped(conn, user, case_id, "retention.manage")
    try:
        RetentionService(conn).set_legal_hold(
            body.evidence_id, actor_id=user.user_id, on=body.on,
            reason=body.reason)
    except RetentionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"evidence_id": str(body.evidence_id),
            "case_id": str(case_id), "legal_hold": body.on}


# ---------------------------------------------------------------------------
# Break-glass
# ---------------------------------------------------------------------------

def _grant(g: Grant) -> dict:
    return {
        "id": str(g.id),
        "user_id": str(g.user_id),
        "case_id": str(g.case_id) if g.case_id else None,
        "justification": g.justification,
        "started_at": g.started_at.isoformat() if g.started_at else None,
        "expires_at": g.expires_at.isoformat() if g.expires_at else None,
        "is_live": g.is_live(),
        # A @property, not a method. Calling it raised TypeError and
        # every break-glass response 500'd -- including the review
        # queue, which IS the control. The grant row was still
        # written, so access was granted invisibly and the officer
        # who must review it could not list it.
        "awaiting_review": g.awaiting_review,
        "action_count": getattr(g, "action_count", 0),
        "reviewed_by": str(g.reviewed_by) if g.reviewed_by else None,
        "reviewed_at": g.reviewed_at.isoformat() if g.reviewed_at else None,
        "review_outcome": getattr(g, "review_outcome", None),
    }


class InvokeBody(BaseModel):
    #: Long enough to be reviewable. This is the text a security officer
    #: reads, and "urgent" is not reviewable.
    justification: str = Field(min_length=40)
    case_id: UUID | None = None
    classification: str | None = None
    permissions: list[str] = Field(default_factory=list)
    #: The service caps this independently; the bound here just fails
    #: earlier and more legibly.
    duration_hours: int = Field(default=4, ge=1, le=8)


@break_glass_router.post("", response_model=dict, status_code=201,
                         dependencies=[Depends(rate_limit("merge"))])
def invoke(
    body: InvokeBody,
    user: CurrentUser = Depends(require_global("break_glass.invoke")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Grant yourself emergency access. Deliberately easy.

    docs/05 wants break-glass "available, loud and short". Making it hard
    to obtain does not stop the emergency; it makes people route around
    the system during one, which is worse than the access. So the controls
    sit everywhere except the door: a justification long enough to review,
    a hard duration cap, an audit entry per action taken under it, and a
    mandatory review by somebody who is not you.

    It refuses outright when no active user holds `SECURITY_OFFICER` -- a
    grant nobody will review is just access with a better story.
    """
    try:
        grant = BreakGlassService(conn).invoke(
            user_id=user.user_id, case_id=body.case_id,
            justification=body.justification,
            classification=body.classification,
            permissions=body.permissions or None,
            duration=timedelta(hours=body.duration_hours))
    except BreakGlassError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {**_grant(grant),
            "notice": ("Every action taken under this grant is audited "
                       "against it, a security officer who is not you must "
                       "review it, and it expires on its own.")}


@break_glass_router.get("/unreviewed", response_model=dict)
def unreviewed(
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global("break_glass.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The security officer's queue. This is the control.

    `break_glass.review` is granted to SECURITY_OFFICER and to nobody
    else, because a team that can review its own emergencies has the
    separation on paper only.
    """
    grants = BreakGlassService(conn).unreviewed(limit=limit)
    return {"grants": [_grant(g) for g in grants], "count": len(grants),
            "notice": ("Unreviewed emergency access is just access. This "
                       "queue emptying is the control working; it staying "
                       "full is the control failing.")}


class ReviewBody(BaseModel):
    outcome: str
    note: str | None = None


@break_glass_router.post("/{grant_id}/review", response_model=dict)
def review(
    grant_id: UUID, body: ReviewBody,
    user: CurrentUser = Depends(require_global("break_glass.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record the mandatory post-hoc review.

    The service refuses a reviewer who is the invoker -- reviewing your
    own emergency is not a review -- and refuses to revisit a completed
    one, because a disagreement is its own record rather than an edit.
    There is deliberately no endpoint to un-review.
    """
    try:
        grant = BreakGlassService(conn).review(
            grant_id, reviewer_id=user.user_id, outcome=body.outcome,
            note=body.note)
    except BreakGlassError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return _grant(grant)


@break_glass_router.post("/{grant_id}/revoke", response_model=dict)
def revoke(
    grant_id: UUID,
    user: CurrentUser = Depends(require_global("break_glass.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """End a live grant early.

    The review is still required afterwards: revoking is not reviewing,
    and the actions already taken under the grant are the thing being
    reviewed.
    """
    try:
        return _grant(BreakGlassService(conn).revoke(
            grant_id, actor_id=user.user_id))
    except BreakGlassError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@break_glass_router.get("/mine", response_model=dict)
def mine(
    case_id: UUID | None = Query(None),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Whether the caller currently holds a live grant.

    No permission beyond being signed in: this answers "am I operating
    under break-glass right now", and an interface that cannot tell you
    that is one where you forget you are.
    """
    grant = BreakGlassService(conn).live_grant(user.user_id, case_id)
    return {"live": grant is not None,
            "grant": _grant(grant) if grant else None}
