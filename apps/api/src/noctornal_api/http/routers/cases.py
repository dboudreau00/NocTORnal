"""Case endpoints. Creation needs a global case.create; everything else is
case-scoped through the five-part gate.

## 2026-07-30: the case file could not be corrected, shared or closed

`CaseService` has had `update_metadata`, `assign_user_checked` and
`revoke_user` since Phase 1 and migration 0053 recorded that `case.update`,
`case.close` and `case.grant` were seeded, granted, and checked by nothing
— the service methods existed, no router exposed them. In practice that
meant: a typo'd case title was permanent, a case could only ever be worked
by the person who created it (assignment happened once, inside `create`),
and the lifecycle endpoint below was the only reachable mutation.

This module now exposes the four missing operations. Three of them needed
guards that the service layer does not provide, and those guards are the
interesting part of this file:

1. **Classification may be raised, never lowered here** (`update_case`).
2. **A case assignment that confers nothing is refused** rather than
   written and silently ignored by every read path (`assign_case_user`).
3. **`ARCHIVED -> PURGED` is re-gated onto `case.delete`** (`transition`),
   because marking a case for destruction is not a "close".

## Where the audit rows come from

Every mutation here is audited *inside* `CaseService`, in the same
transaction as the write (`CASE_UPDATED`, `CASE_STATUS_CHANGED`,
`CASE_ACCESS_GRANTED`). This router deliberately does not write its own
audit rows for the success path — two rows per action, one of which can
commit without the other, is worse than one.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.cases import CaseService
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    require,
    require_global,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.security.access import Tlp, tlp_from_name

router = APIRouter(tags=["cases"])


class CreateCaseBody(BaseModel):
    code: str
    title: str
    legal_basis: str
    retention_until: date
    review_due: date
    classification: str = "AMBER"
    summary: str | None = None
    authority_ref: str | None = None
    compartments: list[str] = []


class CaseOut(BaseModel):
    id: str
    code: str
    title: str
    status: str
    classification: str
    owner_user_id: str
    legal_basis: str
    retention_until: date
    review_due: date
    created_at: datetime


def _out(c) -> CaseOut:
    return CaseOut(
        id=str(c.id), code=c.code, title=c.title, status=c.status,
        classification=c.classification, owner_user_id=str(c.owner_user_id),
        legal_basis=c.legal_basis, retention_until=c.retention_until,
        review_due=c.review_due, created_at=c.created_at,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/cases", response_model=CaseOut, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def create_case(body: CreateCaseBody,
                user: CurrentUser = Depends(require_global("case.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    svc = CaseService(conn)
    case_id = svc.create(
        code=body.code, title=body.title, legal_basis=body.legal_basis,
        retention_until=body.retention_until, review_due=body.review_due,
        owner_user_id=user.user_id, created_by=user.user_id,
        classification=body.classification, compartments=body.compartments,
        summary=body.summary, authority_ref=body.authority_ref,
    )
    return _out(svc.get(case_id))


@router.get("/cases", response_model=list[CaseOut],
            dependencies=[Depends(rate_limit("graph.view"))])
def list_cases(user: CurrentUser = Depends(current_user),
               conn: psycopg.Connection = Depends(get_conn)) -> list[CaseOut]:
    return [_out(c) for c in CaseService(conn).list_for_user(user.user_id)]


@router.get("/cases/{case_id}", response_model=CaseOut,
            dependencies=[Depends(rate_limit("graph.view"))])
def get_case(case_id: UUID,
             _: CurrentUser = Depends(require("case.read")),
             conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    case = CaseService(conn).get(case_id)
    if case is None:
        raise Problem(404, "Not found", "case does not exist")
    return _out(case)


# ---------------------------------------------------------------------
# PATCH /cases/{case_id} — correct the case file
# ---------------------------------------------------------------------

class UpdateCaseBody(BaseModel):
    """Every field optional; omitted means "leave alone".

    Deliberately absent:

    - `code` — the case's durable identifier (invariant 9). It is quoted in
      warrants, exhibit labels and other agencies' correspondence. Renaming
      it would silently invalidate every external reference.
    - `status` — the lifecycle has a validated transition table; it moves
      through `POST /cases/{case_id}/status`, not through a metadata edit.
    - `compartments` — `update_metadata` cannot write them, and adding a
      compartment locks out every assignee not read into it. That needs its
      own endpoint with the same "who loses access" reporting as below.
    - `owner_user_id` — changing the owner is a grant, not a metadata edit;
      it belongs on `POST /cases/{case_id}/users`.
    """
    # min_length=1: `update_metadata` treats None as "not supplied", so an
    # empty string is not a no-op — it would write an untitled case.
    title: str | None = Field(default=None, min_length=1)
    summary: str | None = None
    authority_ref: str | None = None
    review_due: date | None = None
    retention_until: date | None = None
    classification: str | None = None


@router.patch("/cases/{case_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def update_case(case_id: UUID, body: UpdateCaseBody,
                user: CurrentUser = Depends(require("case.update")),
                conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Edit governance and descriptive metadata.

    ## Classification: raising is allowed, lowering is refused

    These two directions are not the same operation wearing different signs.

    RAISING is safe for disclosure. `effective_labels` (deps.py) decides
    every access on the STRICTER of the case's label and the element's, so
    the moment the case becomes RED every node, edge and exhibit inside it
    is read as RED too, whatever its own label says. The DB floor trigger
    (`core.enforce_tlp_floor`) deliberately does not re-check pre-existing
    rows on a case raise, precisely so the case can be raised without
    stranding them.

    LOWERING is a DECLASSIFICATION of everything the case protects, and it
    is not recoverable by lowering it back: whoever read it in the meantime
    has read it. It also widens silently — the elements that were forced up
    to the old floor keep their own labels, but everything protected ONLY
    by the case label (the case file itself, and every child table without
    its own classification column) drops in one statement, with no review
    and no second signature. `case.update` is "Edit case metadata" in the
    seed, held by CASE_OWNER; it was never meant to carry that.

    So this endpoint refuses it. Declassification needs its own verb with
    step-up and dual control, the way `evidence.purge` and `case.delete`
    have them. Until that verb exists the honest answer is 400 with the
    reason, not a quiet downgrade.

    ## Raising is still capped by the caller's own clearance

    `check_writable_labels` refuses to author content above the caller's
    clearance. Without it a CASE_OWNER cleared to AMBER could raise their
    case to RED and instantly lose the case they were mid-way through
    running — the same "wrote it, cannot see it" trap the helper was built
    for on the node path.

    ## Who loses access, reported rather than discovered

    Raising the classification silently evicts every assignee cleared below
    the new level: they simply stop seeing the case, with no error anywhere
    (`list_for_user` filters them out; the gate 404s them). Invariant 12 —
    nothing is silently dropped — so the response names them. The caller
    may well intend it; they should not have to find out by being asked.
    """
    svc = CaseService(conn)
    current = svc.get(case_id)
    if current is None:
        # Unreachable in practice: require() resolves the case's labels
        # first and 404s on a case that does not exist. Kept because a
        # missing row must never fall through to an AttributeError 500.
        raise Problem(404, "Not found", "case does not exist")

    # PURGED is terminal and means "this case has been marked for
    # destruction". Editing its governance record after that point would
    # rewrite the very metadata a retention review reads to justify the
    # purge. Every other status stays editable — an archived case with a
    # wrong authority_ref should still be correctable.
    if current.status == "PURGED":
        raise Problem(400, "Invalid request",
                      "a PURGED case is a closed record and cannot be edited")

    # `update_metadata` reads None as "not supplied", so a JSON null cannot
    # clear a field — it is indistinguishable from omitting the key. Rather
    # than let `{"summary": null}` 200 while doing nothing, drop the nulls
    # here and let the emptiness check below refuse the request. Clearing a
    # field back to NULL needs a service-layer change (see `concerns`).
    supplied = {k: v for k, v in body.model_dump(exclude_unset=True).items()
                if v is not None}

    access_lost: list[dict] = []
    classification = body.classification
    if classification is not None:
        if classification not in Tlp.__members__:
            # Validated here rather than letting it reach the tlp enum
            # column: an unknown label would surface as a psycopg
            # InvalidTextRepresentation and come back as a 500.
            raise Problem(400, "Invalid request",
                          f"unknown classification {classification!r} — one of "
                          f"{', '.join(Tlp.__members__)}")
        now_tlp = tlp_from_name(current.classification)
        new_tlp = Tlp[classification]
        if new_tlp < now_tlp:
            raise Problem(
                400, "Invalid request",
                f"refusing to lower this case from {current.classification} to "
                f"{classification}. Lowering a case's TLP declassifies "
                "everything it protects and cannot be undone by raising it "
                "again; it needs a dedicated declassification verb with "
                "step-up and a second authoriser, which does not exist yet.")
        if new_tlp == now_tlp:
            # Drop it, so the CASE_UPDATED audit detail does not record a
            # classification change that never happened — and so a PATCH
            # whose ONLY field was the label it already has is refused
            # below rather than answering 200 to a no-op.
            classification = None
            supplied.pop("classification", None)
        else:
            check_writable_labels(conn, user, classification=classification)
            access_lost = _assignees_below(conn, case_id, new_tlp)

    if not supplied:
        # `update_metadata` returns early and writes no audit row when
        # nothing changed, so this would otherwise 200 having done nothing
        # and left no trace that it was attempted (invariant 12).
        raise Problem(400, "Invalid request",
                      "nothing to change — supply a non-null title, summary, "
                      "authority_ref, review_due, retention_until, or a "
                      "classification different from the current one")

    svc.update_metadata(
        case_id, updated_by=user.user_id,
        title=body.title, summary=body.summary,
        authority_ref=body.authority_ref, review_due=body.review_due,
        retention_until=body.retention_until, classification=classification,
    )
    updated = svc.get(case_id)
    # Flattened rather than nested under a "case" key so a client that only
    # reads .status/.title sees the same shape GET /cases/{id} returns.
    return {**_out(updated).model_dump(mode="json"), "access_lost": access_lost}


def _assignees_below(conn: psycopg.Connection, case_id: UUID,
                     new_tlp: Tlp) -> list[dict]:
    """Live assignees whose clearance will not reach `new_tlp`.

    Compared in Python against the `Tlp` lattice rather than in SQL: the
    column is the `core.tlp` enum, and comparing it to a bound text
    parameter depends on Postgres inferring the cast, which is exactly the
    kind of thing that works in a test and fails on a driver upgrade.
    """
    rows = conn.execute(
        """SELECT u.id, u.display_name, u.tlp_clearance
             FROM iam.case_assignment a
             JOIN iam.app_user u ON u.id = a.user_id
            WHERE a.case_id = %s
              AND (a.expires_at IS NULL OR a.expires_at > now())
              AND u.is_active""",
        (case_id,),
    ).fetchall()
    return [
        {"user_id": str(r[0]), "display_name": r[1], "tlp_clearance": r[2]}
        for r in rows
        if tlp_from_name(r[2]) < new_tlp
    ]


# ---------------------------------------------------------------------
# Case access: who is on this case
# ---------------------------------------------------------------------

class AssignUserBody(BaseModel):
    #: The durable identifier, never the email (invariant 9): `app_user.email`
    #: is citext-unique but a person's address changes and can be reassigned
    #: within an organisation. A grant must not follow the mailbox.
    user_id: UUID
    role_key: str
    #: docs/05 wants case access time-boxed by default. Not forced here —
    #: a case owner with an expiring grant is its own failure mode — but
    #: validated so a grant cannot be born already dead.
    expires_at: datetime | None = None


@router.post("/cases/{case_id}/users", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def assign_case_user(case_id: UUID, body: AssignUserBody,
                     user: CurrentUser = Depends(require("case.grant")),
                     conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Grant (or change) a user's access to this case.

    `case.grant` is `requires_step_up = true` in the seed, and `require()`
    reads that off the permission row and enforces it as check five of the
    gate. There is deliberately no hand-rolled step-up call here: a second
    implementation of an assurance check is a second place for it to be
    wrong, and `require_step_up` exists for the opposite case (danger the
    permission row does NOT capture).

    `assign_user_checked` — not `assign_user` — because an assignee who
    cannot clear the case's classification or is not read into its
    compartments is a reachable state that every listing then quietly
    filters away. The grant would appear to succeed and confer nothing.

    Four things it does not check, which are checked here:

    - **the role exists and confers something.** `_grant` inserts straight
      into `case_assignment`; an unknown `role_key` trips a foreign key and
      would surface as a 500, and a real role holding no permissions is a
      grant that does nothing.
    - **the account is live.** `list_for_user` and the gate both require
      `is_active`; assigning a deactivated account writes a row that no
      code path will ever honour.
    - **`expires_at` is in the future.** A past expiry writes an assignment
      that is expired the instant it commits.
    - **the owner is not demoted.** `_grant` is an UPSERT on
      (case_id, user_id), so re-assigning the owner REPLACES their
      CASE_OWNER row. `revoke_user` refuses to remove the owner's access;
      nothing stopped you achieving the same thing by regrading them to
      READ_ONLY, which would lock the case's owner out of their own case
      with no way back short of SQL.
    """
    case = CaseService(conn).get(case_id)
    if case is None:
        raise Problem(404, "Not found", "case does not exist")

    if body.expires_at is not None and body.expires_at <= _now():
        raise Problem(400, "Invalid request",
                      "expires_at is in the past — that grant would be "
                      "expired before it was written")

    role = conn.execute(
        """SELECT r.key,
                  ARRAY(SELECT rp.permission_key FROM iam.role_permission rp
                         WHERE rp.role_key = r.key ORDER BY rp.permission_key)
             FROM iam.role r WHERE r.key = %s""",
        (body.role_key,),
    ).fetchone()
    if role is None:
        raise Problem(400, "Invalid request", f"unknown role {body.role_key!r}")
    if not role[1]:
        raise Problem(400, "Invalid request",
                      f"role {body.role_key!r} grants no permissions — that "
                      "assignment would confer nothing")

    assignee = conn.execute(
        "SELECT display_name, is_active FROM iam.app_user WHERE id = %s",
        (body.user_id,),
    ).fetchone()
    if assignee is None:
        raise Problem(404, "Not found", "no such user")
    if not assignee[1]:
        raise Problem(400, "Invalid request",
                      "that account is deactivated — the assignment would "
                      "be ignored by every access check")

    # The owner-demotion guard. Mirrors revoke_user's refusal to strip the
    # owner: the two are the same act by different routes.
    if body.user_id == case.owner_user_id and body.role_key != "CASE_OWNER":
        raise Problem(400, "Invalid request",
                      "that user owns this case; regrading them would lock "
                      "the owner out of their own case. Transfer ownership "
                      "first.")

    existing = conn.execute(
        "SELECT role_key FROM iam.case_assignment "
        "WHERE case_id = %s AND user_id = %s",
        (case_id, body.user_id),
    ).fetchone()

    CaseService(conn).assign_user_checked(
        case_id, body.user_id, body.role_key,
        granted_by=user.user_id, expires_at=body.expires_at,
    )
    return {
        "case_id": str(case_id),
        "user_id": str(body.user_id),
        "display_name": assignee[0],
        "role_key": body.role_key,
        "expires_at": body.expires_at.isoformat() if body.expires_at else None,
        # An UPSERT that replaced an existing grade must say so — otherwise
        # demoting a colleague looks identical to adding a new one
        # (invariant 12).
        "replaced_role": existing[0] if existing else None,
        # What this grade actually confers on this case, so "I gave them
        # access and they still cannot upload" is answerable at the moment
        # of granting rather than by reading the seed.
        "grants": list(role[1]),
    }


@router.get("/cases/{case_id}/users", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def list_case_users(case_id: UUID,
                    _: CurrentUser = Depends(require("case.read")),
                    conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Who is assigned to this case, and whether the assignment works.

    `effective` is the point of this endpoint. An assignment row is only
    half of access: the same five-part gate that guards every other
    endpoint also needs an unexpired assignment, a live account, clearance
    that dominates the case, and the case's compartments. A row that fails
    any of those is invisible in its effects and indistinguishable from a
    working one in the table — which is how somebody ends up asking why a
    colleague they "added last week" cannot open the case.

    Recomputed here from the same predicates `CaseService.list_for_user`
    uses, so the two cannot drift into disagreeing about who can read.

    Email is deliberately not returned. LIAISON holds `case.read`, so this
    endpoint is reachable by an external partner, and the roster of a case
    does not need to hand out the staff directory to answer "who is on it".
    """
    labels = conn.execute(
        'SELECT classification, compartments FROM core."case" WHERE id = %s',
        (case_id,),
    ).fetchone()
    if labels is None:
        raise Problem(404, "Not found", "case does not exist")
    case_tlp, case_comp = tlp_from_name(labels[0]), set(labels[1] or [])

    rows = conn.execute(
        """SELECT a.user_id, u.display_name, a.role_key, a.granted_by,
                  a.granted_at, a.expires_at, u.is_active,
                  u.tlp_clearance, u.compartments,
                  EXISTS (SELECT 1 FROM iam.role_permission rp
                           WHERE rp.role_key = a.role_key
                             AND rp.permission_key = 'case.read')
             FROM iam.case_assignment a
             JOIN iam.app_user u ON u.id = a.user_id
            WHERE a.case_id = %s
            ORDER BY a.granted_at""",
        (case_id,),
    ).fetchall()

    now = _now()
    users = []
    for r in rows:
        expired = r[5] is not None and r[5] <= now
        effective = (
            bool(r[9])                       # role grants case.read
            and not expired                  # assignment still live
            and bool(r[6])                   # account active
            and tlp_from_name(r[7]) >= case_tlp   # clearance dominates
            and case_comp <= set(r[8] or []) # read into every compartment
        )
        users.append({
            "user_id": str(r[0]),
            "display_name": r[1],
            "role_key": r[2],
            "granted_by": str(r[3]) if r[3] else None,
            "granted_at": r[4].isoformat(),
            "expires_at": r[5].isoformat() if r[5] else None,
            "expired": expired,
            "is_active": bool(r[6]),
            # Named "effective" rather than "can_read" because it answers
            # the whole gate, not one check.
            "effective": effective,
        })
    return {"case_id": str(case_id), "classification": labels[0],
            "users": users}


# ---------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------

class TransitionBody(BaseModel):
    status: str


@router.post("/cases/{case_id}/status", response_model=CaseOut,
             dependencies=[Depends(rate_limit("request"))])
def transition(case_id: UUID, body: TransitionBody,
               user: CurrentUser = Depends(require("case.close")),
               conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    """Move the case along its lifecycle (`_TRANSITIONS` in cases.py).

    ## Re-gated from case.update to case.close (2026-07-30)

    This endpoint predates the rest of the file and asked for
    `case.update`, the "edit case metadata" verb. `case.close` — "Close a
    case" — was seeded in 0017 for exactly this and had zero call sites.
    No access changes today (0021 grants both to CASE_OWNER and to nobody
    else), so this is a correction of meaning, not of reach: an operator
    tightening the roles later must be able to grant "may correct the case
    file" without also granting "may close it".

    ## PURGED is not a close

    `ARCHIVED -> PURGED` marks a case for destruction. Reaching it through
    the close verb would let a permission with neither step-up nor dual
    control set the flag that authorises destroying a case file, while
    `case.delete` sits in the seed with BOTH (`requires_step_up`,
    `requires_dual_control`) and nothing calling it. So that one transition
    re-enters the gate under `case.delete`.

    That gets the step-up half enforced — `evaluate()` reads
    `requires_step_up` off the permission row. It does NOT get dual
    control: that is the approvals subsystem's job and it is not wired to
    this transition. A single authoriser can still mark a case PURGED. It
    is a marker of intent (the destruction itself is Phase 6), and the
    audit row names them, but it is not the two signatures the seed asks
    for. Flagged rather than left implicit.
    """
    svc = CaseService(conn)
    if body.status == "PURGED":
        authorize_object(conn, user, case_id=case_id,
                         permission_key="case.delete")
    svc.transition_status(case_id, body.status, actor_id=user.user_id)
    return _out(svc.get(case_id))
