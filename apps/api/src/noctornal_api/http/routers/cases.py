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

`revoke_case_user` joined them on 2026-09-22: `revoke_user` had no route
either, so a case shared from the console could not be unshared from it.
It refuses to remove the owner, for the same reason the grant route
refuses to regrade them.

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

from noctornal_api.cases import CaseError, CaseService
from noctornal_api.http.deps import (
    CurrentUser,
    audit_auth_event,
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
    # When the case was last closed. The workspace header states the case's
    # lifecycle state and, for a closed case, since when: material added
    # after this instant postdates the close, which matters for disclosure
    # (ux02-cases:case-status-invisible-in-workspace, 2026-09-22).
    closed_at: datetime | None = None


def _out(c) -> CaseOut:
    return CaseOut(
        id=str(c.id), code=c.code, title=c.title, status=c.status,
        classification=c.classification, owner_user_id=str(c.owner_user_id),
        legal_basis=c.legal_basis, retention_until=c.retention_until,
        review_due=c.review_due, created_at=c.created_at,
        closed_at=c.closed_at,
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
    # RETENTION MAY BE EXTENDED, NEVER SHORTENED HERE.
    #
    # `retention.py:201` selects evidence for destruction with
    # `c.retention_until <= today`, and `evidence.purge` is registered as an
    # unconditional DUAL-CONTROL operation (decision 44). So a caller
    # holding only `case.update` — which ANALYST does not have but any
    # CASE_OWNER does, on a verb described in the seed as "Edit case
    # metadata" — could set this date into the past and have the next purge
    # run destroy the case's evidence with ONE signature instead of two.
    #
    # That is not a retention edit, it is the four-eyes gate walked around,
    # and the audit trail would show a metadata change rather than a
    # destruction. Same shape as the classification rule above and refused
    # the same way: shortening a retention period is a real operation, it
    # just needs its own verb with step-up and a second authoriser, and that
    # verb does not exist yet.
    if (body.retention_until is not None
            and body.retention_until < current.retention_until):
        raise Problem(
            400, "Invalid request",
            f"refusing to shorten retention from {current.retention_until} "
            f"to {body.retention_until}. Evidence is selected for "
            f"destruction by this date, and destruction is dual-controlled: "
            f"moving the date earlier under `case.update` would let one "
            f"person schedule what two are required to authorise. "
            f"Extending it is allowed.")

    if classification is not None:
        if classification not in Tlp.__members__:
            # Validated here rather than letting it reach the tlp enum
            # column: an unknown label would surface as a psycopg
            # InvalidTextRepresentation and come back as a 500.
            raise Problem(400, "Invalid request",
                          f"unknown classification {classification!r}: it "
                          f"must be one of {', '.join(Tlp.__members__)}")
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
                      "nothing to change: supply a non-null title, summary, "
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
    #: The durable identifier (invariant 9): `app_user.email` is
    #: citext-unique but a person's address changes and can be reassigned
    #: within an organisation. A grant must not follow the mailbox.
    user_id: UUID | None = None
    #: OR the colleague's work address, resolved to their id HERE, once, at
    #: the moment of granting. The assignment row still stores `user_id`,
    #: so the grant binds to the person and not the mailbox, and invariant
    #: 9 holds. Added 2026-09-22 (ux16 no-user-id-for-share, ux02
    #: share-needs-raw-uuid): the only way to share a case was to type an
    #: `iam.app_user.id` that no screen available to a case owner ever
    #: showed, and the directory that does show ids needs `user.manage`.
    #: Exactly one address is resolved per request, so this answers "is
    #: this person on the system" for one address a caller already knows
    #: and never lists anybody.
    email: str | None = Field(default=None, min_length=3, max_length=320)
    role_key: str
    #: docs/05 wants case access time-boxed by default. Not forced here —
    #: a case owner with an expiring grant is its own failure mode — but
    #: validated so a grant cannot be born already dead.
    expires_at: datetime | None = None


def _audit_share_refused(conn: psycopg.Connection, user: CurrentUser,
                         case_id: UUID, email: str, reason: str) -> None:
    """Record a grant by address that was refused, with the address.

    Sharing by address answers, for one address at a time, whether an
    active account uses it: an unknown address is a 404, a known one that
    cannot open the case a 400. That cannot be hidden without making the
    Share dialog useless to the owner who mistypes an address, and a grant
    that succeeds says as much anyway. What CAN be ensured is that asking
    leaves a trace: a successful grant is audited by the service, and until
    2026-09-23 a refused one wrote nothing, so a `case.grant` holder could
    walk a list of addresses unseen (verifier follow-up to ux02
    share-needs-raw-uuid). Grants by id are not recorded here: an id is
    not guessable, and the service's own refusal already covers them.
    """
    audit_auth_event(conn, "CASE_SHARE_REFUSED", user.user_id, case_id,
                     {"by": "email", "email": email.strip().lower(),
                      "reason": reason})


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

    if (body.user_id is None) == (body.email is None):
        raise Problem(400, "Invalid request",
                      "name the colleague by user_id or by email, and by "
                      "exactly one of them")

    if body.expires_at is not None:
        # An offset is REQUIRED, and the absence of one is a 400 rather
        # than an assumption.
        #
        # `2027-03-14T17:00:00` is valid ISO 8601 and Pydantic parses it
        # into a naive datetime. Comparing that to the aware `_now()`
        # raises `TypeError: can't compare offset-naive and offset-aware
        # datetimes`, which nothing catches — so the most ordinary
        # possible client mistake was a 500 on an access-control path.
        #
        # Defaulting it to UTC would be worse than refusing. This value
        # decides the instant somebody LOSES access to a case; a grant
        # meant to end at 17:00 local, silently read as 17:00Z, is up to
        # thirteen hours of unintended access on either side, and nothing
        # in the response would say which reading was taken.
        if body.expires_at.utcoffset() is None:
            raise Problem(
                400, "Invalid request",
                "expires_at has no UTC offset. This decides the moment "
                "someone loses access to a case, so it is not guessed: "
                "send an offset-aware timestamp such as "
                "2027-03-14T17:00:00Z or 2027-03-14T17:00:00+01:00.")
        if body.expires_at <= _now():
            raise Problem(400, "Invalid request",
                          "expires_at is in the past: that grant would be "
                          "expired before it was written")

    role = conn.execute(
        """SELECT r.key,
                  ARRAY(SELECT rp.permission_key FROM iam.role_permission rp
                         WHERE rp.role_key = r.key ORDER BY rp.permission_key),
                  r.display_name
             FROM iam.role r WHERE r.key = %s""",
        (body.role_key,),
    ).fetchone()
    if role is None:
        raise Problem(400, "Invalid request", f"unknown role {body.role_key!r}")
    if not role[1]:
        raise Problem(400, "Invalid request",
                      f"role {body.role_key!r} grants no permissions, so that "
                      "assignment would confer nothing")

    # The address is resolved only AFTER everything about the request
    # itself has been validated. Resolved first, a request with a bad
    # role_key answered 404 for an unknown address and 400 for a known one,
    # writing nothing and auditing nothing: a free account-existence probe
    # for any case.grant holder (2026-09-23). From here on, a known address
    # either becomes a grant, which is audited, or is refused for a reason
    # about that grant.
    target = body.user_id
    if target is None:
        # One refusal for "no account" and "deactivated account" alike: the
        # address is guessable where a UUID is not, so the two answers must
        # not differ. An inactive account could not use the grant anyway.
        row = conn.execute(
            "SELECT id FROM iam.app_user WHERE email = %s AND is_active",
            (body.email.strip(),)).fetchone()
        if row is None:
            _audit_share_refused(conn, user, case_id, body.email,
                                 "no_active_account")
            raise Problem(404, "Not found",
                          "no active account uses that address. Check the "
                          "spelling, or ask an administrator whether the "
                          "account exists and is active.")
        target = row[0]

    assignee = conn.execute(
        "SELECT display_name, is_active FROM iam.app_user WHERE id = %s",
        (target,),
    ).fetchone()
    if assignee is None:
        raise Problem(404, "Not found", "no such user")
    if not assignee[1]:
        raise Problem(400, "Invalid request",
                      "that account is deactivated, so the assignment would "
                      "be ignored by every access check")

    # The owner-demotion guard. Mirrors revoke_user's refusal to strip the
    # owner: the two are the same act by different routes.
    if target == case.owner_user_id and body.role_key != "CASE_OWNER":
        if body.email is not None:
            _audit_share_refused(conn, user, case_id, body.email, "owner")
        raise Problem(400, "Invalid request",
                      "that user owns this case; regrading them would lock "
                      "the owner out of their own case. Transfer ownership "
                      "first.")

    existing = conn.execute(
        "SELECT a.role_key, r.display_name FROM iam.case_assignment a "
        "LEFT JOIN iam.role r ON r.key = a.role_key "
        "WHERE a.case_id = %s AND a.user_id = %s",
        (case_id, target),
    ).fetchone()

    try:
        CaseService(conn).assign_user_checked(
            case_id, target, body.role_key,
            granted_by=user.user_id, expires_at=body.expires_at,
        )
    except CaseError as exc:
        if body.email is None:
            raise
        _audit_share_refused(conn, user, case_id, body.email, "labels")
        # The service's refusal names the assignee's clearance ("assignee
        # clearance GREEN is below ..."). Reached by UUID that told a case
        # owner about somebody whose id they already held; reached by a
        # guessable address it would tell them any colleague's clearance.
        # Said the way the roster says it, without the level (2026-09-23).
        raise Problem(
            400, "Invalid request",
            "that colleague could not open this case: their clearance is "
            "below its classification, or they are not read into one of its "
            "compartments. An administrator can check their account.",
        ) from exc
    return {
        "case_id": str(case_id),
        "user_id": str(target),
        "display_name": assignee[0],
        "role_key": body.role_key,
        "expires_at": body.expires_at.isoformat() if body.expires_at else None,
        # An UPSERT that replaced an existing grade must say so — otherwise
        # demoting a colleague looks identical to adding a new one
        # (invariant 12).
        "replaced_role": existing[0] if existing else None,
        # The names a person reads, beside the keys. The owner decided
        # CASE_OWNER is shown as Lead investigator (migration 0062), and
        # the Share panel printed the key because nothing it could read
        # carried the name: `/admin/roles` needs user.manage (final review
        # U21, 2026-09-23).
        "role_name": role[2] or body.role_key,
        "replaced_role_name": ((existing[1] or existing[0])
                               if existing else None),
        # What this grade actually confers on this case, so "I gave them
        # access and they still cannot upload" is answerable at the moment
        # of granting rather than by reading the seed.
        "grants": list(role[1]),
    }


@router.get("/cases/{case_id}/users", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def list_case_users(case_id: UUID,
                    user: CurrentUser = Depends(require("case.read")),
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

    That includes break-glass. `list_for_user` and the gate count a live
    grant, on this case or global, at its level; this compared
    `u.tlp_clearance` alone, so an analyst working in the case under an
    emergency grant was shown to its owner as "cannot open the case",
    "clearance below the case's classification" (final review U22,
    2026-09-23). Such a colleague is now `effective`, and a caller who can
    manage the roster (`you_can_grant`) is also told when that access
    lapses, in `emergency_access_until`, because on that instant they
    drop back to "cannot open" and a clearance change, not a re-share, is
    what fixes it. Anyone else reading the roster, LIAISON included, gets
    null there: whether a colleague can open the case answers their
    question, and who is on emergency access is not a partner's business.

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

    # The last column: when this colleague's live break-glass cover for the
    # case ends, counting only grants (global, or on this case) at or
    # above the case's classification, i.e. the ones that open it. NULL
    # when no such grant is live. Same grant predicate as list_for_user.
    rows = conn.execute(
        """SELECT a.user_id, u.display_name, a.role_key, a.granted_by,
                  a.granted_at, a.expires_at, u.is_active,
                  u.tlp_clearance, u.compartments,
                  EXISTS (SELECT 1 FROM iam.role_permission rp
                           WHERE rp.role_key = a.role_key
                             AND rp.permission_key = 'case.read'),
                  (SELECT max(bg.expires_at) FROM iam.break_glass bg
                    WHERE bg.user_id = a.user_id AND bg.revoked_at IS NULL
                      AND bg.expires_at > now()
                      AND bg.granted_classification >= %s::core.tlp
                      AND (bg.case_id IS NULL OR bg.case_id = a.case_id))
             FROM iam.case_assignment a
             JOIN iam.app_user u ON u.id = a.user_id
            WHERE a.case_id = %s
            ORDER BY a.granted_at""",
        (labels[0], case_id),
    ).fetchall()

    # Whether the CALLER's own case role carries `case.grant`, so the Share
    # panel offers Add and Remove only to somebody who could use them. It
    # showed both to every roster reader, LIAISON and READ_ONLY included,
    # and each click ended in a 403 (2026-09-23). A hint for the console,
    # never a gate: the grant and revoke routes still decide, step-up
    # included. Read before the roster is built because it also decides
    # who is told when a colleague's emergency access ends (U22).
    can_grant = bool(conn.execute(
        """SELECT EXISTS (
               SELECT 1 FROM iam.case_assignment a
                 JOIN iam.role_permission rp ON rp.role_key = a.role_key
                WHERE a.case_id = %s AND a.user_id = %s
                  AND (a.expires_at IS NULL OR a.expires_at > now())
                  AND rp.permission_key = 'case.grant')""",
        (case_id, user.user_id)).fetchone()[0])

    owner = CaseService(conn).get(case_id).owner_user_id
    granters = {r[3] for r in rows if r[3]}
    names = {g[0]: g[1] for g in conn.execute(
        "SELECT id, display_name FROM iam.app_user WHERE id = ANY(%s)",
        (list(granters),)).fetchall()} if granters else {}
    # The name a person reads for each grade on the roster, looked up like
    # the granters' names: the owner decided CASE_OWNER is shown as Lead
    # investigator (0062), every case worker opens this roster, and none
    # of them can read `/admin/roles` (final review U21, 2026-09-23).
    role_names = {g[0]: g[1] for g in conn.execute(
        "SELECT key, display_name FROM iam.role WHERE key = ANY(%s)",
        (list({r[2] for r in rows}),)).fetchall()} if rows else {}
    now = _now()
    users = []
    for r in rows:
        expired = r[5] is not None and r[5] <= now
        # Each failing check, in words, so the Share panel can say WHY a
        # colleague on the roster cannot open the case rather than only
        # that they cannot (ux02 share-needs-raw-uuid, 2026-09-22). The
        # clearance line does not name the colleague's level: LIAISON can
        # read this roster, and "below the case" answers the question
        # without handing a partner the staff's clearances.
        reasons = []
        role_name = role_names.get(r[2]) or r[2]
        if not r[9]:
            reasons.append(f"the {role_name} role does not include reading "
                           f"the case")
        if expired:
            reasons.append("the assignment has expired")
        if not r[6]:
            reasons.append("the account is deactivated")
        # Below the case on their own clearance, but a live grant covers
        # it: the gate opens the case, so this is not a reason (U22).
        below = tlp_from_name(r[7]) < case_tlp
        under_grant = below and r[10] is not None
        if below and not under_grant:
            reasons.append("their clearance is below the case's classification")
        if not case_comp <= set(r[8] or []):
            reasons.append("they are not read into every compartment on this case")
        users.append({
            "user_id": str(r[0]),
            "display_name": r[1],
            "role_key": r[2],
            # The key stays for code and for a tooltip (U21, above).
            "role_name": role_name,
            "is_owner": r[0] == owner,
            "granted_by": str(r[3]) if r[3] else None,
            "granted_by_name": names.get(r[3]) if r[3] else None,
            "granted_at": r[4].isoformat(),
            "expires_at": r[5].isoformat() if r[5] else None,
            "expired": expired,
            "is_active": bool(r[6]),
            # Named "effective" rather than "can_read" because it answers
            # the whole gate, not one check. Derived from `reasons` so the
            # flag and the explanation cannot disagree.
            "effective": not reasons,
            "reasons": reasons,
            # UTC, ISO 8601. Only while `effective` rests on the grant, and
            # only for a caller who can manage the roster (see docstring).
            "emergency_access_until": (
                r[10].astimezone(timezone.utc).isoformat()
                if under_grant and not reasons and can_grant else None),
        })
    return {"case_id": str(case_id), "classification": labels[0],
            "users": users, "you_can_grant": can_grant}


@router.delete("/cases/{case_id}/users/{user_id}", response_model=dict,
               dependencies=[Depends(rate_limit("request"))])
def revoke_case_user(case_id: UUID, user_id: UUID,
                     user: CurrentUser = Depends(require("case.grant")),
                     conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Take a colleague off this case.

    `CaseService.revoke_user` has existed since Phase 1 with no route, so a
    case could be shared from the console and never unshared: the only
    remedy for a grant made to the wrong person was SQL (ux02
    share-needs-raw-uuid, 2026-09-22). Same verb as granting, `case.grant`,
    with the step-up that permission row carries. The service audits
    `CASE_ACCESS_REVOKED` in the same transaction.

    The owner cannot be removed, for the reason `assign_case_user` refuses
    to regrade them: it would lock the case's owner out of their own case.
    """
    case = CaseService(conn).get(case_id)
    if case is None:
        raise Problem(404, "Not found", "case does not exist")
    if user_id == case.owner_user_id:
        raise Problem(400, "Invalid request",
                      "that user owns this case, and removing them would lock "
                      "the owner out of their own case. Transfer ownership "
                      "first.")
    row = conn.execute(
        """SELECT a.role_key, u.display_name, r.display_name
             FROM iam.case_assignment a
             JOIN iam.app_user u ON u.id = a.user_id
             LEFT JOIN iam.role r ON r.key = a.role_key
            WHERE a.case_id = %s AND a.user_id = %s""",
        (case_id, user_id)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "that person is not on this case")
    CaseService(conn).revoke_user(case_id, user_id, revoked_by=user.user_id)
    # `revoked_role_name` for the same reason as the roster's `role_name`
    # (final review U21, 2026-09-23).
    return {"case_id": str(case_id), "user_id": str(user_id),
            "display_name": row[1], "revoked_role": row[0],
            "revoked_role_name": row[2] or row[0]}


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
