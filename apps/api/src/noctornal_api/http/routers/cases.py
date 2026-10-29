"""Case endpoints: creation needs a global case.create; the rest pass the five-part case gate.

Guards the service layer does not provide: classification may be raised, never lowered here; an
assignment that confers nothing is refused; ARCHIVED to PURGED, a mark for destruction rather than
a close, is checked again under `case.delete`; the owner cannot be removed or regraded. Every
mutation is audited inside `CaseService`, in the write's transaction, so this router writes no
success rows of its own.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.cases import (
    CONTENT_READ_ONLY_STATES,
    CaseError,
    CaseService,
    RoleHeldOnAnotherCase,
    allowed_transitions,
)
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    audit_auth_event,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    holds_global,
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
    # When the case was last closed, for the workspace header: material added after it postdates
    # the close, which matters for disclosure.
    closed_at: datetime | None = None
    # True while the case's content is read-only (`CONTENT_READ_ONLY_STATES`), which the gate
    # enforces with a 409. Sent rather than re-derived so the console and the server cannot
    # disagree on which states count.
    read_only: bool = False
    # The rest of the case record, for the console's Case details panel.
    summary: str | None = None
    authority_ref: str | None = None
    # The legal moves from `status`, in lifecycle order: the Status dialog offers these and nothing
    # else. The transition route still decides.
    allowed_transitions: list[str] = []
    # The owner by name, and the caller's own standing on this case: the role that opens it for
    # them, its display name (CASE_OWNER reads as Lead investigator) and what it may do here.
    # A hint for the console, never a gate. Null and empty for a caller with no live assignment.
    owner_name: str | None = None
    my_role: str | None = None
    my_role_name: str | None = None
    my_permissions: list[str] = []
    # Whether the case is under a legal hold, for the header's chip and its Hold control. The
    # reason goes only to a caller who holds `retention.manage` on the case, as the due list's
    # does. `may_hold` says whether the Hold control is offered, asked of the global role and the
    # case's as if the sign-in were fresh (the route asks for one). A hint, never a gate.
    legal_hold: bool = False
    legal_hold_reason: str | None = None
    may_hold: bool = False


def _out(c) -> CaseOut:
    return CaseOut(
        id=str(c.id), code=c.code, title=c.title, status=c.status,
        classification=c.classification, owner_user_id=str(c.owner_user_id),
        legal_basis=c.legal_basis, retention_until=c.retention_until,
        review_due=c.review_due, created_at=c.created_at,
        closed_at=c.closed_at, summary=c.summary,
        authority_ref=c.authority_ref,
        allowed_transitions=allowed_transitions(c.status),
        read_only=c.status in CONTENT_READ_ONLY_STATES,
        legal_hold=c.legal_hold,
    )


def _with_caller(conn: psycopg.Connection, cases: list, user_id: UUID, *,
                 holds: bool = True) -> list[CaseOut]:
    """`_out` for each case, with the owner's name and the caller's live
    role on it, read in two queries whatever the number of cases.

    The role is the caller's unexpired assignment, which is what the gate
    reads a role from (`CaseService` docstring): a global role confers
    nothing on a case."""
    out = [_out(c) for c in cases]
    if not out:
        return out
    ids = [c.id for c in cases]
    owners = {c.owner_user_id for c in cases}
    names = {r[0]: r[1] for r in conn.execute(
        "SELECT id, display_name FROM iam.app_user WHERE id = ANY(%s)",
        (list(owners),)).fetchall()}
    mine = {r[0]: (r[1], r[2], list(r[3] or [])) for r in conn.execute(
        """SELECT a.case_id, a.role_key, r.display_name,
                  ARRAY(SELECT rp.permission_key FROM iam.role_permission rp
                         WHERE rp.role_key = a.role_key
                         ORDER BY rp.permission_key)
             FROM iam.case_assignment a
             LEFT JOIN iam.role r ON r.key = a.role_key
            WHERE a.user_id = %s AND a.case_id = ANY(%s)
              AND (a.expires_at IS NULL OR a.expires_at > now())""",
        (user_id, ids)).fetchall()}
    # The hold's controls and reason are drawn for one case and not for a
    # list (`holds=False`): a listing is not where the text a court order
    # rests on is handed to everyone who may open the page.
    may_hold_globally = holds and holds_global(conn, user_id, "retention.manage")
    for row, case in zip(out, cases, strict=True):
        row.owner_name = names.get(case.owner_user_id)
        role = mine.get(case.id)
        if role:
            row.my_role, row.my_role_name, row.my_permissions = (
                role[0], role[1] or role[0], role[2])
            if holds and "retention.manage" in role[2]:
                row.legal_hold_reason = case.legal_hold_reason
                row.may_hold = may_hold_globally
    return out


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/cases", response_model=CaseOut, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def create_case(body: CreateCaseBody,
                user: CurrentUser = Depends(require_global("case.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    svc = CaseService(conn)
    # The case and its owner's assignment are written together, and the assignment is an IAM write
    # the request role may only read (0109), so creation runs on a system connection after the
    # case.create gate. The read-back is the request's own, under the policy the assignment opens.
    with system_connection(SystemPurpose.CASE_MEMBERSHIP, reuse=conn) as sconn:
        case_id = CaseService(sconn).create(
            code=body.code, title=body.title, legal_basis=body.legal_basis,
            retention_until=body.retention_until, review_due=body.review_due,
            owner_user_id=user.user_id, created_by=user.user_id,
            classification=body.classification, compartments=body.compartments,
            summary=body.summary, authority_ref=body.authority_ref,
        )
    return _with_caller(conn, [svc.get(case_id)], user.user_id)[0]


@router.get("/cases", response_model=list[CaseOut],
            dependencies=[Depends(rate_limit("graph.view"))])
def list_cases(user: CurrentUser = Depends(current_user),
               conn: psycopg.Connection = Depends(get_conn)) -> list[CaseOut]:
    # With the caller's role on each, for the case list's "Your role" column.
    return _with_caller(conn, CaseService(conn).list_for_user(user.user_id),
                        user.user_id, holds=False)


@router.get("/cases/{case_id}", response_model=CaseOut,
            dependencies=[Depends(rate_limit("graph.view"))])
def get_case(case_id: UUID,
             user: CurrentUser = Depends(require("case.read")),
             conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    case = CaseService(conn).get(case_id)
    if case is None:
        raise Problem(404, "Not found", "case does not exist")
    return _with_caller(conn, [case], user.user_id)[0]


# ---------------------------------------------------------------------
# PATCH /cases/{case_id} — correct the case file
# ---------------------------------------------------------------------

class UpdateCaseBody(BaseModel):
    """Every field optional; omitted means "leave alone".

    Deliberately absent: `code`, the durable identifier quoted in warrants and exhibit labels
    (invariant 9); `status`, which moves through `POST /cases/{case_id}/status`; `compartments`,
    since adding one locks out every assignee not read into it; and `owner_user_id`, which is a
    grant on `POST /cases/{case_id}/users`.
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

    Classification may be raised: access is decided on the stricter of the case's and the
    element's label, and `core.enforce_tlp_floor` does not re-check existing rows on a raise.
    Lowering is refused with a 400: it declassifies everything protected only by the case label,
    cannot be undone, and needs its own verb with step-up and dual control. A raise is capped at
    the caller's own clearance (`check_writable_labels`), and the response names the assignees it
    locks out (invariant 12).
    """
    svc = CaseService(conn)
    current = svc.get(case_id)
    if current is None:
        # Unreachable in practice: require() resolves the case's labels
        # first and 404s on a case that does not exist. Kept because a
        # missing row must never fall through to an AttributeError 500.
        raise Problem(404, "Not found", "case does not exist")

    # PURGED marks the case for destruction, and editing its governance record would rewrite the
    # metadata that justifies the purge. Every other status stays editable.
    if current.status == "PURGED":
        raise Problem(400, "Invalid request",
                      "a PURGED case is a closed record and cannot be edited")

    # `update_metadata` reads None as "not supplied", so a JSON null cannot clear a field. Drop the
    # nulls here so the emptiness check below refuses `{"summary": null}` rather than a silent 200.
    # Clearing a field back to NULL needs a service-layer change (see `concerns`).
    supplied = {k: v for k, v in body.model_dump(exclude_unset=True).items()
                if v is not None}

    access_lost: list[dict] = []
    classification = body.classification
    # Retention may be extended, never shortened here. The purge selects evidence by
    # `retention_until <= today` and `evidence.purge` is dual control (decision 44), so a date
    # moved into the past would let one `case.update` signature destroy evidence. Shortening needs
    # its own verb with step-up and a second authoriser.
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
        # `update_metadata` returns early and writes no audit row when nothing changed, so this
        # would otherwise 200 having done nothing and left no trace of the attempt (invariant 12).
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
    # The exhibits' storage locks follow the date, after it has committed: each is locked for a
    # fixed period at lodging, which a case kept longer would outlive. Run whenever the date is
    # supplied, so saving the same date again retries a lock that could not be lengthened
    # (idempotent). A failure never undoes the date; it is counted and audited per exhibit
    # (`EvidenceService.extend_locks`). The counts are of the exhibits this caller may see.
    lock_extension = (_extend_exhibit_locks(conn, case_id, body.retention_until,
                                            user.user_id)
                      if body.retention_until is not None else None)
    updated = _with_caller(conn, [svc.get(case_id)], user.user_id)[0]
    # Flattened rather than nested under a "case" key so a client that only
    # reads .status/.title sees the same shape GET /cases/{id} returns.
    return {**updated.model_dump(mode="json"), "access_lost": access_lost,
            "lock_extension": lock_extension}


def _extend_exhibit_locks(conn: psycopg.Connection, case_id: UUID,
                          retention_until: date, actor_id: UUID) -> dict:
    """`EvidenceService.extend_locks`, with the store built here so a deployment without one
    reports every exhibit as not extended rather than failing a committed case edit. No store is
    built for a case with no exhibits.

    Every live exhibit is locked, since the date governs them all, but the count is drawn under
    the caller's own ceiling so it never numbers an exhibit they cannot see. Shared with the
    Evidence pane's `POST /cases/{id}/evidence/locks`."""
    from noctornal_api.evidence import EvidenceError, EvidenceService, EvidenceStorage
    from noctornal_api.http.deps import user_ceiling

    clearance, compartments = user_ceiling(conn, actor_id, case_id=case_id)
    # Every live exhibit's lock follows the case, including exhibits above the caller's labels, so
    # the lengthening runs on a system connection; the count is still drawn under their ceiling.
    with system_connection(SystemPurpose.EVIDENCE_LOCKS, reuse=conn) as sconn:
        live = sconn.execute(
            """SELECT 1 FROM core.evidence
                WHERE case_id = %s AND purged_at IS NULL AND is_worm_locked
                LIMIT 1""", (case_id,)).fetchone()
        try:
            storage = EvidenceStorage() if live else None
        except EvidenceError:
            storage = None
        return EvidenceService(sconn, storage).extend_locks(
            case_id, retention_until, actor_id,
            ceiling=(clearance.name, sorted(compartments)))


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

#: Roles whose case grant must carry an end (docs/05: LIAISON is time-boxed,
#: `expires_at` required).
TIME_BOXED_ROLES = frozenset({"LIAISON"})


class AssignUserBody(BaseModel):
    #: The durable identifier (invariant 9): `app_user.email` is
    #: citext-unique but a person's address changes and can be reassigned
    #: within an organisation. A grant must not follow the mailbox.
    user_id: UUID | None = None
    #: Or the colleague's work address, resolved to their id here, once, at the moment of granting.
    #: The assignment row stores `user_id`, so the grant binds to the person and not the mailbox
    #: (invariant 9). One address per request, so this never lists anybody.
    email: str | None = Field(default=None, min_length=3, max_length=320)
    role_key: str
    #: docs/05 wants case access time-boxed by default. Not forced here —
    #: a case owner with an expiring grant is its own failure mode — but
    #: validated so a grant cannot be born already dead. Required for a
    #: role in `TIME_BOXED_ROLES` (the external liaison).
    expires_at: datetime | None = None


def _audit_share_refused(conn: psycopg.Connection, user: CurrentUser,
                         case_id: UUID, email: str, reason: str) -> None:
    """Record a grant by address that was refused, with the address.

    Sharing by address says, one address at a time, whether an active account uses it (404 or
    400), which cannot be hidden without making the Share dialog useless. So every refusal leaves
    a trace, and a `case.grant` holder cannot walk a list of addresses unseen. Grants by id are
    not recorded here: an id is not guessable, and the service's own refusal covers them.
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

    Step-up comes from the `case.grant` permission row through `require()`, not a second check
    here. `assign_user_checked` refuses an assignee who cannot clear the case's labels, and the
    service holds a liaison to one case (`SINGLE_CASE_ROLES`). Checked here: the role exists and
    confers something, the account is active, `expires_at` is in the future, and the owner is not
    regraded, which the UPSERT would otherwise do, locking them out of their own case.
    """
    case = CaseService(conn).get(case_id)
    if case is None:
        raise Problem(404, "Not found", "case does not exist")

    if (body.user_id is None) == (body.email is None):
        raise Problem(400, "Invalid request",
                      "name the colleague by user_id or by email, and by "
                      "exactly one of them")

    if body.expires_at is not None:
        # An offset is required: Pydantic parses a naive datetime, which cannot be compared with
        # the aware `_now()`, and assuming UTC could shift the instant somebody loses access to a
        # case by hours without saying so.
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
    # docs/05: an external liaison's access is time-boxed, so `expires_at` is required.
    if body.role_key in TIME_BOXED_ROLES and body.expires_at is None:
        raise Problem(400, "Invalid request",
                      f"a {role[2] or body.role_key} grant must end: give an "
                      "end time (expires_at). External access is time-boxed.")

    # The address is resolved only after the rest of the request is validated, or a bad role_key
    # would answer 404 or 400 by account existence with nothing audited. From here on a known
    # address either becomes an audited grant or is refused for a reason about that grant.
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
        # An assignment is an IAM write (0109): system connection.
        with system_connection(SystemPurpose.CASE_MEMBERSHIP, reuse=conn) as sconn:
            CaseService(sconn).assign_user_checked(
                case_id, target, body.role_key,
                granted_by=user.user_id, expires_at=body.expires_at,
            )
    except RoleHeldOnAnotherCase as exc:
        if body.email is None:
            raise
        _audit_share_refused(conn, user, case_id, body.email,
                             "role_held_on_another_case")
        # Said without the reason, as the labels refusal below is: by a
        # guessable address it would tell any `case.grant` holder whether a
        # colleague or partner is a live liaison on some other case.
        raise Problem(
            400, "Invalid request",
            "that colleague cannot be given this role on this case. An "
            "administrator can check their account.",
        ) from exc
    except CaseError as exc:
        if body.email is None:
            raise
        _audit_share_refused(conn, user, case_id, body.email, "labels")
        # The service's refusal names the assignee's clearance; by a guessable address that would
        # tell the caller any colleague's clearance, so this says it as the roster does, without
        # the level.
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
        # An UPSERT over an existing grade says so, or demoting a colleague would look like adding
        # one (invariant 12).
        "replaced_role": existing[0] if existing else None,
        # The names a person reads, beside the keys (CASE_OWNER is shown as Lead investigator,
        # 0062): the Share panel cannot read `/admin/roles`, which needs user.manage.
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
    """Who is assigned to this case, and whether each assignment works.

    `effective` uses the predicates `CaseService.list_for_user` uses, so the two cannot disagree:
    an unexpired assignment, a live account, clearance that dominates the case (a live break-glass
    grant counts) and the case's compartments. Only a caller who may grant (`you_can_grant`) is
    told when a colleague's emergency access lapses (`emergency_access_until`). Email is withheld
    because LIAISON holds `case.read`, and a partner must not get the staff directory.
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

    # Whether the caller's own case role carries `case.grant`, so the Share panel offers Add and
    # Remove only to somebody who could use them. A hint, never a gate: the grant and revoke routes
    # still decide. Read before the roster, as it also decides who is told when a colleague's
    # emergency access ends.
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
    # The name a person reads for each grade on the roster (CASE_OWNER is Lead investigator, 0062),
    # looked up here because case workers cannot read `/admin/roles`.
    role_names = {g[0]: g[1] for g in conn.execute(
        "SELECT key, display_name FROM iam.role WHERE key = ANY(%s)",
        (list({r[2] for r in rows}),)).fetchall()} if rows else {}
    now = _now()
    users = []
    for r in rows:
        expired = r[5] is not None and r[5] <= now
        # Each failing check, in words, so the Share panel can say why a colleague cannot open the
        # case. The clearance line does not name the level: LIAISON can read this roster.
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

    Same verb as granting, `case.grant`, with its step-up; the service audits `CASE_ACCESS_REVOKED`
    in the same transaction. The owner cannot be removed: it would lock them out of their own case.
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
    # Removing an assignment is an IAM write (0109).
    with system_connection(SystemPurpose.CASE_MEMBERSHIP, reuse=conn) as sconn:
        CaseService(sconn).revoke_user(case_id, user_id, revoked_by=user.user_id)
    # `revoked_role_name` for the same reason as the roster's `role_name`.
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

    Gated on `case.close`. ARCHIVED to PURGED marks the case for destruction, so that one move is
    checked again under `case.delete`, which needs a fresh step-up. It is still one signature: dual
    control for `case.delete` is not enforced yet.
    """
    svc = CaseService(conn)
    if body.status == "PURGED":
        authorize_object(conn, user, case_id=case_id,
                         permission_key="case.delete", after_case_gate=True)
    svc.transition_status(case_id, body.status, actor_id=user.user_id)
    return _with_caller(conn, [svc.get(case_id)], user.user_id)[0]
