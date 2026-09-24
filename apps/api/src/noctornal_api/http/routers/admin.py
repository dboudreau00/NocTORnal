"""Analyst account administration over HTTP (`user.manage`, step-up).

Every route here is gated on `user.manage`, which the seed grants to
SYS_ADMIN alone and marks step-up — `require_global` enforces both, so a
stale session cannot mint accounts. The one exception is `GET /access`,
which reads which of two verbs the CALLER holds, so the console knows
whether to offer the way in (2026-09-22), and, for an administrator, the
names of the failing blocking checks, so it can say on the way in that
something is refusing work (2026-09-23).

Credentials appear ONCE, in the response that generated them, and no
route returns an existing secret. The response says so, because an
administrator who believes they can fetch that password again will close
the tab.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    CurrentUser,
    current_user,
    get_conn,
    require_global,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api import readiness as readiness_register
from noctornal_api.iam_admin import AdminError, IamAdminService, OneTimeCredentials

# Prefixed at /admin rather than /admin/users since 2026-09-02, so the
# readiness register can live beside the account routes without a
# second router to register in app.py. Every account route spells its
# own /users, so the URLs a client already uses are unchanged.
router = APIRouter(prefix="/admin", tags=["admin"])


class CreateBody(BaseModel):
    email: str = Field(min_length=3)
    display_name: str = Field(min_length=1)
    clearance: str = "AMBER"
    roles: list[str] = Field(default_factory=lambda: ["ANALYST"])
    # Read-ins at creation, in the account's own transaction
    # (ux16-admin:no-compartment-readins-in-ui, 2026-09-23). Optional, so
    # every existing client creates exactly what it did before.
    compartments: list[str] = Field(default_factory=list)


class ClearanceBody(BaseModel):
    clearance: str


class RoleBody(BaseModel):
    role: str


def _refuse(exc: AdminError) -> Problem:
    """409 for a rule, 404 for a user that is not there.

    Every route used to answer 409 Conflict, so naming a user id that does
    not exist reported "Conflict" — a refusal about state, for a request
    about a thing that has no state. Only the two role routes could
    produce it, and they produced it two different wrong ways: grant let a
    raw ForeignKeyViolation reach the catch-all as a 500, and revoke
    deleted nothing and answered 200 "revoked".
    """
    detail = safe_detail(exc)
    if "no such user" in str(exc):
        return Problem(404, "Not found", detail)
    return Problem(409, "Conflict", detail)


_SHOWN_ONCE = ("Shown once. Neither the password nor the TOTP secret is "
               "stored in a recoverable form, and no endpoint returns them "
               "again. Hand them over now or re-enrol.")


def _credentials(c: OneTimeCredentials, notice: str = _SHOWN_ONCE) -> dict:
    """The one-time credentials card's payload. `totp_secret` and
    `otpauth_uri` are null for a password reset, which issues no second
    factor: the console draws only what arrived."""
    return {
        "user_id": str(c.user_id),
        "email": c.email,
        "password": c.password or None,
        "totp_secret": c.totp_secret or None,
        "otpauth_uri": c.otpauth_uri or None,
        "notice": notice,
    }


@router.get("/access", response_model=dict)
def access(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Whether the caller may open Administration at all.

    ux16 admin-unreachable-without-a-case (2026-09-22): the accounts panel
    and the readiness register were a tab inside a case, so an account
    holding SYS_ADMIN alone (0021 gives it user.manage and no case.read,
    by design) signed in to an empty case list with no way in. The console
    now offers Administration from the case list, and asks here whether to.

    Any signed-in caller may ask, and the answer is about the caller only:
    whether one of THEIR global roles carries `user.manage`, and whether
    one carries `break_glass.review`. The second is here for the same
    reason as the first: SECURITY_OFFICER is assigned to no case by
    design, and the break-glass review queue was reachable only through a
    case's Lifecycle pane. It is not a gate: every route below, and the
    queue itself, still runs `require_global`, including its step-up
    check, which is why the freshness is not answered here: an
    administrator whose re-challenge has lapsed should still see the way
    in, and be told on arrival why the list refuses them.
    """
    held = {r[0] for r in conn.execute(
        """SELECT DISTINCT rp.permission_key FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND u.is_active
              AND rp.permission_key IN ('user.manage', 'break_glass.review')""",
        (user.user_id,)).fetchall()}
    manage = "user.manage" in held
    # The failing BLOCKING checks, for an account that administers the
    # deployment (ux16-admin:blocking-banner-buried-under-account-list,
    # 2026-09-23). Nothing outside the Admin pane said that four checks
    # were refusing work, so the console now badges the way in with this.
    # `blocking_failures` runs only the four cheap probes, never the object
    # store or Redis, which is why this is safe on every case-list render.
    # Not behind the step-up freshness the register itself sits behind:
    # these NAMES are already told to a collector, who holds no
    # user.manage at all, in the poll route's 409, so they are not a secret
    # to withhold from an administrator between two sign-ins.
    # `readiness_caveats` names the blocking checks that PASS with a
    # caveat, from the same run (2026-09-23,
    # ux16-admin:security-officer-false-green): a lone officer who can
    # invoke break-glass passes and has no emergency access, and the
    # passing rows are folded away, so the Readiness section is marked.
    state = (readiness_register.blocking_state(conn) if manage
             else {"failures": [], "caveats": []})
    return {"user_manage": manage,
            "break_glass_review": "break_glass.review" in held,
            "blocking_failures": state["failures"],
            "readiness_caveats": state["caveats"]}


@router.get("/users", response_model=dict)
def list_users(
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    users = IamAdminService(conn).list_users()
    return {"users": users, "count": len(users),
            # The caller's own id, so the UI can disable self-footguns
            # client-side. The server refuses them regardless.
            "you": str(user.user_id)}


# Its own meter, `admin.credentials`, not the recovery-code one: sharing
# that bucket let a fresh install's operator add two colleagues before a
# 429 (final review U18, 2026-09-23; see the catalogue in ratelimit.py).
@router.post("/users", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("admin.credentials"))])
def create_user(
    body: CreateBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        creds = IamAdminService(conn).create_analyst(
            email=body.email, display_name=body.display_name,
            clearance=body.clearance, roles=body.roles,
            actor_id=user.user_id, compartments=body.compartments)
    except AdminError as exc:
        raise _refuse(exc) from exc
    # The password is the administrator's as much as the account's, so it
    # opens no session: the account replaces it at its first sign-in
    # (final review c8, 2026-09-24). Said on the card that shows it.
    return _credentials(creds, notice=(
        _SHOWN_ONCE + " The password signs in once: at their first sign-in "
        "they must choose their own, so this one never opens a session."))


@router.post("/users/{user_id}/deactivate", response_model=dict)
def deactivate(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).set_active(user_id, active=False,
                                         actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "is_active": False,
            "notice": "Their sessions are revoked; the account and its "
                      "history remain."}


@router.post("/users/{user_id}/reactivate", response_model=dict)
def reactivate(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).set_active(user_id, active=True,
                                         actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "is_active": True}


@router.post("/users/{user_id}/clearance", response_model=dict)
def set_clearance(
    user_id: UUID, body: ClearanceBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).set_clearance(user_id, clearance=body.clearance,
                                            actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "tlp_clearance": body.clearance}


@router.post("/users/{user_id}/roles", response_model=dict)
def grant_role(
    user_id: UUID, body: RoleBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).grant_role(user_id, role=body.role,
                                         actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "granted": body.role.upper()}


@router.delete("/users/{user_id}/roles/{role}", response_model=dict)
def revoke_role(
    user_id: UUID, role: str,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).revoke_role(user_id, role=role,
                                          actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "revoked": role.upper()}


# Same meter as provisioning: both mint a credential in a loop an
# impatient operator will happily click. Not the recovery-code meter,
# which is the administrator's own and too small to share (U18).
@router.post("/users/{user_id}/totp", response_model=dict,
             dependencies=[Depends(rate_limit("admin.credentials"))])
def reenrol_totp(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        creds = IamAdminService(conn).reenrol_totp(user_id,
                                                   actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return _credentials(creds)


# gap-password-reset (2026-09-23). The same meter as provisioning and
# re-enrolment: all three mint a credential an impatient operator will
# click for twice. `require_global` carries the step-up freshness that
# `user.manage` is seeded with, so a session somebody walked away from
# cannot hand out a password; the service refuses the caller's own account.
@router.post("/users/{user_id}/password", response_model=dict,
             dependencies=[Depends(rate_limit("admin.credentials"))])
def reset_password(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        creds = IamAdminService(conn).reset_password(user_id,
                                                     actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return _credentials(creds, notice=(
        "Shown once, and never stored in a recoverable form. It signs in "
        "once: at that sign-in they must choose their own password, so "
        "this one never opens a session. Their authenticator is unchanged, "
        "and every session they had is signed out."))


@router.post("/users/{user_id}/unlock", response_model=dict)
def unlock(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IamAdminService(conn).unlock(user_id, actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "unlocked": True}


@router.get("/readiness", response_model=dict)
def readiness(
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What the deployment can establish about itself, as `{ready, checks,
    blocking_failures}` with evidence per check. See `readiness.py` for
    what is checked and why.

    `blocking_failures` names the failing checks a caller may REFUSE on
    (`readiness.BLOCKING_CHECKS`); `POST /collection/sources/{id}/run` and
    the collection cron are the callers that do, and they name these same
    checks back to whoever they refused. It is derived from the run that
    produced the rows above it rather than from a second probe pass, so it
    cannot name a check those rows show as passing.

    Deliberately NOT "the code-side half of the legal register": that
    phrasing was removed from `readiness.py` on 2026-09-02 because two of
    the register items are only partly checkable from inside the runtime,
    and it survived here -- on the operator-facing OpenAPI description of
    the very endpoint that serves the register, which is where an
    overclaim does the most damage. `ready: true` means the code-side
    preconditions hold, never that the deployment is lawful.

    Gated on `user.manage` rather than a read permission because the
    evidence names the deployment's configuration -- which variables are
    set, where Redis and the object store are, who holds which role --
    and that is an administrator's view, not an analyst's. Every probe is
    guarded, so a service that is down is a failed check with the error
    as evidence and this endpoint still answers 200.
    """
    return readiness_register.report(conn)


@router.get("/roles", response_model=dict)
def roles(
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every role's key and the name a person reads, from `iam.role`.

    Added 2026-09-22 with migration 0062, which renamed CASE_OWNER's
    display name to "Lead investigator" and kept the key. The admin pane
    had only ever shown keys, so the rename would have reached nobody; it
    reads the names here rather than keeping a copy, because a label table
    in the console is the second copy of a rule that goes stale (the role
    picker once offered six roles while the server granted ten).
    `grantable` is `iam_admin.GRANTABLE_ROLES`, the server's own allowlist.
    """
    from noctornal_api.iam_admin import GRANTABLE_ROLES

    rows = conn.execute(
        "SELECT key, display_name, description FROM iam.role ORDER BY key"
    ).fetchall()
    return {"roles": [{"key": k, "display_name": n, "description": d or "",
                       "grantable": k in GRANTABLE_ROLES}
                      for k, n, d in rows]}
