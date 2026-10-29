"""Analyst account administration over HTTP (`user.manage`, step-up).

Every route is gated on `user.manage`, which the seed grants to SYS_ADMIN alone and marks
step-up, so a stale session cannot mint accounts. The exception is `GET /access`, which says
which verbs the caller holds, so the console knows whether to offer the way in, and, for an
administrator, which blocking checks are failing. Credentials appear once, in the response that
generated them, and no route returns an existing secret; the response says so.
"""
from __future__ import annotations

from contextlib import contextmanager
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
from noctornal_api.db import SystemPurpose, system_connection

# Prefixed at /admin, not /admin/users, so the readiness register lives beside the account routes
# without a second router; every account route spells its own /users.
router = APIRouter(prefix="/admin", tags=["admin"])


@contextmanager
def _writer(conn: psycopg.Connection):
    """The administration service on a system connection. Every write here is to the IAM plane,
    which the request role may only read (0109); the gate (`require_global`) has already run on
    the request connection. In development and the suite the system connection is the
    request's own."""
    with system_connection(SystemPurpose.IAM_ADMIN, reuse=conn) as sconn:
        yield IamAdminService(sconn)


class CreateBody(BaseModel):
    email: str = Field(min_length=3)
    display_name: str = Field(min_length=1)
    clearance: str = "AMBER"
    roles: list[str] = Field(default_factory=lambda: ["ANALYST"])
    # Read-ins at creation, in the account's own transaction; optional.
    compartments: list[str] = Field(default_factory=list)


class ClearanceBody(BaseModel):
    clearance: str


class RoleBody(BaseModel):
    role: str


def _refuse(exc: AdminError) -> Problem:
    """409 for a rule, 404 for a user that is not there."""
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
    """Whether the caller may open Administration, which the console offers from the case list.

    Any signed-in caller may ask, and the answer is about the caller's own global roles only. It
    is not a gate: every route still runs `require_global` with its step-up, so freshness is not
    answered here, and an administrator whose re-challenge has lapsed still sees the way in.
    """
    held = {r[0] for r in conn.execute(
        """SELECT DISTINCT rp.permission_key FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND u.is_active
              AND rp.permission_key IN ('user.manage', 'break_glass.review',
                                        -- The two-person policy (F9).
                                        'dual_control.manage',
                                        'dual_control.countersign',
                                        -- F12, 2026-09-24.
                                        'sample.yara.activate',
                                        -- Administration, Egress (S2).
                                        'egress.manage', 'egress.log.read',
                                        -- Similarity indexes (F6.3).
                                        'embedding.manage',
                                        -- Integrations and Providers.
                                        'integration.manage',
                                        -- F13, 2026-09-24.
                                        'sample.screening.review',
                                        'sample.screening.manage')""",
        (user.user_id,)).fetchall()}
    manage = "user.manage" in held
    # The failing blocking checks, for an account that administers the deployment, so the
    # console can badge the way in. Only the four cheap probes run (never the object store or
    # Redis), so this is safe on every case-list render. Not behind step-up freshness: the poll
    # route's 409 already tells these names to a collector, who holds no user.manage.
    # `readiness_caveats` names the blocking checks that pass with a caveat, from the same run.
    state = (readiness_register.blocking_state(conn) if manage
             else {"failures": [], "caveats": []})
    answer = {"user_manage": manage,
              "break_glass_review": "break_glass.review" in held,
              "blocking_failures": state["failures"],
              "readiness_caveats": state["caveats"]}
    # Whether the caller may propose a change to the two-person policy or countersign one, and
    # how many changes wait for their countersignature. Not a gate: every route runs its own.
    from noctornal_api.approvals import ApprovalService
    countersign = "dual_control.countersign" in held
    answer["dual_control_manage"] = "dual_control.manage" in held
    answer["dual_control_countersign"] = countersign
    answer["dual_control_awaiting"] = (
        ApprovalService(conn).awaiting_global_signature(user.user_id)
        if countersign else 0)
    # The Security Officer's way in to the YARA rule sets awaiting activation, shown in
    # Oversight as the preserved samples are.
    answer["sample_yara_activate"] = "sample.yara.activate" in held
    # Whether the caller confirms collection authorities, the Oversight section's way in. Not a
    # gate: every route runs its own.
    answer["collection_authority_confirm"] = conn.execute(
        """SELECT EXISTS (
               SELECT 1 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND u.is_active
                  AND rp.permission_key = 'collection.authority.confirm')""",
        (user.user_id,)).fetchone()[0]
    # Whether the caller may change where anything leaves, or read the egress proxy's connection
    # log, so the Egress section is offered. Not a gate: every route runs its own.
    answer["egress_manage"] = "egress.manage" in held
    answer["egress_log_read"] = "egress.log.read" in held
    # Whether to show Administration, Embeddings. Not a gate: every route there runs
    # require_global.
    answer["embedding_manage"] = "embedding.manage" in held
    # Whether the caller configures the outbound integrations and lookup providers, which shows
    # the Integrations and Providers sections. Not a gate: every route there runs
    # require_global("integration.manage") with its step-up.
    answer["integration_manage"] = "integration.manage" in held
    # The officer's way in to prohibited-content screening, and whether they may import and
    # retire lists there.
    answer["sample_screening_review"] = "sample.screening.review" in held
    answer["sample_screening_manage"] = "sample.screening.manage" in held
    return answer


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


# Its own meter, `admin.credentials`, not the recovery-code one, whose bucket would 429 a fresh
# install's operator after two colleagues (see the catalogue in ratelimit.py).
@router.post("/users", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("admin.credentials"))])
def create_user(
    body: CreateBody,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        with _writer(conn) as svc:
            creds = svc.create_analyst(
                email=body.email, display_name=body.display_name,
                clearance=body.clearance, roles=body.roles,
                actor_id=user.user_id, compartments=body.compartments)
    except AdminError as exc:
        raise _refuse(exc) from exc
    # The password is the administrator's as much as the account's, so it opens no session: the
    # account replaces it at its first sign-in. Said on the card that shows it.
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
        with _writer(conn) as svc:
            svc.set_active(user_id, active=False,
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
        with _writer(conn) as svc:
            svc.set_active(user_id, active=True,
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
        with _writer(conn) as svc:
            svc.set_clearance(user_id, clearance=body.clearance,
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
        with _writer(conn) as svc:
            svc.grant_role(user_id, role=body.role,
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
        with _writer(conn) as svc:
            svc.revoke_role(user_id, role=role,
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
        with _writer(conn) as svc:
            creds = svc.reenrol_totp(user_id,
                                                       actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return _credentials(creds)


# The same meter as provisioning and re-enrolment: all three mint a credential an impatient
# operator will click for twice. `require_global` carries the step-up freshness `user.manage` is
# seeded with, so a session somebody walked away from cannot hand out a password; the service
# refuses the caller's own account.
@router.post("/users/{user_id}/password", response_model=dict,
             dependencies=[Depends(rate_limit("admin.credentials"))])
def reset_password(
    user_id: UUID,
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        with _writer(conn) as svc:
            creds = svc.reset_password(user_id,
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
        with _writer(conn) as svc:
            svc.unlock(user_id, actor_id=user.user_id)
    except AdminError as exc:
        raise _refuse(exc) from exc
    return {"user_id": str(user_id), "unlocked": True}


@router.get("/readiness", response_model=dict)
def readiness(
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What the deployment can establish about itself, as `{ready, checks, blocking_failures}`
    with evidence per check (`readiness.py` says what is checked and why).

    `ready: true` means the code-side preconditions hold, never that the deployment is lawful.
    `blocking_failures` names the failing checks that `POST /collection/sources/{id}/run` and the
    collection cron refuse on, from the same run as the rows. Gated on `user.manage` because the
    evidence names the deployment's configuration; a service that is down is a failed check with
    the error as evidence, and this still answers 200.
    """
    return readiness_register.report(conn)


@router.get("/roles", response_model=dict)
def roles(
    user: CurrentUser = Depends(require_global("user.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every role's key and the name a person reads, from `iam.role` (CASE_OWNER reads "Lead
    investigator", migration 0062).

    The console reads the names here rather than keeping a copy that would go stale. `grantable`
    is `iam_admin.GRANTABLE_ROLES`, the server's own allowlist.
    """
    from noctornal_api.iam_admin import GRANTABLE_ROLES

    rows = conn.execute(
        "SELECT key, display_name, description FROM iam.role ORDER BY key"
    ).fetchall()
    return {"roles": [{"key": k, "display_name": n, "description": d or "",
                       "grantable": k in GRANTABLE_ROLES}
                      for k, n, d in rows]}
