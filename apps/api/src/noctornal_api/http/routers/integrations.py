"""Administration, Integrations: the outbound channels, the outbox, Jira,
and a case owner's veto (F8 and F7, 2026-09-24).

Every route under /integrations runs require_global("integration.manage"),
which is step-up and held by SYS_ADMIN. Nothing here returns a password, a
webhook secret, a raw webhook URL, the Jira credential or its ciphertext:
the overview carries configuration facts and the readiness rows'
verdicts, which the register and this page share through readiness.check
(one reader per fact).

The case router carries the one case-scoped piece: a case owner (case.update)
keeping a case out of Jira, readable by anyone who reads the case.
"""
from __future__ import annotations

import os
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api import jira, readiness, transports
from noctornal_api.http.deps import CurrentUser, get_conn, require, require_global, user_ceiling
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/integrations", tags=["integrations"])
case_router = APIRouter(tags=["integrations"])

_MANAGE = require_global("integration.manage")


def _problem(exc: jira.JiraError) -> Problem:
    status = exc.status
    title = {404: "Not found", 409: "Conflict"}.get(status, "Invalid request")
    return Problem(status, title, safe_detail(exc))


@router.get("", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def overview(
    _: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The channels, their routes, and the outbox row, in one read."""
    host, port, _problem_text = transports.smtp_endpoint()
    smtp_state = transports.route_state(transports.SMTP, conn)
    hook_state = transports.route_state(transports.WEBHOOK, conn)
    url = transports.webhook_url()
    domains = sorted({d.strip().lower().lstrip("@") for d in os.environ.get(
        "NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", "").split(",") if d.strip()})
    return {
        "smtp": {
            "check": readiness.check("smtp_configured", conn).as_dict(),
            "host": host, "port": port,
            "tls": "IMPLICIT" if port == 465 else "STARTTLS",
            "auth": bool(os.environ.get("SMTP_USERNAME") and os.environ.get("SMTP_PASSWORD")),
            "from": os.environ.get("SMTP_FROM", "noctornal@localhost"),
            "ceiling": os.environ.get("NOCTORNAL_SMTP_CEILING") or None,
            "address_domains": domains,
            "route": smtp_state.as_dict(),
            "route_words": transports.route_line(smtp_state),
        },
        "webhook": {
            "configured": url is not None,
            "endpoint": transports.redact_endpoint(url) if url else None,
            "signed": bool(os.environ.get("NOCTORNAL_WEBHOOK_SECRET")),
            "ceiling": os.environ.get("NOCTORNAL_WEBHOOK_CEILING") or None,
            "route": hook_state.as_dict(),
            "route_words": transports.route_line(hook_state) if url else None,
        },
        "jira": jira.JiraAdmin(conn).view(),
        "drain": {"check": readiness.check("notify_outbox_draining", conn).as_dict(),
                  "cron": "scripts/notify_drain.py"},
    }


# --- Jira (F7) ----------------------------------------------------------------

class JiraConfirm(BaseModel):
    ceiling: str
    field_exposure: str
    kinds: list[str]


class JiraCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)
    base_url: str = Field(min_length=8, max_length=500)
    flavour: str = "AUTO"
    auth_kind: str
    auth_user: str | None = Field(default=None, max_length=200)
    credential: str = Field(min_length=8, max_length=4096)
    project_key: str = Field(min_length=2, max_length=20)
    issue_type: str = Field(default="Task", min_length=1, max_length=80)
    ceiling: str = "GREEN"
    field_exposure: str = "SUBJECT"
    kinds: list[str] = Field(default_factory=lambda: list(jira.DEFAULT_KINDS))


class JiraPatch(BaseModel):
    label: str | None = Field(default=None, max_length=80)
    base_url: str | None = Field(default=None, max_length=500)
    flavour: str | None = None
    auth_kind: str | None = None
    auth_user: str | None = Field(default=None, max_length=200)
    project_key: str | None = Field(default=None, max_length=20)
    issue_type: str | None = Field(default=None, max_length=80)
    ceiling: str | None = None
    field_exposure: str | None = None
    kinds: list[str] | None = None
    confirm: JiraConfirm | None = None


class JiraCredential(BaseModel):
    credential: str = Field(min_length=8, max_length=4096)


@router.get("/jira", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def get_jira(
    _: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return jira.JiraAdmin(conn).view()


@router.post("/jira", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("integration.write"))])
def create_jira(
    body: JiraCreate,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    admin = jira.JiraAdmin(conn)
    try:
        dest = admin.create(body.model_dump(), actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc
    return admin.destination_out(dest)


@router.patch("/jira", response_model=dict,
              dependencies=[Depends(rate_limit("integration.write"))])
def patch_jira(
    body: JiraPatch,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    admin = jira.JiraAdmin(conn)
    payload = body.model_dump(exclude_unset=True)
    if body.confirm is not None:
        payload["confirm"] = body.confirm.model_dump()
    try:
        dest = admin.patch(payload, actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc
    return admin.destination_out(dest)


@router.put("/jira/credential", response_model=dict,
            dependencies=[Depends(rate_limit("admin.credentials"))])
def put_jira_credential(
    body: JiraCredential,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    admin = jira.JiraAdmin(conn)
    try:
        dest = admin.set_credential(body.credential, actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc
    return admin.destination_out(dest)


@router.post("/jira/test", response_model=dict,
             dependencies=[Depends(rate_limit("integration.test"))])
def test_jira(
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return jira.JiraAdmin(conn).test(actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc


@router.post("/jira/activate", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def activate_jira(
    body: JiraConfirm,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    admin = jira.JiraAdmin(conn)
    try:
        dest = admin.activate(body.model_dump(), actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc
    return admin.destination_out(dest)


@router.post("/jira/pause", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def pause_jira(
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    admin = jira.JiraAdmin(conn)
    try:
        return admin.destination_out(admin.pause(actor_id=user.user_id))
    except jira.JiraError as exc:
        raise _problem(exc) from exc


@router.post("/jira/resume", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def resume_jira(
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    admin = jira.JiraAdmin(conn)
    try:
        return admin.destination_out(admin.activate({}, actor_id=user.user_id, resume=True))
    except jira.JiraError as exc:
        raise _problem(exc) from exc


@router.post("/jira/retire", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def retire_jira(
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return jira.JiraAdmin(conn).retire(actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc


@router.get("/jira/links", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def jira_links(
    case_id: UUID | None = Query(None),
    state: str | None = Query(None, pattern="^(CREATING|LINKED|CLOSED)$"),
    limit: int = Query(100, ge=1, le=500),
    before: str | None = Query(None, max_length=200),
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return jira.JiraAdmin(conn).links(case_id=case_id, state=state, limit=limit,
                                          before=before, actor_id=user.user_id)
    except jira.JiraError as exc:
        raise _problem(exc) from exc


# --- the case owner's veto (F7) -----------------------------------------------

class CaseRoutingIn(BaseModel):
    jira_blocked: bool
    reason: str | None = Field(default=None, max_length=500)


@case_router.get("/cases/{case_id}/notify-routing", response_model=dict,
                 dependencies=[Depends(rate_limit("request"))])
def get_case_routing(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    clearance, _held = user_ceiling(conn, user.user_id)
    return jira.case_routing(conn, case_id, clearance=clearance.name)


@case_router.put("/cases/{case_id}/notify-routing", response_model=dict,
                 dependencies=[Depends(rate_limit("integration.write"))])
def put_case_routing(
    case_id: UUID,
    body: CaseRoutingIn,
    user: CurrentUser = Depends(require("case.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Governance, not content: a closed case can still be kept out of
    Jira (and is exactly the case an owner most wants kept out)."""
    try:
        with conn.transaction():
            clearance, _held = user_ceiling(conn, user.user_id)
            return jira.set_case_routing(conn, case_id, blocked=body.jira_blocked,
                                         reason=body.reason, actor_id=user.user_id,
                                         clearance=clearance.name)
    except jira.JiraError as exc:
        raise _problem(exc) from exc
