"""Administration, Egress: where anything may leave this deployment
(S2, 2026-09-24; docs/00 decision 68).

Reads (the overview, the connection log, its verification and the dry-run
check) need egress.log.read, held by SYS_ADMIN and SECURITY_OFFICER; the
log and the overview are filtered by the caller's own clearance. Every
write needs egress.manage, a step-up permission held by SYS_ADMIN, and is
metered by admin.egress. The service (egress_admin.py) audits each one.

An exit's host, port, user name and password arrive in one request body,
are sealed for the egress proxy, and appear in no response, no audit
detail and no log line. A 422 names the field and never echoes the value
(http/app.py's validation handler).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api import egress_ledger
from noctornal_api.egress_admin import EgressAdminError, EgressAdminService
from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.security.egress_seal import ExitEndpoint

router = APIRouter(prefix="/admin/egress", tags=["admin"])

MANAGE = "egress.manage"
READ = "egress.log.read"
_WRITE = [Depends(rate_limit("admin.egress"))]


class PolicyBody(BaseModel):
    ceiling: Literal["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"] | None = None
    allowed_ports: list[int] | None = Field(default=None, max_length=16)
    any_public_host: bool | None = None
    allowed_host_suffixes: list[str] | None = Field(default=None, max_length=64)
    allowed_cidrs: list[str] | None = Field(default=None, max_length=64)
    allow_onion: bool | None = None
    resolve_at_proxy: bool | None = None
    idle_timeout_s: int | None = Field(default=None, ge=5, le=3600)
    max_session_s: int | None = Field(default=None, ge=10, le=86400)
    max_concurrent: int | None = Field(default=None, ge=1, le=64)


class CreateProfileBody(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    kind: Literal["RESIDENTIAL", "DATACENTRE", "TOR", "VPN"]
    region: str | None = Field(default=None, max_length=80)
    # Required, with no default: the label a profile may carry is a
    # decision, and a default here would be one nobody took.
    ceiling: Literal["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]
    policy: PolicyBody = Field(default_factory=PolicyBody)


class ExitBody(BaseModel):
    exit_kind: Literal["DIRECT", "HTTP", "HTTPS", "SOCKS5"]
    host: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=255)
    cleartext_ack: bool = False


class ReasonBody(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class LimitsBody(BaseModel):
    idle_timeout_s: int | None = Field(default=None, ge=5, le=3600)
    max_session_s: int | None = Field(default=None, ge=10, le=86400)
    max_concurrent: int | None = Field(default=None, ge=1, le=64)


class CreateRouteBody(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    description: str = Field(min_length=5, max_length=500)
    limits: LimitsBody = Field(default_factory=LimitsBody)


class UpdateRouteBody(BaseModel):
    description: str | None = Field(default=None, min_length=5, max_length=500)
    limits: LimitsBody = Field(default_factory=LimitsBody)
    is_active: bool | None = None


class DestinationBody(BaseModel):
    entry: str = Field(min_length=3, max_length=300)
    note: str = Field(min_length=5, max_length=500)


class CheckBody(BaseModel):
    route_kind: Literal["persona", "integration"]
    route_id: UUID
    host: str = Field(min_length=1, max_length=260)
    port: int = Field(ge=1, le=65535)


def _refuse(exc: EgressAdminError) -> Problem:
    if exc.status == 404:
        return Problem(404, "Not found", safe_detail(exc))
    return Problem(409, "Conflict", safe_detail(exc))


def _svc(conn) -> EgressAdminService:
    return EgressAdminService(conn)


def _clearance(conn, user: CurrentUser) -> tuple[str, frozenset[str]]:
    level, held = user_ceiling(conn, user.user_id)
    return level.name, held


@router.get("", response_model=dict)
def overview(
    user: CurrentUser = Depends(require_global(READ)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Profiles, routes and the proxy's state, within the caller's
    clearance, and what the caller may do here."""
    clearance, held = _clearance(conn, user)
    body = _svc(conn).overview(clearance=clearance, compartments=held)
    manage = conn.execute(
        """SELECT EXISTS (SELECT 1 FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
            WHERE ur.user_id = %s AND rp.permission_key = %s)""",
        (user.user_id, MANAGE)).fetchone()[0]
    body["you"] = {"may_manage": bool(manage), "clearance": clearance}
    return body


@router.post("/profiles", response_model=dict, status_code=201, dependencies=_WRITE)
def create_profile(body: CreateProfileBody,
                   user: CurrentUser = Depends(require_global(MANAGE)),
                   conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).create_profile(
            actor_id=user.user_id, name=body.name, kind=body.kind, region=body.region,
            ceiling=body.ceiling, policy=body.policy.model_dump(exclude_none=True))
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.patch("/profiles/{profile_id}/policy", response_model=dict, dependencies=_WRITE)
def set_policy(profile_id: UUID, body: PolicyBody,
               user: CurrentUser = Depends(require_global(MANAGE)),
               conn: psycopg.Connection = Depends(get_conn)) -> dict:
    clearance, _held = _clearance(conn, user)
    try:
        return _svc(conn).set_policy(actor_id=user.user_id, profile_id=profile_id,
                                     clearance=clearance,
                                     policy=body.model_dump(exclude_none=True))
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.put("/profiles/{profile_id}/exit", response_model=dict, dependencies=_WRITE)
def seal_exit(profile_id: UUID, body: ExitBody,
              user: CurrentUser = Depends(require_global(MANAGE)),
              conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Seal an exit for the egress proxy. The answer carries the key id and
    whether the profile now reaches further, never any part of the exit."""
    endpoint = None
    if body.exit_kind != "DIRECT":
        if not body.host or body.port is None:
            raise Problem(409, "Conflict", "Give the exit's host and port.")
        endpoint = ExitEndpoint(body.host, body.port, body.username, body.password)
    try:
        return _svc(conn).seal_exit(actor_id=user.user_id, profile_id=profile_id,
                                    exit_kind=body.exit_kind, endpoint=endpoint,
                                    cleartext_ack=body.cleartext_ack)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/profiles/{profile_id}/passive-default", response_model=dict,
             dependencies=_WRITE)
def passive_default(profile_id: UUID,
                    user: CurrentUser = Depends(require_global(MANAGE)),
                    conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).set_passive_default(actor_id=user.user_id, profile_id=profile_id)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/profiles/{profile_id}/activate", response_model=dict, dependencies=_WRITE)
def activate(profile_id: UUID, user: CurrentUser = Depends(require_global(MANAGE)),
             conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).set_active(actor_id=user.user_id, profile_id=profile_id,
                                     active=True)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/profiles/{profile_id}/deactivate", response_model=dict, dependencies=_WRITE)
def deactivate(profile_id: UUID, user: CurrentUser = Depends(require_global(MANAGE)),
               conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).set_active(actor_id=user.user_id, profile_id=profile_id,
                                     active=False)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/profiles/{profile_id}/retire", response_model=dict, dependencies=_WRITE)
def retire(profile_id: UUID, body: ReasonBody,
           user: CurrentUser = Depends(require_global(MANAGE)),
           conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).retire(actor_id=user.user_id, profile_id=profile_id,
                                 reason=body.reason)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/routes", response_model=dict, status_code=201, dependencies=_WRITE)
def create_route(body: CreateRouteBody,
                 user: CurrentUser = Depends(require_global(MANAGE)),
                 conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).create_route(actor_id=user.user_id, name=body.name,
                                       description=body.description,
                                       limits=body.limits.model_dump(exclude_none=True))
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.patch("/routes/{route_id}", response_model=dict, dependencies=_WRITE)
def update_route(route_id: UUID, body: UpdateRouteBody,
                 user: CurrentUser = Depends(require_global(MANAGE)),
                 conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).update_route(actor_id=user.user_id, route_id=route_id,
                                       description=body.description,
                                       limits=body.limits.model_dump(exclude_none=True),
                                       is_active=body.is_active)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/routes/{route_id}/retire", response_model=dict, dependencies=_WRITE)
def retire_route(route_id: UUID, body: ReasonBody,
                 user: CurrentUser = Depends(require_global(MANAGE)),
                 conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).retire_route(actor_id=user.user_id, route_id=route_id,
                                       reason=body.reason)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/routes/{route_id}/destinations", response_model=dict, status_code=201,
             dependencies=_WRITE)
def add_destination(route_id: UUID, body: DestinationBody,
                    user: CurrentUser = Depends(require_global(MANAGE)),
                    conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).add_destination(actor_id=user.user_id, route_id=route_id,
                                          entry=body.entry, note=body.note)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.post("/routes/{route_id}/destinations/{destination_id}/retire",
             response_model=dict, dependencies=_WRITE)
def retire_destination(route_id: UUID, destination_id: UUID,
                       user: CurrentUser = Depends(require_global(MANAGE)),
                       conn: psycopg.Connection = Depends(get_conn)) -> dict:
    try:
        return _svc(conn).retire_destination(actor_id=user.user_id, route_id=route_id,
                                             destination_id=destination_id)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc


@router.get("/connections", response_model=dict)
def connections(
    route_id: str | None = Query(default=None, max_length=60),
    event: Literal["OPEN", "REFUSED", "PREAUTH", "REWRAP"] | None = None,
    since: datetime | None = None,
    limit: int = Query(default=200, ge=1, le=500),
    user: CurrentUser = Depends(require_global(READ)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The connection log within the caller's clearance, newest first, each
    OPEN paired with its CLOSE, and how many rows were withheld."""
    if since is not None and since.tzinfo is None:
        raise Problem(422, "Validation failed", "Times are UTC: send an offset.")
    clearance, held = _clearance(conn, user)
    return egress_ledger.listing(conn, clearance=clearance, compartments=held,
                                 route_id=route_id or None, event=event, since=since,
                                 limit=limit)


@router.get("/connections/verify", response_model=dict)
def verify(user: CurrentUser = Depends(require_global(READ)),
           conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Recompute the ledger's hash chain. Counts and a sequence number only."""
    return egress_ledger.verify(conn)


@router.post("/check", response_model=dict, dependencies=_WRITE)
def check(body: CheckBody, user: CurrentUser = Depends(require_global(READ)),
          conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Would a route allow host:port? A dry run by name: no DNS and no
    connection. A profile above the caller's clearance is 404."""
    clearance, held = _clearance(conn, user)
    try:
        return _svc(conn).check(route_kind=body.route_kind, route_id=body.route_id,
                                host=body.host, port=body.port, clearance=clearance,
                                compartments=held)
    except EgressAdminError as exc:
        raise _refuse(exc) from exc
