"""Administration, Providers: the outbound lookup provider registry
(F15.2, 2026-09-24).

Every route runs require_global("integration.manage"), which is step-up
and held by SYS_ADMIN. No answer carries key material or a URL with a
query string; the key is written by PUT and never read back by any route.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api import lookups, providers
from noctornal_api.http.deps import CurrentUser, get_conn, require_global
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/providers", tags=["providers"])
_MANAGE = require_global("integration.manage")


def _problem(exc: Exception) -> Problem:
    status = getattr(exc, "status", 400)
    title = {403: "Forbidden", 404: "Not found", 409: "Conflict"}.get(status,
                                                                     "Invalid request")
    return Problem(status, title, safe_detail(exc))


class ProviderCreate(BaseModel):
    key: str = Field(min_length=2, max_length=33)
    display_name: str | None = Field(default=None, max_length=80)
    adapter: str
    base_url: str | None = Field(default=None, max_length=500)
    egress_route: str | None = Field(default=None, max_length=40)
    exposure_level: str
    exposure_basis: str = Field(min_length=1, max_length=2000)
    classification_ceiling: str | None = None
    result_floor: str | None = None
    use_private_ca: bool = False
    #: A NONE instance's private network (2026-09-25), which its declared
    #: rule carries (docs/20 section 9).
    private_cidr: str | None = Field(default=None, max_length=50)
    cache_ttl_hours: int = Field(default=168, ge=0, le=2160)
    quota_per_minute: int | None = Field(default=None, gt=0)
    quota_per_hour: int | None = Field(default=None, gt=0)
    quota_per_day: int | None = Field(default=None, gt=0)
    quota_per_month: int | None = Field(default=None, gt=0)
    queue_reserve_pct: int = Field(default=20, ge=0, le=90)
    max_response_bytes: int = Field(default=2097152, ge=65536, le=16777216)
    source_classification: str = "GREEN"


class ProviderUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    base_url: str | None = Field(default=None, max_length=500)
    egress_route: str | None = Field(default=None, max_length=40)
    exposure_level: str | None = None
    exposure_basis: str | None = Field(default=None, max_length=2000)
    classification_ceiling: str | None = None
    result_floor: str | None = None
    use_private_ca: bool | None = None
    private_cidr: str | None = Field(default=None, max_length=50)
    cache_ttl_hours: int | None = Field(default=None, ge=0, le=2160)
    quota_per_minute: int | None = Field(default=None, gt=0)
    quota_per_hour: int | None = Field(default=None, gt=0)
    quota_per_day: int | None = Field(default=None, gt=0)
    quota_per_month: int | None = Field(default=None, gt=0)
    queue_reserve_pct: int | None = Field(default=None, ge=0, le=90)
    max_response_bytes: int | None = Field(default=None, ge=65536, le=16777216)


class SecretIn(BaseModel):
    fields: dict[str, str]
    rotate_by: date | None = None


class ReasonIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class EnableIn(BaseModel):
    confirm_exposure: str


class ChangeIn(BaseModel):
    to_level: str
    basis: str = Field(min_length=1, max_length=2000)
    private_cidr: str | None = Field(default=None, max_length=50)


class DecideIn(BaseModel):
    approve: bool
    note: str | None = Field(default=None, max_length=1000)


@router.get("/catalogue", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def catalogue(_: CurrentUser = Depends(_MANAGE)) -> dict:
    return {"adapters": providers.ProviderRegistry.catalogue()}


@router.get("", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def list_providers(
    include_retired: bool = Query(False),
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    switch, _raw = providers.outbound_switch()
    return {"providers": providers.ProviderRegistry(conn).list(
                include_retired=include_retired, actor_id=user.user_id),
            "switch": switch}


def _one(conn, provider_id: UUID, actor_id: UUID) -> dict:
    registry = providers.ProviderRegistry(conn)
    return registry.provider_out(registry.require(provider_id), actor_id=actor_id)


@router.post("", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("integration.write"))])
def create_provider(
    body: ProviderCreate,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        p = providers.ProviderRegistry(conn).create(body.model_dump(), actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, p.id, user.user_id)


@router.patch("/{provider_id}", response_model=dict,
              dependencies=[Depends(rate_limit("integration.write"))])
def update_provider(
    provider_id: UUID, body: ProviderUpdate,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        providers.ProviderRegistry(conn).update(
            provider_id, body.model_dump(exclude_unset=True), actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, provider_id, user.user_id)


@router.put("/{provider_id}/secret", response_model=dict,
            dependencies=[Depends(rate_limit("admin.credentials"))])
def put_secret(
    provider_id: UUID, body: SecretIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    today = datetime.now(timezone.utc).date()
    rotate_by = body.rotate_by or today + timedelta(days=365)
    if not today < rotate_by <= today + timedelta(days=730):
        raise Problem(400, "Invalid request", "Rotate the key within two years.")
    try:
        p = providers.ProviderVault(conn).store(provider_id, body.fields,
                                                actor_id=user.user_id, rotate_by=rotate_by)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return {"secret_held": True, "secret_set_at": p.secret_set_at.isoformat(),
            "rotate_by": p.rotate_by.isoformat(),
            "notice": "Stored sealed. It is never shown again, by any route."}


@router.post("/{provider_id}/secret/clear", response_model=dict,
             dependencies=[Depends(rate_limit("admin.credentials"))])
def clear_secret(
    provider_id: UUID, body: ReasonIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    registry = providers.ProviderRegistry(conn)
    try:
        registry.require(provider_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    providers.ProviderVault(conn).clear(provider_id, actor_id=user.user_id,
                                        reason=body.reason.strip())
    return _one(conn, provider_id, user.user_id)


@router.post("/{provider_id}/enable", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def enable(
    provider_id: UUID, body: EnableIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return providers.ProviderRegistry(conn).enable(
            provider_id, confirm_exposure=body.confirm_exposure, actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc


@router.post("/{provider_id}/disable", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def disable(
    provider_id: UUID, body: ReasonIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        providers.ProviderRegistry(conn).disable(provider_id, reason=body.reason,
                                                 actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, provider_id, user.user_id)


@router.post("/{provider_id}/unlock", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def unlock(
    provider_id: UUID, body: ReasonIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        providers.ProviderRegistry(conn).unlock(provider_id, reason=body.reason,
                                                actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, provider_id, user.user_id)


@router.post("/{provider_id}/retire", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def retire(
    provider_id: UUID, body: ReasonIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        providers.ProviderRegistry(conn).retire(provider_id, reason=body.reason,
                                                actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, provider_id, user.user_id)


@router.post("/{provider_id}/exposure-changes", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("integration.write"))])
def request_change(
    provider_id: UUID, body: ChangeIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        change_id = providers.ProviderRegistry(conn).request_exposure_change(
            provider_id, to_level=body.to_level, basis=body.basis, actor_id=user.user_id,
            private_cidr=body.private_cidr)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return {"change_id": str(change_id), "provider": _one(conn, provider_id, user.user_id)}


@router.post("/{provider_id}/exposure-changes/{change_id}/decide", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def decide_change(
    provider_id: UUID, change_id: UUID, body: DecideIn,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        providers.ProviderRegistry(conn).decide_exposure_change(
            provider_id, change_id, approve=body.approve, note=body.note,
            actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, provider_id, user.user_id)


@router.post("/{provider_id}/exposure-changes/{change_id}/withdraw", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def withdraw_change(
    provider_id: UUID, change_id: UUID,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        providers.ProviderRegistry(conn).withdraw_exposure_change(
            provider_id, change_id, actor_id=user.user_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
    return _one(conn, provider_id, user.user_id)


# --- F15.3: the provider test and its usage -----------------------------------

@router.post("/{provider_id}/test", response_model=dict,
             dependencies=[Depends(rate_limit("integration.test"))])
def test_provider(
    provider_id: UUID,
    user: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return lookups.LookupService(conn).test_provider(provider_id, actor_id=user.user_id)
    except lookups.NotVisible:
        raise Problem(404, "Not found", "no such provider") from None
    except (lookups.LookupRefused, providers.ProviderError) as exc:
        raise _problem(exc) from exc


@router.get("/{provider_id}/usage", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def usage(
    provider_id: UUID,
    _: CurrentUser = Depends(_MANAGE),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return providers.ProviderRegistry(conn).usage(provider_id)
    except providers.ProviderError as exc:
        raise _problem(exc) from exc
