"""The collection authority over HTTP (the collection foundation,
2026-09-24; docs/00 decision 69).

A collection manager (`collection.authority.record`) records a written
authority and the sources under it; a security officer
(`collection.authority.confirm`) confirms it, and each source, as the second
person. Both permissions are step-up. Either side may stop an authority or
one source under it at any time, through its own route, because a route
takes one permission and either side may stop one.

Every route passes the caller's own ceiling: an authority above it is a 404
as for a missing id, a listing withholds whole rows and says only that some
were withheld, and a source above it is hidden from an authority's list.
The authority itself exists outside this system, and every answer says so.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.collection import CollectionError, CollectionNotFound
from noctornal_api.collection_authority import (
    AUTHORITY_NOTICE_LEAD,
    AuthorityError,
    CollectionAuthorityService,
)
from noctornal_api.http.deps import CurrentUser, get_conn, require_global, user_ceiling
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.http.routers.collection import L3_NOTICE, get_adapters

router = APIRouter(prefix="/collection/authorities", tags=["collection"])

AUTHORITY_NOTICE = AUTHORITY_NOTICE_LEAD + L3_NOTICE

RECORD = "collection.authority.record"
CONFIRM = "collection.authority.confirm"


def _service(conn: psycopg.Connection, adapters: dict) -> CollectionAuthorityService:
    return CollectionAuthorityService(conn, adapters)


def _answer(call):
    """The service's refusals as statuses: hidden or missing is 404, a
    two-person or binding rule is 409, anything else it refuses is 400."""
    try:
        return call()
    except CollectionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except AuthorityError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except CollectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


class AuthorityBody(BaseModel):
    persona_id: UUID | None = None
    scope: Literal["PUBLIC_READ", "MEMBER_READ"]
    classification: str = Field(min_length=3, max_length=20)
    authority_ref: str = Field(min_length=3, max_length=200)
    issued_by: str = Field(min_length=1, max_length=200)
    jurisdiction: str = Field(min_length=2, max_length=100)
    legal_basis: str = Field(min_length=1, max_length=500)
    member_authority_ref: str | None = Field(default=None, max_length=200)
    target_description: str = Field(min_length=21, max_length=2000)
    valid_from: datetime
    valid_until: datetime
    #: A persona's authority may name none: it then allows
    #: the persona's own acts and no read. One without a persona needs one.
    source_ids: list[UUID] = Field(default_factory=list, max_length=100)


def _utc_only(*moments: datetime) -> None:
    for moment in moments:
        if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
            raise Problem(422, "Unprocessable", "Times are UTC: send an offset.")


@router.post("", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("collection.authority"))])
def record(
    body: AuthorityBody,
    user: CurrentUser = Depends(require_global(RECORD)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Record an authority as the first person. Nothing is read under it
    until a security officer confirms it and each source under it."""
    _utc_only(body.valid_from, body.valid_until)
    clearance, _ = user_ceiling(conn, user.user_id)
    view = _answer(lambda: _service(conn, adapters).record(
        persona_id=body.persona_id, scope=body.scope,
        classification=body.classification, authority_ref=body.authority_ref,
        issued_by=body.issued_by, jurisdiction=body.jurisdiction,
        legal_basis=body.legal_basis,
        member_authority_ref=body.member_authority_ref,
        target_description=body.target_description,
        valid_from=body.valid_from, valid_until=body.valid_until,
        source_ids=body.source_ids, recorded_by=user.user_id,
        clearance=clearance.name))
    return {"authority": view, "notice": AUTHORITY_NOTICE}


class TargetsBody(BaseModel):
    source_ids: list[UUID] = Field(min_length=1, max_length=100)


@router.post("/{authority_id}/targets", response_model=dict,
             dependencies=[Depends(rate_limit("collection.authority"))])
def add_targets(
    authority_id: UUID, body: TargetsBody,
    user: CurrentUser = Depends(require_global(RECORD)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """More sources under an authority, each waiting for a second person."""
    clearance, _ = user_ceiling(conn, user.user_id)
    view = _answer(lambda: _service(conn, adapters).add_targets(
        authority_id, source_ids=body.source_ids, added_by=user.user_id,
        clearance=clearance.name))
    return {"authority": view, "notice": AUTHORITY_NOTICE}


@router.get("", response_model=dict)
def listing(
    persona_id: UUID | None = Query(default=None),
    state: str | None = Query(default=None, pattern="^(PENDING|NOT_YET_VALID|LIVE|EXPIRED|REVOKED)$"),
    user: CurrentUser = Depends(require_global(RECORD)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """The authorities the caller may see, newest first."""
    clearance, _ = user_ceiling(conn, user.user_id)
    body = _service(conn, adapters).listing(clearance=clearance.name,
                                            persona_id=persona_id, state=state)
    return {**body, "count": len(body["authorities"]), "notice": AUTHORITY_NOTICE}


@router.get("/review", response_model=dict)
def review(
    user: CurrentUser = Depends(require_global(CONFIRM)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """The confirmer's queue: what waits for a second person, oldest first,
    and what is in force."""
    clearance, _ = user_ceiling(conn, user.user_id)
    body = _service(conn, adapters).review(clearance=clearance.name)
    return {**body, "notice": AUTHORITY_NOTICE}


class ConfirmBody(BaseModel):
    note: str = Field(min_length=5, max_length=1000)
    target_ids: list[UUID] = Field(default_factory=list, max_length=100)


@router.post("/{authority_id}/confirm", response_model=dict,
             dependencies=[Depends(rate_limit("collection.authority"))])
def confirm(
    authority_id: UUID, body: ConfirmBody,
    user: CurrentUser = Depends(require_global(CONFIRM)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """Confirm an authority and the sources listed, as the second person:
    409 for the person who recorded it or added a source."""
    clearance, _ = user_ceiling(conn, user.user_id)
    view = _answer(lambda: _service(conn, adapters).confirm(
        authority_id, confirmed_by=user.user_id, note=body.note,
        target_ids=body.target_ids, clearance=clearance.name))
    return {"authority": view, "notice": AUTHORITY_NOTICE}


class StopBody(BaseModel):
    reason: str = Field(min_length=5, max_length=1000)


def _stop(authority_id: UUID, body: StopBody, user: CurrentUser,
          conn: psycopg.Connection, adapters: dict, by_role: str) -> dict:
    clearance, _ = user_ceiling(conn, user.user_id)
    view = _answer(lambda: _service(conn, adapters).revoke(
        authority_id, revoked_by=user.user_id, reason=body.reason,
        by_role=by_role, clearance=clearance.name))
    return {"authority": view, "notice": AUTHORITY_NOTICE}


@router.post("/{authority_id}/revoke", response_model=dict,
             dependencies=[Depends(rate_limit("collection.authority"))])
def revoke(
    authority_id: UUID, body: StopBody,
    user: CurrentUser = Depends(require_global(RECORD)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """The recording side stops an authority."""
    return _stop(authority_id, body, user, conn, adapters, "record")


@router.post("/{authority_id}/refuse", response_model=dict,
             dependencies=[Depends(rate_limit("collection.authority"))])
def refuse(
    authority_id: UUID, body: StopBody,
    user: CurrentUser = Depends(require_global(CONFIRM)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """The confirming side refuses or stops an authority."""
    return _stop(authority_id, body, user, conn, adapters, "confirm")


def _stop_target(target_id: UUID, body: StopBody, user: CurrentUser,
                 conn: psycopg.Connection, adapters: dict, by_role: str) -> dict:
    clearance, _ = user_ceiling(conn, user.user_id)
    view = _answer(lambda: _service(conn, adapters).revoke_target(
        target_id, revoked_by=user.user_id, reason=body.reason,
        by_role=by_role, clearance=clearance.name))
    return {"authority": view, "notice": AUTHORITY_NOTICE}


@router.post("/targets/{target_id}/revoke", response_model=dict,
             dependencies=[Depends(rate_limit("collection.authority"))])
def revoke_target(
    target_id: UUID, body: StopBody,
    user: CurrentUser = Depends(require_global(RECORD)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """The recording side takes one source out from under an authority."""
    return _stop_target(target_id, body, user, conn, adapters, "record")


@router.post("/targets/{target_id}/refuse", response_model=dict,
             dependencies=[Depends(rate_limit("collection.authority"))])
def refuse_target(
    target_id: UUID, body: StopBody,
    user: CurrentUser = Depends(require_global(CONFIRM)),
    conn: psycopg.Connection = Depends(get_conn),
    adapters: dict = Depends(get_adapters),
) -> dict:
    """The confirming side refuses one source under an authority."""
    return _stop_target(target_id, body, user, conn, adapters, "confirm")
