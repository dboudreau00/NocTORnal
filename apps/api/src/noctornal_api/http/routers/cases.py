"""Case endpoints. Creation needs a global case.create; reading/listing is
case-scoped through the gate."""
from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from noctornal_api.cases import CaseService
from noctornal_api.http.deps import CurrentUser, current_user, get_conn, require, require_global
from noctornal_api.http.errors import Problem

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


@router.post("/cases", response_model=CaseOut, status_code=201)
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


@router.get("/cases", response_model=list[CaseOut])
def list_cases(user: CurrentUser = Depends(current_user),
               conn: psycopg.Connection = Depends(get_conn)) -> list[CaseOut]:
    return [_out(c) for c in CaseService(conn).list_for_user(user.user_id)]


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: UUID,
             _: CurrentUser = Depends(require("case.read")),
             conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    case = CaseService(conn).get(case_id)
    if case is None:
        raise Problem(404, "Not found", "case does not exist")
    return _out(case)


class TransitionBody(BaseModel):
    status: str


@router.post("/cases/{case_id}/status", response_model=CaseOut)
def transition(case_id: UUID, body: TransitionBody,
               user: CurrentUser = Depends(require("case.update")),
               conn: psycopg.Connection = Depends(get_conn)) -> CaseOut:
    svc = CaseService(conn)
    svc.transition_status(case_id, body.status, actor_id=user.user_id)
    return _out(svc.get(case_id))
