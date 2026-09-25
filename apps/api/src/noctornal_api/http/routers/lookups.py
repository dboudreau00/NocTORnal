"""A case's lookups (F15.3 and F15.4, 2026-09-24).

Prefix /cases/{case_id}/lookups. Static paths are declared before
/{lookup_id}. No selector value ever travels in a query string: a request,
a plan and a batch send it in the body. Every read uses the CURRENT labels
of the lookup's node, sample and case, and one serialiser that withholds
an answer's outcome from a reader who does not dominate it.

The verbs a route sends under are named in the service (lookups.py), never
as literals here: test_closed_case_read_only.py reads the literals of a
route body, and a read that named a content verb would be refused on a
closed case.
"""
from __future__ import annotations

from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from noctornal_api import lookups
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    get_conn,
    require,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/lookups", tags=["lookups"])


def _refused(exc: lookups.LookupRefused) -> JSONResponse:
    status = exc.status
    title = {400: "Invalid request", 403: "Forbidden", 409: "Conflict"}.get(status,
                                                                          "Conflict")
    return JSONResponse(status_code=status, content={
        "type": "about:blank", "title": title, "status": status,
        "detail": safe_detail(exc), "code": exc.code,
        "retry_at": exc.retry_at.isoformat() if exc.retry_at else None})


def _not_found() -> Problem:
    return Problem(404, "Not found", "no such lookup, subject or provider in this case")


class Subject(BaseModel):
    kind: Literal["SELECTOR", "SAMPLE", "VALUE"]
    selector_id: UUID | None = None
    sample_id: UUID | None = None
    hash: Literal["sha256", "sha1", "md5"] | None = None
    selector_type: str | None = Field(default=None, max_length=40)
    value: str | None = Field(default=None, min_length=1, max_length=2048)
    classification: str | None = None


class LookupBody(BaseModel):
    provider_id: UUID
    operation: str = Field(max_length=64)
    subject: Subject
    confirm_exposure: str
    authorised_by: UUID | None = None
    authorisation_note: str | None = Field(default=None, max_length=2000)
    queue_if_limited: bool = False


class SignOffBody(BaseModel):
    approve: bool
    note: str | None = Field(default=None, max_length=2000)


class ReasonBody(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class Selection(BaseModel):
    selector_ids: list[UUID] | None = Field(default=None, max_length=501)
    node_id: UUID | None = None
    selector_type: str | None = Field(default=None, max_length=40)


class PlanBody(BaseModel):
    provider_id: UUID
    operation: str = Field(max_length=64)
    selection: Selection


class BatchBody(PlanBody):
    confirm_exposure: str
    note: str = Field(min_length=11, max_length=2000)
    plan_digest: str = Field(pattern="^[0-9a-f]{64}$")


def _answer(svc: lookups.LookupService, case_id: UUID, user_id: UUID, outcome: dict):
    """The lookup (and its answer when the caller dominates it) in the
    status the service decided."""
    item = svc.get(case_id, outcome["lookup_id"], user_id=user_id)
    result = None
    if item["result_id"]:
        try:
            result = svc.result(case_id, UUID(item["result_id"]), user_id=user_id)
        except lookups.NotVisible:
            result = {"withheld": True}
    elif item["withheld"]:
        result = {"withheld": True}
    body = {"lookup": item, "result": result,
            "proposals_raised": item["proposals_raised"]}
    for key in ("notice", "not_before"):
        if outcome.get(key) is not None:
            body[key] = (outcome[key].isoformat() if hasattr(outcome[key], "isoformat")
                         else outcome[key])
    status = outcome.get("status", 200)
    if item["withheld"]:
        # The status would say whether a withheld answer could be read
        # (2026-09-25): the reader is told only that there
        # is an answer above their clearance.
        status = 200
    if status >= 500:
        body["detail"] = item.get("error_detail")
    return JSONResponse(status_code=status, content=body)


@router.get("/providers", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def list_providers(
    case_id: UUID,
    selector_type: str | None = Query(None, max_length=40),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return {"providers": lookups.LookupService(conn).providers_for(
        case_id, user_id=user.user_id, selector_type=selector_type)}


@router.get("/authorisers", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def authorisers(
    case_id: UUID,
    classification: str | None = Query(None, pattern="^(CLEAR|GREEN|AMBER)$"),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Clamped to the caller's own clearance: asking with a higher label
    must not list who is cleared to it. The service re-checks the true
    label at request and at sign-off."""
    svc = lookups.LookupService(conn)
    clearance, _held = user_ceiling(conn, user.user_id)
    row = conn.execute('SELECT classification, compartments FROM core."case" WHERE id = %s',
                       (case_id,)).fetchone()
    wanted = classification or row[0]
    order = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")
    if order.index(wanted) > order.index(clearance.name):
        wanted = clearance.name
    if order.index(wanted) < order.index(row[0]):
        wanted = row[0]
    return {"authorisers": svc.lookup_authorisers(
        case_id, classification=wanted, compartments=frozenset(row[1] or []),
        exclude=user.user_id)}


@router.get("/awaiting-signoff", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def awaiting(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return {"lookups": lookups.LookupService(conn).awaiting(case_id, user_id=user.user_id)}


@router.get("/results/{result_id}", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def result(
    case_id: UUID, result_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return lookups.LookupService(conn).result(case_id, result_id, user_id=user.user_id)
    except lookups.NotVisible:
        raise _not_found() from None


@router.post("/results/{result_id}/file", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
def file_result(
    case_id: UUID, result_id: UUID,
    user: CurrentUser = Depends(require("evidence.upload")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Filing is an analyst's act, never automatic: an exhibit is locked
    under COMPLIANCE for the retention period (docs/08)."""
    from noctornal_api.evidence import EvidenceStorage
    svc = lookups.LookupService(conn)
    try:
        got = svc.result(case_id, result_id, user_id=user.user_id)
    except lookups.NotVisible:
        raise _not_found() from None
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.upload",
                     classification=got["classification"], after_case_gate=True)
    check_writable_labels(conn, user, classification=got["classification"])
    try:
        evidence_id = svc.file_as_exhibit(case_id, result_id, user_id=user.user_id,
                                          storage=EvidenceStorage())
    except lookups.LookupRefused as exc:
        return _refused(exc)
    return {"evidence_id": str(evidence_id)}


@router.post("/plan", response_model=dict, dependencies=[Depends(rate_limit("lookup.plan"))])
def plan(
    case_id: UUID, body: PlanBody,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """A read, sent as POST so the selection stays out of the URL: nothing
    is sent and nothing is written."""
    try:
        return lookups.LookupService(conn).plan(
            case_id, user_id=user.user_id, provider_id=body.provider_id,
            operation=body.operation, selection=body.selection.model_dump())
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)


@router.post("/batches", response_model=dict, status_code=202,
             dependencies=[Depends(rate_limit("lookup.request"))])
def commit_batch(
    case_id: UUID, body: BatchBody,
    user: CurrentUser = Depends(require("lookup.request")),
    conn: psycopg.Connection = Depends(get_conn),
):
    try:
        return lookups.LookupService(conn).commit_batch(
            case_id, user_id=user.user_id, provider_id=body.provider_id,
            operation=body.operation, selection=body.selection.model_dump(),
            confirm_exposure=body.confirm_exposure, note=body.note,
            plan_digest=body.plan_digest)
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)


@router.get("/batches", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def batches(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return {"batches": lookups.LookupService(conn).batches(case_id, user_id=user.user_id)}


@router.post("/batches/{batch_id}/cancel", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def cancel_batch(
    case_id: UUID, batch_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Cancelling queued sends sends nothing, so it stays open on a closed
    case."""
    try:
        return {"cancelled": lookups.LookupService(conn).cancel_batch(
            case_id, batch_id, user_id=user.user_id, reason=body.reason)}
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)


@router.post("", dependencies=[Depends(rate_limit("lookup.request"))])
def request(
    case_id: UUID, body: LookupBody,
    user: CurrentUser = Depends(require("lookup.request")),
    conn: psycopg.Connection = Depends(get_conn),
):
    svc = lookups.LookupService(conn)
    try:
        subject = svc.resolve_subject(case_id, body.subject.model_dump(),
                                      user_id=user.user_id)
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)
    # The subject gated again at its own labels, after the case's gate.
    authorize_object(conn, user, case_id=case_id, permission_key="case.read",
                     classification=subject.classification,
                     compartments=subject.compartments - subject.case_compartments,
                     after_case_gate=True)
    try:
        outcome = svc.request(
            case_id, body.subject.model_dump(), provider_id=body.provider_id,
            operation=body.operation, user_id=user.user_id,
            confirm_exposure=body.confirm_exposure, authorised_by=body.authorised_by,
            authorisation_note=body.authorisation_note,
            queue_if_limited=body.queue_if_limited)
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)
    return _answer(svc, case_id, user.user_id, outcome)


@router.get("", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def list_lookups(
    case_id: UUID,
    state: str | None = Query(None, max_length=20),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return {"lookups": lookups.LookupService(conn).list(
        case_id, user_id=user.user_id, state=state, limit=limit)}


@router.get("/{lookup_id}", response_model=dict, dependencies=[Depends(rate_limit("request"))])
def get_lookup(
    case_id: UUID, lookup_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        return lookups.LookupService(conn).get(case_id, lookup_id, user_id=user.user_id)
    except lookups.NotVisible:
        raise _not_found() from None


@router.post("/{lookup_id}/sign-off", dependencies=[Depends(require_step_up),
                                                    Depends(rate_limit("lookup.request"))])
def sign_off(
    case_id: UUID, lookup_id: UUID, body: SignOffBody,
    user: CurrentUser = Depends(require("lookup.authorise", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Anybody but the named authoriser, the requester included, gets the
    404 a missing row gets."""
    svc = lookups.LookupService(conn)
    try:
        outcome = svc.sign_off(case_id, lookup_id, user_id=user.user_id,
                               approve=body.approve, note=body.note)
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)
    return _answer(svc, case_id, user.user_id, outcome)


@router.post("/{lookup_id}/cancel", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def cancel(
    case_id: UUID, lookup_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Withdrawing a request sends nothing, so it stays open on a closed
    case."""
    try:
        lookups.LookupService(conn).cancel(case_id, lookup_id, user_id=user.user_id,
                                           reason=body.reason)
    except lookups.NotVisible:
        raise _not_found() from None
    except lookups.LookupRefused as exc:
        return _refused(exc)
    return {"cancelled": str(lookup_id)}
