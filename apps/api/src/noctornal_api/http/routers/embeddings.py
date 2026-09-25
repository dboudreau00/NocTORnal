"""Similarity status and Administration, Embeddings (F6.3, embeddings,
2026-09-24).

`GET /embeddings/status` answers any signed-in account: whether each mode
can be used, and where the model is, in words. No counts and no host.

Everything under `/admin/embeddings` needs `embedding.manage` (SYS_ADMIN,
step-up). Figures (coverage and the list of gaps) need the global
`collection.read` as well and follow the caller's own case-less clearance
and compartments, because the register is read by administrators who need
not read collected documents, and a count of what is indexed at every
label is a volume disclosure. Case-item figures are not here: they appear
in a case's own similarity answers, to that case's readers. Table sizes
are not here either: they are in the embed-pass log, read at host level.
No answer carries a count to a caller without collection.read, and
activate's refusal carries no number.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field

from noctornal_api import embedders as E
from noctornal_api.db import SystemPurpose
from noctornal_api.embeddings import (
    EmbeddingService,
    EmbedRefused,
    reason_text,
)
from noctornal_api.http.deps import (
    CurrentUser,
    current_user,
    get_conn,
    require_global,
    system_conn,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import enforce
from noctornal_api.http.routers.search import _holds_global

router = APIRouter(tags=["embeddings"])

COVERAGE_NOTE = "Coverage figures are shown to accounts that read collected documents."
#: The console's pass: bounded so a request never runs long.
PASS_SECONDS = 20
PASS_MAX_ITEMS = 2000


@router.get("/embeddings/status", response_model=dict)
def embedding_status(
    _user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return EmbeddingService(conn).status()


def _endpoint_facts(svc: EmbeddingService) -> dict:
    cfg = svc.configuration
    if not cfg.meaning_url_set:
        return {"configured": False}
    settings = cfg.meaning_settings
    if settings is None:
        return {"configured": True, "problems": [p for p in cfg.problems
                                                 if E.MEANING_PREFIX in p]}
    facts = {"configured": True, "endpoint": settings.endpoint, "model": settings.model,
             "ceiling": settings.ceiling, "authority": settings.authority,
             "message_authority": settings.message_authority,
             "local_host": settings.local_host, "problems": []}
    try:
        endpoint = svc.open(settings, context_kind="check")
    except EmbedRefused as exc:
        facts.update(locality=None, destination=None,
                     route_status=reason_text(exc.code))
        return facts
    facts.update(locality=endpoint.locality.words,
                 destination=endpoint.destination.value,
                 route_status="An egress route reaches it.")
    return facts


@router.get("/admin/embeddings", response_model=dict)
def admin_embeddings(
    user: CurrentUser = Depends(require_global("embedding.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    svc = EmbeddingService(conn)
    spaces = svc.spaces()
    answer = {"spaces": [s.public() for s in spaces], "endpoint": _endpoint_facts(svc),
              "wording_setting": svc.configuration.wording_setting,
              "coverage": None, "coverage_note": COVERAGE_NOTE}
    if _holds_global(conn, user, "collection.read"):
        clearance, held = user_ceiling(conn, user.user_id)
        answer["coverage"] = {
            str(s.id): svc.document_coverage(s.slot, clearance=clearance.name, held=held)
            for s in spaces if s.state != "RETIRED"}
        answer["coverage_note"] = None
    return answer


@router.get("/admin/embeddings/gaps", response_model=dict)
def admin_embedding_gaps(
    space_id: UUID,
    status: Literal["EMPTY", "EXCLUDED", "WITHHELD", "FAILED"] | None = None,
    reason: str | None = Query(None, max_length=64),
    limit: int = Query(50, ge=1, le=200),
    after_at: datetime | None = None,
    after_id: UUID | None = None,
    user: CurrentUser = Depends(require_global("embedding.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The documents of one index that are not embedded, with each reason
    in words, at the caller's own labels; keyset paging on (embedded_at,
    document_id).

    `after_at` is parsed here as a time, so a malformed one is a 422 and
    never reaches the SQL cast, where it would be a 500 (2026-09-25). The
    two halves of the key come together or not at all."""
    if (after_at is None) != (after_id is None):
        raise Problem(422, "Unprocessable", "after_at and after_id come together: pass "
                      "both from the previous page's next, or neither.")
    if after_at is not None and after_at.tzinfo is None:
        raise Problem(422, "Unprocessable", "after_at needs a time zone; every time "
                      "here is UTC.")
    if not _holds_global(conn, user, "collection.read"):
        raise Problem(403, "Forbidden", COVERAGE_NOTE)
    svc = EmbeddingService(conn)
    space = svc.space(space_id)
    if space is None:
        raise Problem(404, "Not found", "no such index")
    clearance, held = user_ceiling(conn, user.user_id)
    rows = svc.document_gaps(space.slot, clearance=clearance.name, held=held,
                             status=status, reason=reason, limit=limit,
                             after=(after_at, after_id) if after_at and after_id else None)
    nxt = None
    if len(rows) == limit:
        nxt = {"after_at": rows[-1]["embedded_at"], "after_id": rows[-1]["document_id"]}
    return {"space_id": str(space_id), "gaps": rows, "next": nxt}


class RegisterBody(BaseModel):
    role: Literal["WORDING", "MEANING"]
    reason: str = Field(..., min_length=5, max_length=500)


class ReasonBody(BaseModel):
    reason: str = Field(..., min_length=5, max_length=500)


class ActivateBody(ReasonBody):
    accept_missing: bool = False


class PassBody(BaseModel):
    role: Literal["WORDING", "MEANING"]
    limit: int = Field(500, ge=1, le=PASS_MAX_ITEMS)


def _conflict(exc: EmbedRefused) -> Problem:
    return Problem(409, "Conflict", str(exc))


# The index administration below runs on a system connection (S1,
# 2026-09-25). Registering an index queues EVERY document, exhibit and
# claim; activating one first sweeps the queue of entries whose item is
# gone, by an anti-join; a recheck and a pass work through every row of
# every kind. As the request role each would see only what the
# administrator may read: an index registered by an administrator on no
# case would queue no exhibit or claim at all, and the sweep would delete
# the queue entries of every one it could not see. The gate
# (embedding.manage, step-up) ran on the request connection first.


@router.post("/admin/embeddings/spaces", response_model=dict, status_code=201)
def register_embedding_space(
    body: RegisterBody,
    user: CurrentUser = Depends(require_global("embedding.manage")),
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.EMBEDDINGS)),
) -> dict:
    try:
        space = EmbeddingService(sconn).request_rebuild(body.role, actor_id=user.user_id,
                                                       reason=body.reason)
    except EmbedRefused as exc:
        raise _conflict(exc) from None
    return space.public()


def _live_space(svc: EmbeddingService, space_id: UUID):
    space = svc.space(space_id)
    if space is None:
        raise Problem(404, "Not found", "no such index")
    return space


@router.post("/admin/embeddings/spaces/{space_id}/activate", response_model=dict)
def activate_embedding_space(
    space_id: UUID, body: ActivateBody,
    user: CurrentUser = Depends(require_global("embedding.manage")),
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.EMBEDDINGS)),
) -> dict:
    svc = EmbeddingService(sconn)
    _live_space(svc, space_id)
    try:
        return svc.activate(space_id, actor_id=user.user_id, reason=body.reason,
                            accept_missing=body.accept_missing).public()
    except EmbedRefused as exc:
        raise _conflict(exc) from None


@router.post("/admin/embeddings/spaces/{space_id}/retire", response_model=dict)
def retire_embedding_space(
    space_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("embedding.manage")),
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.EMBEDDINGS)),
) -> dict:
    svc = EmbeddingService(sconn)
    _live_space(svc, space_id)
    try:
        return svc.retire(space_id, actor_id=user.user_id, reason=body.reason).public()
    except EmbedRefused as exc:
        raise _conflict(exc) from None


@router.post("/admin/embeddings/spaces/{space_id}/recheck", response_model=dict)
def recheck_embedding_space(
    space_id: UUID, body: ReasonBody,
    user: CurrentUser = Depends(require_global("embedding.manage")),
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.EMBEDDINGS)),
) -> dict:
    svc = EmbeddingService(sconn)
    _live_space(svc, space_id)
    try:
        return svc.recheck(space_id, actor_id=user.user_id, reason=body.reason).public()
    except EmbedRefused as exc:
        raise _conflict(exc) from None


@router.post("/admin/embeddings/pass", response_model=dict)
def run_embedding_pass(
    body: PassBody, request: Request, response: Response,
    user: CurrentUser = Depends(require_global("embedding.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.EMBEDDINGS)),
) -> dict:
    """One bounded pass from the console. The answer says what happened in
    words and flags, never how many items: counts are the embed-pass
    log's."""
    enforce(request, response, "embedding.pass", f"u:{user.user_id}", conn=conn,
            actor_id=user.user_id)
    svc = EmbeddingService(sconn)
    svc.ensure_spaces(actor_id=user.user_id)
    result = svc.run_pass(body.role, limit=body.limit, max_seconds=PASS_SECONDS,
                          actor_id=user.user_id)
    if result.locked:
        raise Problem(409, "Conflict", "Another embedding pass for this kind of index is "
                      "running. Try again when it has finished.")
    svc._audit("EMBED_PASS_RUN", actor_id=user.user_id, object_id=None,
               detail={"role": body.role, "limit": body.limit,
                       "refused": result.refused})
    return {"role": body.role, "ran": True, "locked": False,
            "any_failed": bool(result.failed), "deferred": bool(result.deferred),
            "refused": result.refused,
            "refused_text": reason_text(result.refused) if result.refused else None}
