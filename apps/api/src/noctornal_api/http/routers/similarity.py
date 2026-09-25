"""Similarity reads: similar wording and similar meaning (F6.3 and F6.4,
embeddings, 2026-09-24).

Every route here is a POST beside the untouched GET text-search routes in
search.py. A pasted passage travels in the BODY, never in a URL, so it
stays out of proxy and server logs; and `/similar` may embed the item
now and, for similar meaning, send its text to the model endpoint, a side
effect no GET may have. Reads they are, so on a closed case they stay
open (test_closed_case_read_only.py lists them as not content).

Who may read what is exactly what the text search already allows:
documents need the global collection.read that /collection/documents
demands and are read at the reader's CASE-LESS labels (a break-glass grant
on one case never raises deployment-wide documents); exhibits need
evidence.read on the case and claims case.read, both at the case-scoped
labels. Every route spends the 'search' meter, and every similar meaning
send spends 'search.meaning' too.

What an answer says: a band for similar wording ("near duplicate", "much
of the same wording", "some shared wording"), the position for similar
meaning, and what the two texts share (selectors, words, phrases). The
number is in the answer for scripts; the console never prints it (docs/13
#9). No answer carries a vector.
"""
from __future__ import annotations

from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field

from noctornal_api import embedders as E
from noctornal_api.embeddings import (
    MIN_MEANING_QUERY,
    MIN_WORDING_QUERY,
    ClaimReader,
    EmbeddingService,
    EmbedBusy,
    EmbedRefused,
    reason_text,
)
from noctornal_api.http.deps import (
    CurrentUser,
    effective_labels,
    get_conn,
    require,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import BodyCappedRoute, body_cap, enforce, rate_limit
from noctornal_api.http.routers.search import (
    _allowed_on_case,
    _holds_global,
    search_documents,
)

router = APIRouter(tags=["similarity"], route_class=BodyCappedRoute)

#: A similarity query is a passage, not a selector: 8,000 characters, and
#: the body is capped at 64 KiB before it is parsed.
MAX_SIMILAR_QUERY = 8000
QUERY_BODY_CAP = 64 * 1024

#: Beside every answer, because similar text is the easiest thing in the
#: product to over-read (invariant 2).
NOT_THE_SAME_AUTHOR = ("Similar text is not the same author: one advert is reposted "
                       "by many personas, and one author writes in many ways.")


class SimilarBody(BaseModel):
    space: Literal["wording", "meaning"] = "wording"
    limit: int = Field(20, ge=1, le=50)
    include_versions: bool = False


class SimilarQueryBody(BaseModel):
    q: str = Field(..., min_length=1, max_length=MAX_SIMILAR_QUERY)
    mode: Literal["wording", "meaning"]
    limit: int = Field(50, ge=1, le=200)


def _role(mode: str) -> str:
    return E.ROLE_WORDING if mode == "wording" else E.ROLE_MEANING


def _refused(exc: EmbedRefused) -> Problem:
    return Problem(409, "Conflict", safe_detail(exc))


def _meter(request: Request, response: Response, user: CurrentUser, conn):
    """The 'search.meaning' spend, run just before anything is sent."""
    def spend() -> None:
        enforce(request, response, "search.meaning", f"u:{user.user_id}",
                conn=conn, actor_id=user.user_id)
    return spend


def _usable(svc: EmbeddingService, role: str, *, free_text: bool):
    """The space a request reads, or a 409 in words."""
    cfg = svc.configuration
    if role == E.ROLE_WORDING and cfg.wording is None:
        raise Problem(409, "Conflict", "Similar wording is off on this deployment.")
    if role == E.ROLE_MEANING and not cfg.meaning_url_set:
        raise Problem(409, "Conflict", "Similar meaning is off: no model endpoint is "
                      "configured, so no case text is sent anywhere to be embedded.")
    space = svc.query_space(role, stored=not free_text)
    if space is None:
        if role == E.ROLE_MEANING and svc.active(role) is not None:
            raise Problem(409, "Conflict", "The model behind the endpoint changed since "
                          "the similar meaning index was built, so new text cannot be "
                          "compared until it is rebuilt. Similar items still work.")
        raise Problem(409, "Conflict", "The similarity index has not been built yet: "
                      "the embedding pass builds it.")
    return space


def _explained(role: str, query_text: str, hits: list[dict], *, limit: int) -> list[dict]:
    """Each hit with what it shares with the query; similar wording hits
    that fall below the bands are dropped. The hit's text, read for this,
    never leaves.

    The query side is worked out once, and similar wording stops at the
    first hit under WORDING_FLOOR: hits come nearest first, so none after
    it can be shown, and explaining them was most of a request's CPU (about
    13 s for 200 hits at the caps, measured 2026-09-25)."""
    query = E.SharedQuery(query_text)
    out = []
    for hit in hits:
        text = hit.pop("text", "") or ""
        if role == E.ROLE_WORDING and hit["similarity"] < E.WORDING_FLOOR:
            break
        shared = query.against(text)
        hit.update(shared.as_dict())
        if role == E.ROLE_WORDING:
            band = E.wording_band(hit["similarity"], shared)
            if band is None:
                continue
            hit["band"] = band
        else:
            hit["band"] = None
        hit["position"] = len(out) + 1
        out.append(hit)
        if len(out) >= limit:
            break
    return out


def _not_in_index(role: str, status: str, reason: str | None) -> Problem:
    which = "similar wording" if role == E.ROLE_WORDING else "similar meaning"
    return Problem(409, "Conflict", f"Not in the {which} index: "
                   + (reason_text(reason) if reason else "it is not embedded yet") + ".")


def _stored_or_now(svc: EmbeddingService, kind: str, item_id: UUID, role: str, space,
                   *, user: CurrentUser, spend, told=None) -> tuple[str, bool]:
    """The item's stored vector, embedding it first when it has none (and
    for similar meaning, gating, metering and auditing that send).

    `told`, for a claim, gives (status, reason) as this reader may be told
    them (EmbeddingService.claim_reader_view): a claim's stored reason can
    describe material it cites that the reader cannot read."""
    def refusal(status, reason):
        if told is not None and status in ("EXCLUDED", "WITHHELD"):
            status, reason = told()
        return _not_in_index(role, status, reason)

    vector = svc.stored_vector(kind, item_id, space.slot)
    if vector is not None:
        return vector, False
    stored = svc.stored_status(kind, item_id, space.slot)
    if stored is not None and stored[0] in ("EMPTY", "EXCLUDED", "WITHHELD"):
        raise refusal(*stored)
    try:
        status, reason = svc.embed_now(kind, item_id, role, actor_id=user.user_id,
                                       before_send=spend if role == E.ROLE_MEANING else None)
    except EmbedBusy as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from None
    except EmbedRefused as exc:
        raise _refused(exc) from None
    if status != "EMBEDDED":
        raise refusal(status, reason)
    vector = svc.stored_vector(kind, item_id, space.slot)
    if vector is None:
        raise _not_in_index(role, "PENDING", None)
    return vector, True


def _query_vector(svc: EmbeddingService, role: str, space, text: str, *, conn,
                  case_id: UUID, user: CurrentUser, spend) -> str:
    """A free-text query's vector as pgvector text: similar meaning is
    labelled with the case it was typed in, gated, metered and audited
    before it is sent."""
    label, compartments = effective_labels(conn, case_id)
    try:
        vector = svc.embed_query(role, text, space=space, actor_id=user.user_id,
                                 case_id=case_id, label=label, compartments=compartments,
                                 before_send=spend)
    except EmbedRefused as exc:
        raise _refused(exc) from None
    return E.vector_literal(vector)


def _check_query(role: str, q: str) -> str:
    # A lone surrogate from the JSON body cannot be encoded to send or to
    # hash; it becomes a replacement character here, once.
    text = q.encode("utf-8", "replace").decode("utf-8").strip()
    if role == E.ROLE_WORDING and len(text) < MIN_WORDING_QUERY:
        raise Problem(422, "Unprocessable", "Similar wording compares passages: type or "
                      "paste at least 20 characters, or use Exact words.")
    if role == E.ROLE_MEANING and len(text) < MIN_MEANING_QUERY:
        raise Problem(422, "Unprocessable", "Type at least 3 characters.")
    return text


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------

@router.post("/collection/documents/{document_id}/similar", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
def similar_documents(
    document_id: UUID, body: SimilarBody, request: Request, response: Response,
    user: CurrentUser = Depends(require_global("collection.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Documents like this one. The query document must be readable under
    the same predicates as every hit, else the answer is the 404 an
    unknown id gets. Versions of the query (same source and external id)
    are left out unless asked for, and flagged when included."""
    clearance, held = user_ceiling(conn, user.user_id)
    svc = EmbeddingService(conn)
    doc = svc.readable_document(document_id, clearance=clearance.name, held=held)
    if doc is None:
        raise Problem(404, "Not found", "no such document, or it is above your clearance")
    role = _role(body.space)
    space = _usable(svc, role, free_text=False)
    vector, now = _stored_or_now(svc, "document", document_id, role, space, user=user,
                                 spend=_meter(request, response, user, conn))
    versions = svc.document_versions(doc, clearance=clearance.name, held=held)
    exclude = [document_id] + ([] if body.include_versions else versions)
    rows = svc.document_candidates(
        slot=space.slot, query=vector, clearance=clearance.name, held=held,
        k=body.limit + 1 + len(versions), limit=body.limit + 1, exclude=exclude)
    hits = _explained(role, doc["text"], rows, limit=body.limit)
    version_ids = {str(v) for v in versions}
    for hit in hits:
        hit["is_version_of_query"] = hit["id"] in version_ids
    return {"document_id": str(document_id), "space": body.space, "model": space.model,
            "query_embedded_now": now, "hits": hits,
            "coverage": svc.document_coverage(space.slot, clearance=clearance.name,
                                              held=held),
            "note": NOT_THE_SAME_AUTHOR}


@router.post("/cases/{case_id}/search/documents/similar", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
@body_cap(QUERY_BODY_CAP, what="a similarity query")
def search_documents_similar(
    case_id: UUID, body: SimilarQueryBody, request: Request, response: Response,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Collected documents whose wording or meaning is like the query. A
    caller without the global collection.read gets search_documents' own
    not_searched sentence, not a refusal."""
    role = _role(body.mode)
    if not _holds_global(conn, user, "collection.read"):
        page = search_documents(case_id=case_id, q="-", limit=body.limit, user=user,
                                conn=conn)
        return {"mode": body.mode, "model": None, "hits": [], "total": 0,
                "limit": body.limit, "capped": False, "coverage": None,
                "not_searched": page.not_searched, "note": NOT_THE_SAME_AUTHOR}
    text = _check_query(role, body.q)
    svc = EmbeddingService(conn)
    space = _usable(svc, role, free_text=True)
    query = _query_vector(svc, role, space, text, conn=conn, case_id=case_id, user=user,
                          spend=_meter(request, response, user, conn))
    clearance, held = user_ceiling(conn, user.user_id)
    rows = svc.document_candidates(slot=space.slot, query=query, clearance=clearance.name,
                                   held=held, k=body.limit + 1, limit=body.limit)
    hits = _explained(role, text, rows, limit=body.limit)
    return {"mode": body.mode, "model": space.model, "hits": hits, "total": len(hits),
            "limit": body.limit, "capped": len(rows) >= body.limit,
            "coverage": svc.document_coverage(space.slot, clearance=clearance.name,
                                              held=held),
            "not_searched": None, "note": NOT_THE_SAME_AUTHOR}


# ---------------------------------------------------------------------------
# Case items (F6.4)
# ---------------------------------------------------------------------------

EXHIBIT_NOTE = ("Exhibits are compared by title and description: this build does not "
                "extract their text.")


@router.post("/cases/{case_id}/search/evidence/similar", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
@body_cap(QUERY_BODY_CAP, what="a similarity query")
def search_evidence_similar(
    case_id: UUID, body: SimilarQueryBody, request: Request, response: Response,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    role = _role(body.mode)
    text = _check_query(role, body.q)
    svc = EmbeddingService(conn)
    space = _usable(svc, role, free_text=True)
    query = _query_vector(svc, role, space, text, conn=conn, case_id=case_id, user=user,
                          spend=_meter(request, response, user, conn))
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    rows = svc.evidence_similar(case_id=case_id, slot=space.slot, query=query,
                                clearance=clearance.name, held=held, limit=body.limit)
    hits = _explained(role, text, rows, limit=body.limit)
    return {"mode": body.mode, "model": space.model, "hits": hits, "total": len(hits),
            "limit": body.limit, "capped": len(rows) >= body.limit,
            "coverage": svc.case_coverage("evidence", case_id=case_id, slot=space.slot,
                                          clearance=clearance.name, held=held),
            "note": EXHIBIT_NOTE}


@router.post("/cases/{case_id}/search/assertions/similar", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
@body_cap(QUERY_BODY_CAP, what="a similarity query")
def search_assertions_similar(
    case_id: UUID, body: SimilarQueryBody, request: Request, response: Response,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    role = _role(body.mode)
    text = _check_query(role, body.q)
    svc = EmbeddingService(conn)
    space = _usable(svc, role, free_text=True)
    query = _query_vector(svc, role, space, text, conn=conn, case_id=case_id, user=user,
                          spend=_meter(request, response, user, conn))
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    reader = _claim_reader(conn, user, case_id)
    rows = svc.assertion_similar(
        case_id=case_id, slot=space.slot, query=query, clearance=clearance.name,
        held=held, limit=body.limit, may_see_exhibits=reader.may_see_exhibits)
    hits = _explained(role, text, rows, limit=body.limit)
    return {"mode": body.mode, "model": space.model, "hits": hits, "total": len(hits),
            "limit": body.limit, "capped": len(rows) >= body.limit,
            "coverage": svc.case_coverage("assertion", case_id=case_id, slot=space.slot,
                                          clearance=clearance.name, held=held,
                                          role=role, reader=reader),
            "note": NOT_THE_SAME_AUTHOR}


def _claim_reader(conn, user: CurrentUser, case_id: UUID) -> ClaimReader:
    """What this reader may read of a claim's cited material, by read.py's
    rule: documents and sources under the global collection.read at the
    CASE-LESS labels (a break-glass grant on this case never raises them),
    exhibits under evidence.read on the case."""
    doc_clearance, doc_held = user_ceiling(conn, user.user_id)
    return ClaimReader(doc_clearance.name, frozenset(doc_held),
                       _holds_global(conn, user, "collection.read"),
                       _allowed_on_case(conn, user, case_id, "evidence.read"))


@router.post("/cases/{case_id}/evidence/{evidence_id}/similar", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
def similar_evidence(
    case_id: UUID, evidence_id: UUID, body: SimilarBody, request: Request,
    response: Response,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    svc = EmbeddingService(conn)
    text = svc.readable_evidence(case_id, evidence_id, clearance=clearance.name, held=held)
    if text is None:
        raise Problem(404, "Not found", "no such exhibit in this case")
    role = _role(body.space)
    space = _usable(svc, role, free_text=False)
    vector, now = _stored_or_now(svc, "evidence", evidence_id, role, space, user=user,
                                 spend=_meter(request, response, user, conn))
    rows = svc.evidence_similar(case_id=case_id, slot=space.slot, query=vector,
                                clearance=clearance.name, held=held,
                                limit=body.limit, exclude=[evidence_id])
    return {"evidence_id": str(evidence_id), "space": body.space, "model": space.model,
            "query_embedded_now": now,
            "hits": _explained(role, text, rows, limit=body.limit),
            "coverage": svc.case_coverage("evidence", case_id=case_id, slot=space.slot,
                                          clearance=clearance.name, held=held),
            "note": EXHIBIT_NOTE}


@router.post("/cases/{case_id}/assertions/{assertion_id}/similar", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
def similar_assertions(
    case_id: UUID, assertion_id: UUID, body: SimilarBody, request: Request,
    response: Response,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    svc = EmbeddingService(conn)
    text = svc.readable_assertion(case_id, assertion_id, clearance=clearance.name,
                                  held=held)
    if text is None:
        raise Problem(404, "Not found", "no such claim in this case")
    role = _role(body.space)
    space = _usable(svc, role, free_text=False)
    reader = _claim_reader(conn, user, case_id)

    def told():
        view = svc.claim_reader_view(case_id=case_id, slot=space.slot, role=role,
                                     clearance=clearance.name, held=held, reader=reader,
                                     ids=[assertion_id])
        return view.get(assertion_id, ("NOT_COMPARED", "not_compared"))
    vector, now = _stored_or_now(svc, "assertion", assertion_id, role, space, user=user,
                                 spend=_meter(request, response, user, conn), told=told)
    rows = svc.assertion_similar(
        case_id=case_id, slot=space.slot, query=vector, clearance=clearance.name,
        held=held, limit=body.limit, exclude=[assertion_id],
        may_see_exhibits=reader.may_see_exhibits)
    return {"assertion_id": str(assertion_id), "space": body.space, "model": space.model,
            "query_embedded_now": now,
            "hits": _explained(role, text, rows, limit=body.limit),
            "coverage": svc.case_coverage("assertion", case_id=case_id, slot=space.slot,
                                          clearance=clearance.name, held=held,
                                          role=role, reader=reader),
            "note": NOT_THE_SAME_AUTHOR}
