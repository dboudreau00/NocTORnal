"""Capture and triage: the human half of "machines propose, analysts
dispose".

Three permissions, deliberately distinct. Reading the queue needs
`case.read`; disposing of anything needs `proposal.review`; pasting
material needs `evidence.upload`. Capture and review are kept apart so
that being able to feed the extractor is not the same as being able to
accept what it produces.

No endpoint lets a client DICTATE a proposal. `/capture` accepts text and
the in-process extractor derives the proposals from it — the caller
supplies material, never the finding. A queue that accepted
caller-authored proposals would be a way to push arbitrary suggestions at
an analyst from outside the boundary, which is why docs/12 gives bulk
ingest its own separate, write-only key model instead.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from psycopg.types.json import Json

from noctornal_api.http.deps import (
    CurrentUser,
    check_writable_labels,
    get_conn,
    require,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.proposals import (
    STATE_PROPOSED,
    ProposalError,
    ProposalReview,
    ProposalRow,
    ProposalStore,
)

router = APIRouter(prefix="/cases/{case_id}/proposals", tags=["proposals"])

_STATES = frozenset({"PROPOSED", "ACCEPTED", "REJECTED", "DISPUTED", "SUPERSEDED"})


class ProposalOut(BaseModel):
    id: str
    kind: str
    payload: dict
    origin: str
    score: float | None
    rationale: str
    state: str
    reviewed_by: str | None
    review_note: str | None
    applied_node_id: str | None
    applied_edge_id: str | None
    created_at: str


class DispositionBody(BaseModel):
    note: str | None = None
    classification: str | None = None


class RequiredNoteBody(BaseModel):
    note: str = Field(min_length=1)


def _out(p: ProposalRow) -> ProposalOut:
    return ProposalOut(
        id=str(p.id), kind=p.kind, payload=p.payload, origin=p.origin,
        score=p.score, rationale=p.rationale, state=p.state,
        reviewed_by=str(p.reviewed_by) if p.reviewed_by else None,
        review_note=p.review_note,
        applied_node_id=str(p.applied_node_id) if p.applied_node_id else None,
        applied_edge_id=str(p.applied_edge_id) if p.applied_edge_id else None,
        created_at=p.created_at.isoformat(),
    )


def _owned(conn: psycopg.Connection, case_id: UUID, proposal_id: UUID) -> ProposalRow:
    """A proposal reached through this case's path must belong to it — the
    gate authorised the case, not some other case's queue."""
    row = ProposalStore(conn).get(proposal_id)
    if row is None or row.case_id != case_id:
        raise Problem(404, "Not found", "no such proposal in this case")
    return row


class CaptureBody(BaseModel):
    text: str = Field(min_length=1, max_length=1_000_000)
    title: str | None = None
    external_url: str | None = None
    author_handle: str | None = None
    classification: str = "AMBER"


# A capture loop floods the triage queue. That is an attack on the
# analyst's attention rather than on the server, and it is the more
# effective of the two: a queue with ten thousand junk proposals in it is a
# queue nobody works.
@router.post("/capture", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("capture"))])
def capture(
    case_id: UUID, body: CaptureBody,
    user: CurrentUser = Depends(require("evidence.upload")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Paste text, land it as a document, extract selectors, raise proposals.

    Gated on `evidence.upload` rather than `proposal.review`: pasting
    material is a collection act, and the analyst doing it is not thereby
    entitled to accept what comes out of it. Keeping the two permissions
    apart is what stops capture becoming a way to write the graph without
    review.

    Deliberately capped at 1MB. This is a paste box, not an ingest API --
    docs/12 gives bulk ingest its own write-only key model precisely so
    that path never runs through an analyst's session.
    """
    from noctornal_api.extraction import CaptureService, ExtractionError

    check_writable_labels(conn, user, classification=body.classification)
    try:
        result = CaptureService(conn).capture(
            case_id=case_id, text=body.text, title=body.title,
            external_url=body.external_url, author_handle=body.author_handle,
            classification=body.classification,
        )
    except ExtractionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc

    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, detail)
           VALUES (%s, 'USER', 'DOCUMENT_CAPTURED', 'document', %s, %s, %s)""",
        (user.user_id, result.document_id, case_id, Json(result.summary())),
    )
    return {
        **result.summary(),
        "note": ("Nothing has entered the graph. Each finding is a proposal "
                 "waiting in the triage queue."),
    }


@router.get("", response_model=dict)
def queue(
    case_id: UUID,
    state: str = Query(STATE_PROPOSED),
    limit: int = Query(100, ge=1, le=500),
    _: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The triage queue, most confident first. The counts travel with it so
    the interface can show what is waiting without a second round trip."""
    if state not in _STATES:
        raise Problem(400, "Invalid request",
                      f"unknown state {state!r}; one of {', '.join(sorted(_STATES))}")
    store = ProposalStore(conn)
    return {
        "state": state,
        "counts": store.counts(case_id),
        "proposals": [_out(p) for p in store.queue(case_id, state=state,
                                                   limit=limit)],
    }


@router.post("/{proposal_id}/accept", response_model=ProposalOut)
def accept(
    case_id: UUID, proposal_id: UUID, body: DispositionBody,
    user: CurrentUser = Depends(require("proposal.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ProposalOut:
    """Apply a suggestion to the graph, as the reviewing analyst.

    The element is created through GraphWriteService, so its assertion is
    written in the same transaction and attributed to the reviewer — an
    accepted proposal is a person making a claim on a machine's suggestion,
    not a privileged path around the assertion model.
    """
    _owned(conn, case_id, proposal_id)
    try:
        return _out(ProposalReview(conn).accept(
            proposal_id, reviewed_by=user.user_id, note=body.note,
            classification=body.classification))
    except ProposalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@router.post("/{proposal_id}/reject", response_model=ProposalOut)
def reject(
    case_id: UUID, proposal_id: UUID, body: RequiredNoteBody,
    user: CurrentUser = Depends(require("proposal.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ProposalOut:
    """Dispose without applying. The note is required: parser drift is
    found by reading rejections."""
    _owned(conn, case_id, proposal_id)
    try:
        return _out(ProposalReview(conn).reject(
            proposal_id, reviewed_by=user.user_id, note=body.note))
    except ProposalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@router.post("/{proposal_id}/defer", response_model=ProposalOut)
def defer(
    case_id: UUID, proposal_id: UUID, body: RequiredNoteBody,
    user: CurrentUser = Depends(require("proposal.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ProposalOut:
    """Park an ambiguous suggestion. A queue whose only options are yes and
    no forces a decision on items that do not deserve one yet."""
    _owned(conn, case_id, proposal_id)
    try:
        return _out(ProposalReview(conn).defer(
            proposal_id, reviewed_by=user.user_id, note=body.note))
    except ProposalError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
