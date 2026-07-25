"""Triage: the human half of "machines propose, analysts dispose".

Reading the queue needs `case.read`; disposing of anything needs
`proposal.review`. There is deliberately NO endpoint that creates a
proposal over HTTP — proposals come from extractors running inside the
platform, and an externally-writable proposal queue would be a way to push
suggestions at an analyst from outside the boundary (docs/12 gives ingest
its own key model precisely so that path is separate and write-only).
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.http.deps import CurrentUser, get_conn, require
from noctornal_api.http.errors import Problem
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
