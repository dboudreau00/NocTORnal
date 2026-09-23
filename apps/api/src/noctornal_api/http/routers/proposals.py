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

import logging
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from psycopg.types.json import Json

from noctornal_api import notify_events
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    get_conn,
    require,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.proposals import (
    KIND_ATTRIBUTE,
    KIND_EDGE,
    KIND_NODE,
    STATE_PROPOSED,
    ProposalError,
    ProposalReview,
    ProposalRow,
    ProposalStore,
    accepted_classification,
)

log = logging.getLogger(__name__)

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


def _check_accept_labels(conn: psycopg.Connection, user: CurrentUser,
                         case_id: UUID, row: ProposalRow,
                         requested: str | None) -> None:
    """Hold an accept to the rule every other write route holds: what an
    analyst writes stays within what they can read back.

    Final review C12 (2026-09-23). This route ran `proposal.review` and
    nothing else, then passed the caller's `classification` straight to
    the graph writer. An AMBER reviewer could accept at RED and author an
    element that at once vanished from their own graph, search and lists,
    and that they could neither correct nor retire, which is exactly what
    `check_writable_labels` exists to prevent on graph.py, capture, comms,
    deception, evidence and samples. The database enforces only the case
    FLOOR, so nothing below this caught it.

    NODE and EDGE are checked at the label that will actually be written
    (`accepted_classification`, the same expression the service uses),
    against the case-less ceiling, as every other creation route does: a
    case-scoped break-glass grant does not raise what may be authored.

    ATTRIBUTE writes an assertion onto an existing entity rather than a
    new element, so it is gated the way `graph.py` gates asserting about
    an entity (CR7): against that entity's own labels. Its target must
    also be in this case. Nothing in the database ties an assertion's
    entity to the assertion's case, and the graph route refuses a
    foreign one; this path did not look.
    """
    if row.kind in (KIND_NODE, KIND_EDGE):
        check_writable_labels(
            conn, user,
            classification=accepted_classification(row.payload, requested))
        return
    if row.kind != KIND_ATTRIBUTE:
        return  # the service refuses an unknown kind, writing nothing
    try:
        target = UUID(str((row.payload or {})["node_id"]))
    except (KeyError, ValueError) as exc:
        raise Problem(409, "Conflict",
                      "this proposal does not name a valid entity to attach "
                      "its claim to; nothing was written") from exc
    labels = conn.execute(
        "SELECT case_id, classification, compartments FROM core.node "
        "WHERE id = %s", (target,)).fetchone()
    if labels is None or labels[0] != case_id:
        raise Problem(409, "Conflict",
                      "the entity this proposal makes a claim about is not in "
                      "this case; nothing was written")
    authorize_object(conn, user, case_id=case_id,
                     permission_key="proposal.review",
                     classification=labels[1],
                     compartments=frozenset(labels[2] or []))


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
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc

    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, detail)
           VALUES (%s, 'USER', 'DOCUMENT_CAPTURED', 'document', %s, %s, %s)""",
        (user.user_id, result.document_id, case_id, Json(result.summary())),
    )
    # N2 (2026-09-02). `notify_events.proposals_queued` had existed since
    # Phase 5 with the wording, the priority and the digest default all
    # decided -- and no router called it, so an analyst found out there was
    # triage work by looking. The document and the proposals are committed
    # above; a notify failure is never raised, because a 500 here reads as
    # "the capture failed" and the analyst pastes the same material again.
    #
    # The failure is reported as `owner_notified: null`, NOT false. Until
    # 2026-09-02 it was false, which is the same value this endpoint uses
    # for "there was nothing to say" and "the owner pasted it themselves" --
    # a broken notifier and a deliberate suppression reading identically to
    # the caller. Keeping "we decided not to" apart from "we tried and
    # could not" is exactly the distinction `NotificationService.notify`
    # returning None was built to preserve, and losing it one file
    # downstream is this codebase's signature defect: a failure reported as
    # the wrong thing rather than as a crash.
    try:
        owner_notified: bool | None = notify_events.proposals_queued(
            conn, case_id=case_id, count=len(result.proposal_ids),
            actor_id=user.user_id)
    except Exception:  # noqa: BLE001 - reported in the response, not raised
        log.exception("capture %s was recorded but its notification failed",
                      result.document_id)
        owner_notified = None
    return {
        **result.summary(),
        # true = told. false = deliberately not told (no proposals, or the
        # owner is the person who pasted it -- see proposals_queued).
        # null = the attempt itself failed and is in the log.
        "owner_notified": owner_notified,
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

    Nor a path around the label ceiling: see `_check_accept_labels`.
    """
    row = _owned(conn, case_id, proposal_id)
    _check_accept_labels(conn, user, case_id, row, body.classification)
    try:
        return _out(ProposalReview(conn).accept(
            proposal_id, reviewed_by=user.user_id, note=body.note,
            classification=body.classification))
    except ProposalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


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
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


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
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
