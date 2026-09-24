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
    user_ceiling,
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
    SourceLabels,
    accepted_classification,
    attribute_label_problem,
    strictest,
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
    #: ux08-triage:source-document-not-reachable (2026-09-23). The row
    #: always had its document; the model dropped it, so a card could
    #: neither name the capture it came from nor open it.
    document_id: str | None = None
    document_title: str | None = None
    #: The label an Accept writes by default for NODE and EDGE (the
    #: capture's, never below the case), and the label of the source for
    #: an ATTRIBUTE claim. The card shows it as its TLP chip and offers
    #: nothing below it (ux08-triage:accept-downgrades-classification,
    #: 2026-09-23).
    classification: str | None = None
    #: The entities the payload names, by label and type, for the ones
    #: this reader may see (ux08-triage:attribute-proposal-no-label-no-
    #: value, 2026-09-23).
    refs: dict = Field(default_factory=dict)
    #: Only on the reply to an accept: the assertion it wrote, so the
    #: console's Undo can retract an ATTRIBUTE claim.
    applied_assertion_id: str | None = None
    #: Why an Accept would be refused, for an ATTRIBUTE claim whose entity
    #: is labelled below the material it was found in (final review c1,
    #: 2026-09-24). The card wore the material's TLP chip and offered
    #: Accept, and the accept wrote the claim at the entity's lower label.
    #: Null when the claim may be accepted, or when the reader cannot see
    #: the entity (the card already says so, and its label is not theirs).
    accept_blocked: str | None = None


class DispositionBody(BaseModel):
    note: str | None = None
    classification: str | None = None


class RequiredNoteBody(BaseModel):
    note: str = Field(min_length=1)


def _out(p: ProposalRow, *, classification: str | None = None,
         refs: dict | None = None,
         documents: dict | None = None,
         accept_blocked: str | None = None) -> ProposalOut:
    doc = (documents or {}).get(str(p.document_id)) if p.document_id else None
    return ProposalOut(
        id=str(p.id), kind=p.kind, payload=p.payload, origin=p.origin,
        score=p.score, rationale=p.rationale, state=p.state,
        reviewed_by=str(p.reviewed_by) if p.reviewed_by else None,
        review_note=p.review_note,
        applied_node_id=str(p.applied_node_id) if p.applied_node_id else None,
        applied_edge_id=str(p.applied_edge_id) if p.applied_edge_id else None,
        created_at=p.created_at.isoformat(),
        document_id=str(p.document_id) if p.document_id else None,
        document_title=doc["title"] if doc else None,
        classification=classification,
        refs=refs or {},
        applied_assertion_id=(str(p.applied_assertion_id)
                              if p.applied_assertion_id else None),
        accept_blocked=accept_blocked,
    )


def _named_ids(p: ProposalRow) -> set[str]:
    """The entity ids a proposal's payload names."""
    payload = p.payload or {}
    if p.kind == KIND_ATTRIBUTE:
        keys = ("node_id",)
    elif p.kind == KIND_EDGE:
        keys = ("src_node_id", "dst_node_id")
    else:
        keys = ()
    return {str(payload[k]) for k in keys if payload.get(k)}


def _display_label(p: ProposalRow, labels: SourceLabels) -> str | None:
    """What the card's chip says: for NODE and EDGE the label an Accept
    writes by default, for ATTRIBUTE the strictest of the material and the
    case (its accept writes onto an existing entity, at that entity's
    labels, so there is no new label to choose; an entity labelled below
    this chip refuses the accept, and the card carries `accept_blocked`
    to say so, final review c1, 2026-09-24)."""
    if p.kind in (KIND_NODE, KIND_EDGE):
        try:
            return accepted_classification(p.payload, None,
                                           source=labels.source,
                                           floor=labels.floor)
        except ProposalError:
            return labels.floor
    return strictest((p.payload or {}).get("classification"), labels.source,
                     labels.floor)


def _reader_ceiling(conn: psycopg.Connection, user: CurrentUser,
                    case_id: UUID) -> tuple[str, frozenset[str]]:
    """The reader's clearance for a read of this one case, a case-scoped
    break-glass grant included (`user_ceiling` with the case)."""
    clearance, held = user_ceiling(conn, user.user_id, case_id)
    return clearance.name, held


def _owned(conn: psycopg.Connection, case_id: UUID, proposal_id: UUID,
           user: CurrentUser | None = None) -> ProposalRow:
    """A proposal reached through this case's path must belong to it — the
    gate authorised the case, not some other case's queue.

    With `user`, it must also be one the queue would have SHOWN them: a
    proposal from material above their clearance is the same 404 as one
    that does not exist, so it cannot be rejected or deferred by id by
    somebody who was never shown it (ux08-triage:accept-downgrades-
    classification, 2026-09-23)."""
    row = ProposalStore(conn).get(proposal_id)
    if row is None or row.case_id != case_id:
        raise Problem(404, "Not found", "no such proposal in this case")
    if user is not None:
        clearance, held = _reader_ceiling(conn, user, case_id)
        if not ProposalStore(conn).readable(proposal_id, clearance=clearance,
                                            compartments=held):
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
        labels = ProposalStore(conn).source_labels(row.id)
        try:
            written = accepted_classification(
                row.payload, requested, source=labels.source,
                floor=labels.floor)
        except ProposalError as exc:
            # A label below the capture's, or one that is no label at all:
            # refused before anything is checked or written.
            raise Problem(409, "Conflict", safe_detail(exc)) from exc
        check_writable_labels(conn, user, classification=written)
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
                     permission_key="proposal.review", after_case_gate=True,
                     classification=labels[1],
                     compartments=frozenset(labels[2] or []))
    # And the claim may not land below what it was found in (final review
    # c1, 2026-09-24): the assertion is read at the entity's labels, so a
    # RED, compartmented contact block's identifier accepted onto a CLEAR
    # entity was served to every CLEAR reader of it. After the gate above,
    # so only somebody who may see the entity is told its label.
    problem = attribute_label_problem(
        row.payload, ProposalStore(conn).source_labels(row.id),
        labels[1], labels[2])
    if problem:
        raise Problem(409, "Conflict",
                      f"{problem} Nothing was written: reject or defer it.")


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
    from noctornal_api.extraction import (
        CaptureRefused,
        CaptureService,
        ExtractionError,
    )

    # The label the document will actually be stored at, never below the
    # case, is the one held to the caller's ceiling (final review c15,
    # 2026-09-24); a compartmented case refuses before anything is read.
    try:
        stored = CaptureService(conn).stored_label(case_id, body.classification)
    except CaptureRefused as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except ExtractionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    check_writable_labels(conn, user, classification=stored)
    try:
        result = CaptureService(conn).capture(
            case_id=case_id, text=body.text, title=body.title,
            external_url=body.external_url, author_handle=body.author_handle,
            classification=body.classification,
        )
    except CaptureRefused as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
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
        # At the capture's label, not only the case's (final review u12,
        # 2026-09-24): an owner below it is not told what it raised.
        owner_notified: bool | None = notify_events.proposals_queued(
            conn, case_id=case_id, count=len(result.proposal_ids),
            actor_id=user.user_id, classification=result.classification)
    except Exception:  # noqa: BLE001 - reported in the response, not raised
        log.exception("capture %s was recorded but its notification failed",
                      result.document_id)
        owner_notified = None
    # The labels go back only where the caller may read them (c15
    # follow-up, 2026-09-24). On a re-paste they are the EARLIER capture's
    # as well, and that can sit above this caller: an AMBER analyst
    # re-pasting text first captured at RED was told "RED", the label of a
    # document the collection keeps from them. Null says only that it is
    # above them. The audit row above keeps both, for its own readers.
    reply = result.summary()
    clearance, _held = _reader_ceiling(conn, user, case_id)
    for key in ("classification", "document_classification"):
        if strictest(reply.get(key), clearance) != clearance:
            reply[key] = None
    return {
        **reply,
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
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The triage queue, most confident first. The counts travel with it so
    the interface can show what is waiting without a second round trip.

    Filtered by the reader's clearance against what each proposal came
    from, not only by the case gate (ux08-triage:accept-downgrades-
    classification, 2026-09-23): a rationale quotes the captured text, and
    a RED capture's text was shown to every reader of an AMBER case.

    `pending_by_node` is what the sociogram's proposal ring is drawn from
    (ux08-triage:graph-says-unreviewed-triage-says-nothing): the same
    queue, so the ring and this pane cannot disagree about what waits."""
    from noctornal_api.extraction import CaptureService

    if state not in _STATES:
        raise Problem(400, "Invalid request",
                      f"unknown state {state!r}; one of {', '.join(sorted(_STATES))}")
    clearance, held = _reader_ceiling(conn, user, case_id)
    store = ProposalStore(conn)
    rows = store.queue(case_id, state=state, limit=limit,
                       clearance=clearance, compartments=held)
    named: set[str] = set()
    for p in rows:
        named |= _named_ids(p)
    refs = store.node_refs(case_id, named, clearance=clearance,
                           compartments=held)
    docs = store.documents({p.document_id for p in rows if p.document_id})
    labelled = store.source_labels_many([p.id for p in rows])
    # The labels of the entities ATTRIBUTE claims would land on, for the
    # ones this reader was shown (c1, 2026-09-24): a card whose Accept the
    # server would refuse says so rather than offering it.
    targets = store.entity_labels(case_id, set(refs))
    out = []
    for p in rows:
        labels = labelled[p.id]
        blocked = None
        if p.kind == KIND_ATTRIBUTE:
            target = targets.get(str((p.payload or {}).get("node_id")))
            if target is not None:
                blocked = attribute_label_problem(p.payload, labels, *target)
        out.append(_out(
            p, classification=_display_label(p, labels),
            refs={k: v for k, v in refs.items() if k in _named_ids(p)},
            documents=docs, accept_blocked=blocked))
    return {
        "state": state,
        "counts": store.counts(case_id, clearance=clearance,
                               compartments=held),
        "proposals": out,
        "pending_by_node": store.pending_by_node(
            case_id, clearance=clearance, compartments=held),
        # Why the capture form above this queue is off, or null (final
        # review c15, 2026-09-24): a compartmented case refuses captures,
        # and the case record the console holds does not name its
        # compartments.
        "capture_refused": CaptureService(conn).refusal(case_id),
    }


#: How much of a captured document the source view returns on each side of
#: the match. Enough to read the paragraph a handle sat in; a capture can be
#: a megabyte, and the card is not the place to read all of it.
SOURCE_WINDOW = 1500


@router.get("/{proposal_id}/source", response_model=dict)
def source(
    case_id: UUID, proposal_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The captured text a proposal came from, around the match.

    ux08-triage:source-document-not-reachable (2026-09-23). A card showed
    about ninety characters of context and "found at characters N-M of
    the captured document", with no title and no way to open the capture:
    deciding whether a handle was quoted, signed or real sometimes needs
    the paragraph, and tracing a proposal to its evidence meant leaving
    Triage to search for the document. `collect.document` hangs off a
    source rather than a case, so this is reached THROUGH the proposal:
    the case gate, the proposal's case, and the reader's clearance against
    the proposal's labels, which include the document's. Anything the
    reader may not see is the same 404 a proposal that does not exist
    gets.
    """
    row = _owned(conn, case_id, proposal_id)
    clearance, held = _reader_ceiling(conn, user, case_id)
    store = ProposalStore(conn)
    if not store.readable(proposal_id, clearance=clearance, compartments=held):
        raise Problem(404, "Not found", "no such proposal in this case")
    if row.document_id is None:
        raise Problem(404, "Not found",
                      "this proposal names no captured document; its "
                      "rationale says where it came from")
    doc = conn.execute(
        """SELECT id, title, body_text, classification, captured_at,
                  external_url, purged_at
             FROM collect.document WHERE id = %s""",
        (row.document_id,)).fetchone()
    if doc is None:
        raise Problem(404, "Not found", "the captured document is gone")
    attrs = (row.payload or {}).get("attrs") or {}
    start, end = attrs.get("char_start"), attrs.get("char_end")
    body = doc[2] or ""
    out = {
        "document_id": str(doc[0]), "title": doc[1],
        "classification": doc[3],
        "captured_at": doc[4].isoformat() if doc[4] else None,
        "external_url": doc[5], "purged": doc[6] is not None,
        "length": len(body),
    }
    if doc[6] is not None:
        return {**out, "text": "", "offset": 0, "match": None}
    if (isinstance(start, int) and isinstance(end, int)
            and 0 <= start <= end <= len(body)):
        lo = max(0, start - SOURCE_WINDOW)
        hi = min(len(body), end + SOURCE_WINDOW)
        match = {"start": start - lo, "end": end - lo}
    else:
        lo, hi, match = 0, min(len(body), 2 * SOURCE_WINDOW), None
    return {**out, "text": body[lo:hi], "offset": lo, "match": match}


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
    # A proposal the queue never showed this reader is the same 404 here
    # as on reject and defer, and it is decided FIRST. The material behind
    # the claim counts, not only its target: an ATTRIBUTE is gated below on
    # its entity, and a contact block classified over that entity would
    # otherwise be accepted by someone the queue never showed it to.
    #
    # ux08-triage:accept-downgrades-classification, verifier's fix round
    # (2026-09-23). This check used to run after `_check_accept_labels`
    # and answer 403, so an AMBER reader holding a hidden proposal's id
    # and asking for a label below its capture was told "this proposal
    # came from RED material": the label the queue had kept from them,
    # confirmed by the refusal.
    row = _owned(conn, case_id, proposal_id, user)
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
    _owned(conn, case_id, proposal_id, user)
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
    _owned(conn, case_id, proposal_id, user)
    try:
        return _out(ProposalReview(conn).defer(
            proposal_id, reviewed_by=user.user_id, note=body.note))
    except ProposalError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
