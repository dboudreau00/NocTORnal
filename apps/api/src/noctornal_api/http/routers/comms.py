"""Phase 7 over HTTP: channels, contact blocks, verification, conversations.

The services were built and tested before any of this existed, so the
endpoints are thin. What this file adds is the parts the services cannot
enforce on their own.

## Three things that live here rather than in the services

**The stoplist is split across two routers on purpose.** A GLOBAL entry is
reference data about a forum and needs no case; a CASE entry does. Serving
both from one case-scoped route would let anyone holding the global
permission write into a case they cannot see, and serving both from one
global route would do the reverse. So `/comms/stoplist` writes GLOBAL
entries under a global permission, `/cases/{id}/comms/stoplist` writes
CASE entries under the case gate, and neither can produce the other's
scope.

**Cross-case counts are bounded by the caller's own assignments.**
`shared_service_publishers` and the impersonation query span cases by
design -- that is what makes them useful -- so both take the caller's
visible case ids, resolved HERE from `iam.case_assignment`, never from a
parameter. A caller-supplied case list would be a disclosure oracle: pass
a guessed id, see whether the count moves.

**Verification is metered.** `comms.verify` exists because this is the
only route in the system that forks a subprocess, twice, with a timeout
each.

## What is deliberately absent

There is no endpoint that creates a `comms.channel_binding` from a parsed
contact block. Invariant 3: the parse raises proposals, and proposals are
applied through the existing review path with a human `reviewed_by`. A
"promote this parse" button would be that path with the human removed.
"""
from __future__ import annotations

from datetime import datetime
from functools import lru_cache
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.comms import CommsService, CommsError, coverage_note, normalise
from noctornal_api.contact_blocks import ContactBlockError, ContactBlockService
from noctornal_api.coparticipation import (
    CoParticipationError,
    CoParticipationParams,
    CoParticipationService,
)
from noctornal_api.http.deps import (
    CurrentUser,
    check_writable_labels,
    current_user,
    get_conn,
    require,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.pgp import PgpError, PgpService, verifier_version


@lru_cache(maxsize=1)
def _verifier_version_cached() -> str | None:
    """The gpg version string, resolved once per process.

    `verifier_version()` shells out. It is called to LABEL a listing, not
    to make a decision, and the binary does not change under a running
    process -- so calling it per request bought nothing and handed any
    holder of `comms.read` an unmetered fork.
    """
    return verifier_version()

router = APIRouter(prefix="/cases/{case_id}/comms", tags=["comms"])
#: Not case-scoped: platform reference data and the GLOBAL stoplist.
global_router = APIRouter(prefix="/comms", tags=["comms"])


def _visible_cases(conn: psycopg.Connection, user: CurrentUser,
                   exclude: UUID) -> tuple[UUID, ...]:
    """Cases this caller is assigned to.

    Resolved from the database, never from a request parameter. A
    caller-supplied case list turns any cross-case count into an oracle:
    pass a guessed id and watch whether the number changes.
    """
    rows = conn.execute(
        """SELECT ca.case_id
             FROM iam.case_assignment ca
             JOIN core."case" c ON c.id = ca.case_id
             JOIN iam.app_user u ON u.id = ca.user_id
            WHERE ca.user_id = %s AND ca.case_id <> %s
              AND (ca.expires_at IS NULL OR ca.expires_at > now())
              AND u.is_active
              -- The verb. An assignment under a role that does not hold
              -- comms.read is not "visible" for this purpose.
              AND EXISTS (SELECT 1 FROM iam.role_permission rp
                           WHERE rp.role_key = ca.role_key
                             AND rp.permission_key = 'comms.read')
              -- Clearance and compartments. `assign_user` performs no
              -- clearance check, a case's classification can be raised
              -- after assignment, and a user's clearance can be lowered --
              -- so an assignment to a case the five-part gate would REFUSE
              -- is a reachable state, and `assign_user_checked` exists
              -- because of it. Without these two lines the impersonation
              -- query returned publisher handles and source URLs out of a
              -- case the caller cannot open.
              AND c.classification <= u.tlp_clearance
              AND c.compartments <@ u.compartments""",
        (user.user_id, exclude)).fetchall()
    return tuple(r[0] for r in rows)


# ---------------------------------------------------------------------------
# Platforms -- reference data, and the coverage notes
# ---------------------------------------------------------------------------

@global_router.get("/platforms", response_model=dict)
def platforms(
    _: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every platform, its durable selector type, and what an analyst
    should understand about seeing little or nothing from it.

    The coverage note is surfaced rather than buried because the failure
    it prevents is silent: a SimpleX-using actor looks inactive, and an
    analyst reads inactivity as a finding.
    """
    return {"platforms": CommsService(conn).platforms()}


@global_router.get("/normalise", response_model=dict)
def normalise_preview(
    platform_key: str = Query(...),
    observed: str = Query(...),
    _: CurrentUser = Depends(current_user),
) -> dict:
    """What this identifier reduces to, and why -- WITHOUT storing it.

    Exists so the UI can show an analyst that their 76-hex Tox ID will be
    indexed on its first 64 characters BEFORE they commit to it. The note
    is the product here: "no durable value" with no explanation reads as
    a broken form.
    """
    try:
        result = normalise(platform_key, observed)
    except CommsError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"platform_key": platform_key, "observed": observed,
            "durable_value": result.durable, "note": result.note,
            "coverage": coverage_note(platform_key)}


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------

class BindBody(BaseModel):
    platform_key: str
    observed: str = Field(min_length=1)
    identity_node_id: UUID | None = None
    verification: str = "CLAIMED"
    verification_note: str | None = None
    co_declaration_ref: str | None = None
    classification: str = "AMBER"
    compartments: list[str] = Field(default_factory=list)


@router.post("/bindings", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("capture"))])
def bind(
    case_id: UUID, body: BindBody,
    user: CurrentUser = Depends(require("comms.bind")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record an observed identifier, normalised to its durable part.

    `verification` defaults to CLAIMED because that is what an identifier
    in a signature block IS. OBSERVED means somebody saw it in use.

    **CONFIRMED cannot be set here.** It was accepted from the request
    body with only a free-text `verification_note` required, which made
    every defence in `pgp.py` optional: an analyst who typed "CONFIRMED"
    reached the grade docs/10 says may carry weight in automatic identity
    resolution without a signature existing at all. The one route to
    CONFIRMED is now `/pgp/verify`, where the fingerprint must match the
    claimed key and the identifier must appear inside the signed bytes.
    """
    if body.verification == "CONFIRMED":
        raise Problem(
            400, "Invalid request",
            "CONFIRMED cannot be asserted directly. docs/10: only CONFIRMED "
            "carries weight in automatic identity resolution, so it is "
            "earned by a verified signature over the identifier, not "
            "declared. POST to /pgp/verify with the signed message and the "
            "public key. If the confirmation rests on something other than "
            "a signature -- an observed login, an admin-confirmed vendor "
            "list -- record the binding as OBSERVED and state the basis in "
            "an assertion, which is reviewable in a way a free-text note "
            "is not.")
    compartments = frozenset(body.compartments)
    check_writable_labels(conn, user, classification=body.classification,
                          compartments=compartments)
    try:
        return CommsService(conn).bind(
            case_id=case_id, platform_key=body.platform_key,
            observed=body.observed, created_by=user.user_id,
            identity_node_id=body.identity_node_id,
            verification=body.verification,
            verification_note=body.verification_note,
            co_declaration_ref=body.co_declaration_ref,
            classification=body.classification, compartments=compartments)
    except CommsError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc


@router.get("/correlate", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def correlate(
    case_id: UUID,
    platform_key: str = Query(...),
    observed: str = Query(...),
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every binding sharing this identifier's DURABLE value, in this case.

    Scoped to the case: correlation across cases is the undecided
    disclosure policy (open question 5), and this endpoint is not the
    place to decide it.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        hits = CommsService(conn, clearance=clearance.name,
                            compartments=compartments).correlate(
            platform_key=platform_key, observed=observed, case_id=case_id)
    except CommsError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    result = normalise(platform_key, observed)
    return {"durable_value": result.durable, "note": result.note,
            "matches": hits,
            "scope": "this case only"}


@router.get("/co-declared", response_model=dict)
def co_declared(
    case_id: UUID,
    reference: str = Query(...),
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every identifier published together in one artefact.

    docs/10: the SET is the finding rather than any member of it. A vendor
    running Jabber + Tox + Session with a PGP key operates differently
    from one running a Telegram bot and nothing else.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    return {"reference": reference,
            "identifiers": CommsService(
                conn, clearance=clearance.name, compartments=compartments
            ).co_declared(case_id, reference)}


@router.get("/shared-devices", response_model=dict)
def shared_devices(
    case_id: UUID,
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Device fingerprints seen against more than one identity.

    Reported as a LEAD, never as a merge: the link is between an identity
    and a device, and concluding the identities are one person is an
    attribution that belongs in an ATTRIBUTED_TO edge with a confidence.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    return {"leads": CommsService(
        conn, clearance=clearance.name, compartments=compartments
    ).shared_devices(case_id)}


# ---------------------------------------------------------------------------
# Contact blocks
# ---------------------------------------------------------------------------

class ContactBlockBody(BaseModel):
    raw_text: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    publisher_handle: str | None = None
    publisher_identity_node_id: UUID | None = None
    document_id: UUID | None = None
    evidence_id: UUID | None = None
    classification: str = "AMBER"
    compartments: list[str] = Field(default_factory=list)


@router.post("/contact-blocks", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("capture"))])
def parse_contact_block(
    case_id: UUID, body: ContactBlockBody,
    user: CurrentUser = Depends(require("comms.bind")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Parse a contact block into structured entries and raise proposals.

    Metered under `capture` for the reason that limit exists: this runs
    extraction over pasted text and raises a proposal per new value, so a
    loop floods the triage queue -- an attack on the analyst's attention
    rather than on the server.

    Nothing here becomes a binding. The entries are a reading, the
    proposals go to the existing review queue, and a person applies them.
    """
    compartments = frozenset(body.compartments)
    check_writable_labels(conn, user, classification=body.classification,
                          compartments=compartments)
    try:
        return ContactBlockService(conn).parse_and_store(
            case_id=case_id, raw_text=body.raw_text,
            source_ref=body.source_ref, created_by=user.user_id,
            publisher_handle=body.publisher_handle,
            publisher_identity_node_id=body.publisher_identity_node_id,
            document_id=body.document_id, evidence_id=body.evidence_id,
            classification=body.classification, compartments=compartments,
            visible_case_ids=_visible_cases(conn, user, case_id))
    except ContactBlockError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc


@router.get("/contact-blocks/{block_id}", response_model=dict)
def contact_block(
    case_id: UUID, block_id: UUID,
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    clearance, compartments = user_ceiling(conn, user.user_id)
    # The BLOCK's own labels, not just its case's: a contact block can be
    # classified above its case, and this returns raw_text -- the whole
    # forum post. Answered as 404 either way, because a status code must
    # not be an existence oracle (deps.py rule 2).
    block = ContactBlockService(conn).get(
        block_id, clearance=clearance.name, compartments=compartments)
    if block is None or block["case_id"] != str(case_id):
        raise Problem(404, "Not found", "no such contact block")
    return block


@router.get("/impersonation", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def impersonation(
    case_id: UUID,
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Blocks with the same selector set under different publishers.

    Both readings are returned -- one operator, or one impersonating the
    other -- because the tool cannot tell them apart and the difference
    decides who the victim is.
    """
    # CR5: the caller's own ceiling, threaded in. This used to filter on
    # case_id alone, and a block may be classified above its case.
    ceiling, comps = user_ceiling(conn, user.user_id)
    return {"candidates": ContactBlockService(conn).impersonation_candidates(
        case_id, visible_case_ids=_visible_cases(conn, user, case_id),
        clearance=ceiling.name, compartments=comps)}


# ---------------------------------------------------------------------------
# The stoplist -- two routers, two scopes, neither able to write the other
# ---------------------------------------------------------------------------

class StoplistBody(BaseModel):
    value: str = Field(min_length=1)
    role: str
    platform_key: str | None = None
    selector_type: str | None = None
    service_name: str | None = None
    note: str = ""


class RetireBody(BaseModel):
    reason: str = Field(min_length=1)


@global_router.post("/stoplist", response_model=dict, status_code=201)
def add_global_stoplist_entry(
    body: StoplistBody,
    user: CurrentUser = Depends(require_global("comms.stoplist.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Add a GLOBAL stoplist entry -- a forum's escrow agent, an admin.

    Global because a forum's escrow belongs to the forum. This route
    cannot create a case-scoped entry: doing so from a globally-gated
    endpoint would write into a case the caller may not be able to see.
    """
    try:
        entry_id = ContactBlockService(conn).add_stoplist_entry(
            durable_or_observed=body.value, role=body.role,
            added_by=user.user_id, platform_key=body.platform_key,
            selector_type=body.selector_type, service_name=body.service_name,
            note=body.note)
    except ContactBlockError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {"id": str(entry_id), "scope": "GLOBAL"}


@global_router.post("/stoplist/{entry_id}/retire", response_model=dict)
def retire_global_stoplist_entry(
    entry_id: UUID, body: RetireBody,
    user: CurrentUser = Depends(require_global("comms.stoplist.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Retire, never delete. Parses already cite this row."""
    try:
        ContactBlockService(conn).retire_stoplist_entry(
            entry_id, retired_by=user.user_id, reason=body.reason,
            # GLOBAL only. This route has no case gate, so without the
            # scope predicate a holder of a global role could retire a
            # CASE entry belonging to a case they cannot even read -- and
            # a retired stoplist entry silently stops flagging its escrow.
            scope="GLOBAL")
    except ContactBlockError as exc:
        raise Problem(404, "Not found", str(exc)) from exc
    return {"id": str(entry_id), "retired": True}


@router.get("/stoplist", response_model=dict)
def stoplist(
    case_id: UUID,
    include_retired: bool = Query(False),
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The list as it applies to THIS case: global entries plus its own."""
    return {"entries": ContactBlockService(conn).stoplist(
        case_id=case_id, include_retired=include_retired)}


@router.post("/stoplist", response_model=dict, status_code=201)
def add_case_stoplist_entry(
    case_id: UUID, body: StoplistBody,
    user: CurrentUser = Depends(require("comms.stoplist.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Add a CASE-scoped entry, behind the case gate."""
    try:
        entry_id = ContactBlockService(conn).add_stoplist_entry(
            durable_or_observed=body.value, role=body.role,
            added_by=user.user_id, platform_key=body.platform_key,
            selector_type=body.selector_type, service_name=body.service_name,
            note=body.note, case_id=case_id)
    except ContactBlockError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {"id": str(entry_id), "scope": "CASE"}


# ---------------------------------------------------------------------------
# PGP verification
# ---------------------------------------------------------------------------

class VerifyBody(BaseModel):
    signed_message: str = Field(min_length=1)
    public_key: str = Field(min_length=1)
    claimed_fingerprint: str = Field(min_length=1)
    confirms_value: str | None = None
    channel_binding_id: UUID | None = None
    contact_block_id: UUID | None = None
    note: str | None = None


@router.post("/pgp/verify", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("comms.verify"))])
def verify(
    case_id: UUID, body: VerifyBody,
    user: CurrentUser = Depends(require("comms.bind")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Verify a clearsigned message and record the outcome.

    Every outcome is recorded, including the failures and the one that
    means nobody looked. On VERIFIED -- and only then -- the named binding
    becomes CONFIRMED.
    """
    try:
        return PgpService(conn).verify_and_record(
            case_id=case_id, signed_message=body.signed_message,
            public_key=body.public_key,
            claimed_fingerprint=body.claimed_fingerprint,
            created_by=user.user_id, confirms_value=body.confirms_value,
            channel_binding_id=body.channel_binding_id,
            contact_block_id=body.contact_block_id, note=body.note)
    except PgpError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc


@router.get("/pgp", response_model=dict)
def verifications(
    case_id: UUID,
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    clearance, compartments = user_ceiling(conn, user.user_id)
    return {"verifications": PgpService(conn).verifications(
                case_id, clearance=clearance.name, compartments=compartments),
            # Cached per process. This called gpg --version on EVERY
            # request, so a read endpoint any comms.read holder can reach
            # forked a subprocess per call -- bounded only by the blanket
            # ceiling, which fails OPEN, while the POST that forks for a
            # real reason is capped at 60/hour.
            "verifier": _verifier_version_cached(),
            "notice": (
                "A CONFIRMED binding means a signature by the CLAIMED key "
                "was made over text CONTAINING the identifier. Anything "
                "less is recorded here with its own outcome and confirms "
                "nothing.")}


@router.get("/pgp/unverified", response_model=dict)
def unverified(
    case_id: UUID,
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """CLAIMED bindings, split by whether anyone has tried to confirm them.

    Without the split, "not confirmed" and "not checked" look identical,
    and an analyst reads an unchecked claim as a checked-and-failed one.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    return {"claims": PgpService(conn).unverified_claims(
        case_id, clearance=clearance.name, compartments=compartments)}


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

class ConversationBody(BaseModel):
    platform_key: str
    provenance_class: str
    external_ref: str | None = None
    title: str | None = None
    is_group: bool = False
    collection_account_id: UUID | None = None
    legal_authority: str | None = None
    classification: str = "AMBER"
    compartments: list[str] = Field(default_factory=list)


@router.post("/conversations", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("capture"))])
def open_conversation(
    case_id: UUID, body: ConversationBody,
    user: CurrentUser = Depends(require("comms.bind")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Start a conversation record.

    `provenance_class` is mandatory and the checks around it are the
    point. Capturing a conversation a persona is a PARTY to is legally
    distinct from capturing one it is not (docs/16 L4), so PERSONA_PARTY
    must name the persona and anything obtained another way must carry a
    written authority. The software cannot judge whether the authority is
    good; it refuses to let there be none recorded.
    """
    compartments = frozenset(body.compartments)
    check_writable_labels(conn, user, classification=body.classification,
                          compartments=compartments)
    try:
        conv_id = CommsService(conn).open_conversation(
            case_id=case_id, platform_key=body.platform_key,
            provenance_class=body.provenance_class,
            external_ref=body.external_ref, title=body.title,
            is_group=body.is_group,
            collection_account_id=body.collection_account_id,
            legal_authority=body.legal_authority,
            classification=body.classification, compartments=compartments)
    except CommsError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"id": str(conv_id),
            "notice": ("docs/16 L4 is BLOCKING and unresolved: interception "
                       "law, one-party versus two-party consent, and the "
                       "retention of uninvolved third parties' content in a "
                       "group channel are external determinations. Recording "
                       "the provenance is not the same as having the "
                       "authority for it.")}


@router.get("/contact-graph", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def contact_graph(
    case_id: UUID,
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Who talks to whom, from metadata alone -- which is what survives
    minimisation."""
    clearance, compartments = user_ceiling(conn, user.user_id)
    return {"conversations": CommsService(
        conn, clearance=clearance.name, compartments=compartments
    ).contact_graph(case_id)}


class IncidentalBody(BaseModel):
    handle: str = Field(min_length=1)
    incidental: bool = True


@router.post("/conversations/{conversation_id}/incidental",
             response_model=dict)
def mark_incidental(
    case_id: UUID, conversation_id: UUID, body: IncidentalBody,
    user: CurrentUser = Depends(require("comms.bind")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Flag a participant as not a subject.

    docs/08 and docs/16 L4: a third party in a group channel has rights,
    and minimisation at closure has to be able to find them. Flagging is
    cheap; discovering afterwards that nobody did is not.
    """
    _own_conversation(conn, case_id, conversation_id)
    CommsService(conn).mark_incidental(conversation_id, body.handle,
                                       incidental=body.incidental)
    return {"conversation_id": str(conversation_id), "handle": body.handle,
            "is_incidental": body.incidental}


class MinimiseBody(BaseModel):
    authority: str = Field(min_length=1)


@router.post("/conversations/{conversation_id}/minimise", response_model=dict)
def minimise(
    case_id: UUID, conversation_id: UUID, body: MinimiseBody,
    user: CurrentUser = Depends(require("comms.minimise")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Drop message BODIES, keep the metadata graph.

    Irreversible, which is why `comms.minimise` is step-up gated in the
    permission seed -- irreversible is irreversible whichever direction it
    protects in. The conversation, its participants and its timing all
    survive, so the contact graph and the co-participation projection are
    unaffected.
    """
    _own_conversation(conn, case_id, conversation_id)
    try:
        dropped = CommsService(conn).minimise(
            conversation_id, actor_id=user.user_id, authority=body.authority)
    except CommsError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"conversation_id": str(conversation_id), "bodies_dropped": dropped,
            "retained": "participants, timing and the contact graph"}


def _own_conversation(conn: psycopg.Connection, case_id: UUID,
                      conversation_id: UUID) -> None:
    """Refuse a conversation belonging to another case.

    The case gate authorises the caller against `case_id` from the path;
    without this, a conversation id from a DIFFERENT case would be
    accepted and minimised under an authorisation that never covered it.
    """
    row = conn.execute(
        "SELECT case_id FROM comms.conversation WHERE id = %s",
        (conversation_id,)).fetchone()
    if row is None or row[0] != case_id:
        raise Problem(404, "Not found", "no such conversation in this case")


# ---------------------------------------------------------------------------
# Co-participation
# ---------------------------------------------------------------------------

@router.get("/co-participation", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def co_participation(
    case_id: UUID,
    min_shared: int = Query(1, ge=1),
    max_room_size: int = Query(50, ge=2, le=500),
    include_incidental: bool = Query(False),
    include_unresolved: bool = Query(False),
    weighting: str = Query("NEWMAN"),
    provenance_class: list[str] = Query(default_factory=list),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    user: CurrentUser = Depends(require("comms.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The bipartite conversation graph projected to one mode.

    Newman weighting by default, so a large channel cannot manufacture a
    clique. Every exclusion is reported in `coverage` rather than applied
    silently: an analyst who cannot tell a sparse network from a filtered
    one draws confident conclusions from an incomplete picture.

    The edges are marked `is_inferred`. Two people in the same room have
    not been observed talking to each other, and invariant 4 exists
    because that distinction has to survive.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        return CoParticipationService(
            conn, clearance=clearance.name, compartments=compartments
        ).project(CoParticipationParams(
            case_id=case_id, min_shared=min_shared,
            max_room_size=max_room_size,
            include_incidental=include_incidental,
            include_unresolved=include_unresolved, weighting=weighting,
            provenance_classes=tuple(provenance_class),
            since=since, until=until))
    except CoParticipationError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
