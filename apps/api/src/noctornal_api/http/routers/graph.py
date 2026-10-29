"""Graph write endpoints: every create goes through GraphWriteService, so an assertion is
written in the same transaction (invariant 1).

Three ways take something out of the live graph, and they are not interchangeable: retracting an
assertion (the element goes only if that was its last live support), retiring the element
(`DELETE`, a soft delete that sets `deleted_at` and hides it from every as-of view too), and
`valid_to`, set by a correction (it stopped being true in the world, so an as-of query into its
period still shows it). None destroys a row (invariant 5).
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.graph import (
    KEEP,
    REVIEW_STATES,
    AssertionInput,
    ClaimNotDatable,
    GraphWriteError,
    GraphWriteService,
    TieConfidenceConflict,
    TieReviewUnchanged,
    hidden_ties_refusal,
)
from noctornal_api.http.deps import (
    CurrentUser,
    check_writable_labels,
    element_labels,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.element_gate import authorize_element, gate_element
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.selectors import (
    CREDENTIAL_REFUSAL,
    SelectorStore,
    carries_credential,
)
from noctornal_api.wording import count_of
from noctornal_ontology import SELECTOR_TYPES, normalise, refusal

router = APIRouter(prefix="/cases/{case_id}", tags=["graph"])


class AssertionBody(BaseModel):
    """The claim a write records, and its grading.

    The four grading fields are required and never defaulted: a grade nobody chose cannot later be
    told from a considered one, and ACH and the confidence filter act on it. The values are checked
    by the database enums.
    """
    basis: str
    reliability: str
    credibility: str
    confidence: str
    rationale: str | None = None
    # E1: an assertion can carry its exhibit at the moment the claim is
    # made. The column has always existed; nothing in the UI used it, which
    # is how a case ends up with fourteen assertions and no evidence.
    evidence_id: UUID | None = None
    external_ref: str | None = None
    observed_at: datetime | None = None


class CreateNodeBody(BaseModel):
    node_type: str
    label: str
    classification: str = "AMBER"
    attrs: dict = {}
    # Required, with its grading: see AssertionBody.
    assertion: AssertionBody
    # U3: the interval this was true in WORLD time. "Was in LockBit until
    # March" is the normal case, not the exception, and the timeline
    # scrubber and trust decay both have nothing to work with without it.
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    # What kind of selector the label is, for a SELECTOR, COMMS_ACCOUNT or WALLET entity. Given, the
    # label is normalised (refused when it reduces to nothing) and recorded in the selector index
    # against the new entity in the same transaction (`create_node`).
    selector_type: str | None = Field(default=None, max_length=64)


class CreateEdgeBody(BaseModel):
    """A new tie and the assertion it rests on.

    The tie's confidence is `assertion.confidence` and nothing else (migration 0064). `confidence`
    is declared at the top level only so a client that sends it there is told, rather than having
    it silently dropped as pydantic drops an unknown field.
    """
    edge_type: str
    src_node_id: UUID
    dst_node_id: UUID
    classification: str = "AMBER"
    # Required, with its grading: see AssertionBody.
    assertion: AssertionBody
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    confidence: str | None = None


class AddAssertionBody(AssertionBody):
    """Another assertion on an existing element. This is how disagreement
    is represented without forcing consensus (docs/01): two analysts, two
    claims, both recorded."""


class RetractBody(BaseModel):
    reason: str = Field(min_length=1)


class SupersedeBody(BaseModel):
    """The date a claim never had, and why that date.

    Nothing else is sent: the replacing claim is the old one in every other
    column (`GraphWriteService.supersede_assertion`), so a request cannot
    regrade, rebase or re-aim a claim under cover of dating it."""
    observed_at: datetime
    rationale: str = Field(min_length=1)


class SupersedeOut(BaseModel):
    """The new claim, and the old one it replaces."""
    id: str
    supersedes: str


class IdOut(BaseModel):
    id: str


def _assertion(body: AssertionBody, created_by: UUID, *,
               claim_path: str | None = None,
               claim_value: dict | None = None) -> AssertionInput:
    """Build the AssertionInput a write is grounded in (invariant 1).

    `claim_path` / `claim_value` default to None so the create endpoints
    below are unaffected: a create's claim IS the element, and the element
    row holds it. The CORRECTION endpoints do pass them, because there the
    claim is "this field is now X" and the element row is about to be
    overwritten — see `_audit_change`.
    """
    return AssertionInput(
        basis=body.basis, created_by=created_by, reliability=body.reliability,
        credibility=body.credibility, confidence=body.confidence,
        rationale=body.rationale, evidence_id=body.evidence_id,
        external_ref=body.external_ref, observed_at=body.observed_at,
        claim_path=claim_path, claim_value=claim_value,
    )


def _interval_sane(valid_from: datetime | None, valid_to: datetime | None) -> None:
    if valid_from and valid_to and valid_to < valid_from:
        raise Problem(400, "Invalid request",
                      "valid_to is before valid_from")


def _check_evidence(conn: psycopg.Connection, case_id: UUID,
                    evidence_id: UUID | None) -> None:
    """An exhibit may only support a claim in ITS OWN case. Without this a
    caller could cite an exhibit from a case they have no access to, and the
    assertion would then display a title and hash they were never cleared
    to see."""
    if evidence_id is None:
        return
    row = conn.execute(
        "SELECT 1 FROM core.evidence WHERE id = %s AND case_id = %s",
        (evidence_id, case_id),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such exhibit in this case")


class NodeCreatedOut(IdOut):
    """A new entity, and what became of its selector when it had one.

    `selector_owner_id` is set when the selector is already recorded against another entity the
    caller can see; the earlier entity keeps its row (re-attribution is never a side effect), and
    the two are a merge lead. The new entity has its own row at its own labels (migration 0134), and
    an entity above the caller is never named, so a value held above them reads as held nowhere."""
    selector_norm: str | None = None
    selector_owner_id: str | None = None
    selector_is_strong: bool | None = None


@router.post("/nodes", response_model=NodeCreatedOut, status_code=201)
def create_node(case_id: UUID, body: CreateNodeBody,
                user: CurrentUser = Depends(require("graph.node.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> NodeCreatedOut:
    check_writable_labels(conn, user, classification=body.classification)
    _check_evidence(conn, case_id, body.assertion.evidence_id)
    _interval_sane(body.valid_from, body.valid_to)
    selector = _selector_for(body.node_type, body.selector_type, body.label)

    def write() -> UUID:
        return GraphWriteService(conn).create_node(
            case_id=case_id, node_type=body.node_type, label=body.label,
            created_by=user.user_id,
            assertion=_assertion(body.assertion, user.user_id),
            attrs=body.attrs, classification=body.classification,
            valid_from=body.valid_from, valid_to=body.valid_to,
        )

    if selector is None:
        return NodeCreatedOut(id=str(write()))
    # One transaction, so an entity whose selector could not be recorded does not exist either. The
    # index is observation bookkeeping, not a graph element (selectors.py), so it needs no second
    # assertion: the entity's founding claim is the observation and dates the selector. The index
    # is keyed by labels, so a value held by an entity above the creator is neither counted,
    # attributed nor told of; the earlier holder named is one the creator may read.
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    store = SelectorStore(conn)
    with conn.transaction():
        node_id = write()
        _row, norm = store.record_for_reader(
            case_id=case_id, selector_type=selector.key,
            raw_value=body.label, node_id=node_id,
            observed_at=body.assertion.observed_at,
            clearance=clearance.name, compartments=held)
    out = NodeCreatedOut(id=str(node_id), selector_norm=norm,
                         selector_is_strong=selector.is_strong)
    holder = store.other_holder(
        case_id=case_id, selector_type=selector.key, raw_value=body.label,
        excluding=node_id, clearance=clearance.name, compartments=held)
    if holder is not None:
        out.selector_owner_id = str(holder)
    return out


# --- before an entity is created: is it already here? ---------------------
# The form asks as the label is typed: a near-duplicate persona splits an actor's ties and degree,
# and the cheapest merge is the one never needed (docs/01).

#: Entity types whose label IS a selector value.
SELECTOR_NODE_TYPES = frozenset({"SELECTOR", "COMMS_ACCOUNT", "WALLET"})
_SELECTOR_TYPES = {s.key: s for s in SELECTOR_TYPES}
#: The most same-label matches returned: ten look-alikes already make the point, and the check is
#: a warning, not a search.
CHECK_MATCHES_MAX = 10


def _selector_for(node_type: str, selector_type: str | None, label: str):
    """The selector type a create names, validated, or None. Refused with
    the ontology's own reason when the label reduces to nothing, which is
    the rule `SelectorStore` enforces on every other path in."""
    if selector_type is None:
        return None
    if node_type not in SELECTOR_NODE_TYPES:
        raise Problem(400, "Invalid request",
                      "selector_type is for a Selector, Comms account or "
                      "Crypto wallet entity, whose label is the selector")
    st = _SELECTOR_TYPES.get(selector_type)
    if st is None:
        raise Problem(400, "Invalid request",
                      f"unknown selector type {selector_type!r}")
    if not normalise(st.key, label).strip():
        raise Problem(400, "Invalid request", refusal(st.key, label))
    # A link's password or token would otherwise become the entity's label, on the graph and in
    # reports.
    if carries_credential(st.key, label):
        raise Problem(400, "Invalid request", CREDENTIAL_REFUSAL)
    return st


def _node_visible(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
                  node_id: UUID) -> bool:
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    return conn.execute(
        """SELECT 1 FROM core.node
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (node_id, case_id, clearance.name, list(compartments)),
    ).fetchone() is not None


@router.get("/graph/nodes/count", response_model=dict)
def count_nodes(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """How many live entities of this case the caller can see, the rows `GET /nodes` lists without
    the page, and in `edges` the ties `GET /edges` lists (both ends visible, inferred ties
    included). Counting only what the caller can see keeps it from measuring what they cannot."""
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    ceiling = (clearance.name, list(compartments))
    total = conn.execute(
        """SELECT count(*) FROM core.node
            WHERE case_id = %s AND deleted_at IS NULL AND merged_into_id IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (case_id, *ceiling),
    ).fetchone()[0]
    edges = conn.execute(
        """SELECT count(*)
             FROM core.edge e
             JOIN core.node s ON s.id = e.src_node_id
             JOIN core.node d ON d.id = e.dst_node_id
            WHERE e.case_id = %s AND e.deleted_at IS NULL
              AND e.classification <= %s::core.tlp AND e.compartments <@ %s
              AND s.deleted_at IS NULL AND d.deleted_at IS NULL
              AND s.classification <= %s::core.tlp AND s.compartments <@ %s
              AND d.classification <= %s::core.tlp AND d.compartments <@ %s""",
        (case_id, *ceiling, *ceiling, *ceiling),
    ).fetchone()[0]
    return {"total": total, "edges": edges}


class NodeCheckBody(BaseModel):
    """What the Add entity form holds so far. POST, not GET, so a label,
    which is case content (a forum handle, a wallet), never rides in a URL
    into an access log."""
    node_type: str = Field(max_length=64)
    label: str = Field(max_length=2000)
    selector_type: str | None = Field(default=None, max_length=64)


class NodeMatchOut(BaseModel):
    id: str
    label: str
    node_type: str


class NodeCheckOut(BaseModel):
    #: Live entities of the same type whose label matches once case and
    #: runs of whitespace are folded, newest first.
    same_label: list[NodeMatchOut]
    #: The canonical form the selector index will hold, or None.
    selector_norm: str | None = None
    #: Why the label cannot be a selector of that type, or None.
    selector_refusal: str | None = None
    selector_is_strong: bool | None = None
    #: The entity this selector is already recorded against, when the
    #: caller can see it.
    selector_owner: NodeMatchOut | None = None


@router.post("/graph/nodes/check", response_model=NodeCheckOut)
def check_new_node(
    case_id: UUID, body: NodeCheckBody,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> NodeCheckOut:
    """Is the entity about to be created already in this case?

    Reads only what the caller may see, filtered by their ceiling as the entity list is. Case and
    runs of whitespace are folded; anything looser (edit distance, homoglyphs) would flood the form
    with false leads. A selector label is also normalised as the index holds it, and the index is
    asked who already owns that value.
    """
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    label = body.label.strip()
    out = NodeCheckOut(same_label=[])
    if label:
        rows = conn.execute(
            """SELECT id, label, node_type FROM core.node
                WHERE case_id = %s AND node_type = %s
                  AND deleted_at IS NULL AND merged_into_id IS NULL
                  AND classification <= %s::core.tlp AND compartments <@ %s
                  AND lower(regexp_replace(btrim(label), '\\s+', ' ', 'g'))
                      = lower(regexp_replace(btrim(%s), '\\s+', ' ', 'g'))
                ORDER BY created_at DESC LIMIT %s""",
            (case_id, body.node_type, clearance.name, list(compartments),
             label, CHECK_MATCHES_MAX),
        ).fetchall()
        out.same_label = [NodeMatchOut(id=str(r[0]), label=r[1], node_type=r[2])
                          for r in rows]
    if (body.selector_type is None or body.node_type not in SELECTOR_NODE_TYPES
            or not label):
        return out
    st = _SELECTOR_TYPES.get(body.selector_type)
    if st is None:
        raise Problem(400, "Invalid request",
                      f"unknown selector type {body.selector_type!r}")
    out.selector_is_strong = st.is_strong
    norm = normalise(st.key, label)
    if not norm.strip():
        out.selector_refusal = refusal(st.key, label)
        return out
    if carries_credential(st.key, label):
        # The form says before Create what create refuses.
        out.selector_refusal = CREDENTIAL_REFUSAL
        return out
    out.selector_norm = norm
    owner = conn.execute(
        """SELECT n.id, n.label, n.node_type
             FROM core.selector s JOIN core.node n ON n.id = s.node_id
            WHERE s.case_id = %s AND s.selector_type = %s AND s.norm_value = %s
              AND n.deleted_at IS NULL
              AND n.classification <= %s::core.tlp AND n.compartments <@ %s
            ORDER BY s.classification DESC, cardinality(s.compartments) DESC,
                     s.created_at, s.id
            LIMIT 1""",
        # One row per value and labels since 0134: the strictest holder the
        # caller may read answers, the same one on every call.
        (case_id, st.key, norm, clearance.name, list(compartments)),
    ).fetchone()
    if owner is not None:
        out.selector_owner = NodeMatchOut(id=str(owner[0]), label=owner[1],
                                          node_type=owner[2])
    return out


@router.post("/edges", response_model=IdOut, status_code=201)
def create_edge(case_id: UUID, body: CreateEdgeBody,
                user: CurrentUser = Depends(require("graph.edge.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
    if body.confidence is not None:
        # A malformed body, so refused before anything is read from the
        # database, and naming the field to use instead. See CreateEdgeBody.
        raise Problem(400, "Invalid request",
                      "a tie's confidence is the grade of the assertion it "
                      "rests on: send it as assertion.confidence, not as a "
                      "top-level confidence")
    check_writable_labels(conn, user, classification=body.classification)
    _check_evidence(conn, case_id, body.assertion.evidence_id)
    _interval_sane(body.valid_from, body.valid_to)
    _gate_endpoints(conn, user, case_id, (body.src_node_id, body.dst_node_id))
    edge_id = GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type=body.edge_type, src_node_id=body.src_node_id,
        dst_node_id=body.dst_node_id, created_by=user.user_id,
        assertion=_assertion(body.assertion, user.user_id),
        classification=body.classification,
        valid_from=body.valid_from, valid_to=body.valid_to,
    )
    return IdOut(id=str(edge_id))


def _gate_endpoints(conn: psycopg.Connection, user: CurrentUser,
                    case_id: UUID, node_ids) -> None:
    """A new tie's two entities, at their own labels, then live.

    Each endpoint passes the gate at its own labels, with one 404 for an entity that is missing, in
    another case or above the caller; the tie's own label is not enough. A tie to a merged-away or
    retired entity is refused, since it would be drawn nowhere and would break the merge's reversal.
    That refusal comes after the gate, so the state is told only to a caller cleared for the entity,
    and the survivor is named only when it is theirs to see too."""
    for node_id in node_ids:
        gate_element(conn, user, case_id=case_id, kind="node",
                     element_id=node_id, permission_key="graph.edge.create",
                     missing_detail="no such node in this case")
    for node_id in node_ids:
        row = conn.execute(
            "SELECT deleted_at, merged_into_id FROM core.node WHERE id = %s",
            (node_id,)).fetchone()
        if row is None:
            raise Problem(404, "Not found", "no such node in this case")
        if row[1] is not None:
            survivor = (f" ({row[1]})" if _node_visible(conn, user, case_id, row[1])
                        else "")
            raise Problem(409, "Conflict",
                          f"that entity was merged into another{survivor}; tie "
                          f"the surviving entity instead")
        if row[0] is not None:
            raise Problem(409, "Conflict",
                          "that entity was retired; a retired entity takes no "
                          "new ties")


# --- assertions on an existing element ----------------------------------


def _element_labels(conn: psycopg.Connection, table: str,
                    element_id: UUID) -> tuple[UUID, str, frozenset[str]] | None:
    """The element's case and its own labels, for the gate.

    An element is protected by both its own labels and its case's (`deps.py` rule 1). This matters
    most on assertion writes: retracting an element's last live assertion dissolves it from every
    analyst's graph, so a caller not cleared to see a RED node must not be able to retract its
    claims.
    """
    if table not in ("node", "edge"):  # not `assert`: stripped under python -O, and this guards SQL text
        raise ValueError("refused identifier outside the allow-list")
    # The element's case and labels as facts (`deps.element_labels`), so the gate still writes its
    # AUTHZ_DENIED row for an element above the caller's labels rather than row-level security
    # giving a silent 404; the answer is the missing element's 404. Content is read after the gate.
    return element_labels(conn, table, element_id)


def _gate_tie_endpoints(conn: psycopg.Connection, user: CurrentUser,
                        case_id: UUID, edge_id: UUID,
                        permission_key: str) -> None:
    """A write on a tie is gated at its two entities' labels as well as its own.

    The projection draws a tie only when both ends are visible, so its own label alone would let a
    reader who cannot see it correct, review or retire it. The refusal is the tie's own: the missing
    tie's 404, with the AUTHZ_DENIED row kept."""
    ends = conn.execute(
        "SELECT src_node_id, dst_node_id FROM core.edge WHERE id = %s",
        (edge_id,)).fetchone()
    for node_id in ends or ():
        facts = element_labels(conn, "node", node_id)
        if facts is not None:
            authorize_element(conn, user, case_id=case_id,
                              permission_key=permission_key,
                              classification=facts[1], compartments=facts[2],
                              missing_detail="no such edge in this case")


def _add_assertion(conn, user, case_id, body, *, node_id=None, edge_id=None) -> IdOut:
    table = "node" if node_id else "edge"
    found = _element_labels(conn, table, node_id or edge_id)
    # The path's case_id is the one the gate authorised, so an element from
    # another case must not be reachable through it.
    if found is None or found[0] != case_id:
        raise Problem(404, "Not found", f"no such {table} in this case")
    # Re-authorise against the element's labels, not just the case's: a RED node can live in an
    # AMBER case, and asserting about it is a write against the node. This second gate counts a
    # break-glass use only if the route's did not. A refusal is the missing element's 404, its
    # AUTHZ_DENIED row kept.
    authorize_element(conn, user, case_id=case_id,
                      permission_key="assertion.create",
                      classification=found[1], compartments=found[2],
                      missing_detail=f"no such {table} in this case")
    if edge_id is not None:
        _gate_tie_endpoints(conn, user, case_id, edge_id, "assertion.create")
    _check_evidence(conn, case_id, body.evidence_id)
    try:
        aid = GraphWriteService(conn).add_assertion(
            case_id=case_id, assertion=_assertion(body, user.user_id),
            node_id=node_id, edge_id=edge_id,
        )
    except GraphWriteError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return IdOut(id=str(aid))


@router.post("/nodes/{node_id}/assertions", response_model=IdOut, status_code=201)
def add_node_assertion(
    case_id: UUID, node_id: UUID, body: AddAssertionBody,
    user: CurrentUser = Depends(require("assertion.create")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IdOut:
    """Attach another claim — typically one carrying an exhibit — to an
    entity that already exists."""
    return _add_assertion(conn, user, case_id, body, node_id=node_id)


@router.post("/edges/{edge_id}/assertions", response_model=IdOut, status_code=201)
def add_edge_assertion(
    case_id: UUID, edge_id: UUID, body: AddAssertionBody,
    user: CurrentUser = Depends(require("assertion.create")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IdOut:
    return _add_assertion(conn, user, case_id, body, edge_id=edge_id)


@router.post("/assertions/{assertion_id}/retract", status_code=204)
def retract_assertion(
    case_id: UUID, assertion_id: UUID, body: RetractBody,
    user: CurrentUser = Depends(require("assertion.retract")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Retract a claim. The row is preserved and stamped, never deleted (invariant 5).

    An element whose last live assertion is retracted disappears from the projection with its
    edges, at every as-of position including those before the retraction, since the live-provenance
    leg (`retracted_at IS NULL AND superseded_at IS NULL`) has no as-of term.
    """
    from fastapi import Response
    # The element's case and labels as facts (`deps.element_labels`), so the gate still writes its
    # AUTHZ_DENIED row for an element above the caller's labels rather than row-level security
    # giving a silent 404; the answer is the missing element's 404. Content is read after the gate.
    subject = element_labels(conn, "assertion", assertion_id)
    if subject is None or subject[0] != case_id:
        raise Problem(404, "Not found", "no such assertion in this case")
    # The element's own labels gate the retraction (the assertion's facts are its subject's
    # labels): retracting the last live assertion dissolves the element from every projection, so a
    # caller must be able to see what they destroy. A refusal is the missing claim's 404, its
    # AUTHZ_DENIED row kept.
    if subject is not None:
        authorize_element(conn, user, case_id=case_id,
                          permission_key="assertion.retract",
                          classification=subject[1], compartments=subject[2],
                          missing_detail="no such assertion in this case")
    try:
        restoration = GraphWriteService(conn).retract_assertion(
            assertion_id, retracted_by=user.user_id, reason=body.reason,
            at=datetime.now(timezone.utc),
        )
    except GraphWriteError as exc:
        # Already retracted, or gone. Saying so is better than a silent
        # 204 that leaves a burned source live in the projection.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    # A retracted correction gives its fields back to the values the live claims support; the audit
    # row names them, and any whose value before the first correction was never recorded. The
    # values themselves are in the claims.
    detail = {"reason": body.reason}
    if restoration and restoration.restored:
        detail["restored"] = list(restoration.restored)
    if restoration and restoration.unknown:
        detail["not_restored"] = list(restoration.unknown)
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, 'USER', 'ASSERTION_RETRACTED', 'assertion', %s, %s, %s)""",
        (user.user_id, assertion_id, case_id, Json(detail)),
    )
    return Response(status_code=204)


@router.post("/assertions/{assertion_id}/supersede", response_model=SupersedeOut,
             status_code=201)
def supersede_assertion(
    case_id: UUID, assertion_id: UUID, body: SupersedeBody,
    user: CurrentUser = Depends(require("assertion.retract")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SupersedeOut:
    """Date a live claim that has none, by supersession (docs/00 open question 11).

    Older claims accepted from Triage carry no date, and invariant 5 forbids writing onto the old
    row, so this records a new claim carrying the date and rationale, citing the old one
    (`supersedes_id`) at the same grade on the same element and material, and stamps the old one
    superseded in the same transaction. A dated claim is corrected by a retraction and a new claim
    instead. Gated on `assertion.retract` and `assertion.create` at the element's labels; the state
    refusals come after the gates, so a caller who may not see the claim is told nothing about it.
    """
    subject = element_labels(conn, "assertion", assertion_id)
    if subject is None or subject[0] != case_id:
        raise Problem(404, "Not found", "no such assertion in this case")
    # A refusal at the claim's labels is the missing claim's 404, its AUTHZ_DENIED row kept. The
    # route's gate names assertion.retract only, so assertion.create is first asked at the case's
    # labels, and a caller without it still gets the gate's 403.
    for permission in ("assertion.retract", "assertion.create"):
        authorize_element(conn, user, case_id=case_id, permission_key=permission,
                          classification=subject[1], compartments=subject[2],
                          missing_detail="no such assertion in this case",
                          case_gated=permission == "assertion.retract")
    # An offset is required, as `expires_at` on a grant requires one: a
    # naive time would be read in the database's zone, and this is the
    # instant First seen and Last seen are drawn from.
    if body.observed_at.utcoffset() is None:
        raise Problem(
            400, "Invalid request",
            "observed_at has no UTC offset. It is the moment the claim was "
            "true, so it is not guessed: send an offset-aware timestamp such "
            "as 2026-03-01T22:30:00Z.")
    if body.observed_at > datetime.now(timezone.utc):
        raise Problem(400, "Invalid request",
                      "observed_at is in the future: a claim cannot have been "
                      "observed later than now")
    try:
        # One transaction, so a claim is never superseded without its audit row, and never audited
        # without being superseded.
        with conn.transaction():
            new_id = GraphWriteService(conn).supersede_assertion(
                assertion_id, case_id=case_id, observed_at=body.observed_at,
                rationale=body.rationale, created_by=user.user_id)
            conn.execute(
                """INSERT INTO audit.event
                       (actor_id, actor_kind, action, object_type, object_id,
                        case_id, detail)
                   VALUES (%s, 'USER', 'ASSERTION_SUPERSEDED', 'assertion',
                           %s, %s, %s)""",
                (user.user_id, assertion_id, case_id,
                 Json({"superseded_by": str(new_id),
                       "observed_at": body.observed_at.isoformat()})))
    except ClaimNotDatable as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except GraphWriteError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return SupersedeOut(id=str(new_id), supersedes=str(assertion_id))


# --- corrections and retirements ----------------------------------------
# The HTTP face of the "correcting and retiring" block in `graph.py`, which explains why every
# correction carries an assertion and why classification, compartments, `sign` and `edge_type`
# are not editable here. Enforced here rather than in the service, as authorisation and HTTP
# concerns: same-case verification of the element id before it is used (404, not 403, so it is no
# existence oracle); the element's own labels as well as the case's; and element state (retired,
# merged away), checked after the gate so it is no state oracle. One permission each: a
# correction's assertion is part of the correction (invariant 1), so it is not also gated on
# `assertion.create`.

#: Columns each change endpoint reads before the write: the values the UPDATE is about to overwrite
#: (for `_audit_change`) plus, for a node, the merge redirect. Literal per table and checked against
#: these keys, so nothing client-supplied reaches the f-string.
_BEFORE_COLUMNS = {
    "node": "label, attrs, merged_into_id",
    "edge": "weight, confidence, attrs",
}


def _gate_for_change(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID, table: str,
    element_id: UUID, permission_key: str,
) -> tuple:
    """Same-case check, then the element-label gate, then the not-retired check; returns the
    element's current values.

    The order is the point: an element from another case gets the same 404 as a missing one, so ids
    cannot be enumerated; only then do the element's own labels reach the gate; and the retired
    check comes after the gate so it leaks no state. Call this outside the write transaction: a
    denial appends an AUTHZ_DENIED row and raises, and inside the transaction that row would roll
    back. The cost is a TOCTOU window, where the service's `deleted_at IS NULL` clause gives a 400
    instead of this 409.
    """
    if table not in _BEFORE_COLUMNS:  # not `assert`: stripped under python -O, and this guards SQL text
        raise ValueError("refused identifier outside the allow-list")
    # The element's case and labels as facts (`deps.element_labels`), so the gate still writes its
    # AUTHZ_DENIED row for an element above the caller's labels rather than row-level security
    # giving a silent 404; the answer is the missing element's 404. Content is read after the gate.
    facts = element_labels(conn, table, element_id)
    if facts is None or facts[0] != case_id:
        raise Problem(404, "Not found", f"no such {table} in this case")
    # A refusal at the element's labels is the missing element's 404, its AUTHZ_DENIED row kept: a
    # 403 would tell a caller holding a leaked id that it names something in the case.
    authorize_element(conn, user, case_id=case_id,
                      permission_key=permission_key,
                      classification=facts[1], compartments=facts[2],
                      missing_detail=f"no such {table} in this case")
    if table == "edge":
        _gate_tie_endpoints(conn, user, case_id, element_id, permission_key)
    row = conn.execute(
        f"SELECT case_id, classification, compartments, deleted_at, "
        f"       {_BEFORE_COLUMNS[table]} "
        f"  FROM core.{table} WHERE id = %s",
        (element_id,),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", f"no such {table} in this case")
    if row[3] is not None:
        # 409, not 404: the caller is cleared for this element and it does
        # exist. Saying "already retired" is the useful answer and reveals
        # nothing they could not already read.
        raise Problem(409, "Conflict",
                      f"this {table} was retired at {row[3].isoformat()}; a "
                      f"retired element is not edited or retired again")
    return tuple(row[4:])


def _audit_change(conn: psycopg.Connection, user: CurrentUser, case_id: UUID, *,
                  action: str, object_type: str, object_id: UUID,
                  detail: dict) -> None:
    """Append the change to the audit log, carrying the overwritten values.

    `update_node` and `update_edge` overwrite columns in place; the new value is in the
    correction's assertion, but the old one survives only here, so for these columns this row is
    the superseded history (invariant 5). `audit.event` is append-only and hash-chained, and
    `/audit` never returns `detail`, so case content here widens no global role's view. Called
    inside the caller's transaction, so a change cannot commit without its audit row. Nesting is
    safe: migration 0022's deferred triggers fire on INSERT into core.node and core.edge and on
    DELETE or UPDATE of an assertion's node_id or edge_id, none of which these paths do.
    """
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id,
                detail)
           VALUES (%s, 'USER', %s, %s, %s, %s, %s)""",
        (user.user_id, action, object_type, object_id, case_id, Json(detail)),
    )


def _claim_path(changed: dict) -> str | None:
    """A single changed field names itself ('label', 'weight'); a
    multi-field correction has no one path, and inventing a composite
    ('label,attrs') would put a string in the column that nothing can
    query. `claim_value` carries every changed field either way."""
    return next(iter(changed)) if len(changed) == 1 else None


def _valid_to_given(body: BaseModel):
    """The end date a correction sets: KEEP when the body leaves it out, None when it sends null
    (the end date is cleared), else the time. An offset is required, as for a supersession's date:
    a naive time would be read in the database's zone, and the as-of view and trust decay are drawn
    from this instant."""
    if "valid_to" not in body.model_fields_set:
        return KEEP
    end = body.valid_to
    if end is not None and end.utcoffset() is None:
        raise Problem(
            400, "Invalid request",
            "valid_to has no UTC offset. It is the moment this stopped being "
            "true, so it is not guessed: send an offset-aware timestamp such "
            "as 2026-03-01T00:00:00Z.")
    return end


def _previous_valid_to(conn: psycopg.Connection, table: str,
                       element_id: UUID) -> str | None:
    """The end date a correction is about to replace, for its audit row."""
    if table not in ("node", "edge"):  # not `assert`: stripped under python -O, and this guards SQL text
        raise ValueError("refused identifier outside the allow-list")
    row = conn.execute(f"SELECT valid_to FROM core.{table} WHERE id = %s",
                       (element_id,)).fetchone()
    return row[0].isoformat() if row and row[0] is not None else None


class UpdateNodeBody(BaseModel):
    """A correction to a node, with the assertion that justifies it.

    `attrs` overwrites the whole attribute object, not a merge, whatever the verb suggests:
    `{"attrs": {}}` clears every attribute, and omitting the field leaves them untouched
    (`COALESCE(%s, attrs)` in the service).
    """
    label: str | None = None
    attrs: dict | None = None
    # When the entity stopped being true in the world: a correction like any other, so the as-of
    # view keeps the past and nothing is retired. Null clears the end date; omitted, it is kept.
    valid_to: datetime | None = None
    # A correction records a claim, so it is graded like one: required, with no defaults.
    assertion: AssertionBody


class UpdateEdgeBody(BaseModel):
    """A correction to an edge. `sign` and `edge_type` are absent on
    purpose — see `GraphWriteService.update_edge`: flipping a vouch into an
    accusation is a different claim, not a typo fix, and belongs in its own
    edge so the disagreement survives. Same replacement semantics for
    `attrs` as `UpdateNodeBody`."""
    # Bounds mirror `core.edge.weight numeric(14,4)`, so an out-of-range
    # value is a 422 with a sentence instead of a driver overflow. Negative
    # is refused because direction lives in `sign`: a negative weight would
    # silently invert the balance and centrality arithmetic.
    weight: float | None = Field(default=None, ge=0, le=9_999_999_999.9999)
    confidence: str | None = None      # validated by the service against the DB enum
    attrs: dict | None = None
    # As on UpdateNodeBody: when the tie stopped being true, null to clear.
    valid_to: datetime | None = None
    # Required, as on UpdateNodeBody. A re-grade sends the same value here
    # and in `confidence`: see update_edge.
    assertion: AssertionBody


class RetireBody(BaseModel):
    """Why this element is being retired.

    Required, as for a retraction: retiring a node dissolves every tie it carries, and what the
    analyst was thinking cannot be reconstructed later. The service takes no reason, so this lands
    in the audit event.
    """
    reason: str = Field(min_length=1)


@router.patch("/graph/nodes/{node_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def update_node(
    case_id: UUID, node_id: UUID, body: UpdateNodeBody,
    user: CurrentUser = Depends(require("graph.node.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct a node's label or attributes, with a graded assertion as its basis (invariant 1).

    `attrs` overwrites the attribute object wholesale (`UpdateNodeBody`), and `valid_to` (null clears
    it) records when the entity stopped being true. The previous values go to the audit row and the
    correction's `prior_value`, so retracting it restores what the remaining claims support. A
    corrected selector label moves the selector index, and `selector_owner_id` names a visible
    entity already holding the new value. Classification, compartments (invariant 8) and
    `node_type` are not editable here.
    """
    old_label, old_attrs, merged_into_id = _gate_for_change(
        conn, user, case_id=case_id, table="node", element_id=node_id,
        permission_key="graph.node.update")
    _check_evidence(conn, case_id, body.assertion.evidence_id)

    end = _valid_to_given(body)
    changed: dict = {}
    if body.label is not None:
        changed["label"] = body.label
    if body.attrs is not None:
        changed["attrs"] = body.attrs
    if end is not KEEP:
        changed["valid_to"] = end.isoformat() if end is not None else None
    # An empty change set is refused by the service, not silently accepted
    # (invariant 12) — it raises before writing anything, so no assertion is
    # left behind claiming a correction that did not happen.

    previous = {key: (old_label if key == "label" else old_attrs)
                for key in changed if key != "valid_to"}
    if end is not KEEP:
        previous["valid_to"] = _previous_valid_to(conn, "node", node_id)

    # No try/except around GraphWriteError: `install_error_handlers` maps it to a 400 through
    # `_safe_detail`, which keeps raw psycopg text (constraint names, values, PL/pgSQL lines) out of
    # the response; re-raising `str(exc)` here would hand exactly that to the client.
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    with conn.transaction():
        lead = GraphWriteService(conn).update_node(
            node_id, case_id=case_id,
            assertion=_assertion(body.assertion, user.user_id,
                                 claim_path=_claim_path(changed),
                                 claim_value=changed or None),
            label=body.label, attrs=body.attrs, valid_to=end,
            clearance=clearance.name, compartments=held,
        )
        _audit_change(conn, user, case_id, action="NODE_UPDATED",
                      object_type="node", object_id=node_id,
                      detail={"fields": sorted(changed), "previous": previous})

    return {
        "node_id": str(node_id),
        "updated": sorted(changed),
        # The corrected selector is already held by another entity the caller can see: a merge
        # lead, as on create. An owner the caller cannot see is not named.
        "selector_owner_id": (str(lead) if lead is not None and _node_visible(
            conn, user, case_id, lead) else None),
        # A node merged into another is in no projection, so a correction to it will not appear on
        # the canvas, and the response says so (invariant 12); unmerging restores it with its new
        # label. The survivor's id only when the caller may read the survivor: an AMBER entity
        # folded into a RED one is an alias of it, which the ledger and approvals also withhold.
        "merged_into_id": (
            str(merged_into_id)
            if merged_into_id
            and _node_visible(conn, user, case_id, merged_into_id) else None),
        "note": ("this node is merged into another and is excluded from the "
                 "live graph; reverse the merge to see the correction on the "
                 "canvas") if merged_into_id else None,
    }


@router.patch("/graph/edges/{edge_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def update_edge(
    case_id: UUID, edge_id: UUID, body: UpdateEdgeBody,
    user: CurrentUser = Depends(require("graph.edge.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct an edge's weight, confidence or attributes, with a graded assertion as its basis.

    A tie's confidence is the highest among its live claims (migration 0064), so a re-grade is
    carried by the correction's assertion: `confidence` marks the correction as a re-grade and must
    equal `assertion.confidence`, or it is refused as contradictory. A `weight` or `attrs`
    correction grades that field, not the tie. Lowering a tie beneath a live claim is a 409 that
    names the remedy (`GraphWriteService.update_edge`). `sign`, `edge_type`, classification and
    compartments are not editable here.
    """
    if (body.confidence is not None
            and body.assertion.confidence != body.confidence):
        raise Problem(400, "Invalid request",
                      "confidence and assertion.confidence disagree. A tie's "
                      "confidence is its assertions' grade, so a re-grade is "
                      "the correction's own grade: send the same value in "
                      "both")
    old_weight, old_confidence, old_attrs = _gate_for_change(
        conn, user, case_id=case_id, table="edge", element_id=edge_id,
        permission_key="graph.edge.update")
    _check_evidence(conn, case_id, body.assertion.evidence_id)

    end = _valid_to_given(body)
    changed: dict = {}
    if body.weight is not None:
        changed["weight"] = body.weight
    if body.confidence is not None:
        changed["confidence"] = body.confidence
    if body.attrs is not None:
        changed["attrs"] = body.attrs
    if end is not KEEP:
        changed["valid_to"] = end.isoformat() if end is not None else None

    # `weight` comes back from numeric(14,4) as a Decimal, which json.dumps
    # cannot serialise — and rounding it to a float to get it into the audit
    # row would corrupt the very value this record exists to preserve.
    # CONVENTIONS: weights are numeric, never float.
    previous = {"weight": str(old_weight), "confidence": old_confidence,
                "attrs": old_attrs}
    if end is not KEEP:
        previous["valid_to"] = _previous_valid_to(conn, "edge", edge_id)
    previous = {key: previous[key] for key in changed}

    try:
        with conn.transaction():
            GraphWriteService(conn).update_edge(
                edge_id, case_id=case_id,
                assertion=_assertion(body.assertion, user.user_id,
                                     claim_path=_claim_path(changed),
                                     claim_value=changed or None),
                weight=body.weight, confidence=body.confidence, attrs=body.attrs,
                valid_to=end,
            )
            _audit_change(conn, user, case_id, action="EDGE_UPDATED",
                          object_type="edge", object_id=edge_id,
                          detail={"fields": sorted(changed), "previous": previous})
    except TieConfidenceConflict as exc:
        # Authored text naming the claims in the way and the remedy. It is raised inside the
        # transaction above, so the correction is rolled back and no audit row is written.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc

    # The tie's confidence AFTER the write, as the rule derived it, so a
    # client never has to assume its re-grade (or a weight fix) left the
    # tie where it expected.
    now_confidence = conn.execute(
        "SELECT confidence::text FROM core.edge WHERE id = %s", (edge_id,)
    ).fetchone()[0]
    return {"edge_id": str(edge_id), "updated": sorted(changed),
            "confidence": now_confidence}


@router.delete("/graph/nodes/{node_id}", response_model=dict,
               dependencies=[Depends(rate_limit("request"))])
def soft_delete_node(
    case_id: UUID, node_id: UUID, body: RetireBody,
    user: CurrentUser = Depends(require("graph.node.delete")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Soft delete: sets `deleted_at` and destroys nothing, for a node that should never have been
    in the case file.

    Unlike `valid_to` (set by a `PATCH`, for something that stopped being true), it removes the node
    from as-of views too, since `deleted_at IS NULL` applies whatever the as-of time. Every live edge
    on the node is retired in the same transaction and counted in `edges_retired`, hence a 200 with
    a body. No assertion is written; the `reason` and previous label go to the audit log.
    """
    label, _attrs, merged_into_id = _gate_for_change(
        conn, user, case_id=case_id, table="node", element_id=node_id,
        permission_key="graph.node.delete")
    if merged_into_id is not None:
        # `MergeService.unmerge` restores the loser's edges and clears the redirect but not
        # `deleted_at`, so retiring a merged-away node would make the merge irreversible in effect
        # while it reports itself reversed (invariant 3).
        raise Problem(409, "Conflict",
                      "this node is merged into another; reverse the merge "
                      "before retiring it, or retire the surviving node")
    _refuse_live_merge_target(conn, user, case_id, node_id)

    at = datetime.now(timezone.utc)
    with conn.transaction():
        # The caller's OWN ceiling, so the cascade cannot retire a tie
        # they are not cleared to see. `require(...)` gated the case and
        # `_gate_for_change` gated this node; neither says anything about
        # the edges hanging off it.
        clearance, compartments = user_ceiling(conn, user.user_id)
        edges_retired = GraphWriteService(conn).soft_delete_node(
            node_id, case_id=case_id, deleted_by=user.user_id, at=at,
            clearance=clearance.name, compartments=compartments)
        _audit_change(conn, user, case_id, action="NODE_SOFT_DELETED",
                      object_type="node", object_id=node_id,
                      detail={"reason": body.reason, "label": label,
                              "edges_retired": edges_retired,
                              "deleted_at": at.isoformat()})

    return {
        "node_id": str(node_id),
        # Named so a client cannot read this as destruction. A caller that
        # only checks the status code sees 200; one that reads the body is
        # told plainly what happened.
        "soft_deleted": True,
        "destroyed": False,
        "deleted_at": at.isoformat(),
        "edges_retired": edges_retired,
        "note": (f"Soft delete: deleted_at was set on this node and on "
                 f"{count_of(edges_retired, 'incident edge', 'incident edges')}"
                 f". Nothing was destroyed "
                 f"(the rows and their assertions remain and the act is "
                 f"attributed), but the node and those ties are now out of "
                 f"the live graph, and out of as-of views of the past too."),
    }


def _refuse_live_merge_target(conn: psycopg.Connection, user: CurrentUser,
                              case_id: UUID, node_id: UUID) -> None:
    """Refuse to retire the surviving side of a live merge, as for the merged-away side: its ties
    would be retired, and the merge's reversal would hand them back to the merged entity still
    retired while saying they were restored.

    Looked for on the GRAPH_GUARD system connection, because a guard that permits on zero must see
    every merge, and a merge of an entity the caller cannot see is hidden from their own (migration
    0132). That one is refused in the words and status of `hidden_ties_refusal`, so the two guards
    cannot be told apart under any withheld-disclosure setting; a merge the caller can see is
    named."""
    from noctornal_api.db import SystemPurpose, system_connection

    with system_connection(SystemPurpose.GRAPH_GUARD, reuse=conn) as guard:
        live = guard.execute(
            """SELECT id, source_node_id FROM core.node_merge
                WHERE target_node_id = %s AND case_id = %s
                  AND reversed_at IS NULL
                ORDER BY merged_at DESC""",
            (node_id, case_id)).fetchall()
    if not live:
        return
    for merge_id, source_id in live:
        if _node_visible_any_state(conn, user, case_id, source_id):
            raise Problem(
                409, "Conflict",
                f"another entity is merged into this one (merge {merge_id}). "
                f"Retiring it would retire the ties that merge moved here, and "
                f"reversing the merge later could not bring them back. Reverse "
                f"the merge first, or retire the merged entities separately.")
    raise GraphWriteError(hidden_ties_refusal(conn, case_id))


def _node_visible_any_state(conn: psycopg.Connection, user: CurrentUser,
                            case_id: UUID, node_id: UUID) -> bool:
    """`_node_visible` without the liveness term: a merged-away entity is
    still the caller's to see when its labels allow."""
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    return conn.execute(
        """SELECT 1 FROM core.node
            WHERE id = %s AND case_id = %s
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (node_id, case_id, clearance.name, list(compartments)),
    ).fetchone() is not None


@router.delete("/graph/edges/{edge_id}", response_model=dict,
               dependencies=[Depends(rate_limit("request"))])
def soft_delete_edge(
    case_id: UUID, edge_id: UUID, body: RetireBody,
    user: CurrentUser = Depends(require("graph.edge.delete")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Soft delete: sets `deleted_at` on one edge and destroys nothing.

    The row and its assertions survive and the act is attributed (`deleted_by`). It still removes
    the tie from the live graph and from as-of views (see `soft_delete_node`), and one tie can
    dissolve a broker, so the reason goes to the audit log.
    """
    old_weight, old_confidence, _attrs = _gate_for_change(
        conn, user, case_id=case_id, table="edge", element_id=edge_id,
        permission_key="graph.edge.delete")

    at = datetime.now(timezone.utc)
    with conn.transaction():
        GraphWriteService(conn).soft_delete_edge(
            edge_id, case_id=case_id, deleted_by=user.user_id, at=at)
        _audit_change(conn, user, case_id, action="EDGE_SOFT_DELETED",
                      object_type="edge", object_id=edge_id,
                      detail={"reason": body.reason,
                              # Decimal → str: see update_edge.
                              "weight": str(old_weight),
                              "confidence": old_confidence,
                              "deleted_at": at.isoformat()})

    return {
        "edge_id": str(edge_id),
        "soft_deleted": True,
        "destroyed": False,
        "deleted_at": at.isoformat(),
        "note": ("Soft delete: deleted_at was set on this edge. Nothing was "
                 "destroyed (the row and its assertions remain and the act "
                 "is attributed), but the tie is now out of the live graph, "
                 "and out of as-of views of the past too."),
    }


# --- reviewing a tie ------------------------------------------------------
# A tie is born in its review state (`GraphWriteService.create_edge`: a person's claim is
# ACCEPTED, a machine's PROPOSED); these routes let a person dispose of a pending tie or reopen a
# disposal, recorded in the audit log as a Triage acceptance is. Gated on `proposal.review`, held
# by CASE_OWNER and REVIEWER but not ANALYST, against the tie's own labels and outside the write
# transaction so a refusal's AUTHZ_DENIED row is kept (see `_gate_for_change`).

#: The longest review note accepted. A note is a sentence or two for the
#: next reader, not a report; the cap keeps an audit row from carrying a
#: pasted document.
REVIEW_NOTE_MAX = 2000


class ReviewBody(BaseModel):
    """A disposal of one tie.

    `review` is ACCEPTED, DISPUTED, or PROPOSED to reopen. A note is
    required for DISPUTED and for a reopening, because the next reader
    needs the reason more than they need the verdict; it is optional for
    ACCEPTED, where the claims and their grading already say why."""
    review: str = Field(max_length=32)
    note: str | None = Field(default=None, max_length=REVIEW_NOTE_MAX)


#: Why a note is demanded, per state that demands one.
_NOTE_REQUIRED = {
    "DISPUTED": "a dispute needs a note saying what is doubted, so the next "
                "reader can act on it",
    "PROPOSED": "reopening a review needs a note saying why the earlier "
                "decision no longer stands",
}


@router.post("/graph/edges/{edge_id}/review", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def review_edge(
    case_id: UUID, edge_id: UUID, body: ReviewBody,
    user: CurrentUser = Depends(require("proposal.review")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Accept or dispute a tie, or reopen its review.

    REJECTED and SUPERSEDED are refused with a 400 naming what to do instead, the tie's current
    state and a retired tie with a 409, and a missing tie, one in another case or one above the
    caller's labels with the same 404. The decision is written to `audit.event` as EDGE_REVIEWED in
    the same transaction as the change; `GET .../review` reads it back.
    """
    wanted = body.review.strip().upper()
    if wanted not in REVIEW_STATES:
        raise Problem(
            400, "Invalid request",
            f"a review sets ACCEPTED or DISPUTED, or PROPOSED to reopen it, "
            f"not {body.review!r}. A tie that is wrong is retired, or its "
            f"claims are retracted with their reasons: a REJECTED tie left "
            f"in the live graph would say two opposite things at once")
    note = (body.note or "").strip() or None
    if wanted in _NOTE_REQUIRED and note is None:
        raise Problem(400, "Invalid request", _NOTE_REQUIRED[wanted])
    _gate_for_change(conn, user, case_id=case_id, table="edge",
                     element_id=edge_id, permission_key="proposal.review")
    try:
        with conn.transaction():
            previous = GraphWriteService(conn).review_edge(
                edge_id, case_id=case_id, review=wanted)
            _audit_change(conn, user, case_id, action="EDGE_REVIEWED",
                          object_type="edge", object_id=edge_id,
                          detail={"review": wanted, "previous": previous,
                                  "note": note})
    except TieReviewUnchanged as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {"edge_id": str(edge_id), "review": wanted, "previous": previous}


class ReviewEventOut(BaseModel):
    review: str
    previous: str | None
    note: str | None
    by: str | None
    by_name: str | None
    at: datetime


class ReviewOut(BaseModel):
    """A tie's review state and how it got there, newest decision first."""
    edge_id: str
    review: str
    #: Who entered the tie and when: with no decision below, the state is
    #: the one it was born in (`GraphWriteService.create_edge`).
    created_by_name: str | None
    created_at: datetime
    #: Set when the tie was applied from a Triage proposal: who accepted
    #: it and when. That acceptance is the tie's first disposal.
    accepted_from_triage_by: str | None = None
    accepted_from_triage_at: datetime | None = None
    history: list[ReviewEventOut]


@router.get("/graph/edges/{edge_id}/review", response_model=ReviewOut)
def edge_review(
    case_id: UUID, edge_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> ReviewOut:
    """Who put a tie in its review state, when, and why.

    The record is the EDGE_REVIEWED audit rows `review_edge` writes, since `edge.review` has no
    reviewer column. `/audit` never returns their `detail`; it is returned here only to a caller
    who may read this case and this tie. A tie above the caller's clearance is the same 404 as one
    that does not exist.
    """
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    row = conn.execute(
        """SELECT e.review::text, e.created_at, u.display_name
             FROM core.edge e
             LEFT JOIN iam.app_user u ON u.id = e.created_by
            WHERE e.id = %s AND e.case_id = %s AND e.deleted_at IS NULL
              AND e.classification <= %s::core.tlp AND e.compartments <@ %s""",
        (edge_id, case_id, clearance.name, list(compartments)),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such edge in this case")
    triage = conn.execute(
        """SELECT u.display_name, p.reviewed_at
             FROM collect.proposal p
             LEFT JOIN iam.app_user u ON u.id = p.reviewed_by
            WHERE p.applied_edge_id = %s AND p.case_id = %s
              AND p.state = 'ACCEPTED'
            ORDER BY p.reviewed_at DESC LIMIT 1""",
        (edge_id, case_id),
    ).fetchone()
    events = conn.execute(
        """SELECT ev.detail, ev.actor_id, u.display_name, ev.occurred_at
             FROM audit.event ev
             LEFT JOIN iam.app_user u ON u.id = ev.actor_id
            WHERE ev.object_id = %s AND ev.object_type = 'edge'
              AND ev.action = 'EDGE_REVIEWED' AND ev.case_id = %s
            ORDER BY ev.seq DESC LIMIT 50""",
        (edge_id, case_id),
    ).fetchall()
    history = []
    for detail, actor, name, at in events:
        d = detail or {}
        # A row with no actor was written by the system: the upgrade (migration 0067) names itself
        # in `by`, and the history says that rather than "by unknown".
        if actor is None and not name:
            name = d.get("by") or None
        history.append(ReviewEventOut(
            review=d.get("review") or "", previous=d.get("previous"),
            note=d.get("note"), by=str(actor) if actor else None,
            by_name=name, at=at))
    return ReviewOut(
        edge_id=str(edge_id), review=row[0], created_at=row[1],
        created_by_name=row[2],
        accepted_from_triage_by=triage[0] if triage else None,
        accepted_from_triage_at=triage[1] if triage else None,
        history=history)
