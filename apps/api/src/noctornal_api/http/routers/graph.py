"""Graph write endpoints — every create goes through GraphWriteService, so
an assertion is written in the same transaction (invariant 1).

Retraction lives here too. It is the operation that makes the assertion
model mean something: retracting the last live assertion behind an element
makes it dissolve from the live graph (`GraphService.project()` requires a
non-retracted assertion) while its row and history survive for temporal
replay. Nothing is ever deleted — invariant 5.

So do corrections and retirements (`PATCH`/`DELETE` on nodes and edges).
Three ways of taking something out of the live graph now meet in this
file, and they are not interchangeable:

- **Retract an assertion** — the source is withdrawn. The element goes
  only if that was its LAST live support.
- **Retire the element** (`DELETE`, a SOFT delete) — it should not be in
  the case file at all: wrong, or a duplicate. Sets `deleted_at`, which
  every read path filters on, so it leaves the live graph AND every as-of
  view.
- **`valid_to`** — it stopped being true in the WORLD. An as-of query into
  the period when it WAS true must still show it, and does.

None of the three destroys a row.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.graph import (
    REVIEW_STATES,
    AssertionInput,
    GraphWriteError,
    GraphWriteService,
    TieConfidenceConflict,
    TieReviewUnchanged,
)
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    element_labels,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.selectors import SelectorStore
from noctornal_api.wording import count_of
from noctornal_ontology import SELECTOR_TYPES, normalise, refusal

router = APIRouter(prefix="/cases/{case_id}", tags=["graph"])


class AssertionBody(BaseModel):
    """The claim a write records, and its grading.

    The four grading fields are REQUIRED (gap-api-grade-required,
    2026-09-23). They used to default to DIRECT_OBSERVATION, F, 6 and LOW,
    and the create bodies defaulted the whole assertion, so a script that
    sent a bare label recorded "we saw this ourselves" in the caller's name
    at a grade nobody chose. A reviewer six months later cannot tell that
    from a considered F6, ACH weights the cell by it, and the confidence
    filter acts on it. A missing field is now a 422 whose detail names it
    (`body.assertion.basis: Field required`), and nothing is filled in. The
    values themselves are checked by the database enums, as before.
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
    # ux06-entry:selector-entities-bypass-normalisation (2026-09-23): what
    # kind of selector the label IS, for a SELECTOR, COMMS_ACCOUNT or
    # WALLET entity. Given, the label is normalised (and refused when it
    # reduces to nothing) and recorded in the selector index against the
    # new entity, in the same transaction. See `create_node`.
    selector_type: str | None = Field(default=None, max_length=64)


class CreateEdgeBody(BaseModel):
    """A new tie and the assertion it rests on.

    The tie's confidence is `assertion.confidence` and nothing else
    (migration 0064). `confidence` is declared at the top level only so a
    client that sends it there is TOLD, instead of having it dropped the
    way pydantic drops an unknown field: that silent drop is exactly how a
    HIGH tie became LOW before 2026-09-22 (ux06 edge-confidence-not-stored).
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

    `selector_owner_id` is set when the selector was ALREADY recorded
    against another entity the caller can see: the index keeps the first
    owner (re-attribution is deliberate, never a side effect), so the new
    entity does not get it, and the two are a merge lead. A strong
    selector held by two entities is how one actor becomes two."""
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
    # One transaction, so an entity whose selector could not be recorded
    # does not exist either. The index is observation bookkeeping, not a
    # graph element (selectors.py), so recording it needs no second
    # assertion: the entity's founding claim is the observation, and its
    # observed time dates the selector.
    with conn.transaction():
        node_id = write()
        row = SelectorStore(conn).record(
            case_id=case_id, selector_type=selector.key,
            raw_value=body.label, node_id=node_id,
            observed_at=body.assertion.observed_at)
    out = NodeCreatedOut(id=str(node_id), selector_norm=row.norm_value,
                         selector_is_strong=selector.is_strong)
    if row.node_id is not None and row.node_id != node_id and _node_visible(
            conn, user, case_id, row.node_id):
        out.selector_owner_id = str(row.node_id)
    return out


# --- before an entity is created: is it already here? ---------------------
#
# ux06-entry:no-duplicate-check-on-create and ux06-entry:selector-entities-
# bypass-normalisation (2026-09-23). Add entity posted straight to /nodes:
# "Harrow_Skua2" for an existing "harrow_skua2" made a second persona that
# split the actor's ties and degree, and a hand-entered selector was taken
# raw, so '@Vendor' never met 'vendor' and a bare Telegram id the Comms pane
# refuses went in unchallenged. docs/01 calls merging "the operation most
# likely to quietly corrupt a case"; the cheapest merge is the one never
# needed. The form asks here as the label is typed.

#: Entity types whose label IS a selector value.
SELECTOR_NODE_TYPES = frozenset({"SELECTOR", "COMMS_ACCOUNT", "WALLET"})
_SELECTOR_TYPES = {s.key: s for s in SELECTOR_TYPES}
#: The most same-label matches returned. A list of ten look-alikes is
#: already the finding; the check is a warning, not a search.
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
    """How many live entities of this case the caller can see: the same
    rows `GET /nodes` lists, without the page. The entity list fetches the
    newest 1000 and counted that page as the case, so a larger case read
    "1000 of 1000" while its oldest entities were missing from the list,
    the Link pickers and the palette (ux06-entry:entity-list-no-find,
    2026-09-23). Counting only what the caller can see keeps it from being
    a measure of what they cannot.

    `edges` is the same for the ties, by the rule `GET /edges` lists them
    (both ends visible, inferred ties included, as the console loads
    them): the count line's "N relationships in the case" was the length
    of a page that stops at 1000 too (the 2026-09-23 verifier)."""
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

    Reads only, and only what the caller may see: every match is filtered
    by their own ceiling, so a RED look-alike stays invisible to an AMBER
    analyst, exactly as it is in the entity list. Case and runs of
    whitespace are folded, which is the typing slip the review showed;
    anything looser (edit distance, homoglyphs) would flood the form with
    false leads on a forum full of "vendor1", "vendor_1", "vendorl".
    For a selector type, the label is also normalised the way the index
    will hold it, and the index is asked who already owns that value.
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
    out.selector_norm = norm
    owner = conn.execute(
        """SELECT n.id, n.label, n.node_type
             FROM core.selector s JOIN core.node n ON n.id = s.node_id
            WHERE s.case_id = %s AND s.selector_type = %s AND s.norm_value = %s
              AND n.deleted_at IS NULL
              AND n.classification <= %s::core.tlp AND n.compartments <@ %s""",
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
    edge_id = GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type=body.edge_type, src_node_id=body.src_node_id,
        dst_node_id=body.dst_node_id, created_by=user.user_id,
        assertion=_assertion(body.assertion, user.user_id),
        classification=body.classification,
        valid_from=body.valid_from, valid_to=body.valid_to,
    )
    return IdOut(id=str(edge_id))


# --- assertions on an existing element ----------------------------------

def _element_case(conn: psycopg.Connection, table: str, element_id: UUID) -> UUID | None:
    assert table in ("node", "edge")     # literal, never client input
    row = conn.execute(
        f"SELECT case_id FROM core.{table} WHERE id = %s", (element_id,)
    ).fetchone()
    return row[0] if row else None


def _element_labels(conn: psycopg.Connection, table: str,
                    element_id: UUID) -> tuple[UUID, str, frozenset[str]] | None:
    """The element's case AND its own labels, for the gate.

    CR7 (2026-07-26). `_add_assertion` and `retract_assertion` authorised
    with `require(...)` alone — the CASE-level form, `classification=None`.
    `create_node` and `create_edge` use `check_writable_labels`, and the
    evidence router resolves the row's labels and passes them to
    `authorize_object`. The assertion endpoints did neither, so
    `deps.py`'s rule 1 ("an element is protected by BOTH its own labels and
    its case's") did not hold on the writes that matter most.

    It matters most because of what retraction DOES: the projection
    requires a live assertion, so retracting the last one dissolves the
    element from every analyst's graph. An AMBER analyst who once held RED
    and noted a RED node's assertion id could therefore destroy that node
    for everyone, while not being cleared to see it.
    """
    assert table in ("node", "edge")
    # The element's case and labels as facts (`deps.element_labels`,
    # S1 2026-09-25), so the gate below still answers an element above the
    # caller's labels with its 403 and AUTHZ_DENIED row, not a silent 404 from
    # row-level security. Content is read only after the gate.
    return element_labels(conn, table, element_id)


def _add_assertion(conn, user, case_id, body, *, node_id=None, edge_id=None) -> IdOut:
    table = "node" if node_id else "edge"
    found = _element_labels(conn, table, node_id or edge_id)
    # The path's case_id is the one the gate authorised, so an element from
    # another case must not be reachable through it.
    if found is None or found[0] != case_id:
        raise Problem(404, "Not found", f"no such {table} in this case")
    # CR7: re-authorise against the ELEMENT's labels, not just the case's.
    # A RED node can live in an AMBER case, and asserting about it is a
    # write against the node.
    # A second gate, after the route's at the case's labels: it counts a
    # break-glass use only if that one did not (sec-breakglass-double-count).
    authorize_object(conn, user, case_id=case_id,
                     permission_key="assertion.create", after_case_gate=True,
                     classification=found[1], compartments=found[2])
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
    """Retract a claim. The row is preserved and stamped, never deleted
    (invariant 5).

    The consequence is deliberate and load-bearing: an element whose LAST
    live assertion is retracted loses all live support and disappears from
    the projection, taking its degree, its centrality and its edges with
    it. Withdraw a source and the part of the network that rested on it
    dissolves — which is the whole point of grounding a graph in evidence.
    The ROW survives, stamped, with its reason. The VIEW does not: the
    projection's live-provenance leg is `retracted_at IS NULL AND
    superseded_at IS NULL` with no as-of term, so the element is gone at
    every as-of position, including ones before the retraction. (Corrected
    2026-09-22, ux05 retract-confirmation-wrong: this said an earlier
    `as_of` still showed it, and the console's confirmation repeated the
    promise. The superseded half is the final review's U11, 2026-09-23.)
    """
    from fastapi import Response
    # The element's case and labels as facts (`deps.element_labels`,
    # S1 2026-09-25), so the gate below still answers an element above the
    # caller's labels with its 403 and AUTHZ_DENIED row, not a silent 404 from
    # row-level security. Content is read only after the gate.
    subject = element_labels(conn, "assertion", assertion_id)
    if subject is None or subject[0] != case_id:
        raise Problem(404, "Not found", "no such assertion in this case")
    # CR7: the element's own labels gate the retraction. Retracting the
    # last live assertion dissolves the element from every projection, so
    # this endpoint destroys graph structure — it must not be reachable by
    # a caller who could not see what they are destroying. (The assertion's
    # facts ARE its subject's labels.)
    if subject is not None:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="assertion.retract", after_case_gate=True,
                         classification=subject[1], compartments=subject[2])
    try:
        GraphWriteService(conn).retract_assertion(
            assertion_id, retracted_by=user.user_id, reason=body.reason,
            at=datetime.now(timezone.utc),
        )
    except GraphWriteError as exc:
        # Already retracted, or gone. Saying so is better than a silent
        # 204 that leaves a burned source live in the projection.
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, 'USER', 'ASSERTION_RETRACTED', 'assertion', %s, %s, %s)""",
        (user.user_id, assertion_id, case_id, Json({"reason": body.reason})),
    )
    return Response(status_code=204)


# --- corrections and retirements ----------------------------------------
#
# The HTTP face of the "correcting and retiring" block in `graph.py`. Read
# that first — it explains why every correction carries an assertion, and
# why classification, compartments, `sign` and `edge_type` are deliberately
# NOT editable through these verbs.
#
# Until now a mistyped node label was permanent: `graph.node.update`,
# `graph.node.delete` and `graph.edge.update` were seeded in 0017 and
# granted in 0021, `graph.edge.delete` was added in 0053, and nothing in
# the product had ever checked any of them. These four endpoints are the
# first callers.
#
# THREE THINGS ARE ENFORCED HERE rather than in the service, because they
# are authorisation and HTTP concerns rather than model concerns:
#
# 1. **Same-case verification on the caller-supplied element id, before the
#    id is used**, answering 404 rather than 403 so the endpoint is not an
#    existence oracle. The service checks `case_id` in its own WHERE clause
#    too — belt and braces — but a service-level miss surfaces as a 400
#    "not found in this case", which reads like a malformed request rather
#    than a missing object.
# 2. **The ELEMENT's own labels, not just the case's** — the CR7 rule
#    documented on `_element_labels` above. A RED node can live in an AMBER
#    case, and correcting or retiring it is a write against the node. The
#    `require(...)` dependency only gates on the case.
# 3. **Element state**: already retired, or merged away. Both are checked
#    AFTER the gate, so neither becomes a state oracle for a caller who is
#    not cleared to know the element exists.
#
# One permission each, not two. A correction inserts an assertion, but it
# is not gated on `assertion.create` as well: the assertion is part OF the
# correction (invariant 1 applied to the change itself), not an independent
# claim someone might be separately entitled to make. Requiring both would
# also mean a role could hold `graph.node.update` and be unable to use it.

#: Columns each change endpoint needs in hand BEFORE the write: the values
#: the UPDATE is about to overwrite (so `_audit_change` can record them —
#: see there for why that matters) plus, for a node, the merge redirect.
#: Literal per table and asserted against these keys, so nothing
#: client-supplied ever reaches the f-string.
_BEFORE_COLUMNS = {
    "node": "label, attrs, merged_into_id",
    "edge": "weight, confidence, attrs",
}


def _gate_for_change(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID, table: str,
    element_id: UUID, permission_key: str,
) -> tuple:
    """Same-case check → element-label gate → not-already-retired check,
    then hand back the element's current values.

    THE ORDER IS THE POINT.

    A caller who names an element from another case gets the same 404 as
    one who names an element that does not exist, so neither this endpoint
    nor its status codes can be used to enumerate other cases' ids. Only
    after that does the element's own classification and compartments reach
    `authorize_object` — the CR7 rule, and the reason a RED node inside an
    AMBER case cannot be quietly rewritten by an AMBER analyst who once saw
    its id.

    The retirement check comes LAST, after the gate, for the same reason
    the hostile-markup refusal in the deception router does: "this one is
    already retired" is a fact about the element, and telling it to someone
    who failed the gate would leak state they are not cleared for.

    **Call this OUTSIDE the write transaction, and leave it there.** A
    denial inside `authorize_object` appends an `AUTHZ_DENIED` row to the
    audit log and then raises. Tidying this call into the `with
    conn.transaction()` block below would roll that row back on the way
    out, so every refused correction and every refused retirement would
    silently vanish from the security record — the opposite of what the
    check is for. The cost of keeping it outside is a TOCTOU window: the
    element can be retired by someone else between the check and the write,
    in which case the service's own `deleted_at IS NULL` clause makes it a
    400 rather than the 409 raised here. That is the right trade.
    """
    assert table in _BEFORE_COLUMNS      # literal, never client input
    # The element's case and labels as facts (`deps.element_labels`,
    # S1 2026-09-25), so the gate below still answers an element above the
    # caller's labels with its 403 and AUTHZ_DENIED row, not a silent 404 from
    # row-level security. Content is read only after the gate.
    facts = element_labels(conn, table, element_id)
    if facts is None or facts[0] != case_id:
        raise Problem(404, "Not found", f"no such {table} in this case")
    authorize_object(conn, user, case_id=case_id,
                     permission_key=permission_key, after_case_gate=True,
                     classification=facts[1], compartments=facts[2])
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
    """Append the change to the audit log, carrying the OVERWRITTEN values.

    This is not decoration. `update_node` / `update_edge` do a destructive
    `UPDATE` on `core.node` / `core.edge`: the NEW value is recoverable
    from the assertion the correction carries (`claim_value`), and the OLD
    one is recoverable from nowhere else, because the column that held it
    has just been overwritten. Invariant 5 says history is superseded, not
    overwritten — for these two columns this row IS the superseded history.

    `audit.event` is the right home for it rather than a new table:
    append-only (invariant 6), hash-chained, and `detail` is deliberately
    never returned by `/audit` (see `routers/audit.py` — the listing
    returns structural columns only). So recording case content here does
    not widen the one globally-scoped role's view of case material.

    Called INSIDE the caller's transaction — the service's own transaction
    becomes a savepoint under it — so a change that committed without its
    audit row is not a state this code can reach. Nesting is safe on these
    paths specifically, and it was checked rather than assumed: 0022's
    deferred constraint triggers fire on INSERT to `core.node`/`core.edge`
    and on DELETE/UPDATE of `assertion.node_id`/`edge_id`. A correction
    UPDATEs node/edge and INSERTs an assertion; a retirement only UPDATEs.
    Neither trips either trigger, so nothing new falls due at the outer
    commit that would otherwise have surfaced as a clean 400 at the inner
    one.
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


class UpdateNodeBody(BaseModel):
    """A correction to a node, with the assertion that justifies it.

    `attrs` is a WHOLE-OBJECT REPLACEMENT, not a merge: sending
    `{"attrs": {"role": "broker"}}` on a node that also had `country`
    leaves it with `role` alone, and `{"attrs": {}}` clears every
    attribute. That is the service's semantics (`COALESCE(%s, attrs)`) and
    it is stated here because the alternative reading — "patch merges" — is
    the one a caller assumes from the verb. Omit the field entirely to
    leave attributes untouched.
    """
    label: str | None = None
    attrs: dict | None = None
    # A correction records a claim, so it is graded like one: required,
    # with no defaults (gap-api-grade-required, 2026-09-23).
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
    # Required, as on UpdateNodeBody. A re-grade sends the same value here
    # and in `confidence`: see update_edge.
    assertion: AssertionBody


class RetireBody(BaseModel):
    """Why this element is being retired.

    Required, exactly as it is for a retraction. Retiring a node dissolves
    every tie it carries, and the one thing a reviewer six months later
    cannot reconstruct is what the analyst was thinking. The service takes
    no reason argument, so this lands in the audit event.
    """
    reason: str = Field(min_length=1)


@router.patch("/graph/nodes/{node_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def update_node(
    case_id: UUID, node_id: UUID, body: UpdateNodeBody,
    user: CurrentUser = Depends(require("graph.node.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct a node's label and/or attributes.

    **An assertion is required** — "we corrected this" is a claim about the
    world and needs a basis like any other (invariant 1). So is its
    grading: the body used to grade an ungraded correction F/6/LOW on the
    caller's behalf, as DIRECT_OBSERVATION, and now a missing field is a 422
    naming it (gap-api-grade-required, 2026-09-23). Cite the exhibit that
    prompted it via `assertion.evidence_id` if there is one.

    `attrs` REPLACES the attribute object wholesale. See `UpdateNodeBody`.

    The previous label and attributes are written to `audit.event.detail`,
    because this endpoint overwrites the columns that held them.

    Not editable here: classification and compartments (an egress decision,
    invariant 8, not a typo fix) and `node_type`.
    """
    old_label, old_attrs, merged_into_id = _gate_for_change(
        conn, user, case_id=case_id, table="node", element_id=node_id,
        permission_key="graph.node.update")
    _check_evidence(conn, case_id, body.assertion.evidence_id)

    changed: dict = {}
    if body.label is not None:
        changed["label"] = body.label
    if body.attrs is not None:
        changed["attrs"] = body.attrs
    # An empty change set is refused by the service, not silently accepted
    # (invariant 12) — it raises before writing anything, so no assertion is
    # left behind claiming a correction that did not happen.

    previous = {key: (old_label if key == "label" else old_attrs)
                for key in changed}

    # No try/except around GraphWriteError: `install_error_handlers`
    # already maps it to a 400 THROUGH `_safe_detail`, which is what keeps a
    # raw psycopg message — constraint names, offending values, PL/pgSQL
    # line numbers — out of the response. Catching it here to re-raise
    # `Problem(400, ..., str(exc))` would hand exactly that to the client.
    with conn.transaction():
        GraphWriteService(conn).update_node(
            node_id, case_id=case_id,
            assertion=_assertion(body.assertion, user.user_id,
                                 claim_path=_claim_path(changed),
                                 claim_value=changed or None),
            label=body.label, attrs=body.attrs,
        )
        _audit_change(conn, user, case_id, action="NODE_UPDATED",
                      object_type="node", object_id=node_id,
                      detail={"fields": sorted(changed), "previous": previous})

    return {
        "node_id": str(node_id),
        "updated": sorted(changed),
        # A node merged into another is excluded from every projection, so
        # a correction to it will not appear on the canvas. Saying so beats
        # a 200 the analyst reads as "done" and then cannot see (invariant
        # 12). The edit is still allowed: unmerging restores the node with
        # whatever label it now carries, so nothing is lost either way.
        "merged_into_id": str(merged_into_id) if merged_into_id else None,
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
    """Correct an edge's weight, confidence and/or attributes.

    **An assertion is required**, for the same reason as `update_node`.

    `confidence` re-grades the tie, and since migration 0064 a tie's
    confidence is the highest among its live claims about the tie, so the
    re-grade is carried BY the correction's assertion: it is recorded
    graded at the value it states. A correction to `weight` or `attrs`
    alone grades that field, not the tie, and leaves the tie's confidence
    where it was. Until 2026-09-22 this docstring called the two
    "different fields", the column was overwritten, the assertion kept its
    default LOW, and every correction opened a new disagreement between
    the tie and its claims (ux05 two-disagreeing-confidences). Sending
    both `confidence` and a different `assertion.confidence` is therefore
    refused as contradictory rather than one being silently preferred.
    Since the assertion's grading became required (gap-api-grade-required,
    2026-09-23) a re-grade always carries both, so it sends the one value
    twice: `confidence` says the correction IS a re-grade of the tie (its
    `claim_path`), and `assertion.confidence` is that claim's grade.

    Lowering a tie beneath a claim that is still live is a 409: see
    `GraphWriteService.update_edge` for why, and for the remedy the
    response names.

    Not editable here: `sign` and `edge_type` (a different claim, not a
    correction; record it as its own edge), classification and
    compartments. See `GraphWriteService.update_edge`.
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

    changed: dict = {}
    if body.weight is not None:
        changed["weight"] = body.weight
    if body.confidence is not None:
        changed["confidence"] = body.confidence
    if body.attrs is not None:
        changed["attrs"] = body.attrs

    # `weight` comes back from numeric(14,4) as a Decimal, which json.dumps
    # cannot serialise — and rounding it to a float to get it into the audit
    # row would corrupt the very value this record exists to preserve.
    # CONVENTIONS: weights are numeric, never float.
    previous = {"weight": str(old_weight), "confidence": old_confidence,
                "attrs": old_attrs}
    previous = {key: previous[key] for key in changed}

    try:
        with conn.transaction():
            GraphWriteService(conn).update_edge(
                edge_id, case_id=case_id,
                assertion=_assertion(body.assertion, user.user_id,
                                     claim_path=_claim_path(changed),
                                     claim_value=changed or None),
                weight=body.weight, confidence=body.confidence, attrs=body.attrs,
            )
            _audit_change(conn, user, case_id, action="EDGE_UPDATED",
                          object_type="edge", object_id=edge_id,
                          detail={"fields": sorted(changed), "previous": previous})
    except TieConfidenceConflict as exc:
        # Authored text naming the claims in the way and the remedy. The
        # service raised it inside the transaction above, which rolled the
        # correction back, and the audit row below it was never reached.
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
    """**Soft delete.** Sets `deleted_at`; destroys nothing.

    The row survives and so does every assertion behind it. Nothing is
    destroyed, the act is attributed (`deleted_by`), and clearing the
    column would bring the node back.

    **It does not preserve visibility, and the difference from `valid_to`
    is worth being exact about.** `as_of` is WORLD time — it filters
    `valid_from`/`valid_to`, and `projections.py` applies `deleted_at IS
    NULL` regardless of it. So a retired node is gone from the sociogram,
    the metrics, the search results AND from an as-of view of last week.
    That is the point: `valid_to` says "this stopped being true in March"
    and an as-of query into February must still show it; this says "this
    should never have been in the case file at all". Reach for the wrong
    one and you either rewrite history or fail to remove a mistake.

    **Every live edge touching this node is retired in the same
    transaction**, and the count comes back as `edges_retired`. This is why
    the endpoint answers 200 with a body rather than 204: retiring one
    actor can remove six ties, and a bare 204 would let an analyst delete a
    hub and never learn what went with it. Explained in
    `GraphWriteService.soft_delete_node` — an edge left live against a
    retired node is invisible on the canvas and still counted by anything
    reading `core.edge` directly.

    No assertion is required, and none is written: a retirement is not a
    claim about the world, it is a statement that this should not have been
    in the case file. The `reason` and the previous label go to the audit
    log. To say instead "this stopped being true in March", set `valid_to`
    — that is temporal validity and it must not be conflated with this.
    """
    label, _attrs, merged_into_id = _gate_for_change(
        conn, user, case_id=case_id, table="node", element_id=node_id,
        permission_key="graph.node.delete")
    if merged_into_id is not None:
        # Refused, and this one is not fussiness. `MergeService.unmerge`
        # restores the loser's edges and clears the redirect — it does NOT
        # clear `deleted_at`. Retiring a merged-away node therefore leaves
        # the reversal restoring live edges onto a deleted endpoint, which
        # the projection drops: the merge becomes irreversible in effect
        # while still reporting itself as reversed. Invariant 3 requires
        # merges to be reversible, so this order of operations is refused.
        raise Problem(409, "Conflict",
                      "this node is merged into another; reverse the merge "
                      "before retiring it, or retire the surviving node")

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
        # The incident edges were counted with a bracketed plural and
        # printed verbatim; the count is known (README screenshot set
        # review, 2026-09-23).
        "note": (f"Soft delete: deleted_at was set on this node and on "
                 f"{count_of(edges_retired, 'incident edge', 'incident edges')}"
                 f". Nothing was destroyed "
                 f"(the rows and their assertions remain and the act is "
                 f"attributed), but the node and those ties are now out of "
                 f"the live graph, and out of as-of views of the past too."),
    }


@router.delete("/graph/edges/{edge_id}", response_model=dict,
               dependencies=[Depends(rate_limit("request"))])
def soft_delete_edge(
    case_id: UUID, edge_id: UUID, body: RetireBody,
    user: CurrentUser = Depends(require("graph.edge.delete")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """**Soft delete.** Sets `deleted_at` on one edge; destroys nothing.

    200 with a body rather than 204, for the same reason as the node
    endpoint: DELETE reads as destruction and this is not that. The row and
    its assertions survive and the act is attributed (`deleted_by`, added
    in 0053 precisely so "who removed this tie?" has an answer).

    It is still a removal from the live graph and from as-of views of the
    past — see `soft_delete_node` for why `deleted_at` and `valid_to` are
    not interchangeable. And retiring a single edge is not a small act:
    dropping one tie can dissolve a broker and redraw the centrality of
    everyone around them. The reason goes to the audit log.
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
#
# gap-tie-review and ux05 review-state-never-leaves-proposed (2026-09-23).
# `core.edge.review` defaulted to PROPOSED and nothing anywhere set it, so
# every tie in every case read "review PROPOSED", every node on the canvas
# carried the "unreviewed proposal" ring, and the inspector's "Unreviewed
# proposals" count always equalled its "Ties in projection". A signal that
# can never clear carries no information, and this one told analysts there
# was work pending that no control could complete.
#
# Two halves. A tie is now BORN in the right state (`GraphWriteService.
# create_edge`: a person's own claim is ACCEPTED, a machine's is PROPOSED,
# and a Triage acceptance passes ACCEPTED). And these two routes let a
# person dispose of what is still pending, or reopen a disposal, with the
# decision recorded where a Triage acceptance is: the audit log.
#
# Gated on `proposal.review`, the verb Triage disposes of a machine's
# suggestion with, and so held by the Lead investigator (CASE_OWNER) and
# the REVIEWER, not by the ANALYST: the owner's decision for this gap. The
# gate runs against the TIE's own labels, the CR7 rule every other change
# here follows, and outside the write transaction so a refusal's
# AUTHZ_DENIED row is kept (see `_gate_for_change`).

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

    Refused: REJECTED and SUPERSEDED (400, naming what to do instead; see
    `graph.REVIEW_STATES`), a state the tie is already in (409, and no
    audit row), a retired tie (409), a tie in another case or one that
    does not exist (404, identical), and a caller who lacks
    `proposal.review` or the clearance for the tie (403).

    The decision goes to `audit.event` as EDGE_REVIEWED with the state
    left, the state set and the note, in the same transaction as the
    change, so a review that happened without its record is not a state
    this code can reach. `GET .../review` reads it back.
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

    `edge.review` has no reviewer column (no migration was open for one),
    so the record is the EDGE_REVIEWED audit rows `review_edge` writes.
    Their `detail` is never returned by `/audit`, which keeps case content
    away from the one role that reads the whole log; it is returned HERE
    only to a caller who may read this case and this tie, the same reader
    the tie's own assertions and their authors' names go to. A tie above
    the caller's clearance is the same 404 as one that does not exist.
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
        # A row with no actor was written by the system, not a person: the
        # upgrade (migration 0067) names itself in `by`
        # (ux05-inspector:review-state-never-leaves-proposed, 2026-09-23),
        # and the history says that rather than "by unknown".
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
