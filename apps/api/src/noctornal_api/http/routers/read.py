"""Graph read endpoints: listing, detail, and the provenance answer.

Everything here filters by the caller's own clearance and compartments, not the case's: an element
may be classified above its case, so case-level authorization alone would disclose labels the
caller may not see. Soft-deleted and merged-away nodes are excluded. The assertion endpoints answer
"why do we believe this?" in one request: source, Admiralty grading, analyst confidence, rationale,
and whether the claim is retracted or superseded.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from noctornal_ontology import SELECTOR_TYPES

from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.errors import Problem

# The register's reading of an exhibit's storage lock, so the inspector's
# list states it as the Evidence pane's card does (x-inspector-chips).
from noctornal_api.http.routers.evidence import (
    NEWEST_LOCK_SQL,
    case_lock_bounds,
    lock_is_short,
    lock_state,
)

# The five-part gate asked as a question rather than raised as a refusal.
# Reused, not re-decided: `search` already answers "may this caller see
# exhibits / collected documents too?" for its combined results, and a
# second copy of an authorization rule is how two of them drift apart.
from noctornal_api.http.routers.search import _allowed_on_case, _holds_global
from noctornal_api.projections import evidence_backing_sql, seen_params, seen_sql

router = APIRouter(prefix="/cases/{case_id}", tags=["read"])


# --- models -------------------------------------------------------------

class NodeOut(BaseModel):
    id: str
    node_type: str
    label: str
    classification: str
    attrs: dict
    #: The earliest and latest `observed_at` among the entity's live claims (or the stored column,
    #: whichever is earlier or later), derived by `projections.seen_sql` because nothing writes the
    #: columns. None when no live claim says when.
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime
    # World-time validity, as the entity form records it.
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class EdgeOut(BaseModel):
    id: str
    edge_type: str
    src_node_id: str
    dst_node_id: str
    src_label: str
    dst_label: str
    sign: int
    weight: float
    confidence: str
    is_inferred: bool
    review: str
    classification: str
    valid_from: datetime | None
    valid_to: datetime | None


class AssertionOut(BaseModel):
    """Why we believe a claim. basis + grading + rationale + provenance."""
    id: str
    basis: str
    reliability: str          # Admiralty A-F
    credibility: str          # Admiralty 1-6
    confidence: str           # ICD 203
    rationale: str | None
    external_ref: str | None
    evidence_id: str | None
    observed_at: datetime | None
    recorded_at: datetime
    retracted_at: datetime | None
    superseded_at: datetime | None
    # Why a source was withdrawn is part of the audit story, so it travels
    # with the assertion rather than living only in audit.event.
    retraction_reason: str | None = None
    created_by: str
    # What was claimed, from what and by whom: what "why is this believed" needs.
    #: The field a claim is about ('label', 'attrs.role', 'comms.tox'), or
    #: None when the claim is the element itself (a create).
    claim_path: str | None = None
    #: What the claim says that field is. JSON as stored: an object for a
    #: correction, often a bare string for an attribute claim.
    claim_value: Any = None
    #: The captured document and collection source the claim came from,
    #: when a collector or triage produced it.
    document_id: str | None = None
    source_id: str | None = None
    #: The author's display name. The same exposure as the case roster
    #: (`GET /cases/{id}/users` returns display names to case.read) and
    #: as the report's assumption register.
    created_by_name: str | None = None
    #: The carried exhibit's title, only when the reader may see that exhibit: `evidence.read` on
    #: the case and the exhibit within the reader's clearance and compartments. None otherwise, so
    #: a title never leaves through a claim to someone the exhibit list would refuse.
    evidence_title: str | None = None
    #: The captured document's title ('' when it has none) and its source's name, under the rule
    #: `GET /collection/documents` applies: global `collection.read`, the document unpurged, the
    #: document's and source's labels within the reader's case-less clearance (a break-glass grant
    #: on this case does not raise it, `_document_ceiling`) and its compartments within the
    #: reader's. None when any leg fails, so such a reader gets only the ids above. A claim names
    #: its source only through its document.
    document_title: str | None = None
    source_name: str | None = None
    #: True when this assertion records a CORRECTION made through
    #: `PATCH /graph/nodes|edges/{id}` rather than a claim about the world
    #: arriving from a source. See `CORRECTION_FIELDS`.
    is_correction: bool = False
    #: Supersession (migration 0131): the claim this one replaces (recorded to give that claim a
    #: date it never had) and the claim that replaced this one. Ids only: the other claim is about
    #: the same entity or tie, so it is no wider a disclosure than this row.
    supersedes_id: str | None = None
    superseded_by: str | None = None

    @property
    def is_live(self) -> bool:
        return self.retracted_at is None and self.superseded_at is None


#: The fields `PATCH /graph/nodes/{id}` and `PATCH /graph/edges/{id}` can change (UpdateNodeBody
#: and UpdateEdgeBody in routers/graph.py). A correction names one in `claim_path`, or leaves it
#: empty and carries several in `claim_value`; attribute claims use dotted paths ('attrs.role'),
#: so the two cannot be confused. test_evidenced_pg.py pins this set to the two request bodies.
CORRECTION_FIELDS = frozenset({"label", "attrs", "weight", "confidence",
                               "valid_to"})


def is_correction(claim_path: str | None, claim_value: Any) -> bool:
    if claim_path is not None:
        return claim_path in CORRECTION_FIELDS
    return (isinstance(claim_value, dict) and bool(claim_value)
            and set(claim_value) <= CORRECTION_FIELDS)


class EvidenceOut(BaseModel):
    id: str
    title: str
    media_type: str
    byte_size: int
    sha256: str
    classification: str
    acquisition_method: str
    acquired_at: datetime
    is_worm_locked: bool


class EvidenceBacking(BaseModel):
    """One way an exhibit is attached to the element being inspected."""
    #: 'ASSERTION' (a live claim carries it) or 'LINK' (attached directly).
    kind: str
    assertion_id: str | None = None
    basis: str | None = None
    at: datetime
    by: str
    by_name: str | None = None
    relevance: str | None = None
    page_ref: str | None = None


class ElementEvidenceOut(EvidenceOut):
    """An exhibit behind one element, and every route by which it is.

    Links and assertion-carried exhibits both, from `projections.evidence_backing_sql`: the same
    attachment rule the canvas mark, the coverage figure and the report use."""
    backing: list[EvidenceBacking]
    purged: bool = False
    #: Whether this exhibit makes the element count as evidenced. False
    #: only when it has been purged; everything else listed here counts.
    counts: bool = True
    #: The storage lock as the Evidence pane's card states it, so the inspector's list draws the
    #: same chip rather than a bare "WORM": a lock lapses. Read the way the register reads them
    #: (`routers.evidence.lock_state`).
    lock_until: date | None = None
    lock_ends_at: datetime | None = None
    lock_lapsed: bool = False
    #: The lock ends before the case's retention date, as the register says
    #: (`routers.evidence.lock_is_short`).
    lock_short_of_case: bool = False
    legal_hold: bool = False
    is_hostile_markup: bool = False
    purged_at: datetime | None = None


# --- helpers ------------------------------------------------------------

def _ceiling(conn: psycopg.Connection, user: CurrentUser, case_id: UUID):
    # Every route here reads one case, so a break-glass grant scoped to it counts.
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    return clearance.name, list(compartments)


def _visible_node(conn, case_id, node_id, clearance, compartments) -> bool:
    return conn.execute(
        """SELECT 1 FROM core.node
            WHERE id = %s AND case_id = %s
              AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (node_id, case_id, clearance, compartments),
    ).fetchone() is not None


def _visible_edge(conn, case_id, edge_id, clearance, compartments) -> bool:
    return conn.execute(
        """SELECT 1 FROM core.edge
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (edge_id, case_id, clearance, compartments),
    ).fetchone() is not None


# --- nodes --------------------------------------------------------------

@router.get("/nodes", response_model=list[NodeOut])
def list_nodes(
    case_id: UUID,
    node_type: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[NodeOut]:
    clearance, compartments = _ceiling(conn, user, case_id)
    rows = conn.execute(
        """SELECT id, node_type, label, classification, attrs,
                  """ + seen_sql() + """, created_at, valid_from, valid_to
             FROM core.node n
            WHERE case_id = %s
              AND deleted_at IS NULL AND merged_into_id IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s
              AND (%s::text IS NULL OR node_type = %s)
            ORDER BY created_at DESC LIMIT %s""",
        # seen_sql's binds first: the reader's ceiling gates the merge tree it reads dates over.
        (*seen_params(clearance, compartments),
         case_id, clearance, compartments, node_type, node_type, limit),
    ).fetchall()
    return [
        NodeOut(id=str(r[0]), node_type=r[1], label=r[2], classification=r[3],
                attrs=r[4] or {}, first_seen=r[5], last_seen=r[6], created_at=r[7],
                valid_from=r[8], valid_to=r[9])
        for r in rows
    ]


@router.get("/nodes/{node_id}", response_model=NodeOut)
def get_node(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> NodeOut:
    clearance, compartments = _ceiling(conn, user, case_id)
    row = conn.execute(
        """SELECT id, node_type, label, classification, attrs,
                  """ + seen_sql() + """, created_at, valid_from, valid_to
             FROM core.node n
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (*seen_params(clearance, compartments),
         node_id, case_id, clearance, compartments),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "node does not exist in this case")
    return NodeOut(id=str(row[0]), node_type=row[1], label=row[2],
                   classification=row[3], attrs=row[4] or {}, first_seen=row[5],
                   last_seen=row[6], created_at=row[7], valid_from=row[8],
                   valid_to=row[9])


@router.get("/nodes/{node_id}/assertions", response_model=list[AssertionOut])
def node_assertions(
    case_id: UUID, node_id: UUID,
    include_retracted: bool = Query(False),
    # Paged like every list: a node can gather any number of claims through ordinary writes.
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[AssertionOut]:
    """Why we believe this node. Retracted/superseded claims are hidden by
    default but retrievable — the graph is a projection of CURRENT claims,
    and the history is what makes it defensible later."""
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    doc_clearance, doc_compartments = _document_ceiling(conn, user)
    return _assertions(conn, "node_id", node_id, include_retracted,
                       clearance, compartments,
                       doc_clearance=doc_clearance,
                       doc_compartments=doc_compartments,
                       limit=limit, offset=offset,
                       **_may_name(conn, user, case_id))


@router.get("/nodes/{node_id}/evidence", response_model=list[ElementEvidenceOut])
def node_evidence(
    case_id: UUID, node_id: UUID,
    # Paged by exhibit at `limit`; the scan behind it is the element's own links.
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[ElementEvidenceOut]:
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    return _element_evidence(conn, "node_id", node_id, case_id,
                             clearance, compartments)[offset:offset + limit]


@router.get("/nodes/{node_id}/selectors", response_model=list[dict])
def node_selectors(
    case_id: UUID, node_id: UUID,
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    # first_seen and last_seen travel with the count: core.selector is where an actor's activity
    # window is recorded.
    rows = conn.execute(
        """SELECT selector_type, raw_value, norm_value, observation_cnt,
                  first_seen, last_seen, id
             FROM core.selector WHERE node_id = %s AND case_id = %s
            ORDER BY selector_type LIMIT %s OFFSET %s""",
        (node_id, case_id, limit, offset),
    ).fetchall()
    return [{"selector_type": r[0], "raw_value": r[1], "norm_value": r[2],
             "observation_cnt": r[3],
             "first_seen": r[4].isoformat() if r[4] else None,
             "last_seen": r[5].isoformat() if r[5] else None,
             # The id, so a selector can be looked up, and the entity, so "Look up all" can plan
             # its selectors.
             "id": str(r[6]), "node_id": str(node_id)} for r in rows]


# --- edges --------------------------------------------------------------

@router.get("/edges", response_model=list[EdgeOut])
def list_edges(
    case_id: UUID,
    # le=2000 is the one deliberate exception to the 1000 cap on this router (CONVENTIONS.md): the
    # console draws a whole case from this list and asks for 2000.
    limit: int = Query(500, ge=1, le=2000),
    include_inferred: bool = Query(True),
    node_id: UUID | None = Query(None),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EdgeOut]:
    """Edges with endpoint labels, ready to render. Both endpoints must be visible to the caller,
    or the edge would betray a hidden node.

    `node_id` narrows the list to the ties at one entity, either end, so the inspector lists every
    tie at it even past the page the console loads for the whole case."""
    clearance, compartments = _ceiling(conn, user, case_id)
    rows = conn.execute(
        """SELECT e.id, e.edge_type, e.src_node_id, e.dst_node_id,
                  s.label, d.label, e.sign, e.weight, e.confidence,
                  e.is_inferred, e.review, e.classification,
                  e.valid_from, e.valid_to
             FROM core.edge e
             JOIN core.node s ON s.id = e.src_node_id
             JOIN core.node d ON d.id = e.dst_node_id
            WHERE e.case_id = %s AND e.deleted_at IS NULL
              AND e.classification <= %s::core.tlp AND e.compartments <@ %s
              AND s.deleted_at IS NULL AND d.deleted_at IS NULL
              AND s.classification <= %s::core.tlp AND s.compartments <@ %s
              AND d.classification <= %s::core.tlp AND d.compartments <@ %s
              AND (%s OR NOT e.is_inferred)
              AND (%s::uuid IS NULL OR e.src_node_id = %s OR e.dst_node_id = %s)
            ORDER BY e.created_at DESC LIMIT %s""",
        (case_id, clearance, compartments, clearance, compartments,
         clearance, compartments, include_inferred,
         node_id, node_id, node_id, limit),
    ).fetchall()
    return [
        EdgeOut(id=str(r[0]), edge_type=r[1], src_node_id=str(r[2]),
                dst_node_id=str(r[3]), src_label=r[4], dst_label=r[5],
                sign=r[6], weight=float(r[7]), confidence=r[8],
                is_inferred=r[9], review=r[10], classification=r[11],
                valid_from=r[12], valid_to=r[13])
        for r in rows
    ]


@router.get("/edges/{edge_id}/assertions", response_model=list[AssertionOut])
def edge_assertions(
    case_id: UUID, edge_id: UUID,
    include_retracted: bool = Query(False),
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[AssertionOut]:
    """Why we believe this edge — the one-click provenance answer."""
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_edge(conn, case_id, edge_id, clearance, compartments):
        raise Problem(404, "Not found", "edge does not exist in this case")
    doc_clearance, doc_compartments = _document_ceiling(conn, user)
    return _assertions(conn, "edge_id", edge_id, include_retracted,
                       clearance, compartments,
                       doc_clearance=doc_clearance,
                       doc_compartments=doc_compartments,
                       limit=limit, offset=offset,
                       **_may_name(conn, user, case_id))


@router.get("/edges/{edge_id}/evidence", response_model=list[ElementEvidenceOut])
def edge_evidence(
    case_id: UUID, edge_id: UUID,
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[ElementEvidenceOut]:
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_edge(conn, case_id, edge_id, clearance, compartments):
        raise Problem(404, "Not found", "edge does not exist in this case")
    return _element_evidence(conn, "edge_id", edge_id, case_id,
                             clearance, compartments)[offset:offset + limit]


# --- evidence listing ---------------------------------------------------

@router.get("/evidence-list", response_model=list[EvidenceOut])
def list_evidence(
    case_id: UUID,
    limit: int = Query(200, ge=1, le=1000),
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EvidenceOut]:
    clearance, compartments = _ceiling(conn, user, case_id)
    rows = conn.execute(
        """SELECT id, title, media_type, byte_size, sha256, classification,
                  acquisition_method, acquired_at, is_worm_locked
             FROM core.evidence
            WHERE case_id = %s
              AND classification <= %s::core.tlp AND compartments <@ %s
            ORDER BY acquired_at DESC LIMIT %s""",
        (case_id, clearance, compartments, limit),
    ).fetchall()
    return [_evidence_out(r) for r in rows]


# --- ontology (for pickers) --------------------------------------------

@router.get("/ontology", response_model=dict)
def ontology(
    case_id: UUID,
    _: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Node and edge vocabularies for the UI's pickers, straight from the
    ontology tables so the client can never offer a type the DB rejects."""
    nodes = conn.execute(
        """SELECT key, display_name, category FROM core.node_type
            WHERE is_active ORDER BY sort_order""",
    ).fetchall()
    # `inverse_name` lets the Link form read the chosen type back both ways ("A vouched for B",
    # "B was vouched by A") before the analyst commits to a direction.
    edges = conn.execute(
        """SELECT key, display_name, src_node_types, dst_node_types,
                  default_sign, is_social_tie, inverse_name
             FROM core.edge_type WHERE is_active ORDER BY key""",
    ).fetchall()
    return {
        "node_types": [{"key": r[0], "display_name": r[1], "category": r[2]}
                       for r in nodes],
        "edge_types": [{"key": r[0], "display_name": r[1], "src": list(r[2]),
                        "dst": list(r[3]), "default_sign": r[4],
                        "is_social_tie": r[5], "inverse_name": r[6]}
                       for r in edges],
        # The selector vocabulary for the Add entity form's picker, straight from the ontology
        # package the store normalises with.
        "selector_types": [{"key": s.key, "display_name": s.display_name,
                            "is_strong": s.is_strong}
                           for s in SELECTOR_TYPES],
    }


# --- shared -------------------------------------------------------------

def _may_name(conn, user: CurrentUser, case_id: UUID) -> dict[str, bool]:
    """Whether this caller may be told what an assertion's exhibit and captured document are
    called, by the permission each list demands.

    The assertion endpoints are gated on `case.read`; listing exhibits needs `evidence.read` and
    listing documents the global `collection.read`, so a title returned under `case.read` alone
    would reach a role those lists refuse. No shipped role is such a role; a custom one can be."""
    return {"may_see_exhibits": _allowed_on_case(conn, user, case_id,
                                                 "evidence.read"),
            "may_see_documents": _holds_global(conn, user, "collection.read")}


def _document_ceiling(conn, user: CurrentUser) -> tuple[str, list[str]]:
    """The clearance and compartments a claim's collected document and source are named under:
    the caller's case-less ceiling, which only a global break-glass grant raises, and their own
    compartments, since a capture into a compartmented case carries the case's keys.

    `collect.document` and `collect.source` have no `case_id` and any number of cases cite them,
    so a grant scoped to the case being read must not raise them, as `/collection/documents`, the
    combined case search and watch hits already refuse to. `_ceiling` passes the case, so it is
    not used for them."""
    clearance, held = user_ceiling(conn, user.user_id)
    return clearance.name, sorted(held)


def _assertions(conn, column: str, element_id: UUID,
                include_retracted: bool, clearance: str,
                compartments: list[str], *, doc_clearance: str,
                doc_compartments: list[str],
                may_see_exhibits: bool = False,
                may_see_documents: bool = False,
                limit: int = 1000, offset: int = 0) -> list[AssertionOut]:
    # `column` is a literal chosen by the caller, never client input. Two ceilings: `clearance` is
    # the case-scoped one and binds only the exhibit leg, pinned to this case by
    # `ev.case_id = a.case_id`; `doc_clearance` and `doc_compartments` are the case-less ones and
    # bind the document and source legs, which belong to no case (`_document_ceiling`). They are
    # keyword-only with no default, so a new caller cannot hand the raised ceiling to those rows.
    if column not in ("node_id", "edge_id"):  # not `assert`: stripped under python -O, and this guards SQL text
        raise ValueError("refused identifier outside the allow-list")
    # Each join carries its permission as a bound boolean and the reader's ceiling, so a claim
    # citing an exhibit or document the reader may not see returns its ids and no name. The
    # document leg is `CollectionService.documents`' rule: unpurged, and the document's and its
    # source's labels within the clearance, because a source's name says which forum we read. A
    # claim with a document names its source only through it, so a withheld document never gets
    # its forum named beside it.
    sql = f"""SELECT a.id, a.basis, a.reliability, a.credibility, a.confidence,
                     a.rationale, a.external_ref, a.evidence_id, a.observed_at,
                     a.recorded_at, a.retracted_at, a.superseded_at,
                     a.created_by, a.retraction_reason,
                     a.claim_path, a.claim_value, a.document_id, a.source_id,
                     u.display_name, ev.title,
                     doc.title,
                     CASE WHEN a.document_id IS NULL THEN src.name
                          ELSE doc.source_name END,
                     doc.seen, a.supersedes_id, a.superseded_by
                FROM core.assertion a
                LEFT JOIN iam.app_user u ON u.id = a.created_by
                LEFT JOIN core.evidence ev
                       ON %s AND ev.id = a.evidence_id
                      AND ev.case_id = a.case_id
                      AND ev.classification <= %s::core.tlp
                      AND ev.compartments <@ %s
                LEFT JOIN LATERAL (
                     SELECT d.title, s.name AS source_name, true AS seen
                       FROM collect.document d
                       JOIN collect.source s ON s.id = d.source_id
                      WHERE %s AND d.id = a.document_id
                        AND d.purged_at IS NULL
                        AND d.classification <= %s::core.tlp
                        AND s.classification <= %s::core.tlp
                        AND d.compartments <@ %s::text[]
                        AND s.compartments <@ %s::text[]) doc ON true
                LEFT JOIN collect.source src
                       ON %s AND src.id = a.source_id
                      AND src.classification <= %s::core.tlp
                      AND src.compartments <@ %s::text[]
               WHERE a.{column} = %s"""
    if not include_retracted:
        sql += " AND a.retracted_at IS NULL AND a.superseded_at IS NULL"
    sql += " ORDER BY a.recorded_at DESC LIMIT %s OFFSET %s"
    # The source's own compartments, on both legs, are held to the reader's as the document's are.
    rows = conn.execute(sql, (
        may_see_exhibits, clearance, compartments,
        may_see_documents, doc_clearance, doc_clearance, doc_compartments,
        doc_compartments,
        may_see_documents, doc_clearance, doc_compartments,
        element_id, limit, offset)).fetchall()

    return [
        AssertionOut(
            id=str(r[0]), basis=r[1], reliability=r[2], credibility=r[3],
            confidence=r[4], rationale=r[5], external_ref=r[6],
            evidence_id=str(r[7]) if r[7] else None, observed_at=r[8],
            recorded_at=r[9], retracted_at=r[10], superseded_at=r[11],
            created_by=str(r[12]), retraction_reason=r[13],
            claim_path=r[14], claim_value=r[15],
            document_id=str(r[16]) if r[16] else None,
            source_id=str(r[17]) if r[17] else None,
            created_by_name=r[18], evidence_title=r[19],
            # '' for a readable document with no title, so the console can
            # say "(untitled)" rather than treat it as withheld.
            document_title=(r[20] or "") if r[22] else None,
            source_name=r[21],
            is_correction=is_correction(r[14], r[15]),
            supersedes_id=str(r[23]) if r[23] else None,
            superseded_by=str(r[24]) if r[24] else None,
        )
        for r in rows
    ]


def _element_evidence(conn, column: str, element_id: UUID, case_id: UUID,
                      clearance: str, compartments: list[str],
                      ) -> list[ElementEvidenceOut]:
    """Every exhibit the reader may see behind one element, grouped, with
    the route(s) by which each is attached.

    Built on `projections.evidence_backing_sql`, the attachment rule the
    projection's `has_evidence` uses, and filtered by the same ceiling, so
    this list is non-empty with a counting exhibit exactly when the canvas
    draws the element as evidenced. test_evidenced_pg.py holds the two to
    that across every case the rule distinguishes."""
    rows = conn.execute(
        f"""SELECT e.id, e.title, e.media_type, e.byte_size, e.sha256,
                   e.classification, e.acquisition_method, e.acquired_at,
                   e.is_worm_locked, e.purged_at,
                   b.kind, b.assertion_id, b.basis, b.at, b.by_user,
                   u.display_name, b.relevance, b.page_ref,
                   e.retention_until, e.legal_hold, e.is_hostile_markup,
                   lk.lock_ends_at
              FROM ({evidence_backing_sql(column, '%s')}) b
              JOIN core.evidence e ON e.id = b.evidence_id
              LEFT JOIN iam.app_user u ON u.id = b.by_user
              -- The lock's newest end, as the register reads it.
              {NEWEST_LOCK_SQL.format(ev='e')}
             WHERE e.case_id = %s
               AND e.classification <= %s::core.tlp AND e.compartments <@ %s
             ORDER BY e.acquired_at DESC, e.id, b.at""",
        (element_id, element_id, case_id, clearance, compartments),
    ).fetchall()
    now = datetime.now(timezone.utc)
    short_before, _ = case_lock_bounds(conn, case_id, now) if rows else (None, None)
    out: dict[str, ElementEvidenceOut] = {}
    for r in rows:
        key = str(r[0])
        if key not in out:
            base = _evidence_out(r[:9])
            ends_at, lapsed = lock_state(r[18], {"lock_ends_at": r[21]}, now)
            out[key] = ElementEvidenceOut(
                **base.model_dump(), backing=[], purged=r[9] is not None,
                counts=r[9] is None, lock_until=r[18], lock_ends_at=ends_at,
                lock_lapsed=lapsed,
                lock_short_of_case=(bool(r[8]) and r[9] is None and lock_is_short(
                    r[18], ends_at, short_before)),
                legal_hold=bool(r[19]),
                is_hostile_markup=bool(r[20]), purged_at=r[9])
        out[key].backing.append(EvidenceBacking(
            kind=r[10], assertion_id=str(r[11]) if r[11] else None,
            basis=r[12], at=r[13], by=str(r[14]), by_name=r[15],
            relevance=r[16], page_ref=r[17]))
    return list(out.values())


def _evidence_out(r) -> EvidenceOut:
    return EvidenceOut(
        id=str(r[0]), title=r[1], media_type=r[2], byte_size=r[3],
        sha256=bytes(r[4]).hex(), classification=r[5], acquisition_method=r[6],
        acquired_at=r[7], is_worm_locked=r[8],
    )
