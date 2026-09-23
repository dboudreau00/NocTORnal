"""Graph read endpoints — listing, detail, and the provenance answer.

Everything here filters by the CALLER's own clearance and compartments, not
the case's: an element may be classified above its case, so case-level
authorization alone would disclose labels the caller may not see (the leak
the HTTP review found in search). Soft-deleted and merged-away nodes are
excluded.

`GET .../nodes/{id}/assertions` and the edge equivalent are the Phase 1
bar: every element answers "why do we believe this?" in one request —
source, Admiralty grading, analyst confidence, rationale, and whether the
claim has been retracted or superseded.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.errors import Problem

# The five-part gate asked as a question rather than raised as a refusal.
# Reused, not re-decided: `search` already answers "may this caller see
# exhibits / collected documents too?" for its combined results, and a
# second copy of an authorization rule is how two of them drift apart.
from noctornal_api.http.routers.search import _allowed_on_case, _holds_global
from noctornal_api.projections import evidence_backing_sql

router = APIRouter(prefix="/cases/{case_id}", tags=["read"])


# --- models -------------------------------------------------------------

class NodeOut(BaseModel):
    id: str
    node_type: str
    label: str
    classification: str
    attrs: dict
    first_seen: datetime | None
    last_seen: datetime | None
    created_at: datetime
    # World-time validity, which the entity form records and the inspector
    # never showed: an edge printed only its start and a node nothing at
    # all (ux05-inspector:dates-shift-a-day, 2026-09-22).
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
    # ux05 assertion-drops-claim-and-source (2026-09-22). "Why is this
    # believed" needs WHAT was claimed, FROM what and BY whom, and this
    # model carried none of the three: a label correction rendered as an
    # ungraded "Direct observation", a triage-accepted attribute showed no
    # attribute and no value, and the author was an 8-character hash.
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
    #: The carried exhibit's title, ONLY when the reader may see that
    #: exhibit: `evidence.read` on the case (what listing exhibits needs)
    #: AND the exhibit within the reader's clearance and compartments.
    #: None otherwise, so an exhibit's title never leaves through a claim
    #: that cites it to someone the exhibit list would refuse.
    evidence_title: str | None = None
    #: The captured document's title ('' when it has none) and its
    #: collection source's name, under exactly the rule
    #: `GET /collection/documents` applies: the global `collection.read`,
    #: the document unpurged, and BOTH the document's and the source's
    #: labels within the reader's CASE-LESS clearance, which a break-glass
    #: grant on this case does not raise (final review C11, 2026-09-23;
    #: `_document_ceiling`). None when any leg fails, so
    #: the ids above are all such a reader gets, as before 2026-09-22. A
    #: claim that cites a document names its source only through it.
    document_title: str | None = None
    source_name: str | None = None
    #: True when this assertion records a CORRECTION made through
    #: `PATCH /graph/nodes|edges/{id}` rather than a claim about the world
    #: arriving from a source. See `CORRECTION_FIELDS`.
    is_correction: bool = False

    @property
    def is_live(self) -> bool:
        return self.retracted_at is None and self.superseded_at is None


#: The fields `PATCH /graph/nodes/{id}` and `PATCH /graph/edges/{id}` can
#: change (routers/graph.py, UpdateNodeBody and UpdateEdgeBody). A
#: correction's assertion names ONE of them in `claim_path`, or leaves the
#: path empty and carries several in `claim_value` (`_claim_path` there).
#: Attribute claims from triage and the contact-block parser use dotted
#: paths ('attrs.role', 'comms.tox'), so the two cannot be confused.
#: test_evidenced_pg.py pins this set to the two request bodies.
CORRECTION_FIELDS = frozenset({"label", "attrs", "weight", "confidence"})


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

    ux05 linked-evidence-vs-evidenced (2026-09-22): this list used to read
    `core.evidence_link` alone while the canvas counted assertion-carried
    exhibits alone. It now lists both, from `projections.
    evidence_backing_sql`, the same attachment rule the canvas mark, the
    coverage figure and the report use."""
    backing: list[EvidenceBacking]
    purged: bool = False
    #: Whether this exhibit makes the element count as evidenced. False
    #: only when it has been purged; everything else listed here counts.
    counts: bool = True


# --- helpers ------------------------------------------------------------

def _ceiling(conn: psycopg.Connection, user: CurrentUser, case_id: UUID):
    # Every route here reads ONE case, so a break-glass grant scoped to it
    # counts (ux15 breakglass-grant-raises-nothing, 2026-09-23).
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
                  first_seen, last_seen, created_at, valid_from, valid_to
             FROM core.node
            WHERE case_id = %s
              AND deleted_at IS NULL AND merged_into_id IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s
              AND (%s::text IS NULL OR node_type = %s)
            ORDER BY created_at DESC LIMIT %s""",
        (case_id, clearance, compartments, node_type, node_type, limit),
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
                  first_seen, last_seen, created_at, valid_from, valid_to
             FROM core.node
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (node_id, case_id, clearance, compartments),
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
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[AssertionOut]:
    """Why we believe this node. Retracted/superseded claims are hidden by
    default but retrievable — the graph is a projection of CURRENT claims,
    and the history is what makes it defensible later."""
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    return _assertions(conn, "node_id", node_id, include_retracted,
                       clearance, compartments,
                       doc_clearance=_document_ceiling(conn, user),
                       **_may_name(conn, user, case_id))


@router.get("/nodes/{node_id}/evidence", response_model=list[ElementEvidenceOut])
def node_evidence(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[ElementEvidenceOut]:
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    return _element_evidence(conn, "node_id", node_id, case_id,
                             clearance, compartments)


@router.get("/nodes/{node_id}/selectors", response_model=list[dict])
def node_selectors(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    rows = conn.execute(
        """SELECT selector_type, raw_value, norm_value, observation_cnt
             FROM core.selector WHERE node_id = %s AND case_id = %s
            ORDER BY selector_type""",
        (node_id, case_id),
    ).fetchall()
    return [{"selector_type": r[0], "raw_value": r[1], "norm_value": r[2],
             "observation_cnt": r[3]} for r in rows]


# --- edges --------------------------------------------------------------

@router.get("/edges", response_model=list[EdgeOut])
def list_edges(
    case_id: UUID,
    limit: int = Query(500, ge=1, le=2000),
    include_inferred: bool = Query(True),
    node_id: UUID | None = Query(None),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EdgeOut]:
    """Edges with endpoint labels, ready to render. Both endpoints must be
    visible to the caller, or the edge would betray a hidden node.

    `node_id` narrows the list to the ties AT one entity, either end. The
    inspector's Relationships section says it lists every tie at the
    entity, and the case-wide page the console loads stops at 1000, so in
    a larger case the ties past that page were silently missing from it
    (the 2026-09-22 verifier, on ux05 parallel-ties-unreachable)."""
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
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[AssertionOut]:
    """Why we believe this edge — the one-click provenance answer."""
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_edge(conn, case_id, edge_id, clearance, compartments):
        raise Problem(404, "Not found", "edge does not exist in this case")
    return _assertions(conn, "edge_id", edge_id, include_retracted,
                       clearance, compartments,
                       doc_clearance=_document_ceiling(conn, user),
                       **_may_name(conn, user, case_id))


@router.get("/edges/{edge_id}/evidence", response_model=list[ElementEvidenceOut])
def edge_evidence(
    case_id: UUID, edge_id: UUID,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[ElementEvidenceOut]:
    clearance, compartments = _ceiling(conn, user, case_id)
    if not _visible_edge(conn, case_id, edge_id, clearance, compartments):
        raise Problem(404, "Not found", "edge does not exist in this case")
    return _element_evidence(conn, "edge_id", edge_id, case_id,
                             clearance, compartments)


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
    edges = conn.execute(
        """SELECT key, display_name, src_node_types, dst_node_types,
                  default_sign, is_social_tie
             FROM core.edge_type WHERE is_active ORDER BY key""",
    ).fetchall()
    return {
        "node_types": [{"key": r[0], "display_name": r[1], "category": r[2]}
                       for r in nodes],
        "edge_types": [{"key": r[0], "display_name": r[1], "src": list(r[2]),
                        "dst": list(r[3]), "default_sign": r[4],
                        "is_social_tie": r[5]} for r in edges],
    }


# --- shared -------------------------------------------------------------

def _may_name(conn, user: CurrentUser, case_id: UUID) -> dict[str, bool]:
    """Whether this caller may be told what an assertion's exhibit and
    captured document are CALLED, by the permission each list demands.

    The assertion endpoints are gated on `case.read`. Listing exhibits
    needs `evidence.read` and listing collected documents needs the global
    `collection.read`, so a title returned here under `case.read` alone
    would reach a role those lists refuse. No shipped role holds case.read
    without evidence.read today; the gate is here so a custom one cannot
    (the 2026-09-22 verifier's point on ux05 assertion-drops-claim-and-
    source)."""
    return {"may_see_exhibits": _allowed_on_case(conn, user, case_id,
                                                 "evidence.read"),
            "may_see_documents": _holds_global(conn, user, "collection.read")}


def _document_ceiling(conn, user: CurrentUser) -> str:
    """The clearance a claim's collected document and source are named
    under: the caller's CASE-LESS ceiling, which only a global break-glass
    grant raises.

    `collect.document` and `collect.source` have no `case_id`. They hang
    off a source that any number of cases cite, so a grant scoped to the
    case being read must not raise them, exactly as `/collection/documents`,
    the combined case search and watch hits already refuse to. `_ceiling`
    passes the case, and until final review C11 (2026-09-23) that raised
    clearance reached these joins too: a Lead investigator under a RED
    grant on case A was told a RED document's title and a RED forum's name
    in the inspector that every collection view still withheld from them,
    and that case B cites as well."""
    return user_ceiling(conn, user.user_id)[0].name


def _assertions(conn, column: str, element_id: UUID,
                include_retracted: bool, clearance: str,
                compartments: list[str], *, doc_clearance: str,
                may_see_exhibits: bool = False,
                may_see_documents: bool = False) -> list[AssertionOut]:
    # `column` is a literal chosen by the caller (never client input), so
    # the interpolation cannot be influenced from outside.
    #
    # Two ceilings, deliberately. `clearance` is the case-scoped one and
    # binds only the exhibit leg, which is pinned to this case by
    # `ev.case_id = a.case_id`. `doc_clearance` is the case-less one and
    # binds the document and source legs, which belong to no case (see
    # `_document_ceiling`). Keyword-only with no default, so a new caller
    # cannot quietly hand the raised ceiling to the deployment-wide rows.
    assert column in ("node_id", "edge_id")
    # Each join carries its permission as a bound boolean AND the READER's
    # ceiling, so a claim citing an exhibit or a document the reader may
    # not see returns the ids it always returned and no name. The document
    # leg is `CollectionService.documents`' rule: unpurged, and both the
    # document's and its source's labels within the clearance, because a
    # source's name is how sensitive it is that we read that forum at all.
    # A claim WITH a document names its source only through that document,
    # so a withheld document never gets its forum named beside it.
    sql = f"""SELECT a.id, a.basis, a.reliability, a.credibility, a.confidence,
                     a.rationale, a.external_ref, a.evidence_id, a.observed_at,
                     a.recorded_at, a.retracted_at, a.superseded_at,
                     a.created_by, a.retraction_reason,
                     a.claim_path, a.claim_value, a.document_id, a.source_id,
                     u.display_name, ev.title,
                     doc.title,
                     CASE WHEN a.document_id IS NULL THEN src.name
                          ELSE doc.source_name END,
                     doc.seen
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
                        AND s.classification <= %s::core.tlp) doc ON true
                LEFT JOIN collect.source src
                       ON %s AND src.id = a.source_id
                      AND src.classification <= %s::core.tlp
               WHERE a.{column} = %s"""
    if not include_retracted:
        sql += " AND a.retracted_at IS NULL AND a.superseded_at IS NULL"
    sql += " ORDER BY a.recorded_at DESC"
    rows = conn.execute(sql, (
        may_see_exhibits, clearance, compartments,
        may_see_documents, doc_clearance, doc_clearance,
        may_see_documents, doc_clearance,
        element_id)).fetchall()
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
                   u.display_name, b.relevance, b.page_ref
              FROM ({evidence_backing_sql(column, '%s')}) b
              JOIN core.evidence e ON e.id = b.evidence_id
              LEFT JOIN iam.app_user u ON u.id = b.by_user
             WHERE e.case_id = %s
               AND e.classification <= %s::core.tlp AND e.compartments <@ %s
             ORDER BY e.acquired_at DESC, e.id, b.at""",
        (element_id, element_id, case_id, clearance, compartments),
    ).fetchall()
    out: dict[str, ElementEvidenceOut] = {}
    for r in rows:
        key = str(r[0])
        if key not in out:
            base = _evidence_out(r[:9])
            out[key] = ElementEvidenceOut(
                **base.model_dump(), backing=[], purged=r[9] is not None,
                counts=r[9] is None)
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
