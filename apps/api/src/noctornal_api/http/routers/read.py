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

    @property
    def is_live(self) -> bool:
        return self.retracted_at is None and self.superseded_at is None


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


# --- helpers ------------------------------------------------------------

def _ceiling(conn: psycopg.Connection, user: CurrentUser):
    clearance, compartments = user_ceiling(conn, user.user_id)
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
    clearance, compartments = _ceiling(conn, user)
    rows = conn.execute(
        """SELECT id, node_type, label, classification, attrs,
                  first_seen, last_seen, created_at
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
                attrs=r[4] or {}, first_seen=r[5], last_seen=r[6], created_at=r[7])
        for r in rows
    ]


@router.get("/nodes/{node_id}", response_model=NodeOut)
def get_node(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> NodeOut:
    clearance, compartments = _ceiling(conn, user)
    row = conn.execute(
        """SELECT id, node_type, label, classification, attrs,
                  first_seen, last_seen, created_at
             FROM core.node
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (node_id, case_id, clearance, compartments),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "node does not exist in this case")
    return NodeOut(id=str(row[0]), node_type=row[1], label=row[2],
                   classification=row[3], attrs=row[4] or {}, first_seen=row[5],
                   last_seen=row[6], created_at=row[7])


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
    clearance, compartments = _ceiling(conn, user)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    return _assertions(conn, "node_id", node_id, include_retracted)


@router.get("/nodes/{node_id}/evidence", response_model=list[EvidenceOut])
def node_evidence(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EvidenceOut]:
    clearance, compartments = _ceiling(conn, user)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "node does not exist in this case")
    rows = conn.execute(
        """SELECT e.id, e.title, e.media_type, e.byte_size, e.sha256,
                  e.classification, e.acquisition_method, e.acquired_at,
                  e.is_worm_locked
             FROM core.evidence e
             JOIN core.evidence_link l ON l.evidence_id = e.id
            WHERE l.node_id = %s AND e.case_id = %s
              AND e.classification <= %s::core.tlp AND e.compartments <@ %s
            ORDER BY e.acquired_at DESC""",
        (node_id, case_id, clearance, compartments),
    ).fetchall()
    return [_evidence_out(r) for r in rows]


@router.get("/nodes/{node_id}/selectors", response_model=list[dict])
def node_selectors(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    clearance, compartments = _ceiling(conn, user)
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
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EdgeOut]:
    """Edges with endpoint labels, ready to render. Both endpoints must be
    visible to the caller, or the edge would betray a hidden node."""
    clearance, compartments = _ceiling(conn, user)
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
            ORDER BY e.created_at DESC LIMIT %s""",
        (case_id, clearance, compartments, clearance, compartments,
         clearance, compartments, include_inferred, limit),
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
    clearance, compartments = _ceiling(conn, user)
    if not _visible_edge(conn, case_id, edge_id, clearance, compartments):
        raise Problem(404, "Not found", "edge does not exist in this case")
    return _assertions(conn, "edge_id", edge_id, include_retracted)


@router.get("/edges/{edge_id}/evidence", response_model=list[EvidenceOut])
def edge_evidence(
    case_id: UUID, edge_id: UUID,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EvidenceOut]:
    clearance, compartments = _ceiling(conn, user)
    if not _visible_edge(conn, case_id, edge_id, clearance, compartments):
        raise Problem(404, "Not found", "edge does not exist in this case")
    rows = conn.execute(
        """SELECT e.id, e.title, e.media_type, e.byte_size, e.sha256,
                  e.classification, e.acquisition_method, e.acquired_at,
                  e.is_worm_locked
             FROM core.evidence e
             JOIN core.evidence_link l ON l.evidence_id = e.id
            WHERE l.edge_id = %s AND e.case_id = %s
              AND e.classification <= %s::core.tlp AND e.compartments <@ %s
            ORDER BY e.acquired_at DESC""",
        (edge_id, case_id, clearance, compartments),
    ).fetchall()
    return [_evidence_out(r) for r in rows]


# --- evidence listing ---------------------------------------------------

@router.get("/evidence-list", response_model=list[EvidenceOut])
def list_evidence(
    case_id: UUID,
    limit: int = Query(200, ge=1, le=1000),
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[EvidenceOut]:
    clearance, compartments = _ceiling(conn, user)
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

def _assertions(conn, column: str, element_id: UUID,
                include_retracted: bool) -> list[AssertionOut]:
    # `column` is a literal chosen by the caller (never client input), so
    # the interpolation cannot be influenced from outside.
    assert column in ("node_id", "edge_id")
    sql = f"""SELECT id, basis, reliability, credibility, confidence, rationale,
                     external_ref, evidence_id, observed_at, recorded_at,
                     retracted_at, superseded_at, created_by, retraction_reason
                FROM core.assertion WHERE {column} = %s"""
    if not include_retracted:
        sql += " AND retracted_at IS NULL AND superseded_at IS NULL"
    sql += " ORDER BY recorded_at DESC"
    rows = conn.execute(sql, (element_id,)).fetchall()
    return [
        AssertionOut(
            id=str(r[0]), basis=r[1], reliability=r[2], credibility=r[3],
            confidence=r[4], rationale=r[5], external_ref=r[6],
            evidence_id=str(r[7]) if r[7] else None, observed_at=r[8],
            recorded_at=r[9], retracted_at=r[10], superseded_at=r[11],
            created_by=str(r[12]), retraction_reason=r[13],
        )
        for r in rows
    ]


def _evidence_out(r) -> EvidenceOut:
    return EvidenceOut(
        id=str(r[0]), title=r[1], media_type=r[2], byte_size=r[3],
        sha256=bytes(r[4]).hex(), classification=r[5], acquisition_method=r[6],
        acquired_at=r[7], is_worm_locked=r[8],
    )
