"""Graph write endpoints — every create goes through GraphWriteService, so
an assertion is written in the same transaction (invariant 1).

Retraction lives here too. It is the operation that makes the assertion
model mean something: retracting the last live assertion behind an element
makes it dissolve from the live graph (`GraphService.project()` requires a
non-retracted assertion) while its row and history survive for temporal
replay. Nothing is ever deleted — invariant 5.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    get_conn,
    require,
)
from noctornal_api.http.errors import Problem

router = APIRouter(prefix="/cases/{case_id}", tags=["graph"])


class AssertionBody(BaseModel):
    basis: str = "DIRECT_OBSERVATION"
    reliability: str = "F"
    credibility: str = "6"
    confidence: str = "LOW"
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
    assertion: AssertionBody = AssertionBody()
    # U3: the interval this was true in WORLD time. "Was in LockBit until
    # March" is the normal case, not the exception, and the timeline
    # scrubber and trust decay both have nothing to work with without it.
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class CreateEdgeBody(BaseModel):
    edge_type: str
    src_node_id: UUID
    dst_node_id: UUID
    classification: str = "AMBER"
    assertion: AssertionBody = AssertionBody()
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class AddAssertionBody(AssertionBody):
    """Another assertion on an existing element. This is how disagreement
    is represented without forcing consensus (docs/01): two analysts, two
    claims, both recorded."""


class RetractBody(BaseModel):
    reason: str = Field(min_length=1)


class IdOut(BaseModel):
    id: str


def _assertion(body: AssertionBody, created_by: UUID) -> AssertionInput:
    return AssertionInput(
        basis=body.basis, created_by=created_by, reliability=body.reliability,
        credibility=body.credibility, confidence=body.confidence,
        rationale=body.rationale, evidence_id=body.evidence_id,
        external_ref=body.external_ref, observed_at=body.observed_at,
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


@router.post("/nodes", response_model=IdOut, status_code=201)
def create_node(case_id: UUID, body: CreateNodeBody,
                user: CurrentUser = Depends(require("graph.node.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
    check_writable_labels(conn, user, classification=body.classification)
    _check_evidence(conn, case_id, body.assertion.evidence_id)
    _interval_sane(body.valid_from, body.valid_to)
    node_id = GraphWriteService(conn).create_node(
        case_id=case_id, node_type=body.node_type, label=body.label,
        created_by=user.user_id, assertion=_assertion(body.assertion, user.user_id),
        attrs=body.attrs, classification=body.classification,
        valid_from=body.valid_from, valid_to=body.valid_to,
    )
    return IdOut(id=str(node_id))


@router.post("/edges", response_model=IdOut, status_code=201)
def create_edge(case_id: UUID, body: CreateEdgeBody,
                user: CurrentUser = Depends(require("graph.edge.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
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
    row = conn.execute(
        f"SELECT case_id, classification, compartments "
        f"  FROM core.{table} WHERE id = %s", (element_id,)
    ).fetchone()
    if row is None:
        return None
    return row[0], row[1], frozenset(row[2] or [])


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
    authorize_object(conn, user, case_id=case_id,
                     permission_key="assertion.create",
                     classification=found[1], compartments=found[2])
    _check_evidence(conn, case_id, body.evidence_id)
    try:
        aid = GraphWriteService(conn).add_assertion(
            case_id=case_id, assertion=_assertion(body, user.user_id),
            node_id=node_id, edge_id=edge_id,
        )
    except GraphWriteError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
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
    History survives, so an `as_of` earlier than the retraction still shows
    the element as it stood.
    """
    from fastapi import Response
    row = conn.execute(
        "SELECT case_id, node_id, edge_id FROM core.assertion WHERE id = %s",
        (assertion_id,),
    ).fetchone()
    if row is None or row[0] != case_id:
        raise Problem(404, "Not found", "no such assertion in this case")
    # CR7: the element's own labels gate the retraction. Retracting the
    # last live assertion dissolves the element from every projection, so
    # this endpoint destroys graph structure — it must not be reachable by
    # a caller who could not see what they are destroying.
    subject = _element_labels(conn, "node" if row[1] else "edge",
                              row[1] or row[2]) if (row[1] or row[2]) else None
    if subject is not None:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="assertion.retract",
                         classification=subject[1], compartments=subject[2])
    try:
        GraphWriteService(conn).retract_assertion(
            assertion_id, retracted_by=user.user_id, reason=body.reason,
            at=datetime.now(timezone.utc),
        )
    except GraphWriteError as exc:
        # Already retracted, or gone. Saying so is better than a silent
        # 204 that leaves a burned source live in the projection.
        raise Problem(409, "Conflict", str(exc)) from exc
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, 'USER', 'ASSERTION_RETRACTED', 'assertion', %s, %s, %s)""",
        (user.user_id, assertion_id, case_id, Json({"reason": body.reason})),
    )
    return Response(status_code=204)
