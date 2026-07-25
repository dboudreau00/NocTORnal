"""Graph write endpoints — every create goes through GraphWriteService, so
an assertion is written in the same transaction (invariant 1)."""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from noctornal_api.graph import AssertionInput, GraphWriteService
from noctornal_api.http.deps import (
    CurrentUser,
    check_writable_labels,
    get_conn,
    require,
)

router = APIRouter(prefix="/cases/{case_id}", tags=["graph"])


class AssertionBody(BaseModel):
    basis: str = "DIRECT_OBSERVATION"
    reliability: str = "F"
    credibility: str = "6"
    confidence: str = "LOW"
    rationale: str | None = None


class CreateNodeBody(BaseModel):
    node_type: str
    label: str
    classification: str = "AMBER"
    attrs: dict = {}
    assertion: AssertionBody = AssertionBody()


class CreateEdgeBody(BaseModel):
    edge_type: str
    src_node_id: UUID
    dst_node_id: UUID
    classification: str = "AMBER"
    assertion: AssertionBody = AssertionBody()


class IdOut(BaseModel):
    id: str


def _assertion(body: AssertionBody, created_by: UUID) -> AssertionInput:
    return AssertionInput(
        basis=body.basis, created_by=created_by, reliability=body.reliability,
        credibility=body.credibility, confidence=body.confidence,
        rationale=body.rationale,
    )


@router.post("/nodes", response_model=IdOut, status_code=201)
def create_node(case_id: UUID, body: CreateNodeBody,
                user: CurrentUser = Depends(require("graph.node.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
    check_writable_labels(conn, user, classification=body.classification)
    node_id = GraphWriteService(conn).create_node(
        case_id=case_id, node_type=body.node_type, label=body.label,
        created_by=user.user_id, assertion=_assertion(body.assertion, user.user_id),
        attrs=body.attrs, classification=body.classification,
    )
    return IdOut(id=str(node_id))


@router.post("/edges", response_model=IdOut, status_code=201)
def create_edge(case_id: UUID, body: CreateEdgeBody,
                user: CurrentUser = Depends(require("graph.edge.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
    check_writable_labels(conn, user, classification=body.classification)
    edge_id = GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type=body.edge_type, src_node_id=body.src_node_id,
        dst_node_id=body.dst_node_id, created_by=user.user_id,
        assertion=_assertion(body.assertion, user.user_id),
        classification=body.classification,
    )
    return IdOut(id=str(edge_id))
