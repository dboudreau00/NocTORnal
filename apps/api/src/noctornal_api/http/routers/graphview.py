"""Phase 2 graph endpoints: projections, ego networks, paths, metrics and
saved layouts.

Everything is derived from a Projection so the parameters that produced a
number travel with it — docs/03 is emphatic that a metric without its
projection is meaningless.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.http.deps import CurrentUser, get_conn, require, user_ceiling
from noctornal_api.http.errors import Problem
from noctornal_api.projections import (
    PRESETS,
    GraphService,
    Projection,
    ProjectionError,
)

from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/graph", tags=["graph-view"])


def _svc(conn: psycopg.Connection, user: CurrentUser) -> GraphService:
    clearance, compartments = user_ceiling(conn, user.user_id)
    return GraphService(conn, clearance=clearance.name, compartments=compartments)


def _projection(case_id: UUID, preset: str, include_inferred: bool,
                min_confidence: str, as_of: datetime | None) -> Projection:
    if preset not in PRESETS:
        raise Problem(400, "Invalid request",
                      f"unknown preset {preset!r}; one of "
                      f"{', '.join(sorted(PRESETS))}")
    return Projection(case_id=case_id, preset=preset,
                      include_inferred=include_inferred,
                      min_confidence=min_confidence, as_of=as_of)


@router.get("/presets", response_model=dict)
def presets(
    case_id: UUID,
    _: CurrentUser = Depends(require("case.read")),
) -> dict:
    """The four projection presets, with the reason each exists — the point
    is that leadership differs between them, and that difference is a
    finding."""
    return {
        "presets": [
            {"key": k, "label": v["label"], "description": v["description"],
             "edge_types": v["edge_types"]}
            for k, v in PRESETS.items()
        ]
    }


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def projected_graph(
    case_id: UUID,
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
    limit: int = Query(2000, ge=1, le=5000),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    svc = _svc(conn, user)
    try:
        sub = svc.project(p, limit=limit)
        # docs/14 U2. Computed here and not inside project(), because ego,
        # path and metrics all call project() internally and would otherwise
        # each pay for two aggregates to answer a question nobody asked.
        withheld = svc.withheld(p)
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {
        "projection": sub.projection,
        "truncated": sub.truncated,
        # Absent entirely when the case discloses nothing -- "withheld:
        # false" would itself be an answer.
        **({"withheld": withheld.as_response()} if withheld.as_response() else {}),
        "nodes": [{**n, "id": str(n["id"])} for n in sub.nodes],
        "edges": [{**e, "id": str(e["id"]),
                   "src_node_id": str(e["src_node_id"]),
                   "dst_node_id": str(e["dst_node_id"])} for e in sub.edges],
    }


@router.get("/ego/{node_id}", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def ego(
    case_id: UUID, node_id: UUID,
    depth: int = Query(1, ge=1, le=4),
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    try:
        sub = _svc(conn, user).ego(p, node_id, depth)
    except ProjectionError as exc:
        # A centre the caller cannot see must not be distinguishable from one
        # that does not exist.
        raise Problem(404, "Not found", "node is not in this projection") from exc
    return {
        "projection": sub.projection,
        "nodes": [{**n, "id": str(n["id"])} for n in sub.nodes],
        "edges": [{**e, "id": str(e["id"]),
                   "src_node_id": str(e["src_node_id"]),
                   "dst_node_id": str(e["dst_node_id"])} for e in sub.edges],
    }


@router.get("/path", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def path(
    case_id: UUID,
    src: UUID = Query(...),
    dst: UUID = Query(...),
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Shortest path between two entities — the shift-click interaction.
    Treated as undirected: "how are these two connected" does not care which
    way an edge points."""
    p = _projection(case_id, preset, include_inferred, min_confidence, None)
    try:
        found = _svc(conn, user).shortest_path(p, src, dst)
    except ProjectionError as exc:
        raise Problem(404, "Not found", "both endpoints must be visible") from exc
    return {"projection": p.describe(),
            "path": [str(n) for n in found],
            "hops": max(0, len(found) - 1),
            "connected": bool(found)}


# Adversarial review found this unmetered while `analytics.suite` was
# metered: same `analytics.run` permission, comparable work, and no
# result cache -- the analytics door was locked and this window was open.
# It shares the suite's budget deliberately.
@router.get("/metrics", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.suite"))])
def metrics(
    case_id: UUID,
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Degree, weighted/signed degree, clustering and k-core over the
    projection. Gated on analytics.run, and the projection parameters travel
    with the answer."""
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    try:
        return _svc(conn, user).metrics(p)
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc


# --- saved layout -------------------------------------------------------

class LayoutPosition(BaseModel):
    node_id: UUID
    x: float
    y: float
    is_pinned: bool = False


class LayoutBody(BaseModel):
    # Bounded. An unbounded list meant one request could pin megabytes of
    # JSON in memory and drive an unbounded loop of INSERTs, all behind a
    # permission an ordinary analyst holds. 20k is far above the largest
    # case this tool is built for (docs/03 bands stop at 5k nodes) and far
    # below anything that hurts.
    positions: list[LayoutPosition] = Field(max_length=20_000)


def _layout_projection_id(conn: psycopg.Connection, case_id: UUID,
                          user_id: UUID) -> UUID:
    """Layouts hang off analytics.projection. One row per case named
    '__layout__' backs the saved canvas, so an analyst's spatial memory
    survives a reload without needing the full projection-management UI
    (docs/06: people navigate these graphs spatially)."""
    # One atomic statement, not SELECT-then-INSERT. Migration 0026 added
    # UNIQUE (case_id, name), which turned this read-modify-write's race
    # from a duplicate row into a unique violation: two concurrent layout
    # saves for a case with no layout row would leave the loser with an
    # unhandled integrity error.
    return conn.execute(
        """INSERT INTO analytics.projection
               (id, case_id, name, edge_types, created_by)
           VALUES (%s, %s, '__layout__', '{}', %s)
           ON CONFLICT (case_id, name) DO UPDATE SET name = EXCLUDED.name
           RETURNING id""",
        (uuid4(), case_id, user_id),
    ).fetchone()[0]


@router.get("/layout", response_model=list[LayoutPosition])
def get_layout(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[LayoutPosition]:
    row = conn.execute(
        """SELECT id FROM analytics.projection
            WHERE case_id = %s AND name = '__layout__'""",
        (case_id,),
    ).fetchone()
    if row is None:
        return []
    rows = conn.execute(
        """SELECT node_id, x, y, is_pinned FROM analytics.layout_position
            WHERE projection_id = %s""",
        (row[0],),
    ).fetchall()
    return [LayoutPosition(node_id=r[0], x=r[1], y=r[2], is_pinned=r[3])
            for r in rows]


@router.put("/layout", status_code=204,
            dependencies=[Depends(rate_limit("graph.view"))])
def save_layout(
    case_id: UUID, body: LayoutBody,
    user: CurrentUser = Depends(require("graph.node.update")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Persist positions. Only nodes actually in this case are stored, so a
    crafted body cannot write rows referencing another case's nodes."""
    from fastapi import Response
    with conn.transaction():
        projection_id = _layout_projection_id(conn, case_id, user.user_id)
        valid = {r[0] for r in conn.execute(
            "SELECT id FROM core.node WHERE case_id = %s", (case_id,)
        ).fetchall()}
        for pos in body.positions:
            if pos.node_id not in valid:
                continue
            conn.execute(
                """INSERT INTO analytics.layout_position
                       (projection_id, node_id, x, y, is_pinned)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (projection_id, node_id) DO UPDATE
                       SET x = EXCLUDED.x, y = EXCLUDED.y,
                           is_pinned = EXCLUDED.is_pinned""",
                (projection_id, pos.node_id, pos.x, pos.y, pos.is_pinned),
            )
    return Response(status_code=204)
