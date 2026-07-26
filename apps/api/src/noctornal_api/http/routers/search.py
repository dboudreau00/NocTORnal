"""Search and selector lookup, scoped to a case and filtered by the
caller's own clearance/compartments (an element may be classified above its
case, so case-level authorization alone would leak labels and titles)."""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from noctornal_api.curation import SearchService
from noctornal_api.http.deps import CurrentUser, get_conn, require, user_ceiling
from noctornal_api.http.limits import rate_limit
from noctornal_api.selectors import SelectorStore

router = APIRouter(prefix="/cases/{case_id}", tags=["search"])


class HitOut(BaseModel):
    id: str
    label: str
    rank: float


# docs/05: "hard limits on export and search". Search is the shape a
# bulk-read of a case file takes, so the limit is about what leaves as much
# as about what the server spends.
@router.get("/search/nodes", response_model=list[HitOut],
            dependencies=[Depends(rate_limit("search"))])
def search_nodes(
    case_id: UUID,
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[HitOut]:
    clearance, compartments = user_ceiling(conn, user.user_id)
    hits = SearchService(conn).search_nodes(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
    )
    return [HitOut(id=str(h.id), label=h.label, rank=h.rank) for h in hits]


@router.get("/search/evidence", response_model=list[HitOut],
            dependencies=[Depends(rate_limit("search"))])
def search_evidence(
    case_id: UUID,
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[HitOut]:
    clearance, compartments = user_ceiling(conn, user.user_id)
    hits = SearchService(conn).search_evidence(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
    )
    return [HitOut(id=str(h.id), label=h.label, rank=h.rank) for h in hits]


class SelectorOut(BaseModel):
    id: str
    selector_type: str
    raw_value: str
    norm_value: str
    node_id: str | None
    observation_cnt: int


def _sel_out(row) -> SelectorOut:
    return SelectorOut(
        id=str(row.id), selector_type=row.selector_type, raw_value=row.raw_value,
        norm_value=row.norm_value,
        node_id=str(row.node_id) if row.node_id else None,
        observation_cnt=row.observation_cnt,
    )


@router.get("/selectors", response_model=SelectorOut | None)
def find_selector(
    case_id: UUID,
    selector_type: str = Query(...),
    value: str = Query(...),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SelectorOut | None:
    """Exact-match selector lookup. The query value is normalised the same
    way it was stored, so callers need not know the canonical form. A
    selector attributed to a node the caller cannot see is withheld — the
    selector is an observable ABOUT that node."""
    row = SelectorStore(conn).find(case_id=case_id, selector_type=selector_type,
                                   raw_value=value)
    if row is None:
        return None
    if row.node_id is not None:
        clearance, compartments = user_ceiling(conn, user.user_id)
        visible = conn.execute(
            """SELECT 1 FROM core.node
                WHERE id = %s AND classification <= %s::core.tlp
                  AND compartments <@ %s""",
            (row.node_id, clearance.name, list(compartments)),
        ).fetchone()
        if visible is None:
            return None
    return _sel_out(row)


class RecordSelectorBody(BaseModel):
    selector_type: str
    raw_value: str
    node_id: UUID | None = None


@router.post("/selectors", response_model=SelectorOut, status_code=201)
def record_selector(
    case_id: UUID, body: RecordSelectorBody,
    _: CurrentUser = Depends(require("graph.node.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SelectorOut:
    row = SelectorStore(conn).record(
        case_id=case_id, selector_type=body.selector_type,
        raw_value=body.raw_value, node_id=body.node_id,
    )
    return _sel_out(row)
