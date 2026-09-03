"""Search and selector lookup, scoped to a case and filtered by the
caller's own clearance/compartments (an element may be classified above its
case, so case-level authorization alone would leak labels and titles).

`/search` (2026-09-02) is the combined box: nodes, evidence and collected
documents in one ranked list. Each kind keeps the permission it has
everywhere else -- `case.read` for nodes, `evidence.read` for evidence,
global `collection.read` for documents, because that is what
`/collection/documents` demands and a search that returned what the list
refuses would be two halves wrong together. A kind the caller may not see
is named in `omitted` rather than silently absent: an empty result that
means "nothing collected" and one that means "you cannot see collected
things" need opposite responses.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from noctornal_api.curation import SearchService
from noctornal_api.http.deps import (
    CurrentUser,
    effective_labels,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.limits import rate_limit
from noctornal_api.security.access import AccessResolutionError, evaluate
from noctornal_api.selectors import SelectorStore
from noctornal_api.stores import PgAccessResolver

router = APIRouter(prefix="/cases/{case_id}", tags=["search"])


class HitOut(BaseModel):
    id: str
    label: str
    rank: float


def _allowed_on_case(conn, user: CurrentUser, case_id: UUID,
                     permission_key: str) -> bool:
    """The five-part gate as a QUESTION rather than a refusal.

    `authorize_object` raises and audits an AUTHZ_DENIED; that is right
    for a route whose whole answer is one permission, and wrong for a
    combined search that legitimately returns the kinds a caller may see
    and names the ones they may not. Resolution failures answer False,
    which fails closed exactly as the raising form does.
    """
    try:
        eff_cls, eff_comp = effective_labels(conn, case_id)
        ctx = PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id,
            permission_key=permission_key,
            object_classification=eff_cls, object_compartments=eff_comp,
            mfa_satisfied_at=user.session_mfa_at)
    except AccessResolutionError:
        return False
    return evaluate(ctx).allowed


def _holds_global(conn, user: CurrentUser, permission_key: str) -> bool:
    """`require_global` as a question. Deliberately answers False for a
    permission flagged `requires_step_up`, whatever the session's
    freshness: nothing here needs one, and a helper that could quietly
    grant a step-up verb without the challenge is a helper somebody will
    reuse."""
    return conn.execute(
        """SELECT 1
             FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.permission p ON p.key = rp.permission_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND rp.permission_key = %s
              AND u.is_active AND NOT p.requires_step_up
            LIMIT 1""",
        (user.user_id, permission_key)).fetchone() is not None


@router.get("/search", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def search_all(
    case_id: UUID,
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Nodes, evidence and collected documents, ranked together.

    Documents were unreachable by search until 2026-09-02 -- the
    collector's whole output, indexed since 0016 and queried by nothing.
    They are filtered by the caller's own ceiling like everything else
    here, and included only when the caller holds the global
    `collection.read` that `/collection/documents` demands; otherwise
    `omitted.documents` says so. Evidence likewise needs `evidence.read`
    on the case. Nodes need `case.read`, which is the gate above.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    omitted: dict[str, str] = {}
    with_evidence = _allowed_on_case(conn, user, case_id, "evidence.read")
    if not with_evidence:
        omitted["evidence"] = "missing evidence.read on this case"
    with_documents = _holds_global(conn, user, "collection.read")
    if not with_documents:
        omitted["documents"] = "missing global collection.read"
    hits = SearchService(conn).search(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
        include_evidence=with_evidence, include_documents=with_documents)
    return {"hits": hits, "count": len(hits), "omitted": omitted,
            "note": ("Documents are every source's, not this case's: a "
                     "collected post hangs off a source and is material in "
                     "however many cases cite it. A kind listed in "
                     "`omitted` was not searched, which is not the same as "
                     "having no matches.")}


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
