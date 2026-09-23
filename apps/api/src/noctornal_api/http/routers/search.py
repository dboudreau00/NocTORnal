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

Since 2026-09-22 (ux09-search) every search here matches word starts,
fragments of names and file names, and the selectors attributed to an
entity, which come back as the hit's `via`; `/search/selectors` is the
selector-only form the command palette uses. The kind routes take
`with_total=true` for `{hits, total, limit}`, so a capped list can say
how many matched, and the combined `/search` always reports `total` and
per-kind `totals`. How a query matches, and why, is in `curation.py`.
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


class SelectorViaOut(BaseModel):
    """Which selector put an entity in the results (selectors-unsearchable,
    2026-09-22). `value` is the selector as observed; `merged_from` names
    the merged record that holds it when that is not the entity itself."""
    selector_type: str
    value: str
    exact: bool
    more: int
    merged_from: str | None = None


class HitOut(BaseModel):
    """`merged_name` is the label of a record merged into this entity
    whose name matched when the entity's own did not, or matched less well
    (final review U10, 2026-09-23), so the pane can say why a name it does
    not show is here. Null otherwise.

    `attribute` is the key of the entity's own attribute that matched,
    when its name did not and neither `via` nor `merged_name` is set
    (README screenshot review, 2026-09-23): "broker" found three entities
    through role=broker, and nothing on screen said so. Null otherwise."""
    id: str
    label: str
    rank: float
    via: SelectorViaOut | None = None
    merged_name: str | None = None
    attribute: str | None = None


class HitPage(BaseModel):
    """`with_total=true`: the capped hits AND how many matched, so a caller
    can say "showing 50 of 73" (silent-truncation-50, 2026-09-22). `total`
    counts only rows the caller may see. The bare list stays the default
    because it is the documented shape every existing client reads."""
    hits: list[HitOut]
    total: int
    limit: int


def _hit_out(h) -> HitOut:
    via = None
    if h.via is not None:
        via = SelectorViaOut(**h.via.as_dict())
    return HitOut(id=str(h.id), label=h.label, rank=h.rank, via=via,
                  merged_name=h.merged_name, attribute=h.attribute)


def _page_out(page, limit: int, with_total: bool) -> list[HitOut] | HitPage:
    hits = [_hit_out(h) for h in page.hits]
    if with_total:
        return HitPage(hits=hits, total=page.total, limit=limit)
    return hits


#: Longer than any selector an analyst pastes (an SSH public key is under
#: 800 characters). Fragment matching since 2026-09-22 costs about one
#: trigram lookup for every character of the query, so an unbounded query
#: is an unbounded index scan, 120 times a minute under the `search` meter.
MAX_QUERY = 1024


_WITH_TOTAL = Query(
    False, description="Wrap the hits as {hits, total, limit} so a capped "
    "list can say how many matched in all.")


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
            mfa_satisfied_at=user.session_mfa_at,
            # A question, not an access: the request it serves was counted
            # at its own gate (final review U19, 2026-09-23, g02).
            count_use=False)
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
    q: str = Query(..., min_length=1, max_length=MAX_QUERY),
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
    # The one search here that does NOT pass `case_id=` (2026-09-23): its
    # documents are every source's, not this case's, so a break-glass grant
    # on this case must not raise them. The per-kind routes below, which
    # the console uses, read only this case and do.
    clearance, compartments = user_ceiling(conn, user.user_id)
    omitted: dict[str, str] = {}
    with_evidence = _allowed_on_case(conn, user, case_id, "evidence.read")
    if not with_evidence:
        omitted["evidence"] = "missing evidence.read on this case"
    with_documents = _holds_global(conn, user, "collection.read")
    if not with_documents:
        omitted["documents"] = "missing global collection.read"
    found = SearchService(conn).search_all(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
        include_evidence=with_evidence, include_documents=with_documents)
    hits, totals = found["hits"], found["totals"]
    return {"hits": hits, "count": len(hits),
            "total": sum(totals.values()), "totals": totals,
            "omitted": omitted,
            "note": ("Documents are every source's, not this case's: a "
                     "collected post hangs off a source and is material in "
                     "however many cases cite it. A kind listed in "
                     "`omitted` was not searched, which is not the same as "
                     "having no matches. `count` is how many hits are "
                     "listed; `total` is how many matched, so a `count` "
                     "below `total` means the list was capped at `limit`.")}


# docs/05: "hard limits on export and search". Search is the shape a
# bulk-read of a case file takes, so the limit is about what leaves as much
# as about what the server spends.
@router.get("/search/nodes", response_model=list[HitOut] | HitPage,
            dependencies=[Depends(rate_limit("search"))])
def search_nodes(
    case_id: UUID,
    q: str = Query(..., min_length=1, max_length=MAX_QUERY),
    limit: int = Query(50, ge=1, le=200),
    with_total: bool = _WITH_TOTAL,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[HitOut] | HitPage:
    """Entities by word start over name and attributes, by any fragment of
    the name, or by a selector attributed to them (reported as `via`).
    Filtered by the caller's own clearance and compartments; a selector is
    matched only through a node the caller may see."""
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    page = SearchService(conn).node_page(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
    )
    return _page_out(page, limit, with_total)


@router.get("/search/selectors", response_model=list[HitOut] | HitPage,
            dependencies=[Depends(rate_limit("search"))])
def search_selectors(
    case_id: UUID,
    q: str = Query(..., min_length=1, max_length=MAX_QUERY),
    limit: int = Query(50, ge=1, le=200),
    with_total: bool = _WITH_TOTAL,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[HitOut] | HitPage:
    """Only the entities a selector matched, each with its `via`: the
    command palette's lookup, which matches names in memory and cannot see
    the selector table. Same gate as `/search/nodes`."""
    # Case-scoped like `/search/nodes`, so a break-glass grant on this case
    # raises both or neither. Written by the search group and the
    # break-glass group in parallel on 2026-09-23; the merge found this route
    # still reading the caller's ceiling alone, so under a grant the palette
    # missed an entity the Search pane found. It reads only this case's
    # rows (selector_page takes case_id), unlike the combined `/search`
    # above, whose documents belong to every source.
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    page = SearchService(conn).selector_page(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
    )
    return _page_out(page, limit, with_total)


@router.get("/search/evidence", response_model=list[HitOut] | HitPage,
            dependencies=[Depends(rate_limit("search"))])
def search_evidence(
    case_id: UUID,
    q: str = Query(..., min_length=1, max_length=MAX_QUERY),
    limit: int = Query(50, ge=1, le=200),
    with_total: bool = _WITH_TOTAL,
    user: CurrentUser = Depends(require("evidence.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[HitOut] | HitPage:
    """Exhibits by word start over title, description and extracted text,
    or by any fragment of the title."""
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    page = SearchService(conn).evidence_page(
        case_id=case_id, query=q, limit=limit,
        clearance=clearance.name, compartments=compartments,
    )
    return _page_out(page, limit, with_total)


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
        clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
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
