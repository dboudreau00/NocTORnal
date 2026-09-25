"""Phase 3 analytics endpoints: the SNA suite, key player, role analysis
(CONCOR), and per-node metric history.

Everything is computed against a named projection and every response
carries the parameters that produced it, because a metric without its
projection is not reproducible (docs/03). Gated on `analytics.run`, the
same permission Phase 2's local metrics use.

The projection is ONE dependency, `analysis_projection`, shared by every
analysis route since 2026-09-24 (L3): five routes had repeated five query
parameters each and checked only the preset, so `/latest` with an unknown
confidence floor answered 404 from a name lookup that could never match.
It now answers 400 before any lookup, like every other route, and the
projection options (the accepted-ties scope, L3; venues projected to
entities, F2) are added in one place.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response

from noctornal_api.affiliation import DEFAULT_MAX_VENUE_SIZE, OneModeParams
from noctornal_api.analytics import (
    KPP_MAX_REMOVE,
    AnalyticsError,
    AnalyticsParams,
)
from noctornal_api.analytics_runs import AnalyticsRunService
from noctornal_api.blockmodel import CONCOR_DEFAULT_DEPTH, CONCOR_MAX_DEPTH
from noctornal_api.http.deps import (
    CurrentUser,
    current_user,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import enforce, rate_limit
from noctornal_api.projections import (
    Projection,
    ProjectionError,
    ProjectionTooLarge,
    validate_projection,
)

router = APIRouter(prefix="/cases/{case_id}/analytics", tags=["analytics"])

# The per-node metrics that can be charted over time. Constrained to a
# whitelist so the history query cannot be steered by arbitrary input.
_HISTORY_METRICS = frozenset({
    "betweenness", "harmonic_closeness", "eigenvector",
    "constraint", "effective_size", "efficiency", "hierarchy",
})


def _svc(conn: psycopg.Connection, user: CurrentUser,
         case_id: UUID) -> AnalyticsRunService:
    # One case's projection, so a break-glass grant scoped to it counts, as
    # it does for the graph it is computed from (ux15, 2026-09-23). A run
    # computed at the raised level is stored under that level's
    # `visibility_clearance` and served to nobody below it.
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    return AnalyticsRunService(conn, clearance=clearance.name,
                               compartments=compartments,
                               actor_id=user.user_id)


def analysis_projection(
    case_id: UUID,
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
    review_scope: str = Query(
        "all", description="all, or accepted: compute over ties a reviewer "
                           "has accepted, counting every tie left out"),
    one_mode: list[str] = Query(
        default_factory=list,
        description="forum or wallet: project those venues to entities. "
                    "Repeat the parameter for both."),
    one_mode_weighting: str = Query("NEWMAN", description="NEWMAN or COUNT"),
    max_venue_size: int = Query(DEFAULT_MAX_VENUE_SIZE, ge=2, le=500,
                                description="A larger venue draws nothing and "
                                            "is named"),
    one_mode_min_shared: int = Query(1, ge=1, le=100),
) -> Projection:
    """The projection every analysis route computes over, validated before
    anything is looked up. An unknown preset, confidence floor, review
    scope, family or weighting is a 400; an out-of-range size is
    FastAPI's 422."""
    p = Projection(
        case_id=case_id, preset=preset, include_inferred=include_inferred,
        min_confidence=min_confidence, as_of=as_of, review_scope=review_scope,
        one_mode=OneModeParams(tuple(one_mode), one_mode_weighting,
                               max_venue_size, one_mode_min_shared))
    try:
        validate_projection(p)
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return p


def _one_mode_meter(
    request: Request,
    response: Response,
    p: Projection = Depends(analysis_projection),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> None:
    """Charge a one-mode read where the transform is paid (F2, 2026-09-24).

    Beside each route's own meter, and only when a venue family is listed,
    so a plain read is charged exactly as before. FastAPI solves
    `analysis_projection` once per request, so this reads the same
    Projection the handler gets."""
    if p.one_mode.enabled():
        enforce(request, response, "analytics.one_mode", f"u:{user.user_id}",
                conn=conn, actor_id=user.user_id)


def _params(decay_half_life_months: float | None,
            leiden_resolution: float) -> AnalyticsParams:
    if decay_half_life_months is not None and decay_half_life_months <= 0:
        raise Problem(400, "Invalid request",
                      "decay_half_life_months must be positive")
    return AnalyticsParams(decay_half_life_months=decay_half_life_months,
                           leiden_resolution=leiden_resolution)


def _answer(call, *, cannot: str = "Cannot compute"):
    """One error mapping for every analysis route: a view too large to
    transform is a 422 (it is valid, just too big), any other projection
    error a 400, and a metric that cannot be computed a 422."""
    try:
        return call()
    except ProjectionTooLarge as exc:
        raise Problem(422, "Cannot compute", safe_detail(exc)) from exc
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    except AnalyticsError as exc:
        raise Problem(422, cannot, safe_detail(exc)) from exc


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.suite")),
                          Depends(_one_mode_meter)])
def suite(
    case_id: UUID,
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(
        None, description="Trust decay half-life. Omit to disable. docs/03 "
                          "suggests 12 months. Never mutates stored weights."),
    leiden_resolution: float = Query(1.0, gt=0, le=10),
    force: bool = Query(False, description="Recompute even on a cache hit"),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Betweenness, harmonic closeness, eigenvector, Burt's structural
    holes, Leiden communities, cut vertices, bridges and signed structural
    balance -- one materialisation, one cache entry.

    Cached on a graph hash taken over the CALLER's visible graph, so a
    result computed for a better-cleared analyst is never served here.
    """
    params = _params(decay_half_life_months, leiden_resolution)
    return _answer(lambda: _svc(conn, user, case_id).suite(
        p, params, force=force).as_response())


# The reads below compute nothing and write nothing, but each one PROJECTS
# the caller's graph to compare hashes, which is the work `GET /graph` does
# on every sociogram refresh. So they share that route's meter,
# `graph.view`, rather than the analytics meters that ration igraph runs
# (2026-09-23), plus `analytics.one_mode` when venues are projected.
@router.get("/latest", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view")),
                          Depends(_one_mode_meter)])
def latest(
    case_id: UUID,
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    leiden_resolution: float = Query(1.0, gt=0, le=10),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The most recent completed suite run for this projection, in the
    suite endpoint's shape plus `computed_at`; 404 when there is none.

    What the pane shows on opening. Takes the same projection parameters
    as the suite -- with the same defaults -- because they are what name
    the projection row: a `latest` that could only say `preset` would
    never find a run made with a non-default confidence floor.

    `current` is a checked verdict since 2026-09-23: true when the
    caller's graph, projected now, hashes as it did when the run was
    computed, false when it has moved. Until then this endpoint never
    compared hashes and answered `current: null`, so the pane could only
    say "not recomputed" and an analyst had to spend a metered run to find
    out whether the numbers still held. `cached: true` says only that the
    bytes came out of `analytics.metric_run`; `computed_at` says WHEN the
    run happened, `current` says WHETHER it still describes the graph.
    """
    params = _params(decay_half_life_months, leiden_resolution)
    found = _answer(lambda: _svc(conn, user, case_id).latest(p, params))
    if found is None:
        raise Problem(404, "Not found",
                      "no completed analytics run for this projection at your "
                      "clearance yet; run the suite first "
                      "(GET /cases/{case_id}/analytics)")
    return found.as_response()


@router.get("/key-player/latest", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view")),
                          Depends(_one_mode_meter)])
def key_player_latest(
    case_id: UUID,
    n: int = Query(3, ge=1, le=KPP_MAX_REMOVE,
                   description="Size of the removal set"),
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The most recent completed key-player run for this projection and
    removal-set size, with `computed_at` and a checked `current`; 404 when
    there is none. What the pane shows under "Key player" when it opens on
    a stored suite, instead of an empty heading."""
    params = _params(decay_half_life_months, 1.0)
    found = _answer(lambda: _svc(conn, user, case_id).latest_key_player(
        p, params, n_remove=n))
    if found is None:
        raise Problem(404, "Not found",
                      "no completed key-player run of this size for this "
                      "projection at your clearance yet")
    return found.as_response()


@router.get("/runs/{run_id}/current", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view")),
                          Depends(_one_mode_meter)])
def run_current(
    case_id: UUID,
    run_id: UUID,
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    leiden_resolution: float = Query(1.0, gt=0, le=10),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Whether one stored run still describes the caller's graph:
    `{run_id, algorithm, computed_at, current}`. The projection parameters
    are the ones the run was computed under; a run of another projection
    is a 422, and a run the caller cannot see is a 404.

    The pane asked this after the graph under it changed; it now asks
    `/currency` once for every card. This stays for API callers."""
    params = _params(decay_half_life_months, leiden_resolution)
    found = _answer(lambda: _svc(conn, user, case_id).currency(p, params, run_id),
                    cannot="Cannot compare")
    if found is None:
        raise Problem(404, "Not found",
                      "no completed run with that id in this case at your "
                      "clearance")
    return found


@router.get("/currency", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view")),
                          Depends(_one_mode_meter)])
def currency(
    case_id: UUID,
    run_id: list[UUID] = Query(..., min_length=1, max_length=4,
                               description="Repeat for every run on screen"),
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    leiden_resolution: float = Query(1.0, gt=0, le=10),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Whether each of up to four stored runs still describes the caller's
    graph, with ONE projection of it (F2, 2026-09-24): `{runs: [...]}` in
    the order asked. A run of another projection answers `current: null`
    with `reason: "other_projection"`, one the caller cannot see
    `reason: "not_found"`. What the Analysis pane asks after every graph
    refresh, instead of one request per card."""
    params = _params(decay_half_life_months, leiden_resolution)
    return _answer(lambda: _svc(conn, user, case_id).currency_many(p, params, run_id),
                   cannot="Cannot compare")


@router.get("/key-player", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.key_player")),
                          Depends(_one_mode_meter)])
def key_player(
    case_id: UUID,
    n: int = Query(3, ge=1, le=KPP_MAX_REMOVE,
                   description="Size of the removal set"),
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    force: bool = Query(False),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """KPP-Neg: which set of n actors, removed, maximally fragments this
    network (Borgatti).

    The response includes the top-n by betweenness and the fragmentation
    each set achieves, because docs/03's point is that they are usually
    NOT the same set -- two high-betweenness actors often broker the same
    pair of clusters, so removing both is redundant.
    """
    params = _params(decay_half_life_months, 1.0)
    return _answer(lambda: _svc(conn, user, case_id).key_player(
        p, params, n_remove=n, force=force).as_response())


@router.get("/concor", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.concor")),
                          Depends(_one_mode_meter)])
def concor(
    case_id: UUID,
    depth: int = Query(CONCOR_DEFAULT_DEPTH, ge=1, le=CONCOR_MAX_DEPTH,
                       description="Splits: up to 2 to the power depth positions"),
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    force: bool = Query(False),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Role analysis: CONCOR positions, entities with the same pattern of
    ties to the same others (F1, 2026-09-24). Cached on the graph hash,
    the depth and every tie's direction, on its own meter. The decay and
    Leiden parameters name the same projection row as the key player's, so
    stored lookups line up; neither moves a position."""
    params = _params(decay_half_life_months, 1.0)
    return _answer(lambda: _svc(conn, user, case_id).concor(
        p, params, depth=depth, force=force).as_response())


@router.get("/concor/latest", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view")),
                          Depends(_one_mode_meter)])
def concor_latest(
    case_id: UUID,
    depth: int = Query(CONCOR_DEFAULT_DEPTH, ge=1, le=CONCOR_MAX_DEPTH),
    p: Projection = Depends(analysis_projection),
    decay_half_life_months: float | None = Query(None),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The most recent completed role analysis for this projection and
    depth, with `computed_at` and a checked `current`; 404 when there is
    none. Served exactly as computed, never upgraded."""
    params = _params(decay_half_life_months, 1.0)
    found = _answer(lambda: _svc(conn, user, case_id).latest_concor(
        p, params, depth=depth))
    if found is None:
        raise Problem(404, "Not found",
                      "no completed role analysis at this depth for this "
                      "projection at your clearance yet")
    return found.as_response()


@router.get("/history/{node_id}", response_model=dict)
def history(
    case_id: UUID,
    node_id: UUID,
    metric: str = Query("betweenness"),
    limit: int = Query(50, ge=1, le=500),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One actor's value for one metric across past runs. docs/03: "a
    rising betweenness trend is a promotion"."""
    if metric not in _HISTORY_METRICS:
        raise Problem(400, "Invalid request",
                      f"unknown metric {metric!r}; one of "
                      f"{', '.join(sorted(_HISTORY_METRICS))}")
    series = _svc(conn, user, case_id).history(case_id, node_id, metric, limit)
    return {"node_id": str(node_id), "metric": metric, "series": series}
