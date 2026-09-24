"""Phase 3 analytics endpoints: the SNA suite, key player, and per-node
metric history.

Everything is computed against a named projection and every response
carries the parameters that produced it, because a metric without its
projection is not reproducible (docs/03). Gated on `analytics.run`, the
same permission Phase 2's local metrics use.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query

from noctornal_api.analytics import (
    KPP_MAX_REMOVE,
    AnalyticsError,
    AnalyticsParams,
)
from noctornal_api.analytics_runs import AnalyticsRunService
from noctornal_api.http.deps import CurrentUser, get_conn, require, user_ceiling
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.projections import PRESETS, Projection, ProjectionError

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


def _projection(case_id: UUID, preset: str, include_inferred: bool,
                min_confidence: str, as_of: datetime | None) -> Projection:
    if preset not in PRESETS:
        raise Problem(400, "Invalid request",
                      f"unknown preset {preset!r}; one of "
                      f"{', '.join(sorted(PRESETS))}")
    return Projection(case_id=case_id, preset=preset,
                      include_inferred=include_inferred,
                      min_confidence=min_confidence, as_of=as_of)


def _params(decay_half_life_months: float | None,
            leiden_resolution: float) -> AnalyticsParams:
    if decay_half_life_months is not None and decay_half_life_months <= 0:
        raise Problem(400, "Invalid request",
                      "decay_half_life_months must be positive")
    return AnalyticsParams(decay_half_life_months=decay_half_life_months,
                           leiden_resolution=leiden_resolution)


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.suite"))])
def suite(
    case_id: UUID,
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
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
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    params = _params(decay_half_life_months, leiden_resolution)
    try:
        return _svc(conn, user, case_id).suite(p, params, force=force).as_response()
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    except AnalyticsError as exc:
        raise Problem(422, "Cannot compute", safe_detail(exc)) from exc


# The three reads below compute nothing and write nothing, but each one
# PROJECTS the caller's graph to compare hashes, which is the work
# `GET /graph` does on every sociogram refresh. So they share that route's
# meter, `graph.view`, rather than the analytics meters that ration igraph
# runs (2026-09-23).
@router.get("/latest", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def latest(
    case_id: UUID,
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
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
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    params = _params(decay_half_life_months, leiden_resolution)
    try:
        found = _svc(conn, user, case_id).latest(p, params)
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    if found is None:
        raise Problem(404, "Not found",
                      "no completed analytics run for this projection at your "
                      "clearance yet; run the suite first "
                      "(GET /cases/{case_id}/analytics)")
    return found.as_response()


@router.get("/key-player/latest", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def key_player_latest(
    case_id: UUID,
    n: int = Query(3, ge=1, le=KPP_MAX_REMOVE,
                   description="Size of the removal set"),
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
    decay_half_life_months: float | None = Query(None),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The most recent completed key-player run for this projection and
    removal-set size, with `computed_at` and a checked `current`; 404 when
    there is none. What the pane shows under "Key player" when it opens on
    a stored suite, instead of an empty heading."""
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    params = _params(decay_half_life_months, 1.0)
    try:
        found = _svc(conn, user, case_id).latest_key_player(p, params, n_remove=n)
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    if found is None:
        raise Problem(404, "Not found",
                      "no completed key-player run of this size for this "
                      "projection at your clearance yet")
    return found.as_response()


@router.get("/runs/{run_id}/current", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def run_current(
    case_id: UUID,
    run_id: UUID,
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
    decay_half_life_months: float | None = Query(None),
    leiden_resolution: float = Query(1.0, gt=0, le=10),
    user: CurrentUser = Depends(require("analytics.run")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Whether one stored run still describes the caller's graph:
    `{run_id, algorithm, computed_at, current}`. The projection parameters
    are the ones the run was computed under; a run of another projection
    is a 422, and a run the caller cannot see is a 404.

    The pane asks this after the graph under it changes, so it can mark
    its numbers stale, or leave them unmarked, from the answer rather
    than from a guess."""
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    params = _params(decay_half_life_months, leiden_resolution)
    try:
        found = _svc(conn, user, case_id).currency(p, params, run_id)
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    except AnalyticsError as exc:
        raise Problem(422, "Cannot compare", safe_detail(exc)) from exc
    if found is None:
        raise Problem(404, "Not found",
                      "no completed run with that id in this case at your "
                      "clearance")
    return found


@router.get("/key-player", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.key_player"))])
def key_player(
    case_id: UUID,
    n: int = Query(3, ge=1, le=KPP_MAX_REMOVE,
                   description="Size of the removal set"),
    preset: str = Query("all"),
    include_inferred: bool = Query(False),
    min_confidence: str = Query("LOW"),
    as_of: datetime | None = Query(None),
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
    p = _projection(case_id, preset, include_inferred, min_confidence, as_of)
    params = _params(decay_half_life_months, 1.0)
    try:
        return _svc(conn, user, case_id).key_player(
            p, params, n_remove=n, force=force).as_response()
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    except AnalyticsError as exc:
        raise Problem(422, "Cannot compute", safe_detail(exc)) from exc


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
