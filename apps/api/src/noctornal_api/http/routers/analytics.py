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
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.projections import PRESETS, Projection, ProjectionError

router = APIRouter(prefix="/cases/{case_id}/analytics", tags=["analytics"])

# The per-node metrics that can be charted over time. Constrained to a
# whitelist so the history query cannot be steered by arbitrary input.
_HISTORY_METRICS = frozenset({
    "betweenness", "harmonic_closeness", "eigenvector",
    "constraint", "effective_size", "efficiency", "hierarchy",
})


def _svc(conn: psycopg.Connection, user: CurrentUser) -> AnalyticsRunService:
    clearance, compartments = user_ceiling(conn, user.user_id)
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
        return _svc(conn, user).suite(p, params, force=force).as_response()
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    except AnalyticsError as exc:
        raise Problem(422, "Cannot compute", str(exc)) from exc


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
        return _svc(conn, user).key_player(
            p, params, n_remove=n, force=force).as_response()
    except ProjectionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    except AnalyticsError as exc:
        raise Problem(422, "Cannot compute", str(exc)) from exc


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
    series = _svc(conn, user).history(case_id, node_id, metric, limit)
    return {"node_id": str(node_id), "metric": metric, "series": series}
