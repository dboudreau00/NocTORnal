"""Metric runs: cache, persistence and audit around the maths in
`analytics.py` (Phase 3, docs/02 + docs/03).

`analytics.py` is deliberately database-free -- it takes a projected
`Subgraph` and returns numbers. This module is the part that talks to
Postgres: it resolves the projection row, decides whether an existing run
can be reused, computes when it cannot, and records what happened.

**The cache rule, which is a security rule.** docs/02 asks for a graph
hash as the cache key: "Unchanged hash -> serve cached metrics, skip the
run entirely." The subtlety this codebase adds is that
`GraphService.project()` filters by the CALLER's clearance and
compartments, so two analysts asking the same question of the same case are
asking about different graphs. A betweenness score computed over a graph
containing RED nodes, served to an AMBER analyst, would hand them a number
whose explanation lies entirely in nodes they may not see -- a structural
leak that the row-level filtering exists to prevent.

Two mechanisms stop that, and either alone would be sufficient:

1. `graph_hash` is taken over the caller-VISIBLE node and edge lists, so a
   different clearance produces a different hash and therefore misses the
   cache.
2. The lookup ALSO filters on `visibility_clearance` and
   `visibility_compartments`, so even a hash collision, or a future change
   to how the hash is derived, cannot cross a clearance boundary.

**Why both `result` and `node_metric` are written.** `metric_run.result`
holds the exact payload served, so a cache hit is a single row read and the
served answer is byte-identical to the computed one. `node_metric` holds
the same per-node numbers relationally, which is what makes "show me this
actor's betweenness across every run this quarter" answerable -- docs/03
wants metric time series per node, because a rising betweenness trend is a
promotion. They are written in one transaction, so they cannot disagree.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Json

from noctornal_api.analytics import (
    AnalyticsError,
    AnalyticsParams,
    graph_hash,
    key_player,
    materialise,
    run_suite,
)
from noctornal_api.projections import GraphService, Projection

SUITE = "sna_suite"
KPP_NEG = "kpp_neg"

# Metrics stored per node in analytics.node_metric. Graph-level results
# (balance, cut vertices, key player) live in metric_run.result -- they are
# properties of the graph, not of any node.
_NODE_METRICS = (
    "betweenness",
    "harmonic_closeness",
    "eigenvector",
    "constraint",
    "effective_size",
    "efficiency",
    "hierarchy",
)


@dataclass(frozen=True)
class RunResult:
    payload: dict
    run_id: UUID
    cached: bool

    def as_response(self) -> dict:
        return {**self.payload, "run_id": str(self.run_id), "cached": self.cached}


class AnalyticsRunService:
    """Runs metrics for ONE caller, at that caller's visibility.

    The clearance and compartments passed here must be the caller's own --
    they are both the filter used to build the graph and the scope the
    cached result is stored under.
    """

    def __init__(self, conn: psycopg.Connection, *, clearance: str,
                 compartments: frozenset[str], actor_id: UUID):
        self._c = conn
        self._clearance = clearance
        self._comp = frozenset(compartments)
        self._actor = actor_id
        self._graph = GraphService(conn, clearance=clearance,
                                   compartments=self._comp)

    # -- public ------------------------------------------------------------
    def suite(self, p: Projection, params: AnalyticsParams,
              *, force: bool = False) -> RunResult:
        """The whole SNA suite over one projection, cached on graph hash."""
        return self._run(p, params, SUITE, {}, force=force,
                         compute=lambda sub: run_suite(sub, p, params))

    def key_player(self, p: Projection, params: AnalyticsParams, *,
                   n_remove: int, force: bool = False) -> RunResult:
        """KPP-Neg. Kept as its own algorithm rather than folded into the
        suite because it is combinatorial: its cost scales with `n_remove`,
        so it must be cached against that parameter and requested
        deliberately rather than computed on every panel load."""
        def compute(sub):
            if sub.truncated:
                # Refuse outright rather than answer. Every other metric can
                # carry a "partial graph" caveat, but this one names people
                # for removal: a takedown set derived from a graph that is
                # not the case is worse than no answer at all.
                raise AnalyticsError(
                    "the projection was truncated at its node limit, so a "
                    "removal set computed from it would not describe this "
                    "case. Narrow the projection until it fits."
                )
            m = materialise(sub, params)
            out = key_player(m, n_remove)
            return {
                "projection": p.describe(),
                "params": params.describe(),
                "node_count": m.n,
                "edge_count": m.edge_count,
                "dyad_count": m.dyad_count,
                "key_player": out,
            }
        return self._run(p, params, KPP_NEG, {"n_remove": n_remove},
                         force=force, compute=compute)

    def history(self, case_id: UUID, node_id: UUID, metric: str,
                limit: int = 50) -> list[dict]:
        """One node's value for one metric across runs -- the time series
        docs/03 asks for ("a rising betweenness trend is a promotion").

        Scoped to runs computed at the caller's own visibility, so an
        analyst cannot read back a series computed over a graph they were
        never allowed to see.
        """
        rows = self._c.execute(
            """SELECT r.started_at, nm.value, nm.rank, nm.percentile,
                      r.is_approximate, r.node_count, pr.preset, pr.params
                 FROM analytics.node_metric nm
                 JOIN analytics.metric_run r ON r.id = nm.metric_run_id
                 JOIN analytics.projection pr ON pr.id = r.projection_id
                WHERE pr.case_id = %s AND nm.node_id = %s AND nm.metric = %s
                  AND r.status = 'COMPLETE'
                  AND r.visibility_clearance = %s::core.tlp
                  AND r.visibility_compartments = %s
                ORDER BY r.started_at DESC
                LIMIT %s""",
            (case_id, node_id, metric, self._clearance,
             sorted(self._comp), limit),
        ).fetchall()
        return [
            {"at": r[0].isoformat(), "value": r[1], "rank": r[2],
             "percentile": float(r[3]) if r[3] is not None else None,
             "is_approximate": r[4], "node_count": r[5],
             "preset": r[6], "params": r[7]}
            for r in rows
        ]

    # -- internals ---------------------------------------------------------
    def _run(self, p: Projection, params: AnalyticsParams, algorithm: str,
             extra_params: dict, *, force: bool, compute) -> RunResult:
        # Project FIRST. This is the clearance-filtered graph, and it is
        # also what the cache key is derived from, so there is no path that
        # serves a cached number without re-deriving the caller's own view.
        sub = self._graph.project(p, limit=5000)
        digest = self._cache_key(sub, p, params, extra_params)
        projection_id = self._upsert_projection(p, params)

        if not force:
            hit = self._lookup(projection_id, algorithm, digest)
            if hit is not None:
                run_id, payload = hit
                return RunResult(payload, run_id, cached=True)

        started = time.monotonic()
        run_id = uuid4()
        self._c.execute(
            """INSERT INTO analytics.metric_run
                   (id, projection_id, algorithm, params, graph_hash, status,
                    node_count, edge_count, created_by,
                    visibility_clearance, visibility_compartments)
               VALUES (%s, %s, %s, %s, %s, 'RUNNING', %s, %s, %s,
                       %s::core.tlp, %s)""",
            (run_id, projection_id, algorithm,
             Json({**params.describe(), **extra_params}), digest,
             len(sub.nodes), len(sub.edges), self._actor,
             self._clearance, sorted(self._comp)),
        )
        try:
            payload = compute(sub)
        except Exception as exc:
            # Invariant 12: nothing is silently dropped. Catching only
            # AnalyticsError would leave a run stuck at RUNNING forever after
            # any unexpected failure, and a stuck RUNNING row reads as "still
            # working" rather than "this broke". Every exception marks the run
            # FAILED and is then re-raised unchanged.
            self._c.execute(
                """UPDATE analytics.metric_run
                      SET status = 'FAILED', error = %s, finished_at = now(),
                          duration_ms = %s
                    WHERE id = %s""",
                (f"{type(exc).__name__}: {exc}",
                 int((time.monotonic() - started) * 1000), run_id),
            )
            self._audit(p.case_id, run_id, algorithm, "ANALYTICS_RUN_FAILED",
                        {"error_type": type(exc).__name__})
            raise

        duration = int((time.monotonic() - started) * 1000)
        payload = {**payload, "computed_at_ms": duration}
        # CR9 (2026-07-26): the failure handler covers the PERSISTENCE too.
        #
        # The comment above claims "every exception marks the run FAILED",
        # and the try/except above wrapped only `compute(sub)` -- so a
        # failure in the COMPLETE write or in `_persist_node_metrics`
        # stranded the run at RUNNING with no FAILED status and no
        # ANALYTICS_RUN_FAILED audit event. The RUNNING row was inserted on
        # an autocommit connection, so it survives the rollback.
        #
        # CR8 made this reachable rather than theoretical: `Json(NaN)`
        # raises HERE, inside the write, which is precisely the region the
        # handler did not cover. Each retry then inserted another stranded
        # RUNNING row.
        try:
            with self._c.transaction():
                self._c.execute(
                    """UPDATE analytics.metric_run
                          SET status = 'COMPLETE', finished_at = now(),
                              duration_ms = %s, result = %s,
                              is_approximate = %s, sample_size = %s
                        WHERE id = %s""",
                    (duration, Json(payload),
                     bool(payload.get("is_approximate")
                          or payload.get("key_player", {}).get("is_approximate")),
                     payload.get("sample_size"), run_id),
                )
                self._persist_node_metrics(run_id, payload)
        except Exception as exc:
            self._c.execute(
                """UPDATE analytics.metric_run
                      SET status = 'FAILED', error = %s, finished_at = now(),
                          duration_ms = %s
                    WHERE id = %s""",
                (f"persist: {type(exc).__name__}: {exc}", duration, run_id),
            )
            self._audit(p.case_id, run_id, algorithm, "ANALYTICS_RUN_FAILED",
                        {"error_type": type(exc).__name__, "stage": "persist"})
            raise
        self._audit(p.case_id, run_id, algorithm, "ANALYTICS_RUN",
                    {"duration_ms": duration,
                     "node_count": len(sub.nodes),
                     "is_approximate": bool(payload.get("is_approximate"))})
        return RunResult(payload, run_id, cached=False)

    def _cache_key(self, sub, p: Projection, params: AnalyticsParams,
                   extra: dict) -> bytes:
        """The projection digest, extended by any algorithm parameters that
        change the answer (notably KPP's `n_remove`)."""
        base = graph_hash(sub, p, params)
        if not extra:
            return base
        h = hashlib.sha256()
        h.update(base)
        h.update(json.dumps(extra, sort_keys=True).encode())
        return h.digest()

    def _lookup(self, projection_id: UUID, algorithm: str,
                digest: bytes) -> tuple[UUID, dict] | None:
        row = self._c.execute(
            """SELECT id, result FROM analytics.metric_run
                WHERE projection_id = %s AND algorithm = %s
                  AND graph_hash = %s AND status = 'COMPLETE'
                  -- Belt and braces with the hash: a cached run is only
                  -- ever served back to the same visibility it was
                  -- computed under. This is deliberately stricter than
                  -- necessary -- two clearances that happen to see an
                  -- identical graph will each compute their own run rather
                  -- than share one. That costs a recomputation in the case
                  -- where nothing in the projection is classified above the
                  -- lower clearance; it buys a guarantee that does not
                  -- depend on the hash being collision-free.
                  AND visibility_clearance = %s::core.tlp
                  AND visibility_compartments = %s
                ORDER BY started_at DESC LIMIT 1""",
            (projection_id, algorithm, digest, self._clearance,
             sorted(self._comp)),
        ).fetchone()
        if row is None:
            return None
        return row[0], row[1]

    def _upsert_projection(self, p: Projection, params: AnalyticsParams) -> UUID:
        """One projection row per distinct parameter set per case.

        The name is derived from the parameters rather than chosen, so
        repeated runs reuse one row instead of accumulating thousands, and
        two callers asking the same question land on the same projection.
        `preset` and `params` carry the readable form.
        """
        fingerprint = hashlib.sha256(
            json.dumps({**p.describe(), **params.describe()},
                       sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        name = f"auto:{p.preset}:{fingerprint}"
        edge_types = p.resolved_edge_types()
        row = self._c.execute(
            """INSERT INTO analytics.projection
                   (id, case_id, name, edge_types, include_inferred,
                    min_confidence, as_of_to, is_directed, preset, params,
                    created_by)
               VALUES (%s, %s, %s, %s, %s, %s::core.analytic_confidence,
                       %s, false, %s, %s, %s)
               ON CONFLICT (case_id, name) DO UPDATE SET name = EXCLUDED.name
               RETURNING id""",
            (uuid4(), p.case_id, name, edge_types or [], p.include_inferred,
             p.min_confidence, p.as_of, p.preset,
             Json({**p.describe(), **params.describe()}), self._actor),
        ).fetchone()
        return row[0]

    def _persist_node_metrics(self, run_id: UUID, payload: dict) -> None:
        """Write the per-node numbers relationally so they are queryable
        across runs. The suite carries them; KPP-Neg does not (its answer is
        a set, not a per-node score), so this is a no-op for it."""
        nodes = payload.get("nodes")
        if not nodes:
            return
        rows = []
        for n in nodes:
            for metric in _NODE_METRICS:
                value = n.get(metric)
                if value is None:
                    continue        # undefined (e.g. constraint of an isolate)
                rows.append((run_id, n["id"], metric, float(value),
                             n.get(f"{metric}_rank"), n.get(f"{metric}_percentile")))
        if rows:
            self._c.cursor().executemany(
                """INSERT INTO analytics.node_metric
                       (metric_run_id, node_id, metric, value, rank, percentile)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (metric_run_id, node_id, metric) DO NOTHING""",
                rows,
            )
        communities = [
            (run_id, n["id"], int(n["community"]))
            for n in nodes if n.get("community") is not None
        ]
        if communities:
            self._c.cursor().executemany(
                """INSERT INTO analytics.community_assignment
                       (metric_run_id, node_id, community_id)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (metric_run_id, node_id) DO NOTHING""",
                communities,
            )

    def _audit(self, case_id: UUID, run_id: UUID, algorithm: str,
               action: str, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'metric_run', %s, %s, %s)""",
            (self._actor, action, run_id, case_id,
             Json({**detail, "algorithm": algorithm})),
        )
