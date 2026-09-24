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
from datetime import datetime
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Json

from noctornal_api.analytics import (
    CONSTRAINT_ORDER,
    AnalyticsError,
    AnalyticsParams,
    _least_constrained_first,
    _rank_and_percentile,
    assign_broker_leads,
    graph_hash,
    key_player,
    materialise,
    run_suite,
)
from noctornal_api.projections import GraphService, Projection

SUITE = "sna_suite"
KPP_NEG = "kpp_neg"

#: The node-row limit every run projects at. One constant, because the
#: currency check has to re-project exactly as the run did: a different
#: limit is a different node set and so a different hash.
PROJECT_LIMIT = 5000


def upgrade_stored(payload: dict) -> dict:
    """A stored suite payload brought up to the rules this build computes by.

    `metric_run.result` is the exact payload a run served, and a cache hit
    or `latest` hands it back. Two things it carries were computed by rules
    replaced on 2026-09-23, and serving them unchanged would put the old
    defects back on screen for every run made before the upgrade:

    - `constraint_percentile` ran against `constraint_rank`
      (ux10-analytics:rank-percentile-opposite-directions);
    - the broker leads used an absolute constraint cut-off that tagged the
      busiest actors (ux10-analytics:broker-lead-card-overclaims).

    Both are recomputed from the payload's own per-node numbers, so the
    answer is what this build would have said about the same graph, and
    the payload says which parts were redone (`upgraded`). The
    community sizes the pane now prints are counted from the rows too. A
    payload that already carries `constraint_order` is returned as is,
    apart from the disputed count below.
    """
    payload = _with_disputed(payload)
    nodes = payload.get("nodes")
    if not isinstance(nodes, list) or payload.get("constraint_order") == CONSTRAINT_ORDER:
        return payload
    out = {**payload, "nodes": [dict(n) for n in nodes]}
    rows = out["nodes"]
    _, pct = _rank_and_percentile(
        _least_constrained_first([n.get("constraint") for n in rows]))
    for n, p in zip(rows, pct, strict=True):
        n["constraint_percentile"] = p
    out["broker_rule"] = assign_broker_leads(rows)
    out["constraint_order"] = CONSTRAINT_ORDER
    cohesion = dict(out.get("cohesion") or {})
    if "community_sizes" not in cohesion:
        sizes: dict[int, int] = {}
        for n in rows:
            if n.get("community") is not None:
                sizes[n["community"]] = sizes.get(n["community"], 0) + 1
        cohesion["community_sizes"] = [
            {"community": c, "size": s}
            for c, s in sorted(sizes.items(), key=lambda kv: (-kv[1], kv[0]))]
        out["cohesion"] = cohesion
    out["upgraded"] = [*out.get("upgraded", []),
                       "constraint_percentile", "broker_leads", "community_sizes"]
    return out


def _with_disputed(payload: dict) -> dict:
    """A stored `review_coverage` given the disputed count it was stored
    without (release review c11, 2026-09-24).

    Runs computed before DISPUTED was counted left those ties in no bucket.
    They are the remainder: `graph.REVIEW_STATES` lets a reviewer set only
    ACCEPTED, DISPUTED or PROPOSED, REJECTED is counted, and nothing sets
    SUPERSEDED on a tie. So `ties` less the three counted states is exactly
    the disputed ties, and the pane can warn about a stored run as it does
    about a fresh one rather than read it as all settled. A payload that
    already counts them is returned as is (the same object)."""
    rc = payload.get("review_coverage")
    if not isinstance(rc, dict) or "disputed" in rc:
        return payload
    counted = sum(int(rc.get(k) or 0) for k in ("proposed", "accepted", "rejected"))
    disputed = max(0, int(rc.get("ties") or 0) - counted)
    return {**payload, "review_coverage": {**rc, "disputed": disputed},
            "upgraded": [*payload.get("upgraded", []), "review_coverage"]}


def upgraded_constraint_percentile(node_count: int | None, *, defined: int | None,
                                   above: int | None, equal: int | None,
                                   stored: float) -> float:
    """One pre-fix `node_metric` constraint percentile, re-ranked the way
    `upgrade_stored` re-ranks the payload, from the run's own rows.

    "100 minus the stored one" is exact only for a graph with no isolates
    (found reviewing the 2026-09-23 fix): the old percentile put every
    isolate (undefined constraint) BELOW the actors, and so does the new
    one, so turning the old one round moves the actors down by the
    isolates' share. A NIGHTJAR-shaped run (46 of 146 nodes without a
    constraint) read rank 1 at about p68 in the trend table while the
    actor table said p98 for the same run: the very "1st beside a middling
    percentile" this fix exists to remove
    (ux10-analytics:rank-percentile-opposite-directions).

    So the percentile is counted again, with `_rank_and_percentile`'s
    mid-rank definition over `_least_constrained_first`: strictly below an
    actor are the isolates (`node_count - defined`, since an isolate's
    undefined constraint writes no row) and every actor MORE constrained
    (`above`), plus half the ties (`equal`, the actor itself included). The
    expression is the helper's own, so the two tables agree to the digit.
    Without the counts (a run with no `node_count`) the old turn-round is
    the best there is, and is kept rather than printing nothing.
    """
    if not node_count or defined is None or above is None or equal is None:
        return round(100.0 - stored, 2)
    below = (node_count - defined) + above
    return round(100.0 * (below + 0.5 * equal) / node_count, 2)


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
    #: WHERE THE BYTES CAME FROM, and nothing more: True when this answer
    #: was read out of `analytics.metric_run`, False when it was computed
    #: during this request. It is NOT a freshness verdict -- see `current`.
    cached: bool
    #: When the run finished, for a result read back by `latest`. None on
    #: the compute and cache-hit paths, where the answer is "now" or the
    #: caller asked for a hash match rather than a moment in time.
    computed_at: datetime | None = None
    #: THE CURRENCY VERDICT, split out of `cached` on 2026-09-02. True when
    #: this answer is known to describe the caller's graph as it stands now,
    #: either because it was just computed or because its `graph_hash`
    #: matches the graph projected for this request. False when that
    #: comparison was made and failed: `latest` re-projects and compares
    #: since 2026-09-23, so it says "checked, and stale" here rather than
    #: "not checked". None means NOT CHECKED, which no path returns today.
    #:
    #: Before the split, `latest` and a `_lookup` hit both reached the wire
    #: as `cached: true` with nothing to separate them, so a client that
    #: rendered `cached` -- and the console's only renderer of it prints
    #: "unchanged since the last run" -- would tell an analyst the case
    #: graph was unchanged when it had moved underneath them. Staleness
    #: reported as freshness is this codebase's signature defect, and a
    #: timestamp is not a substitute: `computed_at` says when, never whether.
    #:
    #: The three-valued field existed for exactly the "read it back AND
    #: re-hash" path `latest` became, so it had somewhere honest to put
    #: "checked, and stale" instead of overloading `cached` again.
    #: Defaults to None -- "not checked" -- rather than True, so a future
    #: construction site that forgets the field cannot silently claim
    #: currency. Every path that HAS checked sets it explicitly.
    current: bool | None = None

    def as_response(self) -> dict:
        out = {**self.payload, "run_id": str(self.run_id),
               # Both fields on every response. A currency verdict that
               # appeared only on some of them would send clients straight
               # back to inferring freshness from whichever other keys were
               # present, which is the habit that produced the defect.
               "cached": self.cached, "current": self.current}
        if self.computed_at is not None:
            # The ONE place the shape is extended, so `latest` is the suite
            # response plus this field and cannot drift into its own shape.
            out["computed_at"] = self.computed_at.isoformat()
        return out


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

    def latest(self, p: Projection, params: AnalyticsParams) -> RunResult | None:
        """The most recent COMPLETE suite run for this projection, at the
        caller's visibility, or None when there is none.

        Until 2026-09-02 the analytics pane was empty until somebody
        pressed "Run analysis", although every completed run was already
        on `analytics.metric_run` with its full `result` payload: the
        persistence was written for cache hits and time series and never
        read back as "what was the last answer". So an analyst opening a
        case saw nothing, ran the suite again, and was served the cached
        row anyway.

        CHECKED AGAINST THE GRAPH since 2026-09-23. It used to read the row
        back without re-projecting and answer `current=None`, not checked,
        and the pane could only say "not recomputed": whether the numbers
        still described the case was a question an analyst had to spend a
        metered run to ask, so in practice they were read as current
        (ux10-analytics:stored-run-currency-and-timestamp and
        analysis-survives-graph-changes). Projecting is a read, the same
        read the sociogram makes on every refresh, and the digest it gives
        is the one `_lookup` matches on: so `current` is now True when the
        caller's graph hashes as it did when the run was computed and False
        when it has moved. `cached` still says only that the bytes came out
        of storage. Nothing is computed and no projection row is written:
        a read that leaves a row behind is not a read.

        Scoped by `visibility_clearance` / `visibility_compartments`
        exactly as `history` and `_lookup` are, and for the same reason:
        a run computed over a better-cleared analyst's graph is never
        served to a lesser one, because the score's explanation would lie
        in nodes they may not see.
        """
        row = self._newest(p, params, SUITE)
        if row is None:
            return None
        run_id, payload, finished_at, digest, _extra = row
        return RunResult(upgrade_stored(payload), run_id, cached=True,
                         computed_at=finished_at,
                         current=self._matches(p, params, {}, digest))

    def latest_key_player(self, p: Projection, params: AnalyticsParams, *,
                          n_remove: int) -> RunResult | None:
        """The most recent COMPLETE key-player run for this projection and
        removal-set size, checked against the graph as `latest` is.

        ux10-analytics:kpp-blank-on-stored-run (2026-09-23). The pane opened
        on the stored suite and left "Key player: who holds this network
        together" as an empty heading, which reads as "nobody does" or as a
        broken feature, although the key-player run was stored beside the
        suite. It is read back here the same way, keyed on the size it was
        computed for, because a 3-actor set says nothing about a 4-actor one.
        """
        row = self._newest(p, params, KPP_NEG, n_remove=n_remove)
        if row is None:
            return None
        run_id, payload, finished_at, digest, _extra = row
        return RunResult(payload, run_id, cached=True, computed_at=finished_at,
                         current=self._matches(p, params, {"n_remove": n_remove},
                                               digest))

    def currency(self, p: Projection, params: AnalyticsParams,
                 run_id: UUID) -> dict | None:
        """Whether ONE stored run still describes the caller's graph, or
        None when the caller cannot see that run.

        The pane calls this after the graph under it moves (an edit, a
        retirement, another analyst's change arriving live) instead of
        blanking numbers that may still hold or leaving numbers that may
        not (ux10-analytics:analysis-survives-graph-changes, 2026-09-23).
        The run must have been computed under the projection the caller
        names: asked about another projection the answer would compare two
        different questions, so that is a refusal, not a False.
        """
        row = self._c.execute(
            """SELECT r.algorithm, r.params, r.graph_hash, r.finished_at, pr.name
                 FROM analytics.metric_run r
                 JOIN analytics.projection pr ON pr.id = r.projection_id
                WHERE r.id = %s AND pr.case_id = %s AND r.status = 'COMPLETE'
                  AND r.visibility_clearance = %s::core.tlp
                  AND r.visibility_compartments = %s""",
            (run_id, p.case_id, self._clearance, sorted(self._comp)),
        ).fetchone()
        if row is None:
            return None
        algorithm, run_params, digest, finished_at, name = row
        if name != self._projection_name(p, params):
            raise AnalyticsError(
                "that run was computed under a different projection; ask "
                "about it with the parameters it was run with")
        extra = ({"n_remove": int((run_params or {}).get("n_remove"))}
                 if algorithm == KPP_NEG else {})
        return {"run_id": str(run_id), "algorithm": algorithm,
                "computed_at": finished_at.isoformat() if finished_at else None,
                "current": self._matches(p, params, extra, digest)}

    def history(self, case_id: UUID, node_id: UUID, metric: str,
                limit: int = 50) -> list[dict]:
        """One node's value for one metric across runs -- the time series
        docs/03 asks for ("a rising betweenness trend is a promotion").

        Scoped to runs computed at the caller's own visibility, so an
        analyst cannot read back a series computed over a graph they were
        never allowed to see.

        Each point says which world time it measured (`as_of`, None for the
        live graph, when the run's own start is the world time) and the
        projection it was measured under, because points taken at different
        confidence floors or with inferred ties in and out are different
        measurements and the chart must not join them into one line
        (ux10-analytics:trend-mixes-run-time-and-world-time, 2026-09-23).
        A constraint percentile stored before `constraint_order` existed ran
        the other way, and is re-ranked here so one column means one thing:
        see `upgraded_constraint_percentile` for why "100 minus it" is not
        the answer.
        """
        rows = self._c.execute(
            """SELECT r.started_at, nm.value, nm.rank, nm.percentile,
                      r.is_approximate, r.node_count, pr.preset, pr.params,
                      r.id, (r.result ->> 'constraint_order') IS NOT NULL,
                      c.defined, c.above, c.equal
                 FROM analytics.node_metric nm
                 JOIN analytics.metric_run r ON r.id = nm.metric_run_id
                 JOIN analytics.projection pr ON pr.id = r.projection_id
                 -- The run's other constraint rows, counted only for a
                 -- constraint point from a run stored before the fix; the
                 -- outer-only conditions make it a one-time filter, so
                 -- every other point skips the scan.
                 LEFT JOIN LATERAL (
                     SELECT count(*) AS defined,
                            count(*) FILTER (WHERE o.value > nm.value) AS above,
                            count(*) FILTER (WHERE o.value = nm.value) AS equal
                       FROM analytics.node_metric o
                      WHERE o.metric_run_id = r.id AND o.metric = 'constraint'
                        AND nm.metric = 'constraint'
                        AND (r.result ->> 'constraint_order') IS NULL
                 ) c ON true
                WHERE pr.case_id = %s AND nm.node_id = %s AND nm.metric = %s
                  AND r.status = 'COMPLETE'
                  AND r.visibility_clearance = %s::core.tlp
                  AND r.visibility_compartments = %s
                ORDER BY r.started_at DESC
                LIMIT %s""",
            (case_id, node_id, metric, self._clearance,
             sorted(self._comp), limit),
        ).fetchall()
        out = []
        for r in rows:
            pct = float(r[3]) if r[3] is not None else None
            if metric == "constraint" and pct is not None and not r[9]:
                pct = upgraded_constraint_percentile(
                    r[5], defined=r[10], above=r[11], equal=r[12], stored=pct)
            params = r[7] or {}
            out.append({
                "at": r[0].isoformat(), "value": r[1], "rank": r[2],
                "percentile": pct, "is_approximate": r[4],
                "node_count": r[5], "preset": r[6], "params": params,
                "run_id": str(r[8]),
                "as_of": params.get("as_of"),
                "min_confidence": params.get("min_confidence"),
                "include_inferred": params.get("include_inferred"),
                "decay_half_life_months": params.get("decay_half_life_months"),
            })
        return out

    def _newest(self, p: Projection, params: AnalyticsParams, algorithm: str,
                *, n_remove: int | None = None):
        """The newest COMPLETE run of one algorithm for this projection at
        the caller's visibility: (id, result, finished_at, graph_hash,
        params), or None. The key-player size narrows it when given."""
        return self._c.execute(
            """SELECT r.id, r.result, r.finished_at, r.graph_hash, r.params
                 FROM analytics.metric_run r
                 JOIN analytics.projection pr ON pr.id = r.projection_id
                WHERE pr.case_id = %s AND pr.name = %s
                  AND r.algorithm = %s AND r.status = 'COMPLETE'
                  AND r.visibility_clearance = %s::core.tlp
                  AND r.visibility_compartments = %s
                  AND (%s::int IS NULL OR (r.params ->> 'n_remove')::int = %s)
                ORDER BY r.finished_at DESC NULLS LAST, r.started_at DESC
                LIMIT 1""",
            (p.case_id, self._projection_name(p, params), algorithm,
             self._clearance, sorted(self._comp), n_remove, n_remove),
        ).fetchone()

    def _matches(self, p: Projection, params: AnalyticsParams, extra: dict,
                 stored: bytes | None) -> bool:
        """Does the caller's graph, projected now, hash as a run's did?

        The same projection, limit and key derivation `_run` uses, so a
        True here is exactly the condition under which `_lookup` would
        serve that run again, and a False is exactly a cache miss."""
        if stored is None:
            return False
        sub = self._graph.project(p, limit=PROJECT_LIMIT)
        return self._cache_key(sub, p, params, extra) == bytes(stored)

    # -- internals ---------------------------------------------------------
    def _run(self, p: Projection, params: AnalyticsParams, algorithm: str,
             extra_params: dict, *, force: bool, compute) -> RunResult:
        # Project FIRST. This is the clearance-filtered graph, and it is
        # also what the cache key is derived from, so there is no path that
        # serves a cached number without re-deriving the caller's own view.
        sub = self._graph.project(p, limit=PROJECT_LIMIT)
        digest = self._cache_key(sub, p, params, extra_params)
        projection_id = self._upsert_projection(p, params)

        if not force:
            hit = self._lookup(projection_id, algorithm, digest)
            if hit is not None:
                run_id, payload = hit
                # `current=True` is stated rather than left to the default:
                # this path earns it by comparison, because `_lookup`
                # matched `digest` (the hash of the graph just projected
                # above) against the hash the run was computed under.
                # `latest` makes the same comparison through `_matches`.
                return RunResult(upgrade_stored(payload), run_id, cached=True,
                                 current=True)

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
        # Computed from the projection taken at the top of this call, so it
        # describes the graph as it stands now: `current=True` by construction.
        return RunResult(payload, run_id, cached=False, current=True)

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
        name = self._projection_name(p, params)
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

    @staticmethod
    def _projection_name(p: Projection, params: AnalyticsParams) -> str:
        """The derived name `_upsert_projection` stores and `latest` looks
        up. One function for both, because a `latest` that fingerprinted
        the parameters its own way would look for a row the upsert never
        wrote and answer 404 to a case with a dozen completed runs."""
        fingerprint = hashlib.sha256(
            json.dumps({**p.describe(), **params.describe()},
                       sort_keys=True, default=str).encode()
        ).hexdigest()[:16]
        return f"auto:{p.preset}:{fingerprint}"

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
