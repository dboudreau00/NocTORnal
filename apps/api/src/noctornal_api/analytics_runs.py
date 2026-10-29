"""Metric runs: cache, persistence and audit around the maths in `analytics.py` (docs/02, docs/03).

`analytics.py` is database-free. This module resolves the projection row, reuses a run when it can,
computes when it cannot, and records what happened.

The cache is a security boundary. `GraphService.project()` filters by the caller's clearance and
compartments, so a score computed over RED nodes and served to an AMBER analyst would leak structure
they may not see. `graph_hash` is taken over the caller-visible nodes and edges, and the lookup also
filters on `visibility_clearance` and `visibility_compartments`, so even a hash collision cannot
cross a clearance boundary.

`metric_run.result` holds the exact payload served (a cache hit is one row read, byte-identical to
the computed answer) and `node_metric` the same per-node numbers relationally, for time series per
node (docs/03). Both are written in one transaction, so they cannot disagree.
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

# blockmodel and rege are imported at module top so an install without numpy fails at boot, not on
# the first role analysis.
from noctornal_api import blockmodel
from noctornal_api import rege as regular
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
    one_mode_block,
    review_scope_block,
    run_suite,
)
from noctornal_api.projections import (
    REVIEW_SCOPE_ALL,
    GraphService,
    Projection,
    ProjectionTooLarge,
)

SUITE = "sna_suite"
KPP_NEG = "kpp_neg"
CONCOR = "concor"
REGE = "rege"
#: The role analyses whose cache key folds every tie's ends, type and direction, because their
#: relations depend on direction.
_DIRECTED_KEYS = (CONCOR, REGE)

#: The node-row limit every run projects at. One constant, because the
#: currency check has to re-project exactly as the run did: a different
#: limit is a different node set and so a different hash.
PROJECT_LIMIT = 5000


def upgrade_stored(payload: dict) -> dict:
    """A stored suite payload brought up to the rules this build computes by.

    `metric_run.result` is the exact payload a run served, and a cache hit or `latest` hands it
    back. Runs stored by older builds carry a `constraint_percentile` that ran the opposite way to
    `constraint_rank`, and broker leads chosen by an absolute constraint cut-off that tagged the
    busiest actors. Both are recomputed from the payload's own per-node numbers, so the answer is
    what this build would say about the same graph, and the payload lists what was redone
    (`upgraded`). Community sizes are counted from the rows too. A payload that already carries
    `constraint_order` is returned as is, apart from the disputed count (`_with_disputed`).
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
    """A stored `review_coverage` given the disputed count that older runs lack.

    Runs computed before DISPUTED was counted left those ties in no bucket. Nothing sets SUPERSEDED
    on a tie, so `ties` less the proposed, accepted and rejected counts is exactly the disputed
    count, and the pane can warn about a stored run as about a fresh one. A payload that already
    counts them is returned as is (the same object)."""
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
    """A stored constraint percentile re-ranked the way `upgrade_stored` re-ranks the payload.

    "100 minus the stored one" is exact only for a graph with no isolates: both rankings put
    isolates (undefined constraint) below the actors, so turning the old percentile round moves the
    actors down by the isolates' share. The percentile is counted again with
    `_rank_and_percentile`'s mid-rank definition over `_least_constrained_first`: below an actor are
    the isolates (`node_count - defined`, since an isolate writes no row), every actor more
    constrained (`above`) and half the ties (`equal`, the actor included). The expression is the
    helper's own, so the trend and actor tables agree to the digit. Without the counts (a run with
    no `node_count`) the turn-round is kept rather than printing nothing.
    """
    if not node_count or defined is None or above is None or equal is None:
        return round(100.0 - stored, 2)
    below = (node_count - defined) + above
    return round(100.0 * (below + 0.5 * equal) / node_count, 2)


def _scope_detail(p: Projection) -> dict:
    """What an audit event adds for the projection options: only what is not the default, so audit
    rows keep their shape and a default run's detail has neither key."""
    out: dict = {}
    if p.review_scope != REVIEW_SCOPE_ALL:
        out["review_scope"] = p.review_scope
    if p.one_mode.enabled():
        out["one_mode"] = list(p.one_mode.families)
    return out


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
    #: Where the answer came from, not whether it is fresh: True when read out of
    #: `analytics.metric_run`, False when computed during this request. See `current`.
    cached: bool
    #: When the run finished, for a result read back by `latest`. None on
    #: the compute and cache-hit paths, where the answer is "now" or the
    #: caller asked for a hash match rather than a moment in time.
    computed_at: datetime | None = None
    #: Whether this answer is known to describe the caller's graph as it stands now: True when it
    #: was just computed or its `graph_hash` matches the graph projected for this request, False
    #: when that comparison was made and failed (`latest` re-projects and compares). Kept apart from
    #: `cached` so a stored answer is never reported as fresh; `computed_at` says when, never
    #: whether.
    #:
    #: Defaults to None, meaning not checked, so a construction site that forgets the field cannot
    #: claim currency. Every path that has checked sets it explicitly.
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
    """Runs metrics for one caller, at that caller's visibility.

    The clearance and compartments passed in must be the caller's own: they are both the filter used
    to build the graph and the scope the cached result is stored under.
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
                # What the view left out and what it derived, as on the suite; None when not asked
                # for.
                "review_scope": review_scope_block(p, sub),
                "one_mode": one_mode_block(sub),
                "key_player": out,
            }
        return self._run(p, params, KPP_NEG, {"n_remove": n_remove},
                         force=force, compute=compute)

    def concor(self, p: Projection, params: AnalyticsParams, *,
               depth: int = blockmodel.CONCOR_DEFAULT_DEPTH,
               force: bool = False) -> RunResult:
        """CONCOR positions: its own run and cache entry, keyed on the depth like key player on its
        size.

        Refusals that need no matrix are taken before a run is recorded, so a view with fewer than
        two tied entities leaves no FAILED row and no audit event."""
        return self._run(p, params, CONCOR, {"depth": depth}, force=force,
                         compute=lambda sub: blockmodel.concor(sub, p, params, depth=depth),
                         precheck=blockmodel.precheck)

    def latest_concor(self, p: Projection, params: AnalyticsParams, *,
                      depth: int) -> RunResult | None:
        """The newest complete role analysis for this projection and depth,
        checked against the graph as `latest` is. Never upgraded: a stored
        CONCOR payload is served exactly as it was computed."""
        row = self._newest(p, params, CONCOR, depth=depth)
        if row is None:
            return None
        run_id, payload, finished_at, digest, _extra = row
        return RunResult(payload, run_id, cached=True, computed_at=finished_at,
                         current=self._matches(p, params, {"depth": depth}, digest,
                                               algorithm=CONCOR))

    def rege(self, p: Projection, params: AnalyticsParams, *,
             roles: int = regular.REGE_DEFAULT_ROLES,
             weighting: str = regular.DEFAULT_WEIGHTING,
             force: bool = False) -> RunResult:
        """Regular roles by REGE, on CONCOR's pattern: its own run and cache entry, keyed on the
        number of roles, the weighting and every tie's direction. The parameters and every refusal
        that needs no matrix are checked before a run is recorded, so none leaves a FAILED row or an
        audit event."""
        extra = {"roles": roles, "weighting": weighting}
        return self._run(p, params, REGE, extra, force=force,
                         compute=lambda sub: regular.rege(sub, p, params, roles=roles,
                                                          weighting=weighting),
                         precheck=lambda sub: regular.precheck(sub, roles=roles,
                                                               weighting=weighting))

    def latest_rege(self, p: Projection, params: AnalyticsParams, *, roles: int,
                    weighting: str) -> RunResult | None:
        """The newest complete regular-role run for this projection, number
        of roles and weighting, checked against the graph as `latest` is.
        Served exactly as computed, as a CONCOR run is."""
        extra = {"roles": roles, "weighting": weighting}
        row = self._newest(p, params, REGE, match=extra)
        if row is None:
            return None
        run_id, payload, finished_at, digest, _extra = row
        return RunResult(payload, run_id, cached=True, computed_at=finished_at,
                         current=self._matches(p, params, extra, digest, algorithm=REGE))

    def latest(self, p: Projection, params: AnalyticsParams) -> RunResult | None:
        """The most recent complete suite run for this projection, at the caller's visibility, or
        None.

        The stored run is checked against the graph: the caller's graph is re-projected and its
        digest compared with the one `_lookup` matches on, so `current` is True when it hashes as it
        did when the run was computed and False when it has moved. `cached` says only that the bytes
        came out of storage. Nothing is computed and no projection row is written: a read must not
        leave a row behind.

        Scoped by `visibility_clearance` and `visibility_compartments` as `history` and `_lookup`
        are: a run computed over a better-cleared analyst's graph is never served to a lesser one.
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
        """The most recent complete key-player run for this projection and removal-set size.

        Checked against the graph as `latest` is, and keyed on the removal-set size, because a
        3-actor set says nothing about a 4-actor one.
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
        """Whether one stored run still describes the caller's graph, or None when the caller cannot
        see it.

        The pane calls this after the graph under it moves (an edit, a retirement, another analyst's
        change arriving live). The run must have been computed under the projection the caller
        names: asked about another projection the answer would compare two different questions, so
        that is a refusal, not a False.
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
        return {"run_id": str(run_id), "algorithm": algorithm,
                "computed_at": finished_at.isoformat() if finished_at else None,
                "current": self._matches(p, params, self._extra_for(algorithm, run_params),
                                         digest, algorithm=algorithm)}

    def currency_many(self, p: Projection, params: AnalyticsParams,
                      run_ids: list[UUID]) -> dict:
        """Whether each of several stored runs still describes the caller's graph, projecting it
        once.

        One call answers for every card, in the order asked, each run read at the caller's
        visibility as `currency()` reads one:

        - `{run_id, algorithm, computed_at, current}` for a run of this projection;
        - `{run_id, current: None, reason: "other_projection"}` for a run computed under another
          one, which `currency()` refuses;
        - `{run_id, current: None, reason: "not_found"}` for one the caller cannot see, which
          `currency()` answers 404.

        The projection is taken lazily, only when some run is comparable. A view over the
        derived-tie limit is `current: false`, as `_matches` says (a stored run exists only for a
        view within it).
        """
        rows = self._c.execute(
            """SELECT r.id, r.algorithm, r.params, r.graph_hash, r.finished_at, pr.name
                 FROM analytics.metric_run r
                 JOIN analytics.projection pr ON pr.id = r.projection_id
                WHERE r.id = ANY(%s) AND pr.case_id = %s AND r.status = 'COMPLETE'
                  AND r.visibility_clearance = %s::core.tlp
                  AND r.visibility_compartments = %s""",
            (list(run_ids), p.case_id, self._clearance, sorted(self._comp)),
        ).fetchall()
        found = {row[0]: row for row in rows}
        name = self._projection_name(p, params)
        projected: dict = {}

        def view():
            if "sub" not in projected:
                try:
                    projected["sub"] = self._graph.project(p, limit=PROJECT_LIMIT)
                except ProjectionTooLarge:
                    projected["sub"] = None
            return projected["sub"]

        out = []
        for run_id in run_ids:
            row = found.get(run_id)
            if row is None:
                out.append({"run_id": str(run_id), "current": None, "reason": "not_found"})
                continue
            _, algorithm, run_params, digest, finished_at, run_name = row
            if run_name != name:
                out.append({"run_id": str(run_id), "current": None,
                            "reason": "other_projection"})
                continue
            sub = view()
            current = (sub is not None and digest is not None
                       and self._cache_key(sub, p, params,
                                           self._extra_for(algorithm, run_params),
                                           algorithm) == bytes(digest))
            out.append({"run_id": str(run_id), "algorithm": algorithm,
                        "computed_at": finished_at.isoformat() if finished_at else None,
                        "current": bool(current)})
        return {"runs": out}

    @staticmethod
    def _extra_for(algorithm: str, run_params: dict | None) -> dict:
        """The algorithm parameters a run's cache key was extended by, read back from its stored
        params.

        One helper for `currency` and `currency_many`, so a new algorithm cannot be compared without
        its own (KPP_NEG's size, CONCOR's depth, REGE's roles and weighting)."""
        run_params = run_params or {}
        if algorithm == KPP_NEG:
            return {"n_remove": int(run_params.get("n_remove"))}
        if algorithm == CONCOR:
            return {"depth": int(run_params.get("depth"))}
        if algorithm == REGE:
            return {"roles": int(run_params.get("roles")),
                    "weighting": str(run_params.get("weighting"))}
        return {}

    def history(self, case_id: UUID, node_id: UUID, metric: str,
                limit: int = 50) -> list[dict]:
        """One node's value for one metric across runs: the time series docs/03 asks for ("a rising
        betweenness trend is a promotion").

        Scoped to runs computed at the caller's own visibility, so an analyst cannot read back a
        series computed over a graph they were never allowed to see.

        Each point says which world time it measured (`as_of`, None for the live graph, when the
        run's own start is the world time) and the projection used, because points taken at
        different confidence floors or with inferred ties in and out are different measurements and
        the chart must not join them into one line. A constraint percentile stored before
        `constraint_order` existed ran the other way and is re-ranked here so one column means one
        thing (see `upgraded_constraint_percentile`).
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
                *, n_remove: int | None = None, depth: int | None = None,
                match: dict | None = None):
        """The newest complete run of one algorithm for this projection at the caller's visibility:
        (id, result, finished_at, graph_hash, params), or None.

        The key-player size or CONCOR's depth narrows it when given; `match` narrows it to runs
        whose stored params contain every key and value given (REGE's roles and weighting)."""
        return self._c.execute(
            """SELECT r.id, r.result, r.finished_at, r.graph_hash, r.params
                 FROM analytics.metric_run r
                 JOIN analytics.projection pr ON pr.id = r.projection_id
                WHERE pr.case_id = %s AND pr.name = %s
                  AND r.algorithm = %s AND r.status = 'COMPLETE'
                  AND r.visibility_clearance = %s::core.tlp
                  AND r.visibility_compartments = %s
                  AND (%s::int IS NULL OR (r.params ->> 'n_remove')::int = %s)
                  AND (%s::int IS NULL OR (r.params ->> 'depth')::int = %s)
                  AND (%s::jsonb IS NULL OR r.params @> %s::jsonb)
                ORDER BY r.finished_at DESC NULLS LAST, r.started_at DESC
                LIMIT 1""",
            (p.case_id, self._projection_name(p, params), algorithm,
             self._clearance, sorted(self._comp), n_remove, n_remove, depth, depth,
             Json(match) if match else None, Json(match) if match else None),
        ).fetchone()

    def _matches(self, p: Projection, params: AnalyticsParams, extra: dict,
                 stored: bytes | None, *, algorithm: str | None = None) -> bool:
        """Does the caller's graph, projected now, hash as a run's did?

        The same projection, limit and key derivation `_run` uses, so True is exactly the condition
        under which `_lookup` would serve that run again and False is exactly a cache miss.

        A view now over the one-mode derived-tie limit is False: a stored run exists only for a view
        that was within it, so the view has changed, and a stored read answers 200 with
        `current: false` rather than refusing to show the numbers."""
        if stored is None:
            return False
        try:
            sub = self._graph.project(p, limit=PROJECT_LIMIT)
        except ProjectionTooLarge:
            return False
        return self._cache_key(sub, p, params, extra, algorithm) == bytes(stored)

    # -- internals ---------------------------------------------------------
    def _run(self, p: Projection, params: AnalyticsParams, algorithm: str,
             extra_params: dict, *, force: bool, compute, precheck=None) -> RunResult:
        # Project FIRST. This is the clearance-filtered graph, and it is
        # also what the cache key is derived from, so there is no path that
        # serves a cached number without re-deriving the caller's own view.
        sub = self._graph.project(p, limit=PROJECT_LIMIT)
        digest = self._cache_key(sub, p, params, extra_params, algorithm)
        projection_id = self._upsert_projection(p, params)

        if not force:
            hit = self._lookup(projection_id, algorithm, digest)
            if hit is not None:
                run_id, payload = hit
                # `current=True` is stated rather than left to the default: `_lookup` matched
                # `digest` (the hash of the graph just projected above) against the hash the run was
                # computed under. `latest` makes the same comparison through `_matches`.
                #
                # Only a SUITE payload is upgraded: `upgrade_stored` reads any payload with a nodes
                # list and no constraint_order as an old suite payload, which would give a CONCOR
                # hit a different shape from the one `latest_concor` serves, against the
                # byte-identical guarantee in the module docstring.
                if algorithm == SUITE:
                    payload = upgrade_stored(payload)
                return RunResult(payload, run_id, cached=True, current=True)

        if precheck is not None:
            # A refusal known without computing (CONCOR's cap and its
            # two-entity floor) is answered before a run is recorded, as an
            # unknown preset is: no RUNNING row, no FAILED row, no audit.
            precheck(sub)

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
            # Invariant 12: nothing is silently dropped. Catching only AnalyticsError would leave a
            # run stuck at RUNNING after any unexpected failure, and a stuck RUNNING row reads as
            # "still working" rather than "this broke". Every exception marks the run FAILED and is
            # then re-raised unchanged.
            self._c.execute(
                """UPDATE analytics.metric_run
                      SET status = 'FAILED', error = %s, finished_at = now(),
                          duration_ms = %s
                    WHERE id = %s""",
                (f"{type(exc).__name__}: {exc}",
                 int((time.monotonic() - started) * 1000), run_id),
            )
            self._audit(p.case_id, run_id, algorithm, "ANALYTICS_RUN_FAILED",
                        {"error_type": type(exc).__name__, **_scope_detail(p)})
            raise

        duration = int((time.monotonic() - started) * 1000)
        payload = {**payload, "computed_at_ms": duration}
        # The failure handler covers the persistence too, not only `compute(sub)`. The RUNNING row
        # was inserted on an autocommit connection, so it survives a rollback: a failure in the
        # COMPLETE write or in `_persist_node_metrics` (`Json(NaN)` raises there) would otherwise
        # strand the run at RUNNING with no FAILED status and no ANALYTICS_RUN_FAILED audit event.
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
                        {"error_type": type(exc).__name__, "stage": "persist",
                         **_scope_detail(p)})
            raise
        self._audit(p.case_id, run_id, algorithm, "ANALYTICS_RUN",
                    {"duration_ms": duration,
                     "node_count": len(sub.nodes),
                     "is_approximate": bool(payload.get("is_approximate")),
                     **_scope_detail(p)})
        # Computed from the projection taken at the top of this call, so it
        # describes the graph as it stands now: `current=True` by construction.
        return RunResult(payload, run_id, cached=False, current=True)

    def _cache_key(self, sub, p: Projection, params: AnalyticsParams,
                   extra: dict, algorithm: str | None = None) -> bytes:
        """The projection digest, extended by any algorithm parameters that change the answer (KPP's
        `n_remove`, CONCOR's `depth`).

        The CONCOR and REGE keys also fold every tie's ends, type and direction: `graph_hash`
        carries no edge type, so swapping an undirected tie for a directed one of the same sign,
        weight, dates, review and evidence would not change it, and these relations depend on
        direction (a tie given never matches one received). The suite and key-player keys do not
        fold them, so they stay identical to the ones already stored."""
        base = graph_hash(sub, p, params)
        if not extra and algorithm not in _DIRECTED_KEYS:
            return base
        h = hashlib.sha256()
        h.update(base)
        h.update(json.dumps(extra, sort_keys=True).encode())
        if algorithm in _DIRECTED_KEYS:
            h.update(b"directions\x00")
            for row in blockmodel.direction_rows(sub):
                h.update(json.dumps(row).encode())
                h.update(b"\x00")
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
        # A CONCOR row carries its position's block index rather than a community, and a REGE row
        # its role's index, in the same table keyed by run: the run's algorithm says which kind a
        # row is, so no new table or migration is needed.
        communities = [
            (run_id, n["id"], int(n["community"]))
            for n in nodes if n.get("community") is not None
        ] + [
            (run_id, n["id"], int(n["block_index"]))
            for n in nodes
            if n.get("community") is None and n.get("block_index") is not None
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
