"""Phase 3 analytics: the SNA maths, over igraph (docs/03, docs/09).

Phase 2 shipped the metrics cheap enough to compute live in Python --
degree, weighted and signed degree, clustering, k-core. This module adds
the ones that are not: betweenness, closeness, eigenvector, Burt's
structural holes, Leiden communities, cut vertices and bridges, signed
structural balance, and the key-player problem.

Four rules govern everything here.

**Nothing is computed against "the graph".** Every function takes a
`Subgraph` produced by `GraphService.project()`, which has already applied
the caller's clearance and compartments and the projection's filters. This
module never touches the database and never re-queries the graph, so it
cannot accidentally widen what the caller can see. The projection
parameters travel with every answer.

**The graph is simple and undirected for structural metrics.** Betweenness,
constraint and clustering are defined over neighbour sets, so two actors
joined by both a vouch and an accusation are ONE dyad. Phase 2 made the
same choice and reports `dyad_count` beside `edge_count` so the difference
does not read as a bug; this module inherits it. Direction is preserved
separately where it carries meaning: docs/03 is explicit that in-degree of
positive edges (vouches received, accumulated reputation) and out-degree
(vouches given, reputation staked) "mean opposite things", so they are
reported apart.

**Signs are not weights.** A negative tie is a real, strong relationship
that happens to be hostile. Metrics that assume a tie is a conduit --
closeness, eigenvector -- would be nonsense over a graph containing
hostility, so eigenvector is computed over the POSITIVE subgraph only and
says so. Metrics about structural position -- betweenness, constraint --
use the absolute tie strength, because brokering between two people who
hate each other is still brokering.

**Approximation is disclosed, never hidden.** Above a node-count threshold
betweenness switches to Brandes pivot sampling and the result carries
`is_approximate` and `sample_size`. docs/03: analysts will make removal
decisions from these numbers and are entitled to know the error bars exist.
"""
from __future__ import annotations

import hashlib
import math
import random
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import igraph

from noctornal_api.projections import Projection, Subgraph

# docs/03 performance bands: "< 5k nodes: exact, everything, synchronous".
# The ceiling here is deliberately below that, because this runs inside a
# request: past it, betweenness switches to sampling rather than blocking.
EXACT_BETWEENNESS_MAX_NODES = 3000
DEFAULT_PIVOTS = 512

# Key player is combinatorial. Greedy plus local search is affordable, but
# only with both the removal-set size and the graph capped -- an uncapped
# run on a large case would hang a request with no way to see why.
KPP_MAX_REMOVE = 10
KPP_MAX_NODES = 5000

# Triangle enumeration is O(n^3) in the worst case. Balance analysis stops
# rather than silently truncating (invariant 12).
TRIAD_MAX_NODES = 2000
MAX_UNBALANCED_TRIADS_RETURNED = 200

# docs/03: "Trust decay: apply a half-life at projection time. Default 12
# months, configurable per case. Never mutate the stored weight."
DEFAULT_HALF_LIFE_MONTHS = 12.0
_DAYS_PER_MONTH = 365.2425 / 12.0


class AnalyticsError(Exception):
    """A metric could not be computed over this projection (empty graph,
    a cap exceeded, or a parameter out of range)."""


@dataclass(frozen=True)
class AnalyticsParams:
    """Everything besides the projection that changes a number. Stored on
    the metric run and echoed in the response, because a metric whose
    parameters are not recorded is not reproducible (docs/03)."""

    # None means decay is OFF. It defaults to off deliberately: switching it
    # on silently would change every number relative to Phase 2's local
    # metrics, and an analyst comparing the two panels would see a
    # discrepancy with no visible cause.
    decay_half_life_months: float | None = None
    # The reference instant decay measures age from. Defaults to now.
    decay_reference: datetime | None = None
    betweenness_pivots: int = DEFAULT_PIVOTS
    leiden_resolution: float = 1.0
    # Fixed so a rerun over an unchanged graph returns an identical
    # partition. Leiden is stochastic; an analyst watching communities
    # reshuffle on every refresh would rightly stop trusting them.
    seed: int = 20260724

    def describe(self) -> dict:
        return {
            "decay_half_life_months": self.decay_half_life_months,
            "decay_reference": (self.decay_reference.isoformat()
                                if self.decay_reference else None),
            "betweenness_pivots": self.betweenness_pivots,
            "leiden_resolution": self.leiden_resolution,
            "seed": self.seed,
        }


@dataclass
class Materialised:
    """A projected subgraph collapsed to a simple undirected igraph, plus
    the bookkeeping needed to explain the collapse to an analyst."""

    g: igraph.Graph
    node_ids: list[UUID]                    # igraph vertex index -> node id
    labels: list[str]
    node_types: list[str]
    # Per igraph edge, parallel to g.es:
    strength: list[float]                   # absolute decayed tie strength
    sign: list[int]                         # net valence: +1, -1, or 0
    contested: list[bool]                   # dyad carries BOTH + and - ties

    edge_count: int = 0                     # projection edges, before collapse
    dyad_count: int = 0                     # after collapse
    undated_edges: int = 0                  # no valid_from/valid_to: undecayable
    self_loops_dropped: int = 0

    def index_of(self) -> dict[UUID, int]:
        return {n: i for i, n in enumerate(self.node_ids)}

    @property
    def n(self) -> int:
        return len(self.node_ids)


# --------------------------------------------------------------------------
# Trust decay
# --------------------------------------------------------------------------

def _edge_age_days(edge: dict, reference: datetime) -> float | None:
    """Age of a tie in days, or None when the graph does not date it.

    The anchor is WORLD time, never record time. `created_at` says when an
    analyst typed the row, so decaying by it would treat a freshly-entered
    2019 vouch as fresh and a long-standing tie as stale purely because
    nobody edited it -- exactly backwards. `valid_to` (the tie ended) is
    preferred over `valid_from` (it started), since a relationship known to
    have ended is the more recent fact about it.

    Undated ties are NOT decayed. Guessing an age would silently
    down-weight ties whose age is simply unrecorded, and docs/14 U3 notes
    that nothing in the UI sets these intervals yet -- so on today's data
    most ties are undated. The count is reported so the answer can say the
    decay did not bite rather than implying it did.
    """
    anchor = edge.get("valid_to") or edge.get("valid_from")
    if anchor is None:
        return None
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    return max(0.0, (reference - anchor).total_seconds() / 86400.0)


def _decay_factor(age_days: float, half_life_months: float) -> float:
    """Exponential half-life: a tie one half-life old counts for half."""
    if half_life_months <= 0:
        raise AnalyticsError("decay half-life must be positive")
    return 0.5 ** (age_days / (half_life_months * _DAYS_PER_MONTH))


# --------------------------------------------------------------------------
# Materialisation
# --------------------------------------------------------------------------

def materialise(sub: Subgraph, params: AnalyticsParams | None = None) -> Materialised:
    """Collapse a projected subgraph into a simple undirected igraph.

    Parallel edges between the same pair become one dyad whose strength is
    the sum of the decayed weights. The dyad's sign is the sign of the
    summed SIGNED strength, and a dyad carrying both positive and negative
    ties is flagged `contested` -- that combination (A vouches for B and
    also accuses B) is a lead in its own right, not noise to average away.
    """
    params = params or AnalyticsParams()
    reference = params.decay_reference or datetime.now(timezone.utc)
    half_life = params.decay_half_life_months

    node_ids = [n["id"] for n in sub.nodes]
    index = {n: i for i, n in enumerate(node_ids)}

    # Accumulate per unordered pair.
    pos: dict[tuple[int, int], float] = {}
    neg: dict[tuple[int, int], float] = {}
    unsigned: dict[tuple[int, int], float] = {}
    undated = 0
    self_loops = 0

    for e in sub.edges:
        a, b = e["src_node_id"], e["dst_node_id"]
        if a not in index or b not in index:
            continue                       # endpoint not visible: skip
        i, j = index[a], index[b]
        if i == j:
            self_loops += 1                # DB forbids these, but be safe
            continue
        key = (i, j) if i < j else (j, i)

        w = float(e["weight"])
        if half_life is not None:
            age = _edge_age_days(e, reference)
            if age is None:
                undated += 1
            else:
                w *= _decay_factor(age, half_life)

        sign = int(e["sign"])
        if sign > 0:
            pos[key] = pos.get(key, 0.0) + w
        elif sign < 0:
            neg[key] = neg.get(key, 0.0) + w
        else:
            # Sign 0 is "a tie with no valence" (POSTS_ON, CONTROLS). It
            # still connects, so it counts for structure, but it must not
            # enter balance analysis as if it were friendly.
            unsigned[key] = unsigned.get(key, 0.0) + w

    pairs = sorted(set(pos) | set(neg) | set(unsigned))
    edges: list[tuple[int, int]] = []
    strength: list[float] = []
    signs: list[int] = []
    contested: list[bool] = []
    for key in pairs:
        p, ng, un = pos.get(key, 0.0), neg.get(key, 0.0), unsigned.get(key, 0.0)
        edges.append(key)
        strength.append(p + ng + un)
        net = p - ng
        signs.append(1 if net > 0 else (-1 if net < 0 else 0))
        contested.append(p > 0 and ng > 0)

    g = igraph.Graph(n=len(node_ids), edges=edges, directed=False)
    return Materialised(
        g=g,
        node_ids=node_ids,
        labels=[n["label"] for n in sub.nodes],
        node_types=[n["node_type"] for n in sub.nodes],
        strength=strength,
        sign=signs,
        contested=contested,
        edge_count=len(sub.edges),
        dyad_count=len(edges),
        undated_edges=undated,
        self_loops_dropped=self_loops,
    )


# --------------------------------------------------------------------------
# Cache key
# --------------------------------------------------------------------------

def graph_hash(sub: Subgraph, p: Projection, params: AnalyticsParams) -> bytes:
    """A deterministic digest of everything that could change a number.

    docs/02: "Hash the sorted edge list of the projection. Unchanged hash ->
    serve cached metrics, skip the run entirely."

    Two properties matter beyond determinism.

    The digest covers the NODE set as well as the edge list, because an
    isolated node changes density, percentile ranks and fragmentation
    without touching a single edge.

    And it is taken over the subgraph AS THE CALLER SEES IT. Because
    `project()` has already dropped everything above the caller's clearance,
    two analysts with different clearance hash different edge lists and so
    land on different cache entries. That is what stops a cached run
    computed over RED nodes from being served to an AMBER analyst, whose
    view would otherwise gain betweenness scores explained by nodes they
    cannot see.
    """
    h = hashlib.sha256()
    h.update(b"noctornal-analytics-v1\x00")
    for key, value in sorted(p.describe().items()):
        h.update(f"{key}={value}\x00".encode())
    for key, value in sorted(params.describe().items()):
        h.update(f"{key}={value}\x00".encode())
    h.update(b"nodes\x00")
    for nid in sorted(str(n["id"]) for n in sub.nodes):
        h.update(nid.encode())
        h.update(b"\x00")
    h.update(b"edges\x00")
    rows = sorted(
        (str(e["src_node_id"]), str(e["dst_node_id"]), str(e["sign"]),
         format(float(e["weight"]), ".6f"), str(e["valid_from"]), str(e["valid_to"]))
        for e in sub.edges
    )
    for row in rows:
        h.update("|".join(row).encode())
        h.update(b"\x00")
    return h.digest()


# --------------------------------------------------------------------------
# Ranking helpers
# --------------------------------------------------------------------------

def _rank_and_percentile(values: list[float]) -> tuple[list[int], list[float]]:
    """Rank 1 = highest, ties share a rank. Percentile is the mid-rank
    definition (everything strictly below, plus half the ties), which keeps
    a field of identical values at 50 rather than pinning it to 0 or 100.

    docs/03: "Always show rank and percentile alongside raw value.
    Betweenness of 0.0341 means nothing to anyone; '3rd of 214' does."
    """
    n = len(values)
    if n == 0:
        return [], []
    order = sorted(range(n), key=lambda i: -values[i])
    ranks = [0] * n
    rank = 0
    prev = None
    for position, i in enumerate(order):
        if prev is None or values[i] != prev:
            rank = position + 1
            prev = values[i]
        ranks[i] = rank

    # Counting "how many are below me" per value pairwise would be O(n^2),
    # which at a few thousand nodes costs seconds per metric inside a
    # request. One ascending sweep over the sorted values gives the same
    # numbers: everything before a run of equal values is strictly below it.
    ascending = sorted(values)
    below_of: dict[float, int] = {}
    equal_of: dict[float, int] = {}
    idx = 0
    while idx < n:
        v = ascending[idx]
        end = idx
        while end < n and ascending[end] == v:
            end += 1
        below_of[v] = idx
        equal_of[v] = end - idx
        idx = end
    pct = [round(100.0 * (below_of[v] + 0.5 * equal_of[v]) / n, 2) for v in values]
    return ranks, pct


def _clean(x: float) -> float | None:
    """igraph returns NaN for constraint on an isolated vertex. NaN is not
    valid JSON and 0.0 would be a lie (an isolate is not unconstrained --
    constraint is undefined for it)."""
    if x is None or math.isnan(x) or math.isinf(x):
        return None
    return round(float(x), 6)


# --------------------------------------------------------------------------
# Burt's structural holes
# --------------------------------------------------------------------------

def burt(m: Materialised) -> dict[str, list[float | None]]:
    """Effective size, efficiency, constraint and hierarchy.

    docs/03: "Burt's constraint is arguably the single most useful metric
    for cybercrime network analysis and almost no commercial link-analysis
    tool exposes it." Low constraint means an actor spans otherwise
    disconnected groups and profits from the gap -- the initial access
    broker, the launderer, the escrow provider.

    Constraint comes from igraph's C implementation. Effective size,
    efficiency and hierarchy are computed here because igraph does not
    expose them, following Burt (1992) with the proportional tie strengths
    p_ij = w_ij / sum_k w_ik over the symmetric weighted adjacency.

    Absolute tie strength is used, not signed: brokering between two people
    who are hostile to each other is still brokering, and a hostile tie
    still constrains the actor who holds it.
    """
    g, w = m.g, m.strength
    n = m.n
    constraint = [_clean(x) for x in g.constraint(weights=w or None)]

    # Symmetric weighted neighbourhood, built once.
    nbr: list[dict[int, float]] = [dict() for _ in range(n)]
    for e_idx, e in enumerate(g.es):
        s, t = e.source, e.target
        nbr[s][t] = nbr[s].get(t, 0.0) + w[e_idx]
        nbr[t][s] = nbr[t].get(s, 0.0) + w[e_idx]

    effective: list[float | None] = []
    efficiency: list[float | None] = []
    hierarchy: list[float | None] = []

    for i in range(n):
        neigh = nbr[i]
        deg = len(neigh)
        if deg == 0:
            effective.append(None)
            efficiency.append(None)
            hierarchy.append(None)
            continue

        total = sum(neigh.values()) or 1.0
        p = {q: wq / total for q, wq in neigh.items()}

        # Effective size: degree minus the redundancy inside the
        # neighbourhood. m_jq normalises j's tie to q by j's strongest tie.
        es = 0.0
        for j in neigh:
            redundancy = 0.0
            j_nbr = nbr[j]
            j_max = max(j_nbr.values()) if j_nbr else 0.0
            if j_max > 0:
                for q, p_iq in p.items():
                    if q == i or q == j:
                        continue
                    w_jq = j_nbr.get(q)
                    if w_jq:
                        redundancy += p_iq * (w_jq / j_max)
            es += 1.0 - redundancy
        effective.append(round(es, 6))
        efficiency.append(round(es / deg, 6))

        # Burt's hierarchy: how concentrated the constraint is in one tie.
        # 0 = constraint spread evenly, 1 = one relationship dominates.
        if deg < 2 or constraint[i] is None or constraint[i] == 0:
            hierarchy.append(None)
            continue
        c_mean = constraint[i] / deg
        acc = 0.0
        for j in neigh:
            c_ij = p.get(j, 0.0)
            for q, p_iq in p.items():
                if q in (i, j):
                    continue
                c_ij += p_iq * (nbr[q].get(j, 0.0) / (sum(nbr[q].values()) or 1.0))
            c_ij = c_ij ** 2
            if c_ij > 0 and c_mean > 0:
                ratio = c_ij / c_mean
                if ratio > 0:
                    acc += ratio * math.log(ratio)
        denom = deg * math.log(deg)
        hierarchy.append(round(acc / denom, 6) if denom > 0 else None)

    return {
        "constraint": constraint,
        "effective_size": effective,
        "efficiency": efficiency,
        "hierarchy": hierarchy,
    }


# --------------------------------------------------------------------------
# Centrality
# --------------------------------------------------------------------------

def centrality(m: Materialised, params: AnalyticsParams) -> dict:
    """Betweenness, closeness, harmonic and eigenvector.

    Distance-based centralities need a COST, but the stored weight is an
    affinity: a strong tie is a shorter social distance, not a longer one.
    Feeding affinity to a shortest-path routine inverts the meaning, so the
    cost passed to igraph is 1/strength.

    Closeness is reported as HARMONIC closeness. Classical closeness is
    undefined on a disconnected graph, and criminal networks are routinely
    disconnected; igraph would silently compute it per component, making
    scores from different components incomparable. Harmonic centrality sums
    reciprocal distances, treats unreachable pairs as contributing zero, and
    is defined on any graph.

    Eigenvector is computed over the POSITIVE subgraph only. It measures
    embeddedness among the important, which presumes a tie confers standing;
    being accused by a well-connected actor does not make you influential.
    igraph accepts negative weights here but warns that the result may be
    meaningless, and it is right.
    """
    g, n = m.g, m.n
    out: dict = {}
    strength = m.strength

    if n == 0:
        return {"betweenness": [], "harmonic_closeness": [], "eigenvector": [],
                "is_approximate": False, "sample_size": None}

    cost = [1.0 / s if s > 0 else 1.0 for s in strength] or None

    approximate = n > EXACT_BETWEENNESS_MAX_NODES and params.betweenness_pivots > 0
    if approximate:
        # Brandes pivot sampling (docs/02): single-source shortest paths from
        # k random pivots, scaled by n/k. igraph 1.0 has no
        # estimate_betweenness, but `sources` gives exactly the pivot set.
        rng = random.Random(params.seed)
        pivots = rng.sample(range(n), min(params.betweenness_pivots, n))
        raw = g.betweenness(weights=cost, sources=pivots)
        scale = n / len(pivots)
        btw = [x * scale for x in raw]
        sample_size = len(pivots)
    else:
        btw = g.betweenness(weights=cost)
        sample_size = None

    out["betweenness"] = [round(float(x), 6) for x in btw]
    out["is_approximate"] = approximate
    out["sample_size"] = sample_size

    out["harmonic_closeness"] = [
        _clean(x) for x in g.harmonic_centrality(weights=cost, normalized=True)
    ]

    positive = [i for i, s in enumerate(m.sign) if s > 0]
    if positive:
        sub = g.subgraph_edges(positive, delete_vertices=False)
        sub_w = [strength[i] for i in positive]
        # igraph warns -- correctly -- that eigenvector centrality is not
        # meaningful on a disconnected graph: the power iteration converges
        # on the dominant component and everything outside it collapses
        # towards zero, so a well-connected actor in a smaller component
        # reads as unimportant. Criminal networks are routinely
        # disconnected, so this is the normal case, not an edge case.
        # The numbers are still comparable WITHIN the dominant component,
        # so they are returned with the caveat attached rather than
        # withheld -- but the caveat is not optional.
        components = [c for c in sub.connected_components(mode="weak") if len(c) > 1]
        meaningful = len(components) <= 1
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            try:
                ev = sub.eigenvector_centrality(weights=sub_w, scale=True)
            except Exception:
                # ARPACK can fail to converge on degenerate graphs. A
                # missing number is honest; a fabricated zero is not.
                ev = [float("nan")] * n
        out["eigenvector"] = [_clean(x) for x in ev]
        out["eigenvector_meaningful"] = meaningful
        out["eigenvector_note"] = (
            "computed over positive ties only"
            if meaningful else
            "computed over positive ties only, and the positive graph has {} "
            "separate components -- eigenvector centrality is only comparable "
            "WITHIN a component, so treat cross-component comparisons as "
            "meaningless".format(len(components))
        )
    else:
        out["eigenvector"] = [None] * n
        out["eigenvector_meaningful"] = False
        out["eigenvector_note"] = "no positive ties in this projection"
    out["eigenvector_basis"] = "positive ties only"
    return out


# --------------------------------------------------------------------------
# Cohesion
# --------------------------------------------------------------------------

def cohesion(m: Materialised, params: AnalyticsParams) -> dict:
    """Leiden communities, components, cut vertices and bridges.

    Leiden rather than Louvain: docs/03 notes Louvain can produce
    internally disconnected communities, which in this domain would mean a
    "cell" whose members have no path to each other.

    Cut vertices and bridges are single points of failure in the network's
    structure -- remove one and the graph falls apart. They are the cheap,
    exact companion to the key-player search.
    """
    import leidenalg

    g, n = m.g, m.n
    if n == 0:
        return {"membership": [], "community_count": 0, "modularity": None,
                "components": 0, "cut_vertices": [], "bridges": []}

    partition = leidenalg.find_partition(
        g,
        leidenalg.RBConfigurationVertexPartition,
        weights=m.strength or None,
        resolution_parameter=params.leiden_resolution,
        seed=params.seed,
        n_iterations=2,
    )
    membership = list(partition.membership)

    comps = g.connected_components(mode="weak")
    cut = sorted(g.articulation_points())
    bridge_edges = g.bridges()

    return {
        "membership": membership,
        "community_count": len(set(membership)),
        "modularity": _clean(partition.modularity),
        "components": len(comps),
        "component_sizes": sorted((len(c) for c in comps), reverse=True),
        "cut_vertices": [
            {"node_id": str(m.node_ids[i]), "label": m.labels[i]} for i in cut
        ],
        "bridges": [
            {"source": str(m.node_ids[g.es[i].source]),
             "source_label": m.labels[g.es[i].source],
             "target": str(m.node_ids[g.es[i].target]),
             "target_label": m.labels[g.es[i].target]}
            for i in bridge_edges
        ],
    }


# --------------------------------------------------------------------------
# Signed structural balance
# --------------------------------------------------------------------------

def balance(m: Materialised) -> dict:
    """Structural balance over the signed triads, and the unbalanced ones
    enumerated as leads.

    docs/03: "A vouches for B, B vouches for C, A accuses C is an unstable
    configuration: either the data is wrong, a relationship is breaking, or
    one of them is running two personas."

    Only triads whose three dyads ALL carry a valence take part. A tie with
    sign 0 (POSTS_ON, CONTROLS) is structural, not social approval, and
    counting it as friendly would manufacture balance that is not there.
    The count of skipped triads is reported so a low signed-triad count
    reads as thin data rather than a balanced network.
    """
    g, n = m.g, m.n
    if n > TRIAD_MAX_NODES:
        raise AnalyticsError(
            f"balance analysis is capped at {TRIAD_MAX_NODES} nodes; this "
            f"projection has {n}. Narrow the projection first."
        )
    sign_of: dict[tuple[int, int], int] = {}
    for idx, e in enumerate(g.es):
        a, b = e.source, e.target
        sign_of[(a, b) if a < b else (b, a)] = m.sign[idx]

    balanced = unbalanced = skipped = 0
    leads: list[dict] = []
    for tri in g.cliques(3, 3):
        i, j, k = sorted(tri)
        s1 = sign_of.get((i, j), 0)
        s2 = sign_of.get((i, k), 0)
        s3 = sign_of.get((j, k), 0)
        if s1 == 0 or s2 == 0 or s3 == 0:
            skipped += 1
            continue
        product = s1 * s2 * s3
        if product > 0:
            balanced += 1
            continue
        unbalanced += 1
        if len(leads) < MAX_UNBALANCED_TRIADS_RETURNED:
            negatives = sum(1 for s in (s1, s2, s3) if s < 0)
            leads.append({
                "nodes": [
                    {"node_id": str(m.node_ids[x]), "label": m.labels[x]}
                    for x in (i, j, k)
                ],
                "signs": [s1, s2, s3],
                # Two readings, per docs/03. One negative: the odd one out
                # is either mis-graded or the friendship is breaking. Three
                # negatives: mutual hostility with no ally, which is stable
                # in practice but classically unbalanced.
                "reading": ("one hostile tie inside an otherwise friendly "
                            "triangle: check the grading, or a relationship "
                            "is breaking")
                if negatives == 1 else
                ("all three ties hostile: classically unbalanced, but common "
                 "in practice among rivals with no common ally"),
            })

    signed_total = balanced + unbalanced
    return {
        "signed_triads": signed_total,
        "balanced": balanced,
        "unbalanced": unbalanced,
        "skipped_unsigned_triads": skipped,
        "balance_ratio": round(balanced / signed_total, 4) if signed_total else None,
        "unbalanced_triads": leads,
        "unbalanced_truncated": unbalanced > len(leads),
        "contested_dyads": [
            {"source": str(m.node_ids[g.es[i].source]),
             "source_label": m.labels[g.es[i].source],
             "target": str(m.node_ids[g.es[i].target]),
             "target_label": m.labels[g.es[i].target]}
            for i, c in enumerate(m.contested) if c
        ],
    }


# --------------------------------------------------------------------------
# Key player (Borgatti KPP-Neg)
# --------------------------------------------------------------------------

def fragmentation(g: igraph.Graph, removed: frozenset[int] = frozenset()) -> float:
    """Borgatti's F: the proportion of node pairs that CANNOT reach each
    other. 0 = fully connected, approaching 1 = fully atomised.

    F = 1 - sum_i s_i(s_i - 1) / n(n - 1), over remaining component sizes.
    """
    keep = [v for v in range(g.vcount()) if v not in removed]
    n = len(keep)
    if n < 2:
        return 1.0
    sub = g.subgraph(keep)
    connected_pairs = sum(len(c) * (len(c) - 1) for c in sub.connected_components(mode="weak"))
    return 1.0 - connected_pairs / (n * (n - 1))


def key_player(m: Materialised, n_remove: int) -> dict:
    """KPP-Neg: which set of n actors, removed, maximally fragments this
    network (Borgatti 2006).

    docs/03 flags the part that makes this worth building: "the optimal
    removal set is usually not the top-n individually-central actors. Two
    high-betweenness nodes often broker the same two clusters, so removing
    both is redundant." The response therefore reports the top-n by
    betweenness alongside the optimised set and the fragmentation each
    achieves, so the analyst can see the difference rather than take it on
    trust.

    Greedy seed then a swap local search, which is what docs/03 specifies.
    Neither is guaranteed optimal, and the result says so.
    """
    if not 1 <= n_remove <= KPP_MAX_REMOVE:
        raise AnalyticsError(
            f"removal set size must be between 1 and {KPP_MAX_REMOVE}")
    if m.n > KPP_MAX_NODES:
        raise AnalyticsError(
            f"key player is capped at {KPP_MAX_NODES} nodes; this projection "
            f"has {m.n}. Narrow the projection first.")
    if m.n <= n_remove:
        raise AnalyticsError(
            "the projection has no more nodes than the removal set size")

    g = m.g
    base = fragmentation(g)

    # Greedy seed: repeatedly take the node adding the most fragmentation.
    chosen: list[int] = []
    current = base
    for _ in range(n_remove):
        best, best_f = None, current
        for v in range(m.n):
            if v in chosen:
                continue
            f = fragmentation(g, frozenset(chosen + [v]))
            if best is None or f > best_f:
                best, best_f = v, f
        if best is None:
            # No single addition improves F. Take the highest-degree
            # remaining node so the set is still the requested size.
            remaining = [v for v in range(m.n) if v not in chosen]
            best = max(remaining, key=lambda v: g.degree(v))
            best_f = fragmentation(g, frozenset(chosen + [best]))
        chosen.append(best)
        current = best_f

    # Local search: swap one member for one outsider while it helps.
    improved = True
    passes = 0
    while improved and passes < 4:
        improved = False
        passes += 1
        for pos in range(len(chosen)):
            for v in range(m.n):
                if v in chosen:
                    continue
                trial = chosen[:pos] + [v] + chosen[pos + 1:]
                f = fragmentation(g, frozenset(trial))
                if f > current + 1e-12:
                    chosen, current, improved = trial, f, True

    # The comparison that makes the point: top-n by betweenness.
    btw = g.betweenness(weights=[1.0 / s if s > 0 else 1.0 for s in m.strength] or None)
    top_btw = sorted(range(m.n), key=lambda v: -btw[v])[:n_remove]
    top_btw_f = fragmentation(g, frozenset(top_btw))

    def describe(idxs) -> list[dict]:
        return [{"node_id": str(m.node_ids[i]), "label": m.labels[i],
                 "node_type": m.node_types[i]} for i in idxs]

    remaining = [v for v in range(m.n) if v not in set(chosen)]
    after = g.subgraph(remaining)
    return {
        "n_remove": n_remove,
        "fragmentation_before": round(base, 6),
        "fragmentation_after": round(current, 6),
        "delta": round(current - base, 6),
        "removal_set": describe(chosen),
        "top_betweenness_set": describe(top_btw),
        "top_betweenness_fragmentation": round(top_btw_f, 6),
        # The headline: when these differ, the optimised set is a genuinely
        # different and better answer than "arrest the most central people".
        "beats_top_betweenness": current > top_btw_f + 1e-12,
        "fragments_after": sorted(
            (len(c) for c in after.connected_components(mode="weak")), reverse=True
        ),
        "is_approximate": True,
        "method": "greedy seed with swap local search; not guaranteed optimal",
    }


# --------------------------------------------------------------------------
# The suite
# --------------------------------------------------------------------------

def run_suite(sub: Subgraph, p: Projection,
              params: AnalyticsParams | None = None) -> dict:
    """Everything cheap enough to compute in one pass over one materialised
    graph, assembled into the shape the API and UI consume.

    One igraph build serves every metric, which is why they share a run and
    a cache entry rather than being requested piecemeal.
    """
    params = params or AnalyticsParams()
    m = materialise(sub, params)
    if m.n == 0:
        raise AnalyticsError("this projection contains no visible nodes")

    g = m.g
    cent = centrality(m, params)
    holes = burt(m)
    coh = cohesion(m, params)
    try:
        bal = balance(m)
    except AnalyticsError as exc:
        bal = {"unavailable": str(exc)}

    degree = g.degree()
    # docs/03: received vouches (accumulated reputation) and given vouches
    # (reputation staked) "mean opposite things", so direction is preserved
    # here even though the structural metrics are undirected.
    pos_in: dict[UUID, int] = dict.fromkeys(m.node_ids, 0)
    pos_out: dict[UUID, int] = dict.fromkeys(m.node_ids, 0)
    neg_in: dict[UUID, int] = dict.fromkeys(m.node_ids, 0)
    neg_out: dict[UUID, int] = dict.fromkeys(m.node_ids, 0)
    visible = set(m.node_ids)
    for e in sub.edges:
        s, d, sg = e["src_node_id"], e["dst_node_id"], int(e["sign"])
        if s not in visible or d not in visible or sg == 0:
            continue
        if sg > 0:
            pos_out[s] += 1
            pos_in[d] += 1
        else:
            neg_out[s] += 1
            neg_in[d] += 1

    ranked = {
        name: _rank_and_percentile([v if v is not None else float("-inf")
                                    for v in values])
        for name, values in (
            ("betweenness", cent["betweenness"]),
            ("harmonic_closeness", cent["harmonic_closeness"]),
            ("eigenvector", cent["eigenvector"]),
            ("effective_size", holes["effective_size"]),
        )
    }
    # Constraint is ranked ASCENDING: low constraint is the interesting end,
    # because it means the actor spans a structural hole. Rank 1 = least
    # constrained = the broker.
    c_vals = [v if v is not None else float("inf") for v in holes["constraint"]]
    c_ranks, _ = _rank_and_percentile([-v for v in c_vals])
    _, c_pct = _rank_and_percentile([v if v is not None else float("-inf")
                                     for v in holes["constraint"]])

    nodes = []
    for i, nid in enumerate(m.node_ids):
        nodes.append({
            "id": str(nid),
            "label": m.labels[i],
            "node_type": m.node_types[i],
            "degree": degree[i],
            "positive_in_degree": pos_in[nid],
            "positive_out_degree": pos_out[nid],
            "negative_in_degree": neg_in[nid],
            "negative_out_degree": neg_out[nid],
            "betweenness": cent["betweenness"][i],
            "betweenness_rank": ranked["betweenness"][0][i],
            "betweenness_percentile": ranked["betweenness"][1][i],
            "harmonic_closeness": cent["harmonic_closeness"][i],
            "harmonic_closeness_rank": ranked["harmonic_closeness"][0][i],
            "eigenvector": cent["eigenvector"][i],
            "eigenvector_rank": ranked["eigenvector"][0][i],
            "constraint": holes["constraint"][i],
            "constraint_rank": c_ranks[i],
            "constraint_percentile": c_pct[i],
            "effective_size": holes["effective_size"][i],
            "effective_size_rank": ranked["effective_size"][0][i],
            "efficiency": holes["efficiency"][i],
            "hierarchy": holes["hierarchy"][i],
            "community": coh["membership"][i] if coh["membership"] else None,
            "is_cut_vertex": any(
                cv["node_id"] == str(nid) for cv in coh["cut_vertices"]
            ),
            "broker_signature": _broker_signature(
                degree[i], cent["betweenness"][i], holes["constraint"][i],
                ranked["betweenness"][1][i],
            ),
        })
    nodes.sort(key=lambda r: (-r["betweenness"], r["label"]))

    return {
        "projection": p.describe(),
        "params": params.describe(),
        # A metric over a CUT-OFF node set is not a metric over the case.
        # Degree survives truncation; betweenness, modularity and
        # fragmentation do not, because they depend on paths that may run
        # through the nodes that were dropped.
        "truncated": sub.truncated,
        "truncation_note": (
            "the node set was cut off at the projection limit -- global "
            "metrics below are computed over a PARTIAL graph and understate "
            "paths through the omitted nodes"
        ) if sub.truncated else None,
        "node_count": m.n,
        "edge_count": m.edge_count,
        "dyad_count": m.dyad_count,
        "dyad_note": "metrics treat the graph as simple: parallel edges "
                     "between the same pair count once",
        # CR8 (2026-07-26): through `_clean`, not `round`.
        #
        # `run_suite` guards n == 0 but not n == 1, and igraph's density()
        # on a single vertex is NaN (the denominator n(n-1) is zero).
        # `round(NaN, 6)` is still NaN, psycopg serialises it as a literal
        # `NaN`, and Postgres jsonb rejects that -- so any single-node
        # projection 500s the whole suite. Density was the ONLY float in
        # this payload not already routed through `_clean`, which exists
        # for exactly this and returns None instead.
        #
        # A single-node projection is not exotic: a case with one entity,
        # or TLP filtering that leaves one visible node, reaches it.
        "density": _clean(g.density()),
        "is_approximate": cent["is_approximate"],
        "sample_size": cent["sample_size"],
        "approximation_note": (
            "betweenness estimated from {} pivot sources (Brandes sampling)"
            .format(cent["sample_size"]) if cent["is_approximate"]
            else "all metrics exact"
        ),
        "eigenvector_meaningful": cent["eigenvector_meaningful"],
        "eigenvector_note": cent["eigenvector_note"],
        "mode_warning": _mode_warning(m.node_types, degree),
        "decay": {
            "half_life_months": params.decay_half_life_months,
            "undated_edges": m.undated_edges,
            # Decay cannot bite on ties with no interval recorded. Saying so
            # stops "decay is on" being read as "decay was applied".
            "note": (
                "decay is off" if params.decay_half_life_months is None
                else ("applied" if m.undated_edges == 0 else
                      "{} of {} ties carry no valid_from/valid_to and were "
                      "NOT decayed".format(m.undated_edges, m.edge_count))
            ),
        },
        "cohesion": {k: v for k, v in coh.items() if k != "membership"},
        "balance": bal,
        "nodes": nodes,
    }


def _mode_warning(node_types: list[str], degrees: list[int]) -> str | None:
    """Warn when a projection mixes actors with artefacts or contexts.

    docs/03 is blunt that identity plumbing "will wreck centrality if
    included", and names CONTROLS specifically -- yet the Financial preset
    includes CONTROLS, TX_INPUT and TX_OUTPUT, which make WALLET and
    TRANSACTION first-class vertices, and Communication includes
    PARTICIPANT_IN, which does the same for CONVERSATION. That is a
    two-mode (affiliation) graph, and centrality over it answers a
    different question than the analyst thinks they asked: a wallet with
    many controllers scores as a broker.

    Silently rewriting the presets would change every number the Phase 2
    sociogram already shows, so the honest move is to say so and let the
    analyst decide. docs/03's proper fix -- bipartite projection to one-mode
    with Newman weighting -- is a larger change, recorded as an open item.
    """
    from noctornal_ontology.definition import NODE_TYPES

    category = {n.key: n.category for n in NODE_TYPES}
    tied = sorted({t for t, d in zip(node_types, degrees, strict=False)
                   if category.get(t) != "ACTOR" and d > 0})
    isolated = sorted({t for t, d in zip(node_types, degrees, strict=False)
                       if category.get(t) != "ACTOR" and d == 0})
    if tied:
        return (
            "This projection is TWO-MODE: non-actor vertices ({}) carry ties. "
            "Centrality treats them as if they were people, so an artefact "
            "with several controllers scores as a broker. Read brokerage here "
            "as 'central in the actor-artefact graph', not 'central among "
            "actors'."
        ).format(", ".join(tied))
    if isolated:
        # A different, smaller problem: these do not distort brokerage
        # because they have no ties, but they DO sit in the denominator of
        # density and of every percentile.
        return (
            "This projection includes non-actor vertices ({}) with no ties in "
            "it. They do not affect brokerage, but they are counted in the "
            "node total, so density and every percentile are computed over a "
            "larger population than the actors alone."
        ).format(", ".join(isolated))
    return None


def _broker_signature(degree: int, betweenness: float,
                      constraint: float | None, btw_pct: float) -> str | None:
    """The pattern docs/03 wants the UI to teach rather than merely print:
    "high betweenness with low degree is the classic broker signature. Few
    connections, but they are the only connections between clusters."

    Returned as a sentence rather than a flag so the interface explains the
    finding instead of showing a badge whose meaning an analyst has to
    remember.
    """
    if betweenness <= 0:
        return None
    if degree <= 3 and btw_pct >= 80:
        return ("Broker signature: few ties but high brokerage -- these may be "
                "the only connections between clusters, which usually matters "
                "more than the loudest poster.")
    if constraint is not None and constraint < 0.4 and btw_pct >= 70:
        return ("Spans a structural hole: low constraint with high brokerage. "
                "Burt's reading is an actor who profits from the gap between "
                "otherwise disconnected groups.")
    return None
