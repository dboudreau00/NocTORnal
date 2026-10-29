"""The SNA maths, over igraph (docs/03, docs/09).

The metrics not cheap enough to compute live in Python: betweenness, closeness, eigenvector, Burt's
structural holes, Leiden communities, cut vertices and bridges, signed structural balance, and the
key-player problem. Four rules govern everything here.

**Nothing is computed against "the graph".** Every function takes a `Subgraph` produced by
`GraphService.project()`, which has already applied the caller's clearance and compartments and
the projection's filters. This module never touches the database and never re-queries the graph,
so it cannot widen what the caller can see. The projection parameters travel with every answer.

**The graph is simple and undirected for structural metrics.** Betweenness, constraint and
clustering are defined over neighbour sets, so two actors joined by both a vouch and an accusation
are one dyad, and `dyad_count` is reported beside `edge_count`. Direction is kept where it carries
meaning: positive in-degree (vouches received) and out-degree (vouches given) "mean opposite
things" (docs/03), so they are reported apart.

**Signs are not weights.** A negative tie is a real, strong, hostile relationship. Metrics that
treat a tie as a conduit (closeness, eigenvector) would be nonsense over hostility, so eigenvector
runs over the positive subgraph only and says so; positional metrics (betweenness, constraint) use
the absolute strength, because brokering between enemies is still brokering.

**Approximation is disclosed, never hidden.** Above a node-count threshold betweenness switches to
Brandes pivot sampling and the result carries `is_approximate` and `sample_size`: analysts make
removal decisions from these numbers and are entitled to the error bars.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import statistics
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import igraph

from noctornal_api import affiliation
from noctornal_api.projections import REVIEW_SCOPE_ALL, Projection, Subgraph

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

    # None means decay is off, deliberately: switched on silently it would change every number
    # relative to the live local metrics, and an analyst comparing the two panels would see a
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

    The anchor is world time, never record time: `created_at` says when an analyst typed the row,
    so decaying by it would treat a freshly entered 2019 vouch as fresh. `valid_to` (the tie ended)
    is preferred over `valid_from`, being the more recent fact. Undated ties are not decayed,
    because guessing an age would silently down-weight them; the count is reported so the answer
    can say the decay did not bite.
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
    """A deterministic digest of everything that could change a number (docs/02: an unchanged hash
    serves the cached metrics).

    It covers the node set as well as the edge list, because an isolated node changes density,
    percentile ranks and fragmentation. And it is taken over the subgraph as the caller sees it,
    after `project()` has dropped everything above their clearance, so analysts with different
    clearances land on different cache entries: a run computed over RED nodes is never served to
    an AMBER analyst.
    """
    h = hashlib.sha256()
    # The rows carry each tie's review state and whether an exhibit backs it, and each node's label
    # and type beside its id: the payload reports that coverage and names people, so a tie reviewed
    # or evidenced, or an entity renamed (a label that named the wrong person, say), is a different
    # answer and must not be served or called current as the same one. Bumping the version retires
    # every stored run: a cache miss, and `current` false until run again.
    h.update(b"noctornal-analytics-v3\x00")
    for key, value in sorted(p.describe().items()):
        h.update(f"{key}={value}\x00".encode())
    for key, value in sorted(params.describe().items()):
        h.update(f"{key}={value}\x00".encode())
    h.update(b"nodes\x00")
    # A label is anybody's text and may hold any separator, so each row is
    # written unambiguously (JSON quotes and escapes it): no label can be
    # worded to make two different node sets hash alike.
    for row in sorted((str(n["id"]), str(n.get("label") or ""),
                       str(n.get("node_type") or "")) for n in sub.nodes):
        h.update(json.dumps(row).encode())
        h.update(b"\x00")
    h.update(b"edges\x00")
    rows = sorted(
        (str(e["src_node_id"]), str(e["dst_node_id"]), str(e["sign"]),
         format(float(e["weight"]), ".6f"), str(e["valid_from"]), str(e["valid_to"]),
         str(e.get("review")), str(bool(e.get("has_evidence"))))
        for e in sub.edges
    )
    for row in rows:
        h.update("|".join(row).encode())
        h.update(b"\x00")
    # The accepted-ties scope's left-out counts and the one-mode coverage are folded in only when
    # present, so a default Subgraph's digest does not change and no stored run goes stale. Both are
    # in the payload: a tie added, reviewed or superseded under the accepted scope is a different
    # answer, and the one-mode coverage names venues and sizes that never reach `nodes`, so a
    # renamed oversized forum, or one raised above the caller's clearance, changes the digest.
    if sub.review_left_out is not None:
        h.update(b"review_left_out\x00")
        h.update(json.dumps(sub.review_left_out, sort_keys=True).encode())
        h.update(b"\x00")
    if sub.one_mode is not None:
        h.update(b"one_mode\x00")
        h.update(json.dumps(sub.one_mode, sort_keys=True, default=str).encode())
        h.update(b"\x00")
    return h.digest()


# --------------------------------------------------------------------------
# What the projection options did
# --------------------------------------------------------------------------

REVIEW_SCOPE_NOTE = (
    "Computed over accepted ties only. Ties that are unreviewed proposals, "
    "disputed, rejected or superseded were left out and are counted here.")


def review_scope_block(p: Projection, sub: Subgraph) -> dict | None:
    """What the accepted-ties scope left out, for the payload; None under
    the default scope, so a default payload is unchanged.
    `review_coverage` is deliberately NOT changed: under this scope it
    truthfully reads "all reviewed" of what the numbers rest on, and this
    block says what they do not rest on."""
    if p.review_scope == REVIEW_SCOPE_ALL:
        return None
    return {"scope": p.review_scope, "left_out": sub.review_left_out or {"ties": {}},
            "note": REVIEW_SCOPE_NOTE}


def one_mode_block(sub: Subgraph) -> dict | None:
    """The one-mode coverage with the prose that reads it; None when no venue family was projected.
    The prose is added here and never hashed, so a copy edit never makes a stored run stale."""
    if sub.one_mode is None:
        return None
    families = "+".join(sub.one_mode.get("families") or [])
    return {**sub.one_mode, "size_note": affiliation.SIZE_NOTE,
            "reading": affiliation.READING,
            "method": affiliation.METHOD.format(
                family=families, weighting=sub.one_mode.get("weighting"))}


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
    """Effective size, efficiency, constraint and hierarchy (Burt's structural holes, docs/03).

    Low constraint means an actor spans otherwise disconnected groups: the initial access broker,
    the launderer, the escrow provider. Constraint comes from igraph; effective size, efficiency
    and hierarchy are computed here, which igraph does not expose, following Burt (1992) with
    p_ij = w_ij / sum_k w_ik over the symmetric weighted adjacency. Absolute tie strength, not
    signed: brokering between enemies is still brokering, and a hostile tie still constrains.
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

    The stored weight is an affinity, and a shortest-path routine needs a cost, so the cost passed
    to igraph is 1/strength. Closeness is reported as harmonic closeness, defined on a disconnected
    graph (criminal networks routinely are), where classical closeness computed per component would
    make scores incomparable. Eigenvector runs over the positive subgraph only: it presumes a tie
    confers standing, and being accused by a well-connected actor does not.
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
        # Eigenvector centrality is not meaningful across a disconnected graph: the power iteration
        # converges on the dominant component and a well-connected actor elsewhere reads as
        # unimportant. The numbers are still comparable within the dominant component, so they are
        # returned with the caveat attached, never without it.
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
            "separate components: eigenvector centrality is only comparable "
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

    Leiden rather than Louvain, which can produce internally disconnected communities: a "cell"
    whose members have no path to each other (docs/03). Cut vertices and bridges are the cheap,
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

    # Community sizes travel with the answer, largest first, each with the id the rows carry, so
    # nobody counts rows by eye.
    sizes: dict[int, int] = {}
    for c in membership:
        sizes[c] = sizes.get(c, 0) + 1

    return {
        "membership": membership,
        "community_count": len(set(membership)),
        "community_sizes": [
            {"community": c, "size": s}
            for c, s in sorted(sizes.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
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
    """Structural balance over the signed triads, and the unbalanced ones enumerated as leads
    (docs/03).

    Only triads whose three dyads all carry a valence take part: a sign-0 tie (POSTS_ON, CONTROLS)
    is structural, not social approval, and counting it as friendly would manufacture balance. The
    skipped triads are counted, so a low signed-triad count reads as thin data rather than a
    balanced network.
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
    """KPP-Neg: which set of n actors, removed, maximally fragments this network (Borgatti 2006).

    The optimal removal set is usually not the top n by centrality, since two high-betweenness
    actors often broker the same clusters (docs/03), so the response reports the top n by
    betweenness beside the optimised set with the fragmentation each achieves. Greedy seed then a
    swap local search, as docs/03 specifies; neither is guaranteed optimal, and the result says so.
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
        if sub.one_mode is not None:
            # Said as what happened: the view had nodes, and they were all venues.
            raise AnalyticsError("projecting the venues left no entities in this view")
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
    # Constraint is ranked ascending: low constraint means the actor spans a structural hole, so
    # rank 1 is the least constrained, the broker. The percentile runs the same way, the least
    # constrained highest as in the betweenness column, and `constraint_order` says so on the
    # payload, so a stored run computed the other way can be brought up to date
    # (`analytics_runs.upgrade_stored`). An isolate's undefined constraint sorts to the constrained
    # end.
    c_ranks, c_pct = _rank_and_percentile(_least_constrained_first(holes["constraint"]))

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
        })
    nodes.sort(key=lambda r: (-r["betweenness"], r["label"]))
    leads = assign_broker_leads(nodes)

    return {
        "projection": p.describe(),
        "params": params.describe(),
        "constraint_order": CONSTRAINT_ORDER,
        "broker_rule": leads,
        "review_coverage": review_coverage(sub),
        # None unless the projection asked for them.
        "review_scope": review_scope_block(p, sub),
        "one_mode": one_mode_block(sub),
        # A metric over a CUT-OFF node set is not a metric over the case.
        # Degree survives truncation; betweenness, modularity and
        # fragmentation do not, because they depend on paths that may run
        # through the nodes that were dropped.
        "truncated": sub.truncated,
        "truncation_note": (
            "the node set was cut off at the projection limit: global "
            "metrics below are computed over a PARTIAL graph and understate "
            "paths through the omitted nodes"
        ) if sub.truncated else None,
        "node_count": m.n,
        "edge_count": m.edge_count,
        "dyad_count": m.dyad_count,
        "dyad_note": "metrics treat the graph as simple: parallel edges "
                     "between the same pair count once",
        # Through `_clean`, not `round`: igraph's density() on a single vertex is NaN, which jsonb
        # refuses, and a one-node projection is common (one entity, or one left visible).
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
        "mode_warning": _mode_warning(
            m.node_types, degree,
            projectable=tuple(f for f in affiliation.FAMILIES
                              if f not in p.one_mode.families)),
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


def _mode_warning(node_types: list[str], degrees: list[int],
                  projectable: tuple[str, ...] = ()) -> str | None:
    """Warn when a projection mixes actors with artefacts or contexts.

    The Financial preset's CONTROLS, TX_INPUT and TX_OUTPUT make WALLET and TRANSACTION vertices,
    and Communication's PARTICIPANT_IN does the same for CONVERSATION: a two-mode graph, over which
    centrality answers a different question (a wallet with many controllers scores as a broker).
    Rewriting the presets silently would change every number the sociogram shows, so this says so
    and the analyst decides; the one-mode projection is an option (`affiliation.py`), never a
    rewritten preset (decision 33). `projectable` is the families not projected in this run: when a
    tied non-actor type is one of their venues, the sentence names the option. Both branches stay
    whatever is projected, since a projected view can still hold an isolated SELECTOR or a tied
    SERVICE. CONVERSATION is in no family (decision 73), so that warning names no option.
    """
    from noctornal_ontology.definition import NODE_TYPES

    category = {n.key: n.category for n in NODE_TYPES}
    tied = sorted({t for t, d in zip(node_types, degrees, strict=False)
                   if category.get(t) != "ACTOR" and d > 0})
    isolated = sorted({t for t, d in zip(node_types, degrees, strict=False)
                       if category.get(t) != "ACTOR" and d == 0})
    if tied:
        text = (
            "This projection is TWO-MODE: non-actor vertices ({}) carry ties. "
            "Centrality treats them as if they were people, so an artefact "
            "with several controllers scores as a broker. Read brokerage here "
            "as 'central in the actor-artefact graph', not 'central among "
            "actors'."
        ).format(", ".join(tied))
        options = [affiliation.FAMILIES[f].label.lower() for f in projectable
                   if f in affiliation.FAMILIES
                   and set(affiliation.FAMILIES[f].venue_types) & set(tied)]
        if options:
            text += (" Projecting " + " or ".join(options) + " to entities, under "
                     "the Analysis pane's projection options, computes over "
                     "entities alone.")
        return text
    if isolated:
        # A different, smaller problem: these do not distort brokerage
        # because they have no ties, but they DO sit in the denominator of
        # density and of every percentile.
        return (
            "This projection includes non-actor vertices ({}) with no ties, "
            "so density and every percentile are computed over a larger "
            "population than the actors alone."
        ).format(", ".join(isolated))
    return None


#: What `constraint_rank` and `constraint_percentile` mean on a payload that says so: rank 1 and
#: the highest percentile are the least constrained actor. A stored payload without this key has
#: its percentile running the other way.
CONSTRAINT_ORDER = "least_constrained_first"

#: The broker leads' thresholds, as percentiles among the actors that have
#: at least one tie (see `assign_broker_leads`).
FEW_TIES_BETWEENNESS_PCT = 80.0
FEW_TIES_MAX_DEGREE = 3
HOLE_BETWEENNESS_PCT = 75.0
HOLE_CONSTRAINT_PCT = 75.0

_LEAD_TEXT = {
    "few_ties": (
        "Broker signature: few ties but high brokerage. These may be the "
        "only connections between clusters, which usually matters more than "
        "the loudest poster."),
    "structural_hole": (
        "Spans a structural hole: among the least constrained and the most "
        "brokering actors here. Burt's reading is that this actor's contacts "
        "are poorly connected to each other, so what passes between them "
        "tends to pass through this actor."),
}


def _least_constrained_first(values: list[float | None]) -> list[float]:
    """Constraint turned so that `_rank_and_percentile`'s "highest first"
    puts the least constrained actor at rank 1 and at the top percentile.
    Undefined (an isolate) sorts to the constrained end."""
    return [-v if v is not None else float("-inf") for v in values]


def assign_broker_leads(nodes: list[dict]) -> dict:
    """Mark the actors the pane offers as "Brokers worth a look", on the
    node rows themselves (`broker_kind`, `broker_signature`), and return the
    rule that chose them.

    The broker signature is high betweenness with low degree (docs/03), said as a sentence rather
    than a badge so the interface explains the finding. The sentence ends up in reports about
    people, so both leads rank the actor against the others rather than against an absolute
    threshold, which can hold for nearly every actor in a case:

    - few ties: three ties or fewer, or fewer than the median actor; and betweenness in the top
      fifth;
    - structural hole: in the least constrained quarter and the top quarter for betweenness.

    The population is the actors with at least one tie: an isolate has no brokerage and no defined
    constraint, and counting isolates would move every percentile when an unconnected entity is
    added. The sentence says what Burt says about the position, not about components, because a
    structural hole is a gap between an actor's own contacts. Runs over node rows rather than the
    igraph build, so a stored run can be brought up to date from its own numbers (`analytics_runs`).
    """
    for n in nodes:
        n["broker_kind"] = None
        n["broker_signature"] = None
    tied = [n for n in nodes if (n.get("degree") or 0) > 0]
    rule = {
        "population": "actors with at least one tie",
        "connected_count": len(tied),
        "median_degree": None,
        "few_ties_max_degree": FEW_TIES_MAX_DEGREE,
        "few_ties_betweenness_percentile": FEW_TIES_BETWEENNESS_PCT,
        "structural_hole_betweenness_percentile": HOLE_BETWEENNESS_PCT,
        "structural_hole_constraint_percentile": HOLE_CONSTRAINT_PCT,
    }
    if not tied:
        return rule
    _, btw_pct = _rank_and_percentile(
        [float(n.get("betweenness") or 0.0) for n in tied])
    _, loose_pct = _rank_and_percentile(
        _least_constrained_first([n.get("constraint") for n in tied]))
    median = statistics.median(n["degree"] for n in tied)
    rule["median_degree"] = median
    for n, bp, cp in zip(tied, btw_pct, loose_pct, strict=True):
        if not n.get("betweenness") or n["betweenness"] <= 0:
            continue
        few = n["degree"] <= FEW_TIES_MAX_DEGREE or n["degree"] < median
        if few and bp >= FEW_TIES_BETWEENNESS_PCT:
            kind = "few_ties"
        elif (n.get("constraint") is not None and cp >= HOLE_CONSTRAINT_PCT
              and bp >= HOLE_BETWEENNESS_PCT):
            kind = "structural_hole"
        else:
            continue
        n["broker_kind"] = kind
        n["broker_signature"] = _LEAD_TEXT[kind]
    return rule


def review_coverage(sub: Subgraph) -> dict:
    """How much of what the numbers rest on an analyst has reviewed, and how
    much an exhibit backs.

    The Analysis pane turns ties into claims about people ("Brokers worth a look", "Removal set"),
    so a removal set computed from unreviewed machine proposals with no exhibit must not read like
    one computed from reviewed, evidenced ties. Counted over the projection's ties, the same
    population as `edge_count`; nothing here filters, since whether to compute over reviewed ties
    only is the projection's question. DISPUTED, the one doubt tie review (`graph.REVIEW_STATES`)
    can record, has a bucket of its own; REJECTED is kept for rows written before tie review
    refused it.
    """
    out = {"ties": len(sub.edges), "proposed": 0, "accepted": 0,
           "disputed": 0, "rejected": 0, "evidenced": 0, "inferred": 0}
    for e in sub.edges:
        state = e.get("review")
        if state == "PROPOSED":
            out["proposed"] += 1
        elif state == "ACCEPTED":
            out["accepted"] += 1
        elif state == "DISPUTED":
            out["disputed"] += 1
        elif state == "REJECTED":
            out["rejected"] += 1
        if e.get("has_evidence"):
            out["evidenced"] += 1
        if e.get("is_inferred"):
            out["inferred"] += 1
    return out
