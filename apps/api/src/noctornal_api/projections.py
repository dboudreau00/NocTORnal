"""Projections and graph queries (Phase 2, docs/03 + docs/09).

A metric computed against "the graph" is meaningless, because every filter
changes every number. So analysis always runs against a **projection**: a
named, reproducible view pinning which edge types count, whether inferred
edges are included, the minimum confidence, and the time window. docs/03
ships four presets, and the point of them is that the leadership picture
differs between them — that difference is itself a finding.

Every query here filters by the CALLER's clearance and compartments, and an
edge is only returned when BOTH endpoints are visible: otherwise an edge
would betray the existence of a node the analyst may not see.

Local metrics (degree, weighted degree, clustering, k-core) are computed in
Python over the projected subgraph. They are the ones cheap enough to be
live per docs/03's "under 5k nodes: exact, synchronous" band; betweenness,
Burt's constraint, Leiden and key-player analysis are Phase 3 and belong in
the analytics worker with igraph.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

import psycopg

# docs/03: "Ship four presets: Communication, Trust, Financial, All ties."
# Edge-type membership comes from the seeded ontology, not from guesswork:
# TRUST is the signed trust layer, COMMUNICATION the interaction layer,
# FINANCIAL the money layer. ALL is every social tie.
PRESETS: dict[str, dict] = {
    "trust": {
        "label": "Trust",
        "description": "Vouches, guarantees, escrow, rip reports, disputes — "
                       "the signed network. Negative ties included, because "
                       "removing them throws away the most diagnostic signal.",
        "edge_types": ["VOUCHED_FOR", "GUARANTOR_FOR", "ESCROW_FOR",
                       "ACCUSED_SCAM", "DISPUTED_WITH", "RIVAL_OF"],
    },
    "communication": {
        "label": "Communication",
        "description": "Who talks to whom, and who replies. Co-participation "
                       "is deliberately excluded: it is a projection, not an "
                       "observation.",
        "edge_types": ["COMMUNICATES_WITH", "REPLIED_TO", "MET_WITH",
                       "PARTICIPANT_IN"],
    },
    "financial": {
        "label": "Financial",
        "description": "Payments, laundering, escrow and wallet control — the "
                       "money picture, which usually names different leaders "
                       "than the trust one does.",
        "edge_types": ["PAID", "LAUNDERED_FOR", "ESCROW_FOR", "CONTROLS",
                       "TX_INPUT", "TX_OUTPUT"],
    },
    "all": {
        "label": "All ties",
        "description": "Every edge type marked as a social tie in the "
                       "ontology. Identity plumbing (SAME_AS, ALIAS_OF) stays "
                       "out — it would make whichever persona you researched "
                       "hardest look the most central.",
        "edge_types": None,          # resolved to is_social_tie at query time
    },
}

_CONFIDENCE_ORDER = {"LOW": 0, "MODERATE": 1, "HIGH": 2}


class ProjectionError(Exception):
    pass


@dataclass(frozen=True)
class Projection:
    """The parameters that make a number reproducible. Shown next to every
    result, always (docs/03: "Show the projection parameters next to the
    results")."""
    case_id: UUID
    preset: str = "all"
    include_inferred: bool = False
    min_confidence: str = "LOW"
    as_of: datetime | None = None      # world-time: the graph as it stood then
    edge_types: list[str] | None = None

    def resolved_edge_types(self) -> list[str] | None:
        if self.edge_types is not None:
            return self.edge_types
        return PRESETS[self.preset]["edge_types"]

    def describe(self) -> dict:
        return {
            "preset": self.preset,
            "label": PRESETS[self.preset]["label"],
            "include_inferred": self.include_inferred,
            "min_confidence": self.min_confidence,
            "as_of": self.as_of.isoformat() if self.as_of else None,
            "edge_types": self.resolved_edge_types(),
        }


@dataclass
class Subgraph:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    projection: dict = field(default_factory=dict)
    truncated: bool = False

    def node_ids(self) -> set[UUID]:
        return {n["id"] for n in self.nodes}


class GraphService:
    def __init__(self, conn: psycopg.Connection, *, clearance: str,
                 compartments: frozenset[str]):
        self._c = conn
        self._clearance = clearance
        self._comp = list(compartments)

    # -- projection --------------------------------------------------------
    def project(self, p: Projection, *, limit: int = 2000) -> Subgraph:
        """The projected subgraph: visible nodes, and edges whose endpoints
        are BOTH visible and which pass the projection's filters."""
        if p.preset not in PRESETS:
            raise ProjectionError(f"unknown preset {p.preset!r}")
        if p.min_confidence not in _CONFIDENCE_ORDER:
            raise ProjectionError(f"unknown confidence {p.min_confidence!r}")

        nodes = self._c.execute(
            """SELECT id, node_type, label, classification, attrs,
                      valid_from, valid_to, first_seen, last_seen
                 FROM core.node n
                WHERE case_id = %s AND deleted_at IS NULL AND merged_into_id IS NULL
                  AND classification <= %s::core.tlp AND compartments <@ %s
                  -- LIVE provenance. Decision 24 makes this the PROJECTION's
                  -- job on purpose: the database guarantees >=1 assertion row
                  -- per element at all times, but retraction must let an
                  -- element lose all live support and DISSOLVE from the live
                  -- graph while its row and history survive for temporal
                  -- replay. Without this leg retraction is cosmetic -- the
                  -- assertion shows RETRACTED while the node keeps its full
                  -- degree, and every metric counts withdrawn evidence.
                  AND EXISTS (SELECT 1 FROM core.assertion a
                               WHERE a.node_id = n.id AND a.retracted_at IS NULL)
                  -- as-of is WORLD time: the thing existed then.
                  AND (%s::timestamptz IS NULL
                       OR (valid_from IS NULL OR valid_from <= %s)
                       AND (valid_to IS NULL OR valid_to >= %s))
                ORDER BY created_at LIMIT %s""",
            (p.case_id, self._clearance, self._comp,
             p.as_of, p.as_of, p.as_of, limit + 1),
        ).fetchall()
        truncated = len(nodes) > limit
        nodes = nodes[:limit]
        node_out = [
            {"id": r[0], "node_type": r[1], "label": r[2], "classification": r[3],
             "attrs": r[4] or {}, "valid_from": r[5], "valid_to": r[6],
             "first_seen": r[7], "last_seen": r[8]}
            for r in nodes
        ]
        ids = [n["id"] for n in node_out]
        edge_out: list[dict] = []
        if ids:
            types = p.resolved_edge_types()
            min_rank = _CONFIDENCE_ORDER[p.min_confidence]
            rows = self._c.execute(
                """SELECT e.id, e.edge_type, e.src_node_id, e.dst_node_id, e.sign,
                          e.weight, e.confidence, e.is_inferred, e.review,
                          e.classification, e.valid_from, e.valid_to, et.is_social_tie
                     FROM core.edge e
                     JOIN core.edge_type et ON et.key = e.edge_type
                    WHERE e.case_id = %s AND e.deleted_at IS NULL
                      AND e.src_node_id = ANY(%s) AND e.dst_node_id = ANY(%s)
                      AND e.classification <= %s::core.tlp AND e.compartments <@ %s
                      AND (%s OR NOT e.is_inferred)
                      -- LIVE provenance, as for nodes above (decision 24).
                      -- Retracting the only assertion behind a tie must
                      -- dissolve the tie from the live graph.
                      AND EXISTS (SELECT 1 FROM core.assertion a
                                   WHERE a.edge_id = e.id
                                     AND a.retracted_at IS NULL)
                      -- NULL types means "the preset is everything social".
                      AND (%s::text[] IS NULL AND et.is_social_tie
                           OR e.edge_type = ANY(%s))
                      AND (%s::timestamptz IS NULL
                           OR (e.valid_from IS NULL OR e.valid_from <= %s)
                           AND (e.valid_to IS NULL OR e.valid_to >= %s))""",
                (p.case_id, ids, ids, self._clearance, self._comp,
                 p.include_inferred, types, types, p.as_of, p.as_of, p.as_of),
            ).fetchall()
            keep = {"LOW", "MODERATE", "HIGH"}
            keep = {c for c in keep if _CONFIDENCE_ORDER[c] >= min_rank}
            edge_out = [
                {"id": r[0], "edge_type": r[1], "src_node_id": r[2],
                 "dst_node_id": r[3], "sign": r[4], "weight": float(r[5]),
                 "confidence": r[6], "is_inferred": r[7], "review": r[8],
                 "classification": r[9], "valid_from": r[10], "valid_to": r[11]}
                for r in rows if r[6] in keep
            ]
        return Subgraph(node_out, edge_out, p.describe(), truncated)

    # -- neighbourhood -----------------------------------------------------
    def ego(self, p: Projection, centre: UUID, depth: int = 1) -> Subgraph:
        """The ego network around one node to `depth` hops — what a
        double-click gives you (docs/06). Computed from the projection so it
        honours the same filters."""
        full = self.project(p, limit=5000)
        if centre not in full.node_ids():
            raise ProjectionError("centre node is not in this projection")
        adjacency: dict[UUID, set[UUID]] = defaultdict(set)
        for e in full.edges:
            adjacency[e["src_node_id"]].add(e["dst_node_id"])
            adjacency[e["dst_node_id"]].add(e["src_node_id"])
        seen = {centre}
        frontier = {centre}
        for _ in range(max(0, depth)):
            nxt: set[UUID] = set()
            for n in frontier:
                nxt |= adjacency[n] - seen
            seen |= nxt
            frontier = nxt
            if not frontier:
                break
        return Subgraph(
            [n for n in full.nodes if n["id"] in seen],
            [e for e in full.edges
             if e["src_node_id"] in seen and e["dst_node_id"] in seen],
            {**full.projection, "ego": str(centre), "depth": depth},
            full.truncated,
        )

    def shortest_path(self, p: Projection, src: UUID, dst: UUID) -> list[UUID]:
        """Unweighted shortest path (BFS) — the shift-click interaction. The
        path is treated as undirected: an analyst asking "how are these two
        connected" does not care about edge direction."""
        full = self.project(p, limit=5000)
        present = full.node_ids()
        if src not in present or dst not in present:
            raise ProjectionError("both endpoints must be in this projection")
        adjacency: dict[UUID, set[UUID]] = defaultdict(set)
        for e in full.edges:
            adjacency[e["src_node_id"]].add(e["dst_node_id"])
            adjacency[e["dst_node_id"]].add(e["src_node_id"])
        prev: dict[UUID, UUID | None] = {src: None}
        queue = [src]
        while queue:
            cur = queue.pop(0)
            if cur == dst:
                break
            for nb in adjacency[cur]:
                if nb not in prev:
                    prev[nb] = cur
                    queue.append(nb)
        if dst not in prev:
            return []
        path, cur = [], dst
        while cur is not None:
            path.append(cur)
            cur = prev[cur]
        return list(reversed(path))

    # -- local metrics -----------------------------------------------------
    def metrics(self, p: Projection) -> dict:
        """Degree, weighted degree, signed degree, clustering and k-core over
        the projection. Cheap enough to be synchronous at this scale; the
        expensive centralities are Phase 3.

        Signed degree is separated deliberately: an actor with many negative
        ties is not the same as a well-connected one, and a single degree
        number hides that.
        """
        sub = self.project(p, limit=5000)
        ids = [n["id"] for n in sub.nodes]
        labels = {n["id"]: n["label"] for n in sub.nodes}
        # A metric over a node set that was CUT OFF is not a metric over the
        # case, and until now the flag was computed and then dropped on the
        # floor. Degree degrades gracefully under truncation; betweenness and
        # community structure do not.
        neighbours: dict[UUID, set[UUID]] = {i: set() for i in ids}
        weighted: dict[UUID, float] = dict.fromkeys(ids, 0.0)
        pos: dict[UUID, int] = dict.fromkeys(ids, 0)
        neg: dict[UUID, int] = dict.fromkeys(ids, 0)
        for e in sub.edges:
            a, b = e["src_node_id"], e["dst_node_id"]
            if a == b or a not in neighbours or b not in neighbours:
                continue
            neighbours[a].add(b)
            neighbours[b].add(a)
            weighted[a] += e["weight"]
            weighted[b] += e["weight"]
            if e["sign"] > 0:
                pos[a] += 1
                pos[b] += 1
            elif e["sign"] < 0:
                neg[a] += 1
                neg[b] += 1

        # Local clustering: how tightly knit a node's neighbourhood is. 1.0
        # means every neighbour knows every other — a clique, not a broker.
        clustering: dict[UUID, float] = {}
        for i in ids:
            nb = neighbours[i]
            k = len(nb)
            if k < 2:
                clustering[i] = 0.0
                continue
            links = sum(1 for x in nb for y in nb if x < y and y in neighbours[x])
            clustering[i] = (2 * links) / (k * (k - 1))

        core = _k_core(neighbours)
        n = len(ids)
        # Metrics treat the graph as SIMPLE: two actors joined by both a vouch
        # and an accusation are one dyad, not two, because degree and
        # clustering are defined over neighbour sets. That makes dyad_count
        # legitimately smaller than the projection's edge count, so both are
        # reported — a silent discrepancy would read as a bug.
        dyads = sum(len(v) for v in neighbours.values()) // 2
        return {
            "projection": sub.projection,
            "truncated": sub.truncated,
            "node_count": n,
            "edge_count": len(sub.edges),
            "dyad_count": dyads,
            "dyad_note": "metrics treat the graph as simple: parallel edges "
                         "between the same pair count once",
            "density": (2 * dyads) / (n * (n - 1)) if n > 1 else 0.0,
            "nodes": [
                {
                    "id": str(i), "label": labels[i],
                    "degree": len(neighbours[i]),
                    "weighted_degree": round(weighted[i], 4),
                    "positive_degree": pos[i],
                    "negative_degree": neg[i],
                    "clustering": round(clustering[i], 4),
                    "k_core": core[i],
                }
                for i in sorted(ids, key=lambda x: -len(neighbours[x]))
            ],
        }


def _k_core(neighbours: dict[UUID, set[UUID]]) -> dict[UUID, int]:
    """k-core decomposition: repeatedly peel nodes with degree < k. The
    remaining core is the durable centre of the network, which is a more
    honest answer than "top N by degree" (docs/03)."""
    degree = {n: len(nb) for n, nb in neighbours.items()}
    core = dict.fromkeys(neighbours, 0)
    remaining = dict(degree)
    k = 0
    while remaining:
        while True:
            peel = [n for n, d in remaining.items() if d <= k]
            if not peel:
                break
            for n in peel:
                core[n] = k
                del remaining[n]
                for nb in neighbours[n]:
                    if nb in remaining:
                        remaining[nb] -= 1
        k += 1
    return core
