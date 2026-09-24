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
        "description": "The signed network of vouches, guarantees, escrow, "
                       "rip reports and disputes. Negative ties included, "
                       "because removing them throws away the most "
                       "diagnostic signal.",
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
        "description": "The money picture of payments, laundering, escrow "
                       "and wallet control. It usually names different "
                       "leaders than the trust network does.",
        "edge_types": ["PAID", "LAUNDERED_FOR", "ESCROW_FOR", "CONTROLS",
                       "TX_INPUT", "TX_OUTPUT"],
    },
    "all": {
        # "All social ties", was "All ties" (ux19-copy
        # one-concept-many-names, 2026-09-23): the case holds identity
        # links this preset leaves out, so "all" beside a count lower than
        # the case's read as relationships lost.
        "label": "All social ties",
        "description": "Every edge type marked as a social tie in the "
                       "ontology. Identity plumbing (SAME_AS, ALIAS_OF) stays "
                       "out, because it would make whichever persona you "
                       "researched hardest look the most central.",
        "edge_types": None,          # resolved to is_social_tie at query time
    },
}

_CONFIDENCE_ORDER = {"LOW": 0, "MODERATE": 1, "HIGH": 2}


# --- what "evidenced" means, in ONE place -------------------------------
#
# ux07 two-evidence-paths-disagree and ux05 linked-evidence-vs-evidenced
# (2026-09-22). An exhibit reaches an element by two routes: a live
# assertion that carries it (`assertion.evidence_id`, the E1 add-form path)
# and a direct attachment (`core.evidence_link`, the inspector's linker).
# Until this date the canvas mark, the coverage figure and the report's
# "Evidenced" column counted only the first, while the inspector listed
# only the second. So an analyst who linked an exhibit saw the element stay
# hollow and the report say "NO", and an element evidenced at creation said
# "No exhibits linked." in its own inspector. Both readings were wrong.
#
# The rule now, used by the projection (`has_evidence`, and through it the
# coverage figure and the report) and by the inspector's evidence list
# (`routers/read.py`), which both build on `evidence_backing_sql`:
#
#   an element is EVIDENCED when an exhibit is attached to it by a live
#   (unretracted) assertion OR by an evidence_link row, and that exhibit is
#   in the element's case, not purged, and visible at the reader's
#   clearance and compartments.
#
# The visibility leg is deliberate. `withheld()` below explains why a mark
# that localises withheld material is the disclosure that matters, and a
# "yes" resting on an exhibit the reader cannot see would be exactly that.
# It is also what keeps the report honest: the report projects at the
# TARGET's clearance and its exhibit register filters the same way, so
# "Evidenced: yes" means an exhibit in that document's own register backs it.
# A purged exhibit is shown by the inspector (flagged) but backs nothing,
# because an element cannot rest on bytes the record says are gone.

_ELEMENT_COLUMNS = ("node_id", "edge_id")


def evidence_backing_sql(column: str, element: str) -> str:
    """Every live attachment of an exhibit to one element, as a SELECT.

    Columns: evidence_id, kind ('LINK' | 'ASSERTION'), assertion_id,
    basis, at, by_user, relevance, page_ref. `column` is 'node_id' or
    'edge_id'; `element` is a SQL expression for the element's id (an
    outer alias such as ``n.id``, or ``%s`` when the caller binds it, in
    which case it is bound TWICE, once per branch). Both are literals from
    this codebase and never client input.
    """
    assert column in _ELEMENT_COLUMNS
    return f"""SELECT bl.evidence_id, 'LINK'::text AS kind,
                      NULL::uuid AS assertion_id, NULL::text AS basis,
                      bl.created_at AS at, bl.created_by AS by_user,
                      bl.relevance, bl.page_ref
                 FROM core.evidence_link bl
                WHERE bl.{column} = {element}
               UNION ALL
               SELECT ba.evidence_id, 'ASSERTION'::text, ba.id,
                      ba.basis::text, ba.recorded_at, ba.created_by,
                      NULL::text, NULL::text
                 FROM core.assertion ba
                WHERE ba.{column} = {element}
                  AND ba.retracted_at IS NULL
                  AND ba.evidence_id IS NOT NULL"""


def evidenced_sql(column: str, alias: str) -> str:
    """The boolean `has_evidence` for the row aliased `alias` ('n' or 'e').

    Takes TWO bind parameters, in order: the reader's clearance and the
    reader's compartments. See the block comment above for the rule.
    """
    assert alias in ("n", "e")
    return f"""EXISTS (SELECT 1
                         FROM ({evidence_backing_sql(column, alias + '.id')}) bk
                         JOIN core.evidence bx ON bx.id = bk.evidence_id
                        WHERE bx.case_id = {alias}.case_id
                          AND bx.purged_at IS NULL
                          AND bx.classification <= %s::core.tlp
                          AND bx.compartments <@ %s)"""


def seen_sql() -> str:
    """`first_seen, last_seen` for the node aliased `n`, derived from the
    entity's live observations. Two select-list items. Takes FOUR bind
    parameters, the reader's clearance and compartments twice over, in the
    order `seen_params` returns them.

    gap-first-seen (decided 2026-09-23). Nothing writes
    `core.node.first_seen` or `last_seen`: `create_node` never set them and
    no importer does, so the entity list's First seen column and the
    inspector's "first seen / last seen" were blank on every estate while
    the claims under them said when the entity was observed. The dates are
    derived instead, without a migration: the earliest and latest
    `observed_at` among the entity's LIVE claims (not retracted, not
    superseded, the projection's own rule), combined with the stored column
    so a value an importer does write one day still counts. LEAST and
    GREATEST skip a NULL, so either side alone is enough and neither
    alone blanks the other. Only the entity's claims count, not claims
    about its ties: a tie's claim is about the relationship. A withdrawn
    sighting stops moving the dates the moment it is withdrawn.

    "The entity's claims" include those of every record merged into it
    (release review c10, 2026-09-24). A merge asserts the two records were
    always the same thing, and it leaves the absorbed record's claims on
    that record (merges.py), which every list and the canvas then hide: so
    merging a 2024 persona into its 2025 one dropped the 2024 sighting from
    the First seen column and the timeline, with no sign anything was left
    out. The walk is recursive because a record that has absorbed others
    can itself be merged onward, and a reversed merge clears the redirect,
    so it stops counting at once. Every hop is held to the READER's
    ceiling, as `curation._merge_chain` holds its chain: an assertion has
    no marking of its own, so an absorbed RED or compartmented persona's
    observation dates would otherwise reach a reader who may see only the
    survivor. A hidden hop ends the walk there. UNION rather than UNION ALL
    so a malformed cycle ends the walk instead of the query.

    The walk runs only for an entity something has been merged into (one
    probe of the partial index on `merged_into_id`); every other entity
    reads its own claims as before. Walking for all of them cost about a
    third more on NIGHTJAR's 146-entity projection, and most never absorb
    anything.
    """
    live = " AND sa.retracted_at IS NULL AND sa.superseded_at IS NULL"
    own = ("(SELECT {agg}(sa.observed_at) FROM core.assertion sa"
           " WHERE sa.node_id = n.id" + live + ")")
    tree = ("(WITH RECURSIVE seen_tree(id) AS (SELECT n.id UNION"
            " SELECT m.id FROM core.node m JOIN seen_tree t ON m.merged_into_id = t.id"
            " WHERE m.case_id = n.case_id AND m.deleted_at IS NULL"
            " AND m.classification <= %s::core.tlp AND m.compartments <@ %s)"
            " SELECT {agg}(sa.observed_at) FROM core.assertion sa"
            " WHERE sa.node_id IN (SELECT id FROM seen_tree)" + live + ")")
    span = ("CASE WHEN EXISTS (SELECT 1 FROM core.node mx WHERE mx.merged_into_id = n.id)"
            " THEN " + tree + " ELSE " + own + " END")
    return (f"LEAST(n.first_seen, {span.format(agg='min')}) AS first_seen, "
            f"GREATEST(n.last_seen, {span.format(agg='max')}) AS last_seen")


def seen_params(clearance: str, compartments) -> tuple:
    """The four binds `seen_sql` takes, in order. One helper so no caller
    counts them by hand."""
    return (clearance, compartments, clearance, compartments)


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


#: What a case is willing to say about material the reader cannot see.
#: Migration 0030 has the reasoning; the short version is that an analyst
#: who cannot tell a sparse network from a censored one draws confident
#: conclusions from an incomplete picture, and that is a worse failure than
#: the one bit of disclosure this costs.
DISCLOSURE_NONE = "NONE"
DISCLOSURE_PRESENCE = "PRESENCE"
DISCLOSURE_COUNT = "COUNT"


@dataclass(frozen=True)
class Withheld:
    """How much of this projection the caller is not being shown.

    Never carries WHICH classification, WHICH compartment, or WHERE. The
    counts are per case; "a hidden tie adjacent to this person" would
    localise the withheld material, which is the disclosure that actually
    matters.
    """

    mode: str
    #: True when anything at all was filtered out by clearance. Always
    #: computed; only REPORTED when the mode allows.
    any_withheld: bool = False
    nodes: int | None = None
    edges: int | None = None

    def as_response(self) -> dict:
        if self.mode == DISCLOSURE_NONE:
            # Not "withheld: false" -- that would itself be an answer. The
            # key is absent, exactly as it was before this existed.
            return {}
        if not self.any_withheld:
            return {"incomplete": False, "mode": self.mode}
        body = {"incomplete": True, "mode": self.mode}
        if self.mode == DISCLOSURE_COUNT:
            body["nodes"] = self.nodes
            body["edges"] = self.edges
        return body


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
                      valid_from, valid_to,
                      -- Derived from the live claims (gap-first-seen,
                      -- 2026-09-23): nothing writes the columns.
                      """ + seen_sql() + """,
                      -- E2: does an exhibit back this element? A case is
                      -- defensible in proportion to how much of it is
                      -- evidenced, and that should be visible on the canvas
                      -- rather than only in the inspector one element at a
                      -- time. The rule is `evidenced_sql`'s (2026-09-22).
                      """ + evidenced_sql("node_id", "n") + """ AS has_evidence
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
                  -- Live is not retracted AND not superseded, as it is for
                  -- core.tie_confidence and the assertion list (final review
                  -- U11, 2026-09-23): a superseded claim has been replaced,
                  -- and it must not hold an element up once its replacement
                  -- is withdrawn, since no card offers to retract it.
                  AND EXISTS (SELECT 1 FROM core.assertion a
                               WHERE a.node_id = n.id AND a.retracted_at IS NULL
                                 AND a.superseded_at IS NULL)
                  -- as-of is WORLD time: the thing existed then.
                  AND (%s::timestamptz IS NULL
                       OR (valid_from IS NULL OR valid_from <= %s)
                       AND (valid_to IS NULL OR valid_to >= %s))
                ORDER BY created_at LIMIT %s""",
            (*seen_params(self._clearance, self._comp),
             self._clearance, self._comp,
             p.case_id, self._clearance, self._comp,
             p.as_of, p.as_of, p.as_of, limit + 1),
        ).fetchall()
        truncated = len(nodes) > limit
        nodes = nodes[:limit]
        node_out = [
            {"id": r[0], "node_type": r[1], "label": r[2], "classification": r[3],
             "attrs": r[4] or {}, "valid_from": r[5], "valid_to": r[6],
             "first_seen": r[7], "last_seen": r[8], "has_evidence": r[9]}
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
                          e.classification, e.valid_from, e.valid_to,
                          et.is_social_tie,
                          """ + evidenced_sql("edge_id", "e") + """ AS has_evidence
                     FROM core.edge e
                     JOIN core.edge_type et ON et.key = e.edge_type
                    WHERE e.case_id = %s AND e.deleted_at IS NULL
                      AND e.src_node_id = ANY(%s) AND e.dst_node_id = ANY(%s)
                      AND e.classification <= %s::core.tlp AND e.compartments <@ %s
                      AND (%s OR NOT e.is_inferred)
                      -- LIVE provenance, as for nodes above (decision 24).
                      -- Retracting the only assertion behind a tie must
                      -- dissolve the tie from the live graph, superseded
                      -- rows included (final review U11, 2026-09-23).
                      AND EXISTS (SELECT 1 FROM core.assertion a
                                   WHERE a.edge_id = e.id
                                     AND a.retracted_at IS NULL
                                     AND a.superseded_at IS NULL)
                      -- NULL types means "the preset is everything social".
                      AND (%s::text[] IS NULL AND et.is_social_tie
                           OR e.edge_type = ANY(%s))
                      AND (%s::timestamptz IS NULL
                           OR (e.valid_from IS NULL OR e.valid_from <= %s)
                           AND (e.valid_to IS NULL OR e.valid_to >= %s))""",
                (self._clearance, self._comp,
                 p.case_id, ids, ids, self._clearance, self._comp,
                 p.include_inferred, types, types, p.as_of, p.as_of, p.as_of),
            ).fetchall()
            keep = {"LOW", "MODERATE", "HIGH"}
            keep = {c for c in keep if _CONFIDENCE_ORDER[c] >= min_rank}
            edge_out = [
                {"id": r[0], "edge_type": r[1], "src_node_id": r[2],
                 "dst_node_id": r[3], "sign": r[4], "weight": float(r[5]),
                 "confidence": r[6], "is_inferred": r[7], "review": r[8],
                 "classification": r[9], "valid_from": r[10], "valid_to": r[11],
                 "has_evidence": r[13]}
                for r in rows if r[6] in keep
            ]
        return Subgraph(node_out, edge_out, p.describe(), truncated)

    # -- what the caller is not being shown (docs/14 U2) -------------------
    def withheld(self, p: Projection) -> Withheld:
        """Count the elements this projection WOULD contain for a fully
        cleared reader and does not contain for this one.

        Deliberately a separate call rather than part of `project()`. The
        graph endpoint wants it once per page; `ego`, `path` and `metrics`
        all call `project()` internally and would otherwise pay for two
        extra aggregates each time, to answer a question nobody asked.

        The counts apply every OTHER filter the projection applies -- preset,
        inferred, confidence, as-of, live provenance, soft deletion. Without
        that they would be meaningless: "1,990 elements withheld" when 1,988
        of them were excluded by the preset is not information, it is alarm.
        """
        mode = self._disclosure_mode(p.case_id)
        if mode == DISCLOSURE_NONE:
            return Withheld(mode)

        hidden_nodes = self._c.execute(
            """SELECT count(*) FROM core.node n
                WHERE case_id = %s AND deleted_at IS NULL
                  AND merged_into_id IS NULL
                  AND NOT (classification <= %s::core.tlp AND compartments <@ %s)
                  AND EXISTS (SELECT 1 FROM core.assertion a
                               WHERE a.node_id = n.id AND a.retracted_at IS NULL
                                 AND a.superseded_at IS NULL)
                  AND (%s::timestamptz IS NULL
                       OR (valid_from IS NULL OR valid_from <= %s)
                       AND (valid_to IS NULL OR valid_to >= %s))""",
            (p.case_id, self._clearance, self._comp,
             p.as_of, p.as_of, p.as_of)).fetchone()[0]

        types = p.resolved_edge_types()
        min_rank = _CONFIDENCE_ORDER[p.min_confidence]
        keep = sorted(c for c in ("LOW", "MODERATE", "HIGH")
                      if _CONFIDENCE_ORDER[c] >= min_rank)
        # An edge is missing from the caller's projection either because of
        # its OWN labels or because an endpoint is invisible -- and the
        # second is the commoner one, since a tie is only ever returned when
        # both ends are. Both count.
        hidden_edges = self._c.execute(
            """SELECT count(*) FROM core.edge e
                 JOIN core.edge_type et ON et.key = e.edge_type
                WHERE e.case_id = %s AND e.deleted_at IS NULL
                  AND (%s OR NOT e.is_inferred)
                  AND (%s::text[] IS NULL AND et.is_social_tie
                       OR e.edge_type = ANY(%s))
                  AND e.confidence::text = ANY(%s)
                  AND EXISTS (SELECT 1 FROM core.assertion a
                               WHERE a.edge_id = e.id AND a.retracted_at IS NULL
                                 AND a.superseded_at IS NULL)
                  AND (%s::timestamptz IS NULL
                       OR (e.valid_from IS NULL OR e.valid_from <= %s)
                       AND (e.valid_to IS NULL OR e.valid_to >= %s))
                  AND NOT (
                        e.classification <= %s::core.tlp
                    AND e.compartments <@ %s
                    AND EXISTS (SELECT 1 FROM core.node sn
                                 WHERE sn.id = e.src_node_id
                                   AND sn.deleted_at IS NULL
                                   AND sn.merged_into_id IS NULL
                                   AND sn.classification <= %s::core.tlp
                                   AND sn.compartments <@ %s)
                    AND EXISTS (SELECT 1 FROM core.node dn
                                 WHERE dn.id = e.dst_node_id
                                   AND dn.deleted_at IS NULL
                                   AND dn.merged_into_id IS NULL
                                   AND dn.classification <= %s::core.tlp
                                   AND dn.compartments <@ %s))""",
            (p.case_id, p.include_inferred, types, types, keep,
             p.as_of, p.as_of, p.as_of,
             self._clearance, self._comp,
             self._clearance, self._comp,
             self._clearance, self._comp)).fetchone()[0]

        return Withheld(mode, any_withheld=bool(hidden_nodes or hidden_edges),
                        nodes=hidden_nodes, edges=hidden_edges)

    def _disclosure_mode(self, case_id: UUID) -> str:
        row = self._c.execute(
            'SELECT withheld_disclosure FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        # A case that has vanished discloses nothing. Failing closed here
        # costs an analyst a banner; failing open costs a disclosure.
        return row[0] if row else DISCLOSURE_NONE

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
        # E2: how much of what is on screen rests on an exhibit. A case is
        # defensible in proportion to how much of it is evidenced, so this
        # is a headline number, not a detail buried in the inspector.
        evidenced_nodes = sum(1 for x in sub.nodes if x.get("has_evidence"))
        evidenced_edges = sum(1 for x in sub.edges if x.get("has_evidence"))
        total_elements = n + len(sub.edges)
        return {
            "projection": sub.projection,
            "truncated": sub.truncated,
            "node_count": n,
            "edge_count": len(sub.edges),
            "dyad_count": dyads,
            "evidence_coverage": {
                "nodes": evidenced_nodes,
                "edges": evidenced_edges,
                "elements": total_elements,
                "ratio": round((evidenced_nodes + evidenced_edges) / total_elements, 4)
                if total_elements else None,
                # Worded from `evidenced_sql`, the one definition the
                # canvas, the inspector and the report share (2026-09-22).
                "note": "share of visible elements backed by an exhibit you "
                        "can see, either carried by a live assertion or "
                        "linked to the element directly",
            },
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
