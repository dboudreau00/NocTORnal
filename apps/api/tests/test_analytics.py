"""The SNA maths (Phase 3, docs/03) -- unit tests, no database.

`analytics.py` is deliberately database-free: it takes a projected
Subgraph and returns numbers. That makes the maths testable against
hand-computed values, which is the only way to know a centrality is right
-- a plausible-looking number from a graph library is not evidence.

Every value asserted here is derived from the published definition, not
from running the code and recording what it printed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from noctornal_api.analytics import (
    AnalyticsError,
    AnalyticsParams,
    balance,
    burt,
    cohesion,
    fragmentation,
    graph_hash,
    key_player,
    materialise,
    run_suite,
    _rank_and_percentile,
)
from noctornal_api.projections import Projection, Subgraph


def build(nodes, edges, *, node_types=None):
    """A Subgraph shaped exactly like GraphService.project() returns."""
    ids = {k: uuid4() for k in nodes}
    types = node_types or {}
    ns = [{"id": ids[k], "label": k, "node_type": types.get(k, "IDENTITY"),
           "classification": "AMBER", "attrs": {}, "valid_from": None,
           "valid_to": None, "first_seen": None, "last_seen": None}
          for k in nodes]
    es = []
    for e in edges:
        a, b = e[0], e[1]
        sign = e[2] if len(e) > 2 else 1
        weight = e[3] if len(e) > 3 else 1.0
        valid_from = e[4] if len(e) > 4 else None
        valid_to = e[5] if len(e) > 5 else None
        es.append({"id": uuid4(), "edge_type": "VOUCHED_FOR",
                   "src_node_id": ids[a], "dst_node_id": ids[b],
                   "sign": sign, "weight": weight, "confidence": "LOW",
                   "is_inferred": False, "review": "ACCEPTED",
                   "classification": "AMBER", "valid_from": valid_from,
                   "valid_to": valid_to})
    return Subgraph(ns, es, {}, False), ids


def proj(**kw):
    return Projection(case_id=uuid4(), **kw)


# --- Burt's structural holes: the differentiator (docs/03, docs/13) -------

def test_burt_effective_size_of_disconnected_alters_equals_degree():
    """Burt: an ego whose alters do not know each other has NO redundancy,
    so effective size == degree and efficiency == 1. This is the structural
    hole in its pure form -- the broker's position."""
    sub, ids = build(["e", "a", "b", "c"], [("e", "a"), ("e", "b"), ("e", "c")])
    m = materialise(sub)
    h = burt(m)
    i = m.node_ids.index(ids["e"])
    assert h["effective_size"][i] == 3.0
    assert h["efficiency"][i] == 1.0
    # Constraint of a star ego = sum of p_ij^2 = 3 * (1/3)^2 = 1/3.
    assert h["constraint"][i] == pytest.approx(1 / 3, abs=1e-6)


def test_burt_effective_size_of_a_closed_clique_collapses_to_one():
    """Every alter knows every other, so all three ties are redundant and
    the ego is worth one non-redundant contact. The opposite pole from the
    broker, and the reason constraint is the metric that matters here."""
    sub, ids = build(
        ["e", "a", "b", "c"],
        [("e", "a"), ("e", "b"), ("e", "c"), ("a", "b"), ("b", "c"), ("a", "c")],
    )
    m = materialise(sub)
    h = burt(m)
    i = m.node_ids.index(ids["e"])
    assert h["effective_size"][i] == 1.0
    assert h["efficiency"][i] == pytest.approx(1 / 3, abs=1e-6)
    # c_ij = (p_ij + sum_q p_iq p_qj)^2 = (1/3 + 2*(1/3)(1/3))^2 = 25/81 each,
    # so constraint = 3 * 25/81 = 25/27.
    assert h["constraint"][i] == pytest.approx(25 / 27, abs=1e-6)


def test_constraint_is_undefined_not_zero_for_an_isolate():
    """An isolate is not "unconstrained" -- constraint is undefined for it.
    Reporting 0.0 would rank it as the best broker in the case."""
    sub, ids = build(["lonely", "a", "b"], [("a", "b")])
    m = materialise(sub)
    h = burt(m)
    i = m.node_ids.index(ids["lonely"])
    assert h["constraint"][i] is None
    assert h["effective_size"][i] is None


# --- the broker signature docs/03 asks the UI to teach --------------------

def test_broker_has_low_degree_and_highest_betweenness():
    """Two triangles joined through one actor. The classic signature:
    `k` has the FEWEST ties of the well-connected nodes but the highest
    brokerage, because its ties are the only route between the clusters."""
    sub, ids = build(
        ["a", "b", "c", "x", "y", "z", "k"],
        [("a", "b"), ("b", "c"), ("a", "c"),
         ("x", "y"), ("y", "z"), ("x", "z"),
         ("a", "k"), ("k", "x")],
    )
    out = run_suite(sub, proj())
    by_label = {n["label"]: n for n in out["nodes"]}
    k, a = by_label["k"], by_label["a"]
    assert k["degree"] == 2 and a["degree"] == 3
    assert k["betweenness"] > a["betweenness"]
    assert k["betweenness_rank"] == 1
    # Lowest constraint = spans the structural hole = rank 1.
    assert k["constraint"] < a["constraint"]
    assert k["constraint_rank"] == 1
    assert "Broker signature" in k["broker_signature"]
    # And it is a cut vertex: removing it splits the network.
    assert k["is_cut_vertex"] is True


def test_cut_vertices_and_bridges_are_found():
    sub, ids = build(
        ["a", "b", "c", "x", "y", "z", "k"],
        [("a", "b"), ("b", "c"), ("a", "c"),
         ("x", "y"), ("y", "z"), ("x", "z"),
         ("a", "k"), ("k", "x")],
    )
    coh = cohesion(materialise(sub), AnalyticsParams())
    assert {v["label"] for v in coh["cut_vertices"]} == {"a", "x", "k"}
    assert {frozenset((b["source_label"], b["target_label"]))
            for b in coh["bridges"]} == {frozenset(("a", "k")),
                                         frozenset(("k", "x"))}
    assert coh["community_count"] == 2


# --- signed structural balance (docs/03) ----------------------------------

def test_docs03_unbalanced_triad_is_detected():
    """docs/03's own example: "A vouches for B, B vouches for C, A accuses C
    is an unstable configuration". Product of signs is negative."""
    sub, _ = build(["A", "B", "C"], [("A", "B", 1), ("B", "C", 1), ("A", "C", -1)])
    b = balance(materialise(sub))
    assert b["signed_triads"] == 1
    assert b["unbalanced"] == 1 and b["balanced"] == 0
    assert b["balance_ratio"] == 0.0
    assert len(b["unbalanced_triads"]) == 1
    assert "breaking" in b["unbalanced_triads"][0]["reading"]


@pytest.mark.parametrize("signs,expect_balanced", [
    ((1, 1, 1), True),      # all friends
    ((1, -1, -1), True),    # the enemy of my enemy
    ((1, 1, -1), False),    # docs/03's unstable case
    ((-1, -1, -1), False),  # classically unbalanced
])
def test_structural_balance_matches_theory(signs, expect_balanced):
    sub, _ = build(["A", "B", "C"],
                   [("A", "B", signs[0]), ("B", "C", signs[1]),
                    ("A", "C", signs[2])])
    b = balance(materialise(sub))
    assert (b["balanced"] == 1) is expect_balanced
    assert (b["unbalanced"] == 1) is (not expect_balanced)


def test_unsigned_ties_never_manufacture_balance():
    """A tie with sign 0 (POSTS_ON, CONTROLS) is structural, not approval.
    Counting it as friendly would invent balance that is not in the data."""
    sub, _ = build(["A", "B", "C"], [("A", "B", 1), ("B", "C", 1), ("A", "C", 0)])
    b = balance(materialise(sub))
    assert b["signed_triads"] == 0
    assert b["skipped_unsigned_triads"] == 1
    assert b["balance_ratio"] is None


def test_a_dyad_carrying_both_a_vouch_and_an_accusation_is_contested():
    """Two actors joined by BOTH a positive and a negative tie is a lead in
    itself, not noise to average away."""
    sub, _ = build(["A", "B"], [("A", "B", 1), ("B", "A", -1)])
    m = materialise(sub)
    assert m.dyad_count == 1 and m.edge_count == 2
    assert m.contested == [True]
    assert balance(m)["contested_dyads"][0]["source_label"] in ("A", "B")


# --- key player (docs/03's headline capability) ---------------------------

def test_fragmentation_bounds():
    sub, _ = build(["a", "b", "c"], [("a", "b"), ("b", "c")])
    m = materialise(sub)
    assert fragmentation(m.g) == 0.0                 # connected
    assert fragmentation(m.g, frozenset([1])) == 1.0  # remove the middle


def test_key_player_finds_a_better_set_than_top_betweenness():
    """docs/03: "the optimal removal set is usually not the top-n
    individually-central actors. Two high-betweenness nodes often broker the
    same two clusters, so removing both is redundant."

    Three 5-cliques. p and q REDUNDANTLY bridge A<->B; r solely bridges
    B<->C. Removing the top-3 by betweenness leaves the network far more
    intact than the optimised set does.
    """
    def clique(prefix, k):
        names = [f"{prefix}{i}" for i in range(k)]
        return names, [(x, y) for i, x in enumerate(names) for y in names[i + 1:]]

    A, ea = clique("A", 5)
    B, eb = clique("B", 5)
    C, ec = clique("C", 5)
    sub, _ = build(
        A + B + C + ["p", "q", "r"],
        ea + eb + ec + [("A0", "p"), ("p", "B0"), ("A1", "q"), ("q", "B1"),
                        ("B2", "r"), ("r", "C0")],
    )
    m = materialise(sub)
    out = key_player(m, 3)
    assert out["fragmentation_after"] > out["top_betweenness_fragmentation"]
    assert out["beats_top_betweenness"] is True
    # Splitting three clusters apart leaves three sizeable fragments.
    assert len(out["fragments_after"]) >= 3
    # The result never claims optimality it cannot prove.
    assert out["is_approximate"] is True


def test_key_player_rejects_an_oversized_removal_set():
    sub, _ = build(["a", "b", "c"], [("a", "b")])
    m = materialise(sub)
    with pytest.raises(AnalyticsError):
        key_player(m, 0)
    with pytest.raises(AnalyticsError):
        key_player(m, 99)


# --- trust decay (docs/03: never mutate the stored weight) ----------------

def test_trust_decay_halves_a_tie_one_half_life_old():
    now = datetime(2026, 7, 24, tzinfo=timezone.utc)
    old = now - timedelta(days=365.2425 / 2)          # 6 months
    sub, _ = build(["a", "b"], [("a", "b", 1, 1.0, old, None)])
    m = materialise(sub, AnalyticsParams(decay_half_life_months=6,
                                         decay_reference=now))
    assert m.strength[0] == pytest.approx(0.5, abs=1e-6)


def test_trust_decay_never_mutates_the_stored_weight():
    """docs/03 is explicit: decay is applied at projection time. The
    Subgraph the caller handed in must come back unchanged."""
    now = datetime(2026, 7, 24, tzinfo=timezone.utc)
    old = now - timedelta(days=3650)
    sub, _ = build(["a", "b"], [("a", "b", 1, 4.0, old, None)])
    materialise(sub, AnalyticsParams(decay_half_life_months=12,
                                     decay_reference=now))
    assert sub.edges[0]["weight"] == 4.0


def test_undated_ties_are_not_decayed_and_the_count_is_reported():
    """Nothing in the UI sets valid_from/valid_to yet (docs/14 U3), so most
    ties are undated. Guessing an age would silently down-weight them;
    saying so lets the answer report that decay did not bite."""
    sub, _ = build(["a", "b"], [("a", "b", 1, 1.0, None, None)])
    params = AnalyticsParams(decay_half_life_months=12)
    m = materialise(sub, params)
    assert m.strength[0] == 1.0
    assert m.undated_edges == 1
    out = run_suite(sub, proj(), params)
    assert "NOT decayed" in out["decay"]["note"]


def test_decay_is_off_by_default():
    sub, _ = build(["a", "b"], [("a", "b", 1, 2.0, None, None)])
    m = materialise(sub)
    assert m.strength[0] == 2.0
    assert run_suite(sub, proj())["decay"]["note"] == "decay is off"


# --- honesty about approximation and meaning (docs/03) --------------------

def test_eigenvector_is_flagged_when_the_positive_graph_is_disconnected():
    """igraph warns that eigenvector centrality is meaningless across
    components. Returning the numbers without the caveat would invite
    exactly the cross-component comparison that is invalid."""
    sub, _ = build(["a", "b", "c", "d"], [("a", "b"), ("c", "d")])
    out = run_suite(sub, proj())
    assert out["eigenvector_meaningful"] is False
    assert "WITHIN a component" in out["eigenvector_note"]


def test_eigenvector_ignores_negative_ties():
    """Being accused by a well-connected actor does not confer standing."""
    sub, _ = build(["a", "b"], [("a", "b", -1)])
    out = run_suite(sub, proj())
    assert out["eigenvector_meaningful"] is False
    assert out["eigenvector_note"] == "no positive ties in this projection"


def test_small_graphs_are_exact_not_approximate():
    sub, _ = build(["a", "b", "c"], [("a", "b"), ("b", "c")])
    out = run_suite(sub, proj())
    assert out["is_approximate"] is False
    assert out["sample_size"] is None
    assert out["approximation_note"] == "all metrics exact"


def test_rank_is_one_based_descending_and_ties_share_a_rank():
    ranks, pct = _rank_and_percentile([10.0, 5.0, 5.0, 1.0])
    assert ranks == [1, 2, 2, 4]
    # Mid-rank percentile: 5.0 has one value below and two equal ->
    # (1 + 0.5*2)/4 = 50.
    assert pct == [87.5, 50.0, 50.0, 12.5]


def test_a_field_of_identical_values_sits_at_the_middle():
    """Not 0 and not 100: nobody is above or below anybody."""
    ranks, pct = _rank_and_percentile([3.0, 3.0, 3.0])
    assert ranks == [1, 1, 1] and pct == [50.0, 50.0, 50.0]


# --- the simple-graph contract Phase 2 established ------------------------

def test_parallel_edges_collapse_to_one_dyad():
    """Inherited from Phase 2: metrics are defined over neighbour sets, so
    two ties between the same pair are one dyad. Both counts are reported so
    the difference does not read as a bug."""
    sub, _ = build(["a", "b"], [("a", "b", 1), ("a", "b", 1), ("b", "a", 1)])
    out = run_suite(sub, proj())
    assert out["edge_count"] == 3
    assert out["dyad_count"] == 1
    assert "parallel edges" in out["dyad_note"]


def test_direction_is_preserved_for_signed_degree():
    """docs/03: vouches RECEIVED (accumulated reputation) and vouches GIVEN
    (reputation staked) "mean opposite things", so they are reported apart
    even though the structural metrics are undirected."""
    sub, ids = build(["a", "b", "c"], [("a", "b", 1), ("c", "b", 1), ("b", "a", -1)])
    out = run_suite(sub, proj())
    by = {n["label"]: n for n in out["nodes"]}
    assert by["b"]["positive_in_degree"] == 2      # vouched for by a and c
    assert by["b"]["positive_out_degree"] == 0
    assert by["b"]["negative_out_degree"] == 1     # b accuses a
    assert by["a"]["negative_in_degree"] == 1


def test_an_edge_to_an_invisible_node_is_dropped():
    """project() already filters, but materialise must not resurrect an
    edge whose endpoint was withheld -- that would betray the node."""
    sub, ids = build(["a", "b"], [("a", "b")])
    ghost = uuid4()
    sub.edges.append({**sub.edges[0], "id": uuid4(), "dst_node_id": ghost})
    m = materialise(sub)
    assert m.dyad_count == 1
    assert ghost not in m.node_ids


# --- the cache key (docs/02) ---------------------------------------------

def test_graph_hash_is_stable_and_sensitive():
    sub, ids = build(["a", "b", "c"], [("a", "b"), ("b", "c")])
    p, params = proj(), AnalyticsParams()
    base = graph_hash(sub, p, params)
    assert base == graph_hash(sub, p, params)
    # An ISOLATED node changes density and every percentile without
    # touching an edge, so the node set must be in the digest.
    bigger, _ = build(["a", "b", "c", "d"], [("a", "b"), ("b", "c")])
    assert graph_hash(bigger, p, params) != base
    # Parameters that change the numbers change the key.
    assert graph_hash(sub, p, AnalyticsParams(decay_half_life_months=12)) != base
    assert graph_hash(sub, proj(preset="trust"), params) != base


def test_empty_projection_is_an_error_not_a_zero():
    sub, _ = build([], [])
    with pytest.raises(AnalyticsError):
        run_suite(sub, proj())


def test_balance_refuses_rather_than_truncating_a_huge_graph():
    """Invariant 12: nothing is silently dropped. Above the cap the answer
    is an explicit refusal, never a quietly partial triad count."""
    from noctornal_api.analytics import TRIAD_MAX_NODES
    names = [f"n{i}" for i in range(TRIAD_MAX_NODES + 1)]
    sub, _ = build(names, [(names[0], names[1])])
    with pytest.raises(AnalyticsError, match="capped"):
        balance(materialise(sub))
    # The suite degrades gracefully rather than failing outright.
    out = run_suite(sub, proj())
    assert "unavailable" in out["balance"]
