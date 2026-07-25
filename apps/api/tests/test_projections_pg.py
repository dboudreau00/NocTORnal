"""Projections, graph queries and local metrics (Phase 2, docs/03).

The load-bearing property is that a projection CHANGES the answer: the trust
picture and the financial picture name different leaders, which docs/03 says
is itself a finding. If every preset returned the same graph the feature
would be decoration.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; projection test is gated"
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'pj-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN "
                  f"(SELECT id FROM analytics.projection WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'pj-%@noctornal.test'")
    c.close()


@pytest.fixture
def world(conn):
    """A small network with a deliberate shape:

        a --VOUCHED_FOR--> b        (trust, positive)
        b --ACCUSED_SCAM--> c       (trust, negative)
        a --PAID--> c               (financial)
        a --COMMUNICATES_WITH--> d  (communication)

    So each preset sees a different subgraph, and `a` is the hub.
    """
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'PJ', 'x', 'RED') RETURNING id""",
        (f"pj-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Projection IT', 'AMBER', %s, 'dev', '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-PJ-{uuid4().hex[:6]}", uid),
    )
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)

    def node(label, ntype="IDENTITY"):
        return g.create_node(case_id=case_id, node_type=ntype, label=label,
                             created_by=uid, assertion=a)

    ids = {k: node(k) for k in ("a", "b", "c", "d")}
    def edge(etype, s, d, **kw):
        return g.create_edge(case_id=case_id, edge_type=etype,
                             src_node_id=ids[s], dst_node_id=ids[d],
                             created_by=uid, assertion=a, **kw)

    edges = {
        "vouch": edge("VOUCHED_FOR", "a", "b"),
        "accuse": edge("ACCUSED_SCAM", "b", "c"),
        "paid": edge("PAID", "a", "c"),
        "comms": edge("COMMUNICATES_WITH", "a", "d"),
    }
    return case_id, uid, ids, edges


def _svc(conn):
    from noctornal_api.projections import GraphService
    return GraphService(conn, clearance="RED", compartments=frozenset())


def _proj(case_id, **kw):
    from noctornal_api.projections import Projection
    return Projection(case_id=case_id, **kw)


# --- the load-bearing test ---------------------------------------------

def test_presets_give_different_graphs(conn, world):
    """Each preset must select a different set of edges — that difference is
    the feature (docs/03), not a side effect."""
    case_id, *_ = world
    svc = _svc(conn)
    seen = {}
    for preset in ("trust", "communication", "financial", "all"):
        sub = svc.project(_proj(case_id, preset=preset))
        seen[preset] = {e["edge_type"] for e in sub.edges}

    assert seen["trust"] == {"VOUCHED_FOR", "ACCUSED_SCAM"}
    assert seen["communication"] == {"COMMUNICATES_WITH"}
    assert seen["financial"] == {"PAID"}
    # "all" is every SOCIAL tie: CONTROLS/POSTS_ON style plumbing is excluded
    # by is_social_tie, but all four of these are social.
    assert seen["all"] == {"VOUCHED_FOR", "ACCUSED_SCAM", "PAID",
                           "COMMUNICATES_WITH"}
    # And they are genuinely different from each other.
    assert len({frozenset(v) for v in seen.values()}) == 4


def test_projection_parameters_travel_with_the_result(conn, world):
    case_id, *_ = world
    sub = _svc(conn).project(_proj(case_id, preset="trust",
                                   min_confidence="MODERATE"))
    assert sub.projection["preset"] == "trust"
    assert sub.projection["min_confidence"] == "MODERATE"
    assert sub.projection["include_inferred"] is False


def test_inferred_edges_excluded_by_default(conn, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    # Must be an edge type the preset would otherwise include: SHARED_INFRA is
    # is_social_tie=false (decision 21), so "all" excludes it whatever the
    # inferred flag says, and the test would prove nothing.
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=ids["c"],
        dst_node_id=ids["d"], created_by=uid, is_inferred=True,
        inference_method="CO_OCCURRENCE",
        assertion=AssertionInput(basis="AUTOMATED_INFERENCE", created_by=uid,
                                 rationale="timing correlation only"),
    )
    svc = _svc(conn)
    default = svc.project(_proj(case_id, preset="all"))
    assert all(not e["is_inferred"] for e in default.edges)
    with_inferred = svc.project(_proj(case_id, preset="all", include_inferred=True))
    assert any(e["is_inferred"] for e in with_inferred.edges)


def test_min_confidence_filters(conn, world):
    case_id, *_ = world
    svc = _svc(conn)
    # Every seeded edge defaults to LOW confidence, so demanding HIGH empties it.
    assert svc.project(_proj(case_id, min_confidence="LOW")).edges
    assert svc.project(_proj(case_id, min_confidence="HIGH")).edges == []


# --- neighbourhood, path, metrics ---------------------------------------

def test_ego_depth(conn, world):
    case_id, _, ids, _ = world
    svc = _svc(conn)
    d1 = svc.ego(_proj(case_id, preset="all"), ids["a"], depth=1)
    # a touches b (vouch), c (paid), d (comms) -> 4 nodes at depth 1
    assert d1.node_ids() == {ids["a"], ids["b"], ids["c"], ids["d"]}
    trust1 = svc.ego(_proj(case_id, preset="trust"), ids["a"], depth=1)
    # In the trust projection a only reaches b.
    assert trust1.node_ids() == {ids["a"], ids["b"]}
    trust2 = svc.ego(_proj(case_id, preset="trust"), ids["a"], depth=2)
    assert trust2.node_ids() == {ids["a"], ids["b"], ids["c"]}


def test_shortest_path_and_projection_dependence(conn, world):
    case_id, _, ids, _ = world
    svc = _svc(conn)
    # In trust, a->b->c is two hops.
    assert svc.shortest_path(_proj(case_id, preset="trust"),
                             ids["a"], ids["c"]) == [ids["a"], ids["b"], ids["c"]]
    # In financial, a->c is direct: the projection changes the answer.
    assert svc.shortest_path(_proj(case_id, preset="financial"),
                             ids["a"], ids["c"]) == [ids["a"], ids["c"]]
    # d is unreachable in the trust projection.
    assert svc.shortest_path(_proj(case_id, preset="trust"),
                             ids["a"], ids["d"]) == []


def test_metrics_degree_and_signs(conn, world):
    case_id, _, ids, _ = world
    m = _svc(conn).metrics(_proj(case_id, preset="all"))
    by_id = {n["id"]: n for n in m["nodes"]}
    a = by_id[str(ids["a"])]
    assert a["degree"] == 3                 # b, c, d
    # All three of a's ties carry the ontology's default_sign of +1:
    # VOUCHED_FOR, PAID and COMMUNICATES_WITH are all positive.
    assert a["positive_degree"] == 3
    assert a["negative_degree"] == 0
    b = by_id[str(ids["b"])]
    assert b["negative_degree"] == 1        # accused c
    assert m["node_count"] == 4 and m["edge_count"] == 4
    # Every pair here is joined by exactly one edge, so dyads == edges.
    assert m["dyad_count"] == 4
    # Ordered by degree descending, so the hub leads.
    assert m["nodes"][0]["id"] == str(ids["a"])


def test_metrics_are_projection_relative(conn, world):
    """The same node has different centrality per projection — the point of
    shipping four presets."""
    case_id, _, ids, _ = world
    svc = _svc(conn)
    deg = {}
    for preset in ("all", "trust", "financial"):
        m = svc.metrics(_proj(case_id, preset=preset))
        deg[preset] = next(n["degree"] for n in m["nodes"]
                           if n["id"] == str(ids["a"]))
    assert deg["all"] == 3
    assert deg["trust"] == 1
    assert deg["financial"] == 1


def test_k_core_peels_periphery(conn):
    """A triangle plus a pendant: the triangle is 2-core, the pendant 1-core."""
    from noctornal_api.projections import _k_core
    from uuid import uuid4 as u
    x, y, z, p = u(), u(), u(), u()
    nb = {x: {y, z}, y: {x, z}, z: {x, y, p}, p: {z}}
    core = _k_core(nb)
    assert core[x] == core[y] == 2
    assert core[z] == 2
    assert core[p] == 1


def test_clustering_of_a_triangle_is_one(conn, world):
    """Close the a-b-c triangle in the trust projection and a's neighbourhood
    becomes fully connected."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="DISPUTED_WITH", src_node_id=ids["a"],
        dst_node_id=ids["c"], created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
    )
    m = _svc(conn).metrics(_proj(case_id, preset="trust"))
    a = next(n for n in m["nodes"] if n["id"] == str(ids["a"]))
    assert a["degree"] == 2 and a["clustering"] == 1.0


# --- clearance still applies -------------------------------------------

def test_projection_hides_over_classified_nodes_and_their_edges(conn, world):
    """An AMBER analyst must not see a RED node, NOR any edge touching it —
    an edge would betray the hidden node's existence."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.projections import GraphService
    case_id, uid, ids, _ = world
    secret = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label="red_persona",
        created_by=uid, classification="RED",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
    )
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=ids["a"],
        dst_node_id=secret, created_by=uid, classification="RED",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
    )
    amber = GraphService(conn, clearance="AMBER", compartments=frozenset())
    sub = amber.project(_proj(case_id, preset="all"))
    assert secret not in sub.node_ids()
    assert all(secret not in (e["src_node_id"], e["dst_node_id"])
               for e in sub.edges)
    # The cleared analyst does see both.
    red = GraphService(conn, clearance="RED", compartments=frozenset())
    assert secret in red.project(_proj(case_id, preset="all")).node_ids()


def test_parallel_edges_count_once_in_metrics(conn, world):
    """Two actors joined by BOTH a vouch and an accusation are one dyad, not
    two: degree is defined over neighbour sets. The response reports both
    numbers so the difference does not read as a bug."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    # a already VOUCHED_FOR b; add the reverse accusation over the same pair.
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="ACCUSED_SCAM", src_node_id=ids["b"],
        dst_node_id=ids["a"], created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
    )
    m = _svc(conn).metrics(_proj(case_id, preset="trust"))
    by_id = {n["id"]: n for n in m["nodes"]}
    a = by_id[str(ids["a"])]
    assert a["degree"] == 1                  # one neighbour, b
    assert a["positive_degree"] == 1         # the vouch
    assert a["negative_degree"] == 1         # and the accusation
    assert m["edge_count"] > m["dyad_count"]
