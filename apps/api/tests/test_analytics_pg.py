"""Phase 3 analytics against Postgres: caching, persistence, clearance
scoping and retraction (docs/03, docs/09).

The unit tests in `test_analytics.py` prove the maths. These prove the
things that only exist once a database is involved: that a cached run is
never served across a clearance boundary, that a failed run is a queryable
fact rather than a row stuck at RUNNING, and that retracting the evidence
behind an element removes it from every metric.

Env-gated on DATABASE_URL, like the other _pg suites.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; analytics test is gated"
)

EMAIL_LIKE = "an-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    psub = f"(SELECT id FROM analytics.projection WHERE case_id IN {csub})"
    # ONE transaction: the deferred invariant-1 triggers fire at commit, so
    # assertions and their elements must disappear together.
    with c.transaction():
        c.execute(f"DELETE FROM analytics.node_metric WHERE metric_run_id IN "
                  f"(SELECT id FROM analytics.metric_run WHERE projection_id IN {psub})")
        c.execute(f"DELETE FROM analytics.community_assignment WHERE metric_run_id IN "
                  f"(SELECT id FROM analytics.metric_run WHERE projection_id IN {psub})")
        c.execute(f"DELETE FROM analytics.metric_run WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def world(conn):
    """A network with enough structure to make every Phase 3 metric mean
    something. The demo case is a 7-node star with no triangles at all, so
    it cannot distinguish a correct betweenness from a broken one.

    Shape (all ties in the TRUST preset):

        cluster 1: a - b - c, fully connected (a triangle)
        cluster 2: x - y - z, fully connected (a triangle)
        broker:    a - k - x    <- the only route between the clusters

    So `k` has DEGREE 2 -- fewer ties than a or x -- but the HIGHEST
    betweenness and the LOWEST constraint. That is docs/03's broker
    signature, and it is the pattern the interface is supposed to teach.

    Signs give one BALANCED triad (a-b-c, all positive) and one UNBALANCED
    triad (x-y-z, one accusation), which is docs/03's own example of a lead.
    """
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'AN', 'x', 'RED') RETURNING id""",
        (f"an-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Analytics IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-AN-{uuid4().hex[:6]}", uid),
    )
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    ids = {k: g.create_node(case_id=case_id, node_type="IDENTITY", label=k,
                            created_by=uid, assertion=a)
           for k in ("a", "b", "c", "x", "y", "z", "k")}

    def edge(etype, s, d, **kw):
        return g.create_edge(case_id=case_id, edge_type=etype,
                             src_node_id=ids[s], dst_node_id=ids[d],
                             created_by=uid, assertion=a, **kw)

    edges = {
        # cluster 1: a balanced triangle
        "ab": edge("VOUCHED_FOR", "a", "b"),
        "bc": edge("VOUCHED_FOR", "b", "c"),
        "ac": edge("VOUCHED_FOR", "a", "c"),
        # cluster 2: an UNBALANCED triangle (two vouches and an accusation)
        "xy": edge("VOUCHED_FOR", "x", "y"),
        "yz": edge("VOUCHED_FOR", "y", "z"),
        "xz": edge("ACCUSED_SCAM", "x", "z"),
        # the broker's two ties
        "ak": edge("VOUCHED_FOR", "a", "k"),
        "kx": edge("VOUCHED_FOR", "k", "x"),
    }
    return case_id, uid, ids, edges


def _svc(conn, uid, clearance="RED", compartments=frozenset()):
    from noctornal_api.analytics_runs import AnalyticsRunService
    return AnalyticsRunService(conn, clearance=clearance,
                               compartments=compartments, actor_id=uid)


def _proj(case_id, **kw):
    from noctornal_api.projections import Projection
    kw.setdefault("preset", "trust")
    return Projection(case_id=case_id, **kw)


def _params(**kw):
    from noctornal_api.analytics import AnalyticsParams
    return AnalyticsParams(**kw)


# --- the broker the whole phase exists to find ---------------------------

def test_broker_is_found_over_a_real_case(conn, world):
    case_id, uid, ids, _ = world
    out = _svc(conn, uid).suite(_proj(case_id), _params()).payload
    by = {n["label"]: n for n in out["nodes"]}
    assert by["k"]["degree"] == 2 < by["a"]["degree"]
    assert by["k"]["betweenness_rank"] == 1
    assert by["k"]["constraint_rank"] == 1
    assert by["k"]["is_cut_vertex"] is True
    assert "Broker signature" in by["k"]["broker_signature"]
    assert out["cohesion"]["community_count"] == 2
    assert {v["label"] for v in out["cohesion"]["cut_vertices"]} == {"a", "x", "k"}


def test_the_case_carries_one_balanced_and_one_unbalanced_triad(conn, world):
    case_id, uid, _, _ = world
    out = _svc(conn, uid).suite(_proj(case_id), _params()).payload
    assert out["balance"]["signed_triads"] == 2
    assert out["balance"]["balanced"] == 1
    assert out["balance"]["unbalanced"] == 1
    lead = out["balance"]["unbalanced_triads"][0]
    assert {n["label"] for n in lead["nodes"]} == {"x", "y", "z"}


# --- invariant 5 / decision 24: retraction dissolves an element ----------

def test_retracting_the_only_assertion_removes_the_edge_from_every_metric(
        conn, world):
    """Decision 24 puts LIVE provenance in the PROJECTION deliberately, so
    an element that loses all non-retracted support must dissolve from the
    live graph while its row survives for temporal replay.

    Retracting the broker's tie must therefore split the network in two --
    which is the demo that sells the assertion model (docs/14 E3).
    """
    from noctornal_api.graph import GraphWriteService
    case_id, uid, ids, edges = world
    svc = _svc(conn, uid)
    before = svc.suite(_proj(case_id), _params()).payload
    assert before["cohesion"]["components"] == 1

    assertion_id = conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s", (edges["kx"],)
    ).fetchone()[0]
    GraphWriteService(conn).retract_assertion(
        assertion_id, retracted_by=uid, reason="source withdrawn",
        at=datetime.now(timezone.utc))

    after = svc.suite(_proj(case_id), _params(), force=True).payload
    assert after["cohesion"]["components"] == 2
    assert after["dyad_count"] == before["dyad_count"] - 1
    # The edge row still exists -- history is superseded, never overwritten.
    assert conn.execute(
        "SELECT deleted_at FROM core.edge WHERE id = %s", (edges["kx"],)
    ).fetchone()[0] is None


def test_retracting_a_nodes_only_assertion_removes_the_node(conn, world):
    from noctornal_api.graph import GraphWriteService
    case_id, uid, ids, _ = world
    svc = _svc(conn, uid)
    assert len(svc.suite(_proj(case_id), _params()).payload["nodes"]) == 7
    assertion_id = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s", (ids["z"],)
    ).fetchone()[0]
    GraphWriteService(conn).retract_assertion(
        assertion_id, retracted_by=uid, reason="wrong person",
        at=datetime.now(timezone.utc))
    after = svc.suite(_proj(case_id), _params(), force=True).payload
    assert {n["label"] for n in after["nodes"]} == {"a", "b", "c", "x", "y", "k"}


# --- the cache, which is a security boundary ----------------------------

def test_an_unchanged_graph_is_served_from_cache(conn, world):
    case_id, uid, _, _ = world
    svc = _svc(conn, uid)
    first = svc.suite(_proj(case_id), _params())
    second = svc.suite(_proj(case_id), _params())
    assert first.cached is False and second.cached is True
    assert first.run_id == second.run_id


def test_changing_the_graph_misses_the_cache(conn, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    svc = _svc(conn, uid)
    first = svc.suite(_proj(case_id), _params())
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=ids["b"],
        dst_node_id=ids["y"], created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid))
    second = svc.suite(_proj(case_id), _params())
    assert second.cached is False
    assert second.run_id != first.run_id


def test_a_cached_run_is_never_served_across_a_clearance_boundary(conn, world):
    """THE security property of the cache. A metric computed over a graph
    containing RED nodes, served to an AMBER analyst, would hand them a
    number whose entire explanation is a node they may not see.

    Both mechanisms are exercised: the graph hash differs because the
    visible edge list differs, AND the lookup filters on the recorded
    visibility class.
    """
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    secret = g.create_node(case_id=case_id, node_type="IDENTITY",
                           label="red_persona", created_by=uid,
                           classification="RED", assertion=a)
    g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                  src_node_id=ids["a"], dst_node_id=secret, created_by=uid,
                  classification="RED", assertion=a)

    red = _svc(conn, uid, clearance="RED").suite(_proj(case_id), _params())
    assert any(n["label"] == "red_persona" for n in red.payload["nodes"])

    amber = _svc(conn, uid, clearance="AMBER").suite(_proj(case_id), _params())
    assert amber.cached is False
    assert amber.run_id != red.run_id
    assert not any(n["label"] == "red_persona" for n in amber.payload["nodes"])
    # And the AMBER answer must not carry the hidden node's structure.
    assert amber.payload["node_count"] == 7


def test_compartments_partition_the_cache_too(conn, world):
    """A run computed by someone read into a compartment must not be served
    to someone who is not. The column is NOT NULL with no default precisely
    so a forgotten write fails loudly instead of matching the empty set."""
    case_id, uid, _, _ = world
    held = _svc(conn, uid, compartments=frozenset({"ALPHA"})).suite(
        _proj(case_id), _params())
    none_held = _svc(conn, uid, compartments=frozenset()).suite(
        _proj(case_id), _params())
    assert none_held.cached is False
    assert none_held.run_id != held.run_id


def test_visibility_is_recorded_on_every_run(conn, world):
    case_id, uid, _, _ = world
    run = _svc(conn, uid, clearance="AMBER",
               compartments=frozenset({"ALPHA"})).suite(_proj(case_id), _params())
    row = conn.execute(
        """SELECT visibility_clearance, visibility_compartments, status
             FROM analytics.metric_run WHERE id = %s""", (run.run_id,)).fetchone()
    assert row[0] == "AMBER"
    assert row[1] == ["ALPHA"]
    assert row[2] == "COMPLETE"


def test_force_recomputes_and_leaves_the_old_run_intact(conn, world):
    case_id, uid, _, _ = world
    svc = _svc(conn, uid)
    first = svc.suite(_proj(case_id), _params())
    forced = svc.suite(_proj(case_id), _params(), force=True)
    assert forced.cached is False and forced.run_id != first.run_id
    assert conn.execute(
        "SELECT status FROM analytics.metric_run WHERE id = %s", (first.run_id,)
    ).fetchone()[0] == "COMPLETE"


# --- persistence --------------------------------------------------------

def test_node_metrics_and_communities_are_persisted(conn, world):
    case_id, uid, ids, _ = world
    run = _svc(conn, uid).suite(_proj(case_id), _params())
    metrics = {r[0] for r in conn.execute(
        "SELECT DISTINCT metric FROM analytics.node_metric WHERE metric_run_id = %s",
        (run.run_id,)).fetchall()}
    assert {"betweenness", "constraint", "effective_size"} <= metrics
    row = conn.execute(
        """SELECT value, rank, percentile FROM analytics.node_metric
            WHERE metric_run_id = %s AND node_id = %s AND metric = 'betweenness'""",
        (run.run_id, ids["k"])).fetchone()
    assert row[0] > 0 and row[1] == 1 and row[2] is not None
    assert conn.execute(
        "SELECT count(*) FROM analytics.community_assignment WHERE metric_run_id = %s",
        (run.run_id,)).fetchone()[0] == 7


def test_one_projection_row_is_reused_across_runs(conn, world):
    case_id, uid, _, _ = world
    svc = _svc(conn, uid)
    svc.suite(_proj(case_id), _params())
    svc.suite(_proj(case_id), _params(), force=True)
    svc.suite(_proj(case_id), _params(), force=True)
    assert conn.execute(
        "SELECT count(*) FROM analytics.projection WHERE case_id = %s AND preset = 'trust'",
        (case_id,)).fetchone()[0] == 1


def test_different_parameters_get_different_projection_rows(conn, world):
    """A different half-life reweights every tie, so it is a different
    projection and must not overwrite the first one's provenance."""
    case_id, uid, _, _ = world
    svc = _svc(conn, uid)
    svc.suite(_proj(case_id), _params())
    svc.suite(_proj(case_id), _params(decay_half_life_months=12))
    names = [r[0] for r in conn.execute(
        "SELECT name FROM analytics.projection WHERE case_id = %s", (case_id,)
    ).fetchall()]
    assert len(names) == 2 and len(set(names)) == 2


def test_a_failed_run_is_recorded_as_failed_with_its_reason(conn, world):
    """Invariant 12: nothing is silently dropped. A run that blows up must
    not sit at RUNNING forever reading as "still working"."""
    from noctornal_api.analytics import AnalyticsError
    case_id, uid, _, _ = world
    svc = _svc(conn, uid)
    # The router bounds n_remove before it gets here, so the service is
    # driven directly: the run row is created first, then the compute
    # rejects the request, which is exactly the path that must not leave a
    # row at RUNNING.
    with pytest.raises(AnalyticsError):
        svc.key_player(_proj(case_id), _params(), n_remove=99)
    rows = conn.execute(
        """SELECT status, error FROM analytics.metric_run r
             JOIN analytics.projection p ON p.id = r.projection_id
            WHERE p.case_id = %s AND r.algorithm = 'kpp_neg'""",
        (case_id,)).fetchall()
    assert rows and all(r[0] == "FAILED" and r[1] for r in rows)


def test_every_run_writes_an_audit_event(conn, world):
    case_id, uid, _, _ = world
    run = _svc(conn, uid).suite(_proj(case_id), _params())
    row = conn.execute(
        """SELECT action, object_type, detail FROM audit.event
            WHERE case_id = %s AND object_id = %s""",
        (case_id, run.run_id)).fetchone()
    assert row[0] == "ANALYTICS_RUN" and row[1] == "metric_run"
    assert row[2]["algorithm"] == "sna_suite"


# --- projections still govern everything --------------------------------

def test_metrics_are_projection_relative(conn, world):
    """The same actor has different centrality per preset. If every preset
    gave the same answer the feature would be decoration (docs/03)."""
    case_id, uid, ids, _ = world
    svc = _svc(conn, uid)
    trust = svc.suite(_proj(case_id, preset="trust"), _params()).payload
    comms = svc.suite(_proj(case_id, preset="communication"), _params())
    assert trust["node_count"] == 7
    # No communication ties were recorded, so that projection has only
    # isolates -- absence of data, correctly, not absence of communication.
    assert comms.payload["dyad_count"] == 0
    assert trust["projection"]["preset"] == "trust"


def test_inferred_edges_stay_out_unless_opted_in(conn, world):
    """Invariant 4: an inferred edge never silently becomes an asserted
    one, and must not quietly change a centrality score."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    svc = _svc(conn, uid)
    base = svc.suite(_proj(case_id), _params()).payload
    GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=ids["b"],
        dst_node_id=ids["y"], created_by=uid, is_inferred=True,
        inference_method="CO_OCCURRENCE",
        assertion=AssertionInput(basis="AUTOMATED_INFERENCE", created_by=uid,
                                 rationale="timing correlation only"))
    same = svc.suite(_proj(case_id), _params()).payload
    assert same["dyad_count"] == base["dyad_count"]
    opted = svc.suite(_proj(case_id, include_inferred=True), _params()).payload
    assert opted["dyad_count"] == base["dyad_count"] + 1


def test_an_edge_to_an_invisible_node_never_appears(conn, world):
    """An edge would betray the existence of a node the analyst may not
    see, so both endpoints must be visible."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, ids, _ = world
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    secret = g.create_node(case_id=case_id, node_type="IDENTITY",
                           label="hidden", created_by=uid,
                           classification="RED", assertion=a)
    g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=ids["k"],
                  dst_node_id=secret, created_by=uid, classification="RED",
                  assertion=a)
    amber = _svc(conn, uid, clearance="AMBER").suite(
        _proj(case_id), _params()).payload
    assert all(n["label"] != "hidden" for n in amber["nodes"])
    # k's degree must not have grown by an edge the analyst cannot see.
    by = {n["label"]: n for n in amber["nodes"]}
    assert by["k"]["degree"] == 2


# --- key player over a real case ----------------------------------------

def test_key_player_names_the_broker(conn, world):
    case_id, uid, _, _ = world
    out = _svc(conn, uid).key_player(_proj(case_id), _params(),
                                     n_remove=1).payload["key_player"]
    assert [r["label"] for r in out["removal_set"]] == ["k"]
    assert out["fragmentation_before"] == 0.0
    assert out["fragmentation_after"] > 0
    assert out["fragments_after"] == [3, 3]


def test_metric_history_is_scoped_to_the_callers_visibility(conn, world):
    case_id, uid, ids, _ = world
    _svc(conn, uid, clearance="RED").suite(_proj(case_id), _params())
    red_series = _svc(conn, uid, clearance="RED").history(
        case_id, ids["k"], "betweenness")
    assert len(red_series) == 1 and red_series[0]["value"] > 0
    # An AMBER analyst must not read back a series computed at RED.
    assert _svc(conn, uid, clearance="AMBER").history(
        case_id, ids["k"], "betweenness") == []
