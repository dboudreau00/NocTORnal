"""F1 against Postgres (2026-09-24): CONCOR runs, their cache, currency,
clearance and persistence.

Held here: a role analysis is cached on the graph hash AND the depth; a
cache hit is served exactly as computed (the suite's upgrade rewrote
CONCOR payloads on every hit); swapping an undirected tie for a directed
one that hashes alike for the suite makes a role run stale (direction was
not in the key); the suite and key-player
keys are unchanged by the algorithm argument; a run never crosses a
clearance boundary; positions land in community_assignment; a refusal
known before computing leaves no run behind, and an unexpected failure is
recorded as FAILED with its audit event.

Shares test_review_scope_pg's world and teardown. Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import test_review_scope_pg as rs
from test_review_scope_pg import DATABASE_URL, World, params

conn = rs.conn

pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; CONCOR test is gated")


@pytest.fixture
def world(conn):
    """Two hubs tied to the same three leaves, and a vouch between two
    leaves: two positions at depth 1."""
    w = World(conn)
    for label in ("H1", "H2", "a", "b", "c"):
        w.node(label)
    for h in ("H1", "H2"):
        for x in ("a", "b", "c"):
            w.tie(h, "COMMUNICATES_WITH", x)
    return w


def _concor(w, depth=1, clearance="RED", **kw):
    return w.svc(clearance=clearance).concor(w.proj(), params(), depth=depth, **kw)


def test_a_concor_run_is_cached_on_graph_hash_and_depth(world):
    first = _concor(world)
    again = _concor(world)
    assert first.cached is False and again.cached is True
    assert again.run_id == first.run_id


def test_a_different_depth_is_a_different_run(world):
    one = _concor(world, depth=1)
    two = _concor(world, depth=2)
    assert two.run_id != one.run_id and two.cached is False
    svc = world.svc()
    assert svc.latest_concor(world.proj(), params(), depth=1).run_id == one.run_id
    assert svc.latest_concor(world.proj(), params(), depth=2).run_id == two.run_id
    assert svc.latest_concor(world.proj(), params(), depth=3) is None


def test_a_cached_concor_run_is_served_exactly_as_computed(world):
    computed = _concor(world).as_response()
    cached = _concor(world).as_response()
    latest = world.svc().latest_concor(world.proj(), params(), depth=1).as_response()
    strip = ("run_id", "cached", "current", "computed_at", "computed_at_ms")
    for body in (cached, latest):
        assert {k: v for k, v in body.items() if k not in strip} == \
            {k: v for k, v in computed.items() if k not in strip}
        assert not {"upgraded", "broker_rule", "constraint_order"} & set(body)


def test_swapping_a_tie_type_makes_a_concor_run_not_current(world):
    """COMMUNICATES_WITH H1-a for REPLIED_TO H1->a: the same ends, sign,
    weight, dates, review and evidence, so the suite hashes alike, but
    CONCOR's relations change with direction."""
    from noctornal_api.analytics import graph_hash
    before_sub = world.graph().project(world.proj())
    first = _concor(world)
    assertion_id = world.conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s",
        (world.edges["H1-COMMUNICATES_WITH-a"],)).fetchone()[0]
    world.g.retract_assertion(assertion_id, retracted_by=world.uid,
                              reason="it was a reply", at=datetime.now(timezone.utc))
    world.tie("H1", "REPLIED_TO", "a")
    after_sub = world.graph().project(world.proj())
    assert graph_hash(before_sub, world.proj(), params()) == \
        graph_hash(after_sub, world.proj(), params())
    stored = world.svc().latest_concor(world.proj(), params(), depth=1)
    assert stored.run_id == first.run_id and stored.current is False
    assert _concor(world).cached is False


def test_the_suite_and_key_player_keys_are_unchanged_by_the_algorithm_argument(world):
    from noctornal_api.analytics import graph_hash
    from noctornal_api.analytics_runs import CONCOR, KPP_NEG, SUITE
    svc = world.svc()
    sub = world.graph().project(world.proj())
    p = world.proj()
    base = graph_hash(sub, p, params())
    assert svc._cache_key(sub, p, params(), {}, SUITE) == base
    assert svc._cache_key(sub, p, params(), {"n_remove": 3}, KPP_NEG) == \
        svc._cache_key(sub, p, params(), {"n_remove": 3})
    assert svc._cache_key(sub, p, params(), {"depth": 1}, CONCOR) != \
        svc._cache_key(sub, p, params(), {"depth": 1})


def test_concor_is_never_served_across_a_clearance_boundary(world):
    red = _concor(world, clearance="RED")
    amber = world.svc(clearance="AMBER")
    assert amber.latest_concor(world.proj(), params(), depth=1) is None
    own = amber.concor(world.proj(), params(), depth=1)
    assert own.run_id != red.run_id and own.cached is False


def test_positions_are_persisted_to_community_assignment_by_block_index(world):
    run = _concor(world)
    rows = dict(world.conn.execute(
        "SELECT node_id, community_id FROM analytics.community_assignment "
        "WHERE metric_run_id = %s", (run.run_id,)).fetchall())
    by_label = {n["label"]: n for n in run.payload["nodes"]}
    assert len(rows) == 5
    for label, row in by_label.items():
        assert rows[world.ids[label]] == row["block_index"]
    assert rows[world.ids["H1"]] == rows[world.ids["H2"]] != rows[world.ids["a"]]
    assert world.conn.execute(
        "SELECT count(*) FROM analytics.node_metric WHERE metric_run_id = %s",
        (run.run_id,)).fetchone()[0] == 0


def _runs(w) -> list[tuple]:
    return w.conn.execute(
        """SELECT r.status FROM analytics.metric_run r
             JOIN analytics.projection pr ON pr.id = r.projection_id
            WHERE pr.case_id = %s AND r.algorithm = 'concor'""",
        (w.case_id,)).fetchall()


def test_a_refusal_known_before_computing_leaves_no_run_behind(conn):
    """Every Run on a case with fewer than two tied
    entities would otherwise write a FAILED run and an audit event."""
    from noctornal_api.analytics import AnalyticsError
    w = World(conn)
    w.node("lonely")
    w.node("F", "FORUM")
    w.tie("lonely", "POSTS_ON", "F")
    with pytest.raises(AnalyticsError, match="at least two entities with ties"):
        w.svc().concor(w.proj(preset="all", edge_types=["POSTS_ON"]), params(), depth=1)
    assert _runs(w) == []


def test_a_failed_concor_run_is_recorded_as_failed(world, monkeypatch):
    from noctornal_api import blockmodel

    def boom(*_a, **_kw):
        raise RuntimeError("numerical trouble")

    monkeypatch.setattr(blockmodel, "concor", boom)
    with pytest.raises(RuntimeError):
        _concor(world)
    assert _runs(world) == [("FAILED",)]
    action = world.conn.execute(
        """SELECT action, detail ->> 'algorithm' FROM audit.event
            WHERE case_id = %s AND object_type = 'metric_run'
            ORDER BY occurred_at DESC LIMIT 1""", (world.case_id,)).fetchone()
    assert action == ("ANALYTICS_RUN_FAILED", "concor")


def test_the_concor_run_writes_an_audit_event_naming_the_algorithm(world):
    run = _concor(world)
    row = world.conn.execute(
        """SELECT action, detail FROM audit.event
            WHERE object_type = 'metric_run' AND object_id = %s""",
        (run.run_id,)).fetchone()
    assert row[0] == "ANALYTICS_RUN" and row[1]["algorithm"] == "concor"
    assert "review_scope" not in row[1] and "one_mode" not in row[1]
