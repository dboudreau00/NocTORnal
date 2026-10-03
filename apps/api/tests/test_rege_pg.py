"""REGE against Postgres (ROADMAP-REMAINING phase 3, 2026-10-02): regular-role
runs, their cache, currency, clearance and persistence, held to CONCOR's
pattern (test_concor_pg.py) point for point.

Held here: a regular-role run is cached on the graph hash, the number of
roles and the weighting, and a different value of either is a different run
that `latest_rege` tells apart; a cache hit is served exactly as computed;
swapping an undirected tie for a directed one that hashes alike for the
suite makes the run stale (direction is in its key); the suite, key-player
and CONCOR keys are unchanged; a run never crosses a clearance boundary;
roles land in community_assignment by block index; every refusal known
before computing (a cap, the two-entity floor, a parameter) leaves no run
behind, and an unexpected failure is recorded as FAILED with its audit
event; currency reads the run's own roles and weighting back.

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
    not DATABASE_URL, reason="DATABASE_URL not set; REGE test is gated")


@pytest.fixture
def world(conn):
    """A directed star, hub to three leaves, and a second hub to two of them:
    two hubs alike in kind, and leaves alike, two roles."""
    w = World(conn)
    for label in ("H1", "H2", "a", "b", "c"):
        w.node(label)
    for x in ("a", "b", "c"):
        w.tie("H1", "VOUCHED_FOR", x)
    for x in ("a", "b"):
        w.tie("H2", "VOUCHED_FOR", x)
    w.tie("H1", "COMMUNICATES_WITH", "H2")
    return w


def _rege(w, roles=2, weighting="presence", clearance="RED", **kw):
    return w.svc(clearance=clearance).rege(w.proj(), params(), roles=roles,
                                          weighting=weighting, **kw)


def _runs(w, algorithm="rege") -> list[tuple]:
    return w.conn.execute(
        """SELECT r.status FROM analytics.metric_run r
             JOIN analytics.projection pr ON pr.id = r.projection_id
            WHERE pr.case_id = %s AND r.algorithm = %s""",
        (w.case_id, algorithm)).fetchall()


def test_a_rege_run_is_cached_on_graph_hash_roles_and_weighting(world):
    first = _rege(world)
    again = _rege(world)
    assert first.cached is False and again.cached is True
    assert again.run_id == first.run_id
    roles = {frozenset(m["label"] for m in r["members"])
             for r in first.payload["rege"]["roles"]}
    assert roles == {frozenset({"H1", "H2"}), frozenset({"a", "b", "c"})}


def test_a_different_number_of_roles_or_weighting_is_a_different_run(world):
    two = _rege(world, roles=2)
    three = _rege(world, roles=3)
    weighted = _rege(world, roles=2, weighting="weight")
    assert len({two.run_id, three.run_id, weighted.run_id}) == 3
    assert not (three.cached or weighted.cached)
    svc = world.svc()
    p = world.proj()
    assert svc.latest_rege(p, params(), roles=2, weighting="presence").run_id == two.run_id
    assert svc.latest_rege(p, params(), roles=3, weighting="presence").run_id == three.run_id
    assert svc.latest_rege(p, params(), roles=2, weighting="weight").run_id == weighted.run_id
    assert svc.latest_rege(p, params(), roles=4, weighting="presence") is None
    assert svc.latest_rege(p, params(), roles=3, weighting="weight") is None


def test_a_cached_rege_run_is_served_exactly_as_computed(world):
    computed = _rege(world).as_response()
    cached = _rege(world).as_response()
    latest = world.svc().latest_rege(world.proj(), params(), roles=2,
                                     weighting="presence").as_response()
    strip = ("run_id", "cached", "current", "computed_at", "computed_at_ms")
    for body in (cached, latest):
        assert {k: v for k, v in body.items() if k not in strip} == \
            {k: v for k, v in computed.items() if k not in strip}
        assert not {"upgraded", "broker_rule", "constraint_order"} & set(body)


def test_swapping_a_tie_type_makes_a_rege_run_not_current(world):
    """COMMUNICATES_WITH H1-H2 for REPLIED_TO H1->H2: the same ends, sign,
    weight, dates, review and evidence, so the suite hashes alike, but a
    tie given never matches one received."""
    from noctornal_api.analytics import graph_hash
    before_sub = world.graph().project(world.proj())
    first = _rege(world)
    assertion_id = world.conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s",
        (world.edges["H1-COMMUNICATES_WITH-H2"],)).fetchone()[0]
    world.g.retract_assertion(assertion_id, retracted_by=world.uid,
                              reason="it was a reply", at=datetime.now(timezone.utc))
    world.tie("H1", "REPLIED_TO", "H2")
    after_sub = world.graph().project(world.proj())
    assert graph_hash(before_sub, world.proj(), params()) == \
        graph_hash(after_sub, world.proj(), params())
    stored = world.svc().latest_rege(world.proj(), params(), roles=2, weighting="presence")
    assert stored.run_id == first.run_id and stored.current is False
    assert _rege(world).cached is False


def test_the_other_keys_are_unchanged_and_rege_folds_direction(world):
    from noctornal_api.analytics import graph_hash
    from noctornal_api.analytics_runs import CONCOR, KPP_NEG, REGE, SUITE
    svc = world.svc()
    sub = world.graph().project(world.proj())
    p = world.proj()
    assert svc._cache_key(sub, p, params(), {}, SUITE) == graph_hash(sub, p, params())
    assert svc._cache_key(sub, p, params(), {"n_remove": 3}, KPP_NEG) == \
        svc._cache_key(sub, p, params(), {"n_remove": 3})
    extra = {"roles": 2, "weighting": "presence"}
    assert svc._cache_key(sub, p, params(), extra, REGE) != \
        svc._cache_key(sub, p, params(), extra)
    assert svc._cache_key(sub, p, params(), {"depth": 1}, CONCOR) != \
        svc._cache_key(sub, p, params(), {"depth": 1})


def test_rege_is_never_served_across_a_clearance_boundary(world):
    red = _rege(world, clearance="RED")
    amber = world.svc(clearance="AMBER")
    assert amber.latest_rege(world.proj(), params(), roles=2, weighting="presence") is None
    own = amber.rege(world.proj(), params(), roles=2, weighting="presence")
    assert own.run_id != red.run_id and own.cached is False


def test_roles_are_persisted_to_community_assignment_by_block_index(world):
    run = _rege(world)
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


def test_the_blocks_density_tied_and_regular_marks_are_stored_and_served(world):
    """The role-to-role image a stored run carries, to the number: the two
    hubs hold five of the six ties they could send to the three leaves (and
    send both ways to each other), so against a view density of 7 in 20 both
    blocks are tied, and every hub sends and every leaf receives, so both are
    regular. Computed, served from the cache and read back as the latest run
    all say the same (g34 review item 2, 2026-10-02: no test outside the pure
    file read a block)."""
    expected = {"alpha": {"positive": 0.35},
                "density": {"positive": [[0.0, 0.0], [pytest.approx(5 / 6, abs=1e-6), 1.0]]},
                "image": {"positive": [[0, 0], [1, 1]]},
                "regular": {"positive": [[0, 0], [1, 1]]}}
    computed = _rege(world)
    cached = _rege(world)
    latest = world.svc().latest_rege(world.proj(), params(), roles=2, weighting="presence")
    for run in (computed, cached, latest):
        g = run.payload["rege"]
        assert [m["label"] for r in g["roles"] for m in r["members"]] == [
            "a", "b", "c", "H1", "H2"]
        for part, want in expected.items():
            assert g[part] == want, (run.cached, part, g[part])
    assert cached.cached is True and latest.cached is True


def test_tied_blocks_that_are_not_regular_are_stored_as_such(conn):
    """The hubs' world above has only blocks that are both or neither. A
    chain of five cut into interior, source and sink has three blocks holding
    a third of the ties they could (more than the view's 0.2, so tied) and
    none regular, whatever ids the database gave the entities: the cut does
    not move here (g34 review item 2, 2026-10-02)."""
    w = World(conn)
    names = ["a", "b", "c", "d", "e"]
    for label in names:
        w.node(label)
    for x, y in zip(names, names[1:], strict=False):
        w.tie(x, "VOUCHED_FOR", y)
    run = w.svc().rege(w.proj(), params(), roles=3)
    g = run.payload["rege"]
    assert [[m["label"] for m in r["members"]] for r in g["roles"]] == [
        ["b", "c", "d"], ["a"], ["e"]]
    third = pytest.approx(1 / 3, abs=1e-6)
    assert g["alpha"] == {"positive": pytest.approx(0.2, abs=1e-6)}
    assert g["density"] == {"positive": [[third, 0.0, third], [third, None, 0.0],
                                         [0.0, 0.0, None]]}
    assert g["image"] == {"positive": [[1, 0, 1], [1, 0, 0], [0, 0, 0]]}
    assert g["regular"] == {"positive": [[0, 0, 0], [0, 0, 0], [0, 0, 0]]}
    stored = w.svc().latest_rege(w.proj(), params(), roles=3, weighting="presence")
    assert stored.payload["rege"]["density"] == g["density"]
    assert stored.payload["rege"]["regular"] == g["regular"]


def test_a_block_exactly_as_dense_as_the_view_is_stored_as_tied(conn):
    """A directed ring of four is one role holding a third of its ordered
    pairs, which is the view's own density: tied counts the equal case, which
    a strict comparison would drop, through the database as well as the pure
    path (g34 review item 2, 2026-10-02)."""
    w = World(conn)
    ring = ["a", "b", "c", "d"]
    for label in ring:
        w.node(label)
    for x, y in zip(ring, ring[1:] + ring[:1], strict=True):
        w.tie(x, "VOUCHED_FOR", y)
    g = w.svc().rege(w.proj(), params(), roles=2).payload["rege"]
    assert g["roles_found"] == 1
    assert g["alpha"] == {"positive": pytest.approx(1 / 3, abs=1e-6)}
    assert g["density"] == {"positive": [[pytest.approx(1 / 3, abs=1e-6)]]}
    assert g["image"] == {"positive": [[1]]} and g["regular"] == {"positive": [[1]]}


def test_a_rege_run_is_recorded_as_approximate_on_its_row_and_in_its_audit_event(world):
    """The service reads the payload's top-level flag: REGE nested its own, so
    the row and the ANALYTICS_RUN event both said exact for an analysis the
    card calls an approximation (g34 review item 3, 2026-10-02)."""
    run = _rege(world)
    assert world.conn.execute(
        "SELECT is_approximate FROM analytics.metric_run WHERE id = %s",
        (run.run_id,)).fetchone()[0] is True
    detail = world.conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_type = 'metric_run' AND object_id = %s AND action = 'ANALYTICS_RUN'""",
        (run.run_id,)).fetchone()[0]
    assert detail["is_approximate"] is True


def test_the_run_records_its_roles_and_weighting(world):
    run = _rege(world, roles=3, weighting="weight")
    stored = world.conn.execute(
        "SELECT params ->> 'roles', params ->> 'weighting' FROM analytics.metric_run "
        "WHERE id = %s", (run.run_id,)).fetchone()
    assert stored == ("3", "weight")


def test_a_refusal_known_before_computing_leaves_no_run_behind(conn, monkeypatch):
    from noctornal_api import rege
    from noctornal_api.analytics import AnalyticsError
    w = World(conn)
    w.node("lonely")
    w.node("F", "FORUM")
    w.tie("lonely", "POSTS_ON", "F")
    with pytest.raises(AnalyticsError, match="at least two entities with ties"):
        w.svc().rege(w.proj(preset="all", edge_types=["POSTS_ON"]), params(), roles=2)
    for label in ("p", "q", "r"):
        w.node(label)
    w.tie("p", "VOUCHED_FOR", "q")
    w.tie("q", "VOUCHED_FOR", "r")
    with pytest.raises(AnalyticsError, match="between 2 and 8"):
        w.svc().rege(w.proj(), params(), roles=9)
    with pytest.raises(AnalyticsError, match="presence or by weight"):
        w.svc().rege(w.proj(), params(), weighting="decayed")
    w.conn.execute("UPDATE core.edge SET weight = 0 WHERE case_id = %s", (w.case_id,))
    with pytest.raises(AnalyticsError, match="no tie in this view carries a positive weight"):
        w.svc().rege(w.proj(), params(), weighting="weight")
    w.conn.execute("UPDATE core.edge SET weight = 1 WHERE case_id = %s", (w.case_id,))
    monkeypatch.setattr(rege, "REGE_MAX_PAIRS", 1)
    with pytest.raises(AnalyticsError, match="capped at 1 tied pairs"):
        w.svc().rege(w.proj(), params())
    monkeypatch.setattr(rege, "REGE_MAX_PAIRS", 2500)
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 1)
    with pytest.raises(AnalyticsError, match="capped at 1 tie directions"):
        w.svc().rege(w.proj(), params())
    assert _runs(w) == []
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE case_id = %s AND object_type = 'metric_run'",
        (w.case_id,)).fetchone()[0] == 0


def test_a_failed_rege_run_is_recorded_as_failed(world, monkeypatch):
    from noctornal_api import rege

    def boom(*_a, **_kw):
        raise RuntimeError("numerical trouble")

    monkeypatch.setattr(rege, "rege", boom)
    with pytest.raises(RuntimeError):
        _rege(world)
    assert _runs(world) == [("FAILED",)]
    action = world.conn.execute(
        """SELECT action, detail ->> 'algorithm' FROM audit.event
            WHERE case_id = %s AND object_type = 'metric_run'
            ORDER BY occurred_at DESC LIMIT 1""", (world.case_id,)).fetchone()
    assert action == ("ANALYTICS_RUN_FAILED", "rege")


def test_the_rege_run_writes_an_audit_event_naming_the_algorithm(world):
    run = _rege(world)
    row = world.conn.execute(
        """SELECT action, detail FROM audit.event
            WHERE object_type = 'metric_run' AND object_id = %s""",
        (run.run_id,)).fetchone()
    assert row[0] == "ANALYTICS_RUN" and row[1]["algorithm"] == "rege"
    assert "review_scope" not in row[1] and "one_mode" not in row[1]


def test_currency_reads_the_runs_own_roles_and_weighting_back(world):
    run = _rege(world, roles=3, weighting="weight")
    svc = world.svc()
    one = svc.currency(world.proj(), params(), run.run_id)
    assert one["algorithm"] == "rege" and one["current"] is True
    many = svc.currency_many(world.proj(), params(), [run.run_id])
    assert many["runs"][0]["current"] is True
    world.tie("b", "VOUCHED_FOR", "c")
    assert svc.currency(world.proj(), params(), run.run_id)["current"] is False


def test_an_accepted_only_rege_run_counts_nothing_unaccepted(conn):
    """The view decides which ties are compared (L3): under the accepted
    scope a proposed tie shapes no role and is counted as left out."""
    w = World(conn)
    for label in ("H1", "H2", "a", "b"):
        w.node(label)
    w.tie("H1", "VOUCHED_FOR", "a")
    w.tie("H2", "VOUCHED_FOR", "b")
    w.tie("a", "VOUCHED_FOR", "b", review="PROPOSED")
    every = w.svc().rege(w.proj(), params(), roles=2)
    accepted = w.svc().rege(w.proj(review_scope="accepted"), params(), roles=2)
    assert every.payload["rege"]["unaccepted_ties"] == 1
    assert accepted.payload["rege"]["unaccepted_ties"] == 0
    assert accepted.payload["review_scope"]["left_out"]["ties"]["proposed"] == 1
    assert accepted.run_id != every.run_id


def test_a_close_knit_crew_over_shared_forums_is_admitted_through_the_real_projection(conn):
    """The g34 verifier's view, end to end (g34 verify item, 2026-10-03): every
    identity posts on every forum and the one-mode projection makes one derived
    tie per pair and forum, so the rows (and the old slot count, twice them)
    far exceed the ties cap while the tie directions, the cells the matrices
    hold, are a small fraction of it. The run is admitted, completes and stores
    its row, and every derived tie is counted on the card."""
    from noctornal_api import rege
    from noctornal_api.affiliation import OneModeParams
    w = World(conn)
    entities = [f"e{i}" for i in range(26)]
    forums = [f"f{j}" for j in range(9)]
    for label in entities:
        w.node(label)
    for label in forums:
        w.node(label, "FORUM")
    for label in entities:
        for forum in forums:
            w.tie(label, "POSTS_ON", forum)
    p = w.proj(one_mode=OneModeParams(families=("forum",)))
    sub = w.graph().project(p)
    tied, _ties, pairs, directions = rege._usable(sub)
    assert len(sub.edges) == 325 * 9                       # one derived tie per pair and forum
    assert 2 * len(sub.edges) > rege.REGE_MAX_TIES         # what the rows alone would have been
    assert (len(tied), pairs, directions) == (26, 325, 650)
    for weighting in ("presence", "weight"):
        run = w.svc().rege(p, params(), roles=4, weighting=weighting)
        assert run.payload["rege"]["relations"][0]["ties"] == 325 * 9
        assert run.payload["rege"]["derived_ties"] is True
    assert _runs(w) == [("COMPLETE",), ("COMPLETE",)]
