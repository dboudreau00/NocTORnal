"""F2 against Postgres (2026-09-24): venues projected to entities over a
real case written through GraphWriteService.

The world: personas A, B and C post on forum F; A controls wallet W1, B
controls W2, and transaction T moves money from W1 to W2; A vouches for C.

Held here: the forum family fetches POSTS_ON under a preset that does not
hold it; with no family listed the rows are exactly today's; a poster the
caller cannot see draws nothing and moves no denominator; the Financial
suite names no wallet or transaction; a one-mode run is its own
projection, cache entry and currency; retracting a membership dissolves
its derived tie (decision 24); and the two cache-key cases the second
design review found (a renamed oversized forum, and one raised above the
caller's clearance, each served back with current: true before the
coverage was hashed).

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
    not DATABASE_URL, reason="DATABASE_URL not set; one-mode test is gated")


def _om(*families, **kw):
    from noctornal_api.affiliation import OneModeParams
    return OneModeParams(tuple(families), **kw)


@pytest.fixture
def world(conn):
    w = World(conn)
    for label in ("A", "B", "C"):
        w.node(label)
    w.node("F", "FORUM")
    w.node("W1", "WALLET")
    w.node("W2", "WALLET")
    w.node("T", "TRANSACTION")
    for who in ("A", "B", "C"):
        w.tie(who, "POSTS_ON", "F")
    w.tie("A", "CONTROLS", "W1")
    w.tie("B", "CONTROLS", "W2")
    w.tie("W1", "TX_INPUT", "T")
    w.tie("T", "TX_OUTPUT", "W2")
    w.tie("A", "VOUCHED_FOR", "C")
    return w


def _derived(sub, w) -> dict:
    name = {v: k for k, v in w.ids.items()}
    return {(e["family"], name[e["src_node_id"]], name[e["dst_node_id"]]): e
            for e in sub.edges if e.get("derived")}


def test_the_forum_family_fetches_posts_on_under_the_all_preset(world):
    sub = world.graph().project(world.proj(one_mode=_om("forum")))
    got = _derived(sub, world)
    assert set(got) == {("forum", *sorted(p, key=lambda x: str(world.ids[x])))
                        for p in (("A", "B"), ("A", "C"), ("B", "C"))}
    assert all(e["weight"] == pytest.approx(0.5) for e in got.values())
    assert world.ids["F"] not in sub.node_ids()
    assert sub.one_mode["venues_projected"] == {"FORUM": 1}


def test_with_one_mode_off_project_returns_exactly_todays_rows(world):
    sub = world.graph().project(world.proj())
    assert [e["edge_type"] for e in sub.edges] == ["VOUCHED_FOR"]
    assert set(sub.edges[0]) == {"id", "edge_type", "src_node_id", "dst_node_id", "sign",
                                 "weight", "confidence", "is_inferred", "review",
                                 "classification", "valid_from", "valid_to",
                                 "has_evidence"}
    assert sub.one_mode is None and sub.review_left_out is None
    assert len(sub.nodes) == 7


def test_a_posts_on_tie_above_the_callers_clearance_draws_nothing_and_moves_no_denominator(world):
    world.node("D")
    world.tie("D", "POSTS_ON", "F", classification="RED")
    amber = world.graph(clearance="AMBER").project(world.proj(one_mode=_om("forum")))
    assert all(e["weight"] == pytest.approx(0.5) for e in _derived(amber, world).values())
    assert not any("D" in k for k in _derived(amber, world))
    red = world.graph(clearance="RED").project(world.proj(one_mode=_om("forum")))
    assert all(e["weight"] == pytest.approx(1 / 3) for e in _derived(red, world).values())


def test_the_financial_suite_one_mode_names_no_wallet_and_no_transaction(world):
    out = world.svc().suite(world.proj(preset="financial", one_mode=_om("wallet")),
                            params()).payload
    # The forum stays, as an isolate: only the wallet family was projected.
    assert {n["node_type"] for n in out["nodes"]} == {"IDENTITY", "FORUM"}
    assert out["one_mode"]["derived_ties"] == {"forum": 0, "wallet_control": 0,
                                               "wallet_flow": 1}
    assert out["one_mode"]["venues_removed"] == {"TRANSACTION": 1, "WALLET": 2}
    # So the isolated branch of the mode warning still speaks, naming it.
    assert "FORUM" in out["mode_warning"] and "WALLET" not in out["mode_warning"]


def test_a_one_mode_run_has_its_own_projection_row_cache_entry_and_currency(world):
    svc = world.svc()
    plain = svc.suite(world.proj(), params())
    om = svc.suite(world.proj(one_mode=_om("forum")), params())
    assert om.run_id != plain.run_id
    assert svc.suite(world.proj(one_mode=_om("forum")), params()).cached is True
    names = world.conn.execute(
        "SELECT count(DISTINCT name) FROM analytics.projection WHERE case_id = %s",
        (world.case_id,)).fetchone()[0]
    assert names == 2
    latest = svc.latest(world.proj(one_mode=_om("forum")), params())
    assert latest.run_id == om.run_id and latest.current is True
    # The weighting is part of the question: another projection, no run.
    assert svc.latest(world.proj(one_mode=_om("forum", weighting="COUNT")),
                      params()) is None


def test_retracting_a_posts_on_claim_dissolves_the_derived_tie(world):
    assertion_id = world.conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s",
        (world.edges["C-POSTS_ON-F"],)).fetchone()[0]
    world.g.retract_assertion(assertion_id, retracted_by=world.uid,
                              reason="misread the board", at=datetime.now(timezone.utc))
    sub = world.graph().project(world.proj(one_mode=_om("forum")))
    got = _derived(sub, world)
    assert len(got) == 1
    (edge,) = got.values()
    assert edge["weight"] == 1.0            # two posters now, 1 / (2 - 1)


def test_the_accepted_scope_counts_affiliations_apart_and_only_those_it_would_consume(world):
    world.conn.execute("UPDATE core.edge SET review = 'PROPOSED' WHERE id = %s",
                       (world.edges["C-POSTS_ON-F"],))
    world.node("S", "SELECTOR")
    world.tie("A", "CONTROLS", "S", review="PROPOSED")
    sub = world.graph().project(world.proj(preset="trust", review_scope="accepted",
                                           one_mode=_om("forum", "wallet")))
    assert sub.review_left_out["affiliations"]["proposed"] == 1
    assert sub.review_left_out["ties"]["proposed"] == 0
    # C still sizes the forum: A and B are tied at 1 / (3 - 1).
    (edge,) = [e for e in _derived(sub, world).values() if e["family"] == "forum"]
    assert edge["weight"] == pytest.approx(0.5)


def test_renaming_an_oversized_forum_is_a_cache_miss_and_not_current(world):
    from noctornal_api.graph import AssertionInput
    p = world.proj(one_mode=_om("forum", max_venue_size=2))
    svc = world.svc()
    first = svc.suite(p, params())
    assert [o["label"] for o in first.payload["one_mode"]["oversized"]] == ["F"]
    world.g.update_node(world.ids["F"], case_id=world.case_id, label="Board renamed",
                        assertion=AssertionInput(basis="DIRECT_OBSERVATION",
                                                 created_by=world.uid,
                                                 rationale="the board's real name"))
    assert svc.latest(p, params()).current is False
    second = svc.suite(p, params())
    assert second.cached is False
    assert [o["label"] for o in second.payload["one_mode"]["oversized"]] == ["Board renamed"]


def test_raising_an_oversized_forum_above_the_caller_is_a_cache_miss_and_not_current(world):
    """The label leak: the forum's name sat in the stored payload, and with
    the coverage unhashed the run was served back to a reader who can no
    longer see the forum, with current: true."""
    p = world.proj(one_mode=_om("forum", max_venue_size=2))
    amber = world.svc(clearance="AMBER")
    first = amber.suite(p, params())
    assert [o["label"] for o in first.payload["one_mode"]["oversized"]] == ["F"]
    world.conn.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s",
                       (world.ids["F"],))
    assert amber.latest(p, params()).current is False
    again = amber.suite(p, params())
    assert again.cached is False
    assert again.payload["one_mode"]["oversized"] == []
