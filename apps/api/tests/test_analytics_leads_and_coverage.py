"""What the Analysis pane's numbers claim about people, held to what they
can support. Pure: no database.

The 2026-09-22 usability review (lens ux10-analytics) found four ways the
suite's payload said more, or other, than its numbers do:

- broker-lead-card-overclaims: "Brokers worth a look" fired on an
  ABSOLUTE constraint below 0.4. In a dense case nearly everyone is below
  0.4, so the lead was "the busiest third", and it told the analyst each
  of them "profits from the gap between otherwise disconnected groups" in
  a network with one component;
- rank-percentile-opposite-directions: constraint rank 1 sat beside p2,
  in the column next to a betweenness rank 1 at p98;
- metrics-hide-review-and-evidence-state: nothing said the ties behind a
  removal set were unreviewed machine proposals with no exhibit;
- communities-anonymous-table-unsortable: communities were bare integers,
  with no sizes anywhere.

And a stored run computed before the fix must not bring the old answers
back (`analytics_runs.upgrade_stored`).
"""
from __future__ import annotations

import random
from uuid import uuid4

from noctornal_api.analytics import (
    CONSTRAINT_ORDER,
    AnalyticsParams,
    _rank_and_percentile,
    graph_hash,
    run_suite,
)
from noctornal_api.analytics_runs import upgrade_stored, upgraded_constraint_percentile
from noctornal_api.projections import Projection, Subgraph


def build(nodes, edges, *, review="ACCEPTED", evidenced=()):
    """A Subgraph shaped as GraphService.project() returns it, review and
    evidence columns included."""
    ids = {k: uuid4() for k in nodes}
    ns = [{"id": ids[k], "label": k, "node_type": "IDENTITY",
           "classification": "AMBER", "attrs": {}, "valid_from": None,
           "valid_to": None, "first_seen": None, "last_seen": None,
           "has_evidence": False} for k in nodes]
    es = []
    for i, (a, b) in enumerate(edges):
        es.append({"id": uuid4(), "edge_type": "VOUCHED_FOR",
                   "src_node_id": ids[a], "dst_node_id": ids[b], "sign": 1,
                   "weight": 1.0, "confidence": "LOW", "is_inferred": False,
                   "review": review if isinstance(review, str) else review[i],
                   "classification": "AMBER", "valid_from": None,
                   "valid_to": None, "has_evidence": i in evidenced})
    return Subgraph(ns, es, {}, False), ids


def proj():
    return Projection(case_id=uuid4())


def dense_one_component(seed=4, n=30, p=0.2):
    """A case shaped like OP-CORVID-26: thirty actors, a mean degree near
    seven, one component. Constraint is below 0.4 for almost everybody."""
    rng = random.Random(seed)
    names = [f"a{i:02d}" for i in range(n)]
    edges = [(names[i], names[j]) for i in range(n) for j in range(i + 1, n)
             if rng.random() < p]
    # A spine, so the fixture is one component whatever the draw.
    edges += [(names[i], names[i + 1]) for i in range(n - 1)]
    return build(names, sorted(set(edges)))


# --- broker-lead-card-overclaims ------------------------------------------

def test_the_structural_hole_lead_is_relative_and_the_fixture_shows_why():
    sub, _ = dense_one_component()
    out = run_suite(sub, proj())
    nodes = out["nodes"]
    n = len(nodes)
    assert out["cohesion"]["components"] == 1

    # The OLD rule, applied to the same numbers, is what the review saw:
    # most actors under 0.4, so it tagged actors from the constrained half.
    under = [x for x in nodes if x["constraint"] is not None and x["constraint"] < 0.4]
    assert len(under) >= n - 2, "the fixture must be dense like CORVID"
    old = [x for x in under if x["betweenness_percentile"] >= 70 and x["betweenness"] > 0]
    assert any(x["constraint_rank"] > n // 2 for x in old), (
        "the fixture no longer exercises the defect: nothing the old rule "
        "tagged sits in the constrained half")

    holes = [x for x in nodes if x["broker_kind"] == "structural_hole"]
    quarter = -(-n // 4)            # ceil(n / 4) ranks make the top quarter
    for x in holes:
        assert x["constraint_rank"] <= quarter + 1, x
        assert x["betweenness_rank"] <= quarter + 1, x
    assert len(holes) < len(old), "the relative rule tags no fewer actors"
    # Nobody from the constrained half is called a structural-hole spanner.
    assert not any(x["constraint_rank"] > n // 2 for x in holes)


def test_the_lead_sentence_claims_nothing_about_disconnected_groups():
    """Burt's structural hole is a gap between an actor's own contacts. It
    exists in a network of one component, where "otherwise disconnected
    groups" is false."""
    sub, _ = dense_one_component()
    out = run_suite(sub, proj())
    texts = {x["broker_signature"] for x in out["nodes"] if x["broker_signature"]}
    assert texts, "the fixture tags nobody, so the check below proves nothing"
    for t in texts:
        assert "disconnected groups" not in t


def test_the_rule_travels_with_the_answer():
    sub, _ = dense_one_component()
    rule = run_suite(sub, proj())["broker_rule"]
    assert rule["connected_count"] == 30
    assert rule["median_degree"] > 0
    assert rule["structural_hole_constraint_percentile"] == 75.0
    assert rule["structural_hole_betweenness_percentile"] == 75.0
    assert rule["few_ties_betweenness_percentile"] == 80.0


def test_isolates_do_not_move_who_is_a_broker():
    """An entity with no tie added to the case moves every percentile over
    the whole population. The leads are ranked among actors WITH ties, so
    it moves none of them."""
    sub, ids = dense_one_component()
    before = {x["label"]: x["broker_kind"] for x in run_suite(sub, proj())["nodes"]}
    more, _ = dense_one_component()
    for k in range(5):
        more.nodes.append({**more.nodes[0], "id": uuid4(), "label": f"iso{k}"})
    after = {x["label"]: x["broker_kind"] for x in run_suite(more, proj())["nodes"]}
    assert {k: v for k, v in after.items() if not k.startswith("iso")} == before
    assert all(after[f"iso{k}"] is None for k in range(5))


def test_an_actor_with_the_median_number_of_ties_is_not_called_few_ties():
    """Found driving OP-NIGHTJAR-26 after the first cut of the fix: "at or
    below the median" put actors with exactly the median nine ties under
    "Few ties, high brokerage". Few is three or fewer, or fewer than most."""
    sub, _ = dense_one_component()
    out = run_suite(sub, proj())
    median = out["broker_rule"]["median_degree"]
    tied = [x for x in out["nodes"] if x["degree"] > 0]
    _, pct = _rank_and_percentile([x["betweenness"] for x in tied])
    at_median = [x for x, p in zip(tied, pct, strict=True)
                 if x["degree"] == median and median > 3 and p >= 80]
    assert at_median, "the fixture no longer has a median-degree top broker"
    for x in at_median:
        assert x["broker_kind"] != "few_ties", x
    for x in out["nodes"]:
        if x["broker_kind"] == "few_ties":
            assert x["degree"] <= 3 or x["degree"] < median, x


def test_the_classic_broker_is_still_found():
    """Two triangles joined through k: fewest ties of the well connected,
    all the brokerage. The relative rule must keep docs/03's own example."""
    sub, _ = build(["a", "b", "c", "x", "y", "z", "k"],
                   [("a", "b"), ("b", "c"), ("a", "c"), ("x", "y"),
                    ("y", "z"), ("x", "z"), ("a", "k"), ("k", "x")])
    by = {x["label"]: x for x in run_suite(sub, proj())["nodes"]}
    assert by["k"]["broker_kind"] == "few_ties"
    assert "Broker signature" in by["k"]["broker_signature"]


# --- rank-percentile-opposite-directions ----------------------------------

def test_constraint_percentile_runs_the_way_its_rank_does():
    sub, _ = dense_one_component()
    out = run_suite(sub, proj())
    assert out["constraint_order"] == CONSTRAINT_ORDER
    nodes = [x for x in out["nodes"] if x["constraint"] is not None]
    loosest = min(nodes, key=lambda x: x["constraint"])
    tightest = max(nodes, key=lambda x: x["constraint"])
    assert loosest["constraint_rank"] == 1
    assert loosest["constraint_percentile"] > 90, loosest
    assert tightest["constraint_percentile"] < 10, tightest
    # And the same direction as betweenness: rank order and percentile
    # order agree for every actor.
    for a in nodes:
        for b in nodes:
            if a["constraint_rank"] < b["constraint_rank"]:
                assert a["constraint_percentile"] > b["constraint_percentile"]


# --- metrics-hide-review-and-evidence-state -------------------------------

def test_the_payload_says_what_the_ties_rest_on():
    sub, _ = build(["a", "b", "c", "d"],
                   [("a", "b"), ("b", "c"), ("c", "d"), ("a", "d")],
                   review=["PROPOSED", "PROPOSED", "ACCEPTED", "REJECTED"],
                   evidenced={2})
    cov = run_suite(sub, proj())["review_coverage"]
    assert cov == {"ties": 4, "proposed": 2, "accepted": 1, "disputed": 0,
                   "rejected": 1, "evidenced": 1, "inferred": 0}


def test_a_disputed_tie_is_counted_as_disputed():
    """Release review c11 (2026-09-24). DISPUTED is the one doubt tie review
    can record (REJECTED is refused), and it landed in no bucket: three
    disputed ties of five read as 0 proposed, 2 accepted, nothing else, so
    the pane said every tie behind the brokers had been reviewed."""
    sub, _ = build(["a", "b", "c", "d", "e"],
                   [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("a", "e")],
                   review=["DISPUTED", "DISPUTED", "DISPUTED", "ACCEPTED", "ACCEPTED"])
    cov = run_suite(sub, proj())["review_coverage"]
    assert cov["disputed"] == 3 and cov["accepted"] == 2 and cov["proposed"] == 0
    assert sum(cov[k] for k in ("proposed", "accepted", "disputed", "rejected")) == cov["ties"]


def test_a_stored_run_is_given_the_disputed_count_it_was_stored_without():
    """A run computed before c11 counted its disputed ties nowhere. They are
    the remainder, since a reviewer can set nothing else, so the stored run
    warns as a fresh one would instead of reading as settled."""
    sub, _ = build(["a", "b", "c", "d", "e"],
                   [("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("a", "e")],
                   review=["DISPUTED", "DISPUTED", "PROPOSED", "ACCEPTED", "REJECTED"])
    fresh = run_suite(sub, proj())
    stored = {**fresh, "review_coverage": {
        k: v for k, v in fresh["review_coverage"].items() if k != "disputed"}}
    up = upgrade_stored(stored)
    assert up["review_coverage"] == fresh["review_coverage"]
    assert "review_coverage" in up["upgraded"]
    assert "disputed" not in stored["review_coverage"], "the stored bytes were edited"
    # A run that counts them is served as it was stored.
    assert upgrade_stored(fresh) is fresh


def test_reviewing_or_evidencing_a_tie_changes_the_cache_key():
    """The coverage is part of the answer, so a run whose ties have since
    been reviewed must not be served, or called current, as the same one."""
    p, params = proj(), AnalyticsParams()
    sub, _ = build(["a", "b"], [("a", "b")], review="PROPOSED")
    base = graph_hash(sub, p, params)
    sub.edges[0]["review"] = "ACCEPTED"
    reviewed = graph_hash(sub, p, params)
    assert reviewed != base
    sub.edges[0]["has_evidence"] = True
    assert graph_hash(sub, p, params) != reviewed


def test_renaming_an_entity_changes_the_cache_key():
    """Release review c16 (2026-09-24). The payload names people, and the
    digest covered ids only, so a renamed entity kept its old name on a
    cache hit and under "nothing it was computed from has changed". A name
    corrected because it held personal data kept printing."""
    p, params = proj(), AnalyticsParams()
    sub, ids = build(["rv_alpha", "rv_delta"], [("rv_alpha", "rv_delta")])
    base = graph_hash(sub, p, params)
    renamed = next(n for n in sub.nodes if n["id"] == ids["rv_delta"])
    renamed["label"] = "rv_delta_renamed"
    after = graph_hash(sub, p, params)
    assert after != base, "a rename left the run current"
    renamed["label"] = "rv_delta"
    assert graph_hash(sub, p, params) == base, "the same names hash alike again"
    renamed["node_type"] = "PERSON"
    assert graph_hash(sub, p, params) != base, "the type colours the name too"
    # No label can be worded to make two node sets hash alike.
    two, _ = build(["a", "b"], [])
    one, _ = build(["a", "b"], [])
    one.nodes[1]["id"] = two.nodes[1]["id"]
    one.nodes[0]["id"] = two.nodes[0]["id"]
    one.nodes[0]["label"] = 'a", "IDENTITY"]\x00["' + str(two.nodes[1]["id"])
    assert graph_hash(one, p, params) != graph_hash(two, p, params)


# --- communities-anonymous-table-unsortable -------------------------------

def test_community_sizes_travel_with_the_answer_largest_first():
    sub, _ = dense_one_component()
    out = run_suite(sub, proj())
    sizes = out["cohesion"]["community_sizes"]
    assert sum(s["size"] for s in sizes) == 30
    assert [s["size"] for s in sizes] == sorted((s["size"] for s in sizes), reverse=True)
    counted = {}
    for x in out["nodes"]:
        counted[x["community"]] = counted.get(x["community"], 0) + 1
    assert {s["community"]: s["size"] for s in sizes} == counted


# --- a run stored before the fix ------------------------------------------

def _as_stored_before_the_fix(payload: dict) -> dict:
    """What a pre-2026-09-23 run left in `metric_run.result`: the percentile
    over raw constraint, the absolute lead rule, no sizes, no marker."""
    old = {k: v for k, v in payload.items()
           if k not in ("constraint_order", "broker_rule", "review_coverage")}
    old["cohesion"] = {k: v for k, v in payload["cohesion"].items()
                       if k != "community_sizes"}
    rows = [dict(x) for x in payload["nodes"]]
    _, raw = _rank_and_percentile([x["constraint"] if x["constraint"] is not None
                                   else float("-inf") for x in rows])
    for x, pct in zip(rows, raw, strict=True):
        x["constraint_percentile"] = pct
        x.pop("broker_kind", None)
        x["broker_signature"] = (
            "Spans a structural hole: low constraint with high brokerage. "
            "Burt's reading is an actor who profits from the gap between "
            "otherwise disconnected groups."
            if x["constraint"] is not None and x["constraint"] < 0.4
            and x["betweenness_percentile"] >= 70 and x["betweenness"] > 0
            else None)
    old["nodes"] = rows
    return old


def test_a_stored_run_is_brought_up_to_the_current_rules():
    sub, _ = dense_one_component()
    fresh = run_suite(sub, proj())
    stored = _as_stored_before_the_fix(fresh)
    up = upgrade_stored(stored)
    assert up["constraint_order"] == CONSTRAINT_ORDER
    assert set(up["upgraded"]) == {"constraint_percentile", "broker_leads",
                                   "community_sizes"}
    by_fresh = {x["id"]: x for x in fresh["nodes"]}
    for x in up["nodes"]:
        f = by_fresh[x["id"]]
        assert x["constraint_percentile"] == f["constraint_percentile"]
        assert x["broker_kind"] == f["broker_kind"]
        assert x["broker_signature"] == f["broker_signature"]
    assert up["cohesion"]["community_sizes"] == fresh["cohesion"]["community_sizes"]
    assert up["broker_rule"] == fresh["broker_rule"]
    # The stored bytes are not edited in place.
    assert "constraint_order" not in stored


def test_a_stored_trend_point_is_re_ranked_not_turned_round():
    """The trend reads a pre-fix run's percentile from `node_metric`, one
    row per actor, and "100 minus it" was exact only without isolates: an
    isolate sits below the actors in both directions, so turning the old
    percentile round moved every actor down by the isolates' share. Found
    reviewing the 2026-09-23 fix: a NIGHTJAR-shaped run put rank 1 at about
    p68 in the trend table while the actor table said p98. Re-ranked from
    the run's own counts, the two tables agree to the digit."""
    connected, _ = dense_one_component()
    names = [n["label"] for n in connected.nodes]
    iso = [f"iso{i}" for i in range(14)]
    sub, _ = build(names + iso, _edge_labels(connected))
    fresh = run_suite(sub, proj())
    stored = _as_stored_before_the_fix(fresh)
    rows = stored["nodes"]
    defined = [x for x in rows if x["constraint"] is not None]
    assert len(rows) - len(defined) == 14, "the fixture has lost its isolates"
    by_fresh = {x["id"]: x for x in fresh["nodes"]}
    got = {}
    for x in defined:
        above = sum(1 for y in defined if y["constraint"] > x["constraint"])
        equal = sum(1 for y in defined if y["constraint"] == x["constraint"])
        got[x["id"]] = upgraded_constraint_percentile(
            len(rows), defined=len(defined), above=above, equal=equal,
            stored=x["constraint_percentile"])
        assert got[x["id"]] == by_fresh[x["id"]]["constraint_percentile"], x["label"]
        assert round(100.0 - x["constraint_percentile"], 2) != got[x["id"]], (
            "with isolates the old turn-round is wrong for every actor; the "
            "fixture no longer shows the defect this test exists for")
    loosest = min(defined, key=lambda x: x["constraint"])
    assert got[loosest["id"]] > 90, got[loosest["id"]]
    # Without the run's counts the turn-round is all there is.
    assert upgraded_constraint_percentile(None, defined=None, above=None, equal=None,
                                          stored=2.0) == 98.0


def _edge_labels(sub):
    label = {n["id"]: n["label"] for n in sub.nodes}
    return [(label[e["src_node_id"]], label[e["dst_node_id"]]) for e in sub.edges]


def test_a_current_payload_is_served_as_it_was_stored():
    sub, _ = dense_one_component()
    fresh = run_suite(sub, proj())
    assert upgrade_stored(fresh) is fresh
    assert upgrade_stored({"key_player": {}}) == {"key_player": {}}
