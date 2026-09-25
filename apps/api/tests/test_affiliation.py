"""F2: bipartite to one-mode projection for the forum and wallet families
(2026-09-24), without a database.

Every world here is spelled out vertex by vertex and row by row, with the
sign and directedness each edge type has in the ontology, and fed through
`projections.one_mode_subgraph`, the code `project()` runs after its
fetch. A row is included only when the real query would fetch it (in the
preset, or an affiliation or identity type of a listed family), so a test
cannot pass on a row production never sees. Ids are UUID(int=k), so a
failure reproduces.

Each of the following has a test that fails without its fix: sizes and
caps under the accepted scope and the confidence floor, the per-type
oversized count, the leg arithmetic, disputed identity links, parallel
memberships and PAID in either direction.

Pure: no database.
"""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone
from uuid import UUID

import pytest
from noctornal_ontology.definition import EDGE_TYPES, NODE_TYPES

from noctornal_api import affiliation
from noctornal_api.affiliation import (
    FAMILIES,
    OneModeError,
    OneModeParams,
    OneModeTooLarge,
    material_edge_types,
)
from noctornal_api.analytics import AnalyticsParams, graph_hash, materialise
from noctornal_api.projections import (
    Projection,
    ProjectionTooLarge,
    one_mode_subgraph,
)

CASE = UUID(int=1)
_ET = {t.key: t for t in EDGE_TYPES}
UTC = timezone.utc


def d(y: int, m: int = 1, day: int = 1) -> datetime:
    return datetime(y, m, day, tzinfo=UTC)


def _world(nodes: dict[str, str], rows: list, *, preset: str = "all",
           families=("forum",), attrs: dict | None = None,
           min_confidence: str = "LOW", review_scope: str = "all",
           weighting: str = "NEWMAN", max_venue_size: int = 50,
           min_shared: int = 1, order_seed: int | None = None):
    """(subgraph, ids). `rows` are (src, edge_type, dst) or (src,
    edge_type, dst, {vf, vt, review, confidence, ev})."""
    ids = {name: UUID(int=100 + i) for i, name in enumerate(nodes)}
    node_out = [{"id": ids[n], "node_type": t, "label": n,
                 "attrs": (attrs or {}).get(n, {}), "classification": "AMBER"}
                for n, t in nodes.items()]
    p = Projection(case_id=CASE, preset=preset, min_confidence=min_confidence,
                   review_scope=review_scope,
                   one_mode=OneModeParams(tuple(families), weighting,
                                          max_venue_size, min_shared))
    types = p.resolved_edge_types()
    material = set(material_edge_types(p.one_mode.families))
    fetched = []
    for k, row in enumerate(rows):
        src, et, dst = row[:3]
        kw = row[3] if len(row) > 3 else {}
        member = _ET[et].is_social_tie if types is None else et in types
        if not member and et not in material:
            continue            # the query would never have fetched it
        fetched.append(({
            "id": UUID(int=10_000 + k), "edge_type": et,
            "src_node_id": ids[src], "dst_node_id": ids[dst],
            "sign": _ET[et].default_sign, "weight": 1.0,
            "confidence": kw.get("confidence", "LOW"), "is_inferred": False,
            "review": kw.get("review", "ACCEPTED"), "classification": "AMBER",
            "valid_from": kw.get("vf"), "valid_to": kw.get("vt"),
            "has_evidence": kw.get("ev", False)}, member))
    if order_seed is not None:
        random.Random(order_seed).shuffle(fetched)
        random.Random(order_seed).shuffle(node_out)
    return one_mode_subgraph(p, node_out, fetched), ids, p


def _derived(sub, ids) -> dict:
    """Derived ties keyed by (family, src name, dst name)."""
    name = {v: k for k, v in ids.items()}
    return {(e["family"], name[e["src_node_id"]], name[e["dst_node_id"]]): e
            for e in sub.edges if e.get("derived")}


def _posters(n: int, forum: str = "F") -> tuple[dict, list]:
    nodes = {f"p{i:02d}": "IDENTITY" for i in range(n)}
    nodes[forum] = "FORUM"
    return nodes, [(f"p{i:02d}", "POSTS_ON", forum) for i in range(n)]


# ---------------------------------------------------------------------------
# Forums
# ---------------------------------------------------------------------------

def test_three_posters_on_one_forum_are_tied_pairwise_at_newman_one_half():
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "c": "IDENTITY",
                          "F": "FORUM"},
                         [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"),
                          ("c", "POSTS_ON", "F")])
    got = _derived(sub, ids)
    assert set(got) == {("forum", "a", "b"), ("forum", "a", "c"), ("forum", "b", "c")}
    assert all(e["weight"] == pytest.approx(0.5) and not e["directed"] for e in got.values())
    assert ids["F"] not in sub.node_ids()
    assert sub.one_mode["venues_projected"] == {"FORUM": 1}
    assert sub.one_mode["derived_ties"] == {"forum": 3, "wallet_control": 0,
                                            "wallet_flow": 0}


def test_count_weighting_counts_shared_venues():
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM", "G": "CHANNEL"},
                         [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"),
                          ("a", "POSTS_ON", "G"), ("b", "POSTS_ON", "G")],
                         weighting="COUNT")
    derived = [e for e in sub.edges if e.get("derived")]
    assert len(derived) == 2 and all(e["weight"] == 1.0 for e in derived)
    m = materialise(sub, AnalyticsParams())
    assert m.strength == [2.0]


def test_a_forum_larger_than_the_limit_is_left_out_and_named():
    nodes, rows = _posters(51)
    sub, ids, _ = _world(nodes, rows)
    assert not [e for e in sub.edges if e.get("derived")]
    assert sub.one_mode["oversized"] == [{
        "node_id": str(ids["F"]), "label": "F", "node_type": "FORUM", "size": 51,
        "visible_size": 51, "size_basis": "case_graph"}]
    assert sub.one_mode["oversized_total"] == 1
    assert sub.one_mode["oversized_by_type"] == {"FORUM": 1}


def test_a_recorded_member_count_raises_the_denominator_and_says_so():
    nodes = {"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"}
    rows = [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F")]
    attrs = {"F": {"member_count": 300}}
    sub, ids, _ = _world(nodes, rows, attrs=attrs, max_venue_size=500)
    (edge,) = _derived(sub, ids).values()
    assert edge["weight"] == pytest.approx(1 / 299)
    sub, ids, _ = _world(nodes, rows, attrs=attrs, max_venue_size=50)
    assert not _derived(sub, ids)
    assert sub.one_mode["oversized"][0] | {"node_id": None} == {
        "node_id": None, "label": "F", "node_type": "FORUM", "size": 300,
        "visible_size": 2, "size_basis": "recorded"}


@pytest.mark.parametrize("value", ["300", 300.5, True, 1])
def test_a_member_count_that_is_not_a_whole_number_of_at_least_two_is_ignored(value):
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F")],
                         attrs={"F": {"member_count": value}})
    (edge,) = _derived(sub, ids).values()
    assert edge["weight"] == 1.0


def test_the_denominator_is_what_the_caller_can_see():
    """The third poster's row is not in the caller's rows (above their
    clearance): it moves nothing."""
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F")])
    (edge,) = _derived(sub, ids).values()
    assert edge["weight"] == 1.0


def test_pairs_below_min_shared_are_dropped_and_counted():
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "c": "IDENTITY",
                          "F": "FORUM", "G": "FORUM"},
                         [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"),
                          ("c", "POSTS_ON", "F"), ("a", "POSTS_ON", "G"),
                          ("b", "POSTS_ON", "G")], min_shared=2)
    derived = [e for e in sub.edges if e.get("derived")]
    names = {v: k for k, v in ids.items()}
    assert sorted((names[e["src_node_id"]], names[e["dst_node_id"]]) for e in derived) \
        == [("a", "b"), ("a", "b")]
    assert sub.one_mode["pairs_below_min_shared"] == 2


def test_posting_at_different_times_is_not_co_affiliation():
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F", {"vf": d(2020), "vt": d(2020, 6)}),
                          ("b", "POSTS_ON", "F", {"vf": d(2021)})])
    assert not _derived(sub, ids)
    assert sub.one_mode["pairs_not_contemporaneous"] == 1
    assert sub.one_mode["venues_without_ties"] == {"FORUM": 1}
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F", {"vf": d(2020), "vt": d(2021, 6)}),
                          ("b", "POSTS_ON", "F", {"vf": d(2021)})])
    (edge,) = _derived(sub, ids).values()
    assert (edge["valid_from"], edge["valid_to"]) == (d(2021), d(2021, 6))


def test_any_of_a_members_parallel_postings_can_make_them_contemporaneous():
    """An accepted 2019 posting and a proposed 2023
    one. Judged on the stronger row alone, a 2023 co-poster read as not
    contemporaneous."""
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F", {"vf": d(2019), "vt": d(2019, 12)}),
                          ("a", "POSTS_ON", "F", {"vf": d(2023), "review": "PROPOSED"}),
                          ("b", "POSTS_ON", "F", {"vf": d(2023, 3)})])
    (edge,) = _derived(sub, ids).values()
    assert edge["valid_from"] == d(2023, 3)
    # Review, confidence and evidence come from the strongest row: accepted.
    assert edge["review"] == "ACCEPTED"
    # And the two postings are one membership: the size is two.
    assert edge["weight"] == 1.0


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

_WALLET_PAIR = {"p": "IDENTITY", "q": "PERSON", "W": "WALLET"}


def test_a_persona_and_its_attributed_person_get_no_tie_from_their_shared_wallet():
    sub, ids, _ = _world(_WALLET_PAIR,
                         [("p", "ATTRIBUTED_TO", "q"), ("p", "CONTROLS", "W"),
                          ("q", "CONFIRMED_CONTROL_OF", "W")],
                         families=("wallet",))
    assert not _derived(sub, ids)
    assert sub.one_mode["pairs_same_identity"] == 1


def test_an_unreviewed_identity_link_still_suppresses_under_the_accepted_scope():
    sub, ids, _ = _world(_WALLET_PAIR,
                         [("p", "ATTRIBUTED_TO", "q", {"review": "PROPOSED"}),
                          ("p", "CONTROLS", "W"), ("q", "CONFIRMED_CONTROL_OF", "W")],
                         families=("wallet",), review_scope="accepted")
    assert not _derived(sub, ids)
    assert sub.one_mode["pairs_same_identity"] == 1


@pytest.mark.parametrize("state", ["DISPUTED", "REJECTED"])
def test_a_disputed_identity_link_does_not_suppress_and_is_counted_apart(state):
    """A contested link kept changing the numbers and was
    counted as "the same identity", the very claim that was disputed."""
    sub, ids, _ = _world(_WALLET_PAIR,
                         [("p", "ATTRIBUTED_TO", "q", {"review": state}),
                          ("p", "CONTROLS", "W"), ("q", "CONFIRMED_CONTROL_OF", "W")],
                         families=("wallet",))
    assert set(_derived(sub, ids)) == {("wallet_control", "p", "q")}
    assert sub.one_mode["pairs_same_identity"] == 0
    assert sub.one_mode["pairs_identity_disputed"] == 1


# ---------------------------------------------------------------------------
# Wallets
# ---------------------------------------------------------------------------

def test_shared_wallet_control_is_newman_weighted():
    sub, ids, _ = _world({"A": "IDENTITY", "B": "IDENTITY", "G": "GROUP", "W": "WALLET"},
                         [("A", "CONTROLS", "W"), ("B", "CONTROLS", "W"),
                          ("G", "CONTROLS", "W")], families=("wallet",))
    got = _derived(sub, ids)
    assert len(got) == 3 and all(e["family"] == "wallet_control" for e in got.values())
    assert all(e["weight"] == pytest.approx(0.5) for e in got.values())


_FLOW = {"A": "IDENTITY", "B": "IDENTITY", "W1": "WALLET", "W2": "WALLET",
         "T": "TRANSACTION"}
_FLOW_ROWS = [("A", "CONTROLS", "W1"), ("W1", "TX_INPUT", "T"),
              ("T", "TX_OUTPUT", "W2"), ("B", "CONTROLS", "W2")]


def test_money_moves_from_the_payers_controller_to_the_payees():
    sub, ids, _ = _world(_FLOW, _FLOW_ROWS, families=("wallet",))
    (key,) = _derived(sub, ids)
    assert key == ("wallet_flow", "A", "B")
    edge = _derived(sub, ids)[key]
    assert edge["directed"] is True and edge["sign"] == 0 and edge["weight"] == 1.0
    assert {n["node_type"] for n in sub.nodes} == {"IDENTITY"}


def test_a_wallet_with_one_controller_in_one_flow_counts_as_projected():
    """Which venue "drew" a flow tie was undefined. The
    transaction draws it, and so do both wallets whose controllers it ties,
    so neither lands in venues_without_ties."""
    sub, _ids, _ = _world(_FLOW, _FLOW_ROWS, families=("wallet",))
    assert sub.one_mode["venues_projected"] == {"TRANSACTION": 1, "WALLET": 2}
    assert sub.one_mode["venues_without_ties"] == {}


def test_a_transaction_with_two_inputs_splits_its_weight():
    nodes = {**_FLOW, "C": "IDENTITY", "W3": "WALLET"}
    rows = _FLOW_ROWS + [("C", "CONTROLS", "W3"), ("W3", "TX_INPUT", "T")]
    got = _derived(*_world(nodes, rows, families=("wallet",))[:2])
    assert got[("wallet_flow", "A", "B")]["weight"] == pytest.approx(0.5)
    assert got[("wallet_flow", "C", "B")]["weight"] == pytest.approx(0.5)


def _coinjoin(accepted_only_legs: bool = False):
    nodes = {"A": "IDENTITY", "B": "IDENTITY", "T": "TRANSACTION"}
    rows = []
    for i in range(26):
        nodes[f"in{i:02d}"] = "WALLET"
        review = "ACCEPTED" if i == 0 or not accepted_only_legs else "PROPOSED"
        rows.append((f"in{i:02d}", "TX_INPUT", "T", {"review": review}))
    for i in range(25):
        nodes[f"out{i:02d}"] = "WALLET"
        review = "ACCEPTED" if i == 0 or not accepted_only_legs else "PROPOSED"
        rows.append(("T", "TX_OUTPUT", f"out{i:02d}", {"review": review}))
    rows += [("A", "CONTROLS", "in00"), ("B", "CONTROLS", "out00")]
    return nodes, rows


def test_a_coinjoin_sized_transaction_is_left_out_and_named():
    nodes, rows = _coinjoin()
    sub, ids, _ = _world(nodes, rows, families=("wallet",))
    assert not _derived(sub, ids)
    assert [o["label"] for o in sub.one_mode["oversized"]] == ["T"]
    assert sub.one_mode["oversized"][0]["size"] == 51


def test_the_accepted_scope_keeps_the_caps_it_is_meant_to_strengthen():
    """With one accepted leg a side the CoinJoin became
    a 1 x 1 transaction drawing a full-weight money tie under the accepted
    scope, named nowhere, while "all" refused it. Sizes come from every
    visible membership now, under either scope."""
    nodes, rows = _coinjoin(accepted_only_legs=True)
    for scope in ("all", "accepted"):
        sub, ids, _ = _world(nodes, rows, families=("wallet",), review_scope=scope)
        assert not _derived(sub, ids), scope
        assert [o["label"] for o in sub.one_mode["oversized"]] == ["T"], scope
    assert sub.one_mode["members_not_drawing"]["review"] == 49


def test_a_large_board_with_a_few_accepted_posters_draws_no_clique():
    nodes, rows = _posters(60)
    rows = [(s, et, t, {"review": "ACCEPTED" if i < 4 else "PROPOSED"})
            for i, (s, et, t) in enumerate(rows)]
    for scope in ("all", "accepted"):
        sub, ids, _ = _world(nodes, rows, review_scope=scope)
        assert not _derived(sub, ids), scope
        assert sub.one_mode["oversized"][0]["size"] == 60, scope


def test_the_confidence_floor_keeps_the_caps_too():
    nodes, rows = _posters(60)
    rows = [(s, et, t, {"confidence": "HIGH" if i < 4 else "LOW"})
            for i, (s, et, t) in enumerate(rows)]
    sub, ids, _ = _world(nodes, rows, min_confidence="HIGH")
    assert not _derived(sub, ids)
    assert sub.one_mode["oversized"][0]["size"] == 60
    assert sub.one_mode["members_not_drawing"] == {"confidence": 56, "review": 0}
    # Within the limit, the LOW posters still count in the denominator: the
    # four HIGH posters of a 10-poster board are tied at 1/9, not 1/3.
    nodes, rows = _posters(10)
    rows = [(s, et, t, {"confidence": "HIGH" if i < 4 else "LOW"})
            for i, (s, et, t) in enumerate(rows)]
    sub, ids, _ = _world(nodes, rows, min_confidence="HIGH")
    got = _derived(sub, ids)
    assert len(got) == 6 and all(e["weight"] == pytest.approx(1 / 9) for e in got.values())


def test_a_wallet_with_more_controllers_than_the_limit_ties_nobody_and_feeds_no_flow():
    nodes = {**_FLOW, "C": "IDENTITY", "D": "IDENTITY"}
    rows = _FLOW_ROWS + [("C", "CONTROLS", "W1"), ("D", "CONTROLS", "W1")]
    sub, ids, _ = _world(nodes, rows, families=("wallet",), max_venue_size=2)
    assert not _derived(sub, ids)
    assert sub.one_mode["flow_legs_through_oversized_wallets"] == 1
    assert sub.one_mode["oversized_by_type"] == {"WALLET": 1}


def test_a_self_transfer_is_counted_not_tied():
    rows = [("A", "CONTROLS", "W1"), ("W1", "TX_INPUT", "T"),
            ("T", "TX_OUTPUT", "W2"), ("A", "CONTROLS", "W2")]
    sub, ids, _ = _world(_FLOW, rows, families=("wallet",))
    assert not _derived(sub, ids)
    assert sub.one_mode["self_transfers"] == 1


def test_unattributed_and_partly_unattributed_transactions_are_counted():
    nodes = {**_FLOW, "W3": "WALLET", "T2": "TRANSACTION", "W4": "WALLET", "W5": "WALLET"}
    rows = _FLOW_ROWS + [("W3", "TX_INPUT", "T"),                 # T: partly
                         ("W4", "TX_INPUT", "T2"), ("T2", "TX_OUTPUT", "W5")]  # T2: none
    sub, _ids, _ = _world(nodes, rows, families=("wallet",))
    assert sub.one_mode["transactions_partly_unattributed"] == 1
    assert sub.one_mode["transactions_unattributed"] == 1


def test_a_direct_paid_tie_suppresses_the_derived_flow_only_when_it_is_in_the_view():
    for pay in (("A", "PAID", "B"), ("B", "PAID", "A")):
        # Either direction: PAID is the actor-level
        # summary.
        sub, ids, _ = _world(_FLOW, _FLOW_ROWS + [pay], preset="financial",
                             families=("wallet",))
        assert ("wallet_flow", "A", "B") not in _derived(sub, ids), pay
        assert sub.one_mode["flow_already_paid"] == 1
    sub, ids, _ = _world(_FLOW, _FLOW_ROWS + [("A", "PAID", "B")], preset="trust",
                         families=("wallet",))
    assert ("wallet_flow", "A", "B") in _derived(sub, ids)
    assert sub.one_mode["flow_already_paid"] == 0


def test_a_wallet_to_wallet_paid_edge_becomes_a_flow():
    sub, ids, _ = _world({"A": "IDENTITY", "B": "IDENTITY", "W1": "WALLET", "W2": "WALLET"},
                         [("A", "CONTROLS", "W1"), ("W1", "PAID", "W2"),
                          ("B", "CONTROLS", "W2")], families=("wallet",))
    edge = _derived(sub, ids)[("wallet_flow", "A", "B")]
    assert edge["weight"] == 1.0 and edge["directed"]


def test_control_that_did_not_cover_the_transaction_pays_nobody():
    rows = [("A", "CONTROLS", "W1", {"vf": d(2020), "vt": d(2020, 12, 31)}),
            ("W1", "TX_INPUT", "T", {"vf": d(2022), "vt": d(2022)}),
            ("T", "TX_OUTPUT", "W2"), ("B", "CONTROLS", "W2")]
    sub, ids, _ = _world(_FLOW, rows, families=("wallet",))
    assert not _derived(sub, ids)
    assert sub.one_mode["flow_legs_not_contemporaneous"] == 1


def test_derived_ties_take_the_weakest_review_the_lowest_confidence_and_need_every_exhibit():
    rows = [("A", "CONTROLS", "W1", {"confidence": "HIGH", "ev": True}),
            ("W1", "TX_INPUT", "T", {"confidence": "MODERATE", "ev": True,
                                     "review": "DISPUTED"}),
            ("T", "TX_OUTPUT", "W2", {"confidence": "HIGH", "ev": True}),
            ("B", "CONTROLS", "W2", {"confidence": "HIGH", "ev": False})]
    edge = _derived(*_world(_FLOW, rows, families=("wallet",))[:2])[
        ("wallet_flow", "A", "B")]
    assert edge["review"] == "DISPUTED"
    assert edge["confidence"] == "MODERATE"
    assert edge["has_evidence"] is False


def test_derived_ties_are_derived_inferred_and_carry_no_valence():
    sub, ids, _ = _world(_FLOW, _FLOW_ROWS, families=("wallet",))
    (edge,) = [e for e in sub.edges if e.get("derived")]
    assert edge["derived"] is True and edge["is_inferred"] is True
    assert edge["sign"] == 0 and edge["id"] is None
    assert edge["edge_type"] == "ONE_MODE:wallet_flow"
    assert not {"label", "compartments", "classification"} & set(edge)


def test_family_material_outside_the_preset_is_never_a_tie_and_never_counted():
    sub, ids, _ = _world({"A": "IDENTITY", "S": "SELECTOR", "B": "IDENTITY"},
                         [("A", "CONTROLS", "S"), ("A", "VOUCHED_FOR", "B")],
                         preset="trust", families=("wallet",))
    assert [e["edge_type"] for e in sub.edges] == ["VOUCHED_FOR"]
    assert sub.one_mode["edges_dropped_with_venues"] == {}


def test_ties_to_removed_venues_are_counted_by_type():
    sub, ids, _ = _world({"A": "IDENTITY", "C": "CHANNEL"},
                         [("A", "CONTROLS", "C")], preset="financial",
                         families=("forum",))
    assert not sub.edges
    assert sub.one_mode["edges_dropped_with_venues"] == {"CONTROLS": 1}


def test_every_removed_venue_is_projected_without_ties_or_oversized():
    """The partition, per type, past the 25 venues the payload names
    (with one oversized total across types it could not be
    computed from the payload)."""
    nodes = {"a": "IDENTITY", "b": "IDENTITY", "lonely": "FORUM", "busy": "FORUM"}
    rows = [("a", "POSTS_ON", "busy"), ("b", "POSTS_ON", "busy"),
            ("a", "POSTS_ON", "lonely")]
    attrs = {}
    for i in range(30):
        nodes[f"huge{i:02d}"] = "CHANNEL" if i % 2 else "FORUM"
        attrs[f"huge{i:02d}"] = {"member_count": 400}
    sub, _ids, _ = _world(nodes, rows, attrs=attrs)
    cov = sub.one_mode
    assert len(cov["oversized"]) == affiliation.OVERSIZED_LISTED
    assert cov["oversized_total"] == 30
    for t in ("FORUM", "CHANNEL"):
        assert cov["venues_removed"].get(t, 0) == (
            cov["venues_projected"].get(t, 0) + cov["venues_without_ties"].get(t, 0)
            + cov["oversized_by_type"].get(t, 0)), t
    assert cov["venues_projected"] == {"FORUM": 1}
    assert cov["venues_without_ties"] == {"FORUM": 1}


# ---------------------------------------------------------------------------
# Cost
# ---------------------------------------------------------------------------

def test_the_derived_tie_limit_is_checked_before_anything_is_built(monkeypatch):
    monkeypatch.setattr(affiliation, "MAX_DERIVED_TIES", 2)
    built = []
    real = affiliation._Derived.__init__

    def spy(self, *a, **kw):
        built.append(a)
        real(self, *a, **kw)

    monkeypatch.setattr(affiliation._Derived, "__init__", spy)
    with pytest.raises(ProjectionTooLarge, match="up to 3 derived ties, over the limit of 2"):
        # min_shared 2 would prune every pair: the bound is taken before it.
        _world({"a": "IDENTITY", "b": "IDENTITY", "c": "IDENTITY", "F": "FORUM"},
               [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"), ("c", "POSTS_ON", "F")],
               min_shared=2)
    assert built == []


def test_a_wide_unattributed_transaction_is_counted_not_walked():
    """Legs with no controller at either end were enumerated
    one by one. 250 x 250 is within max_venue_size 500."""
    nodes = {"T": "TRANSACTION"}
    rows = []
    for i in range(250):
        nodes[f"i{i:03d}"] = "WALLET"
        nodes[f"o{i:03d}"] = "WALLET"
        rows += [(f"i{i:03d}", "TX_INPUT", "T"), ("T", "TX_OUTPUT", f"o{i:03d}")]
    started = time.perf_counter()
    sub, _ids, _ = _world(nodes, rows, families=("wallet",), max_venue_size=500)
    assert time.perf_counter() - started < 2.0
    assert sub.one_mode["transactions_unattributed"] == 1
    assert sub.one_mode["derived_upper_bound"] == 0


def test_the_too_large_error_is_a_projection_error_with_the_bound():
    err = OneModeTooLarge(60_001)
    assert err.bound == 60_001 and "60,001" in str(err) and "50,000" in str(err)


# ---------------------------------------------------------------------------
# Parameters and invariants
# ---------------------------------------------------------------------------

def test_conversation_is_not_a_family():
    """Decision 73: the Comms pane projects conversations, with decision
    58's protections."""
    assert set(FAMILIES) == {"forum", "wallet"}
    with pytest.raises(OneModeError, match="unknown family 'conversation'; one of "
                                           "forum, wallet"):
        OneModeParams(("conversation",)).validate()


def test_families_are_normalised_on_construction():
    assert OneModeParams(("wallet", "forum", "forum")).families == ("forum", "wallet")


@pytest.mark.parametrize("kwargs, message", [
    ({"weighting": "LOG"}, "unknown weighting"),
    ({"max_venue_size": 1}, "max_venue_size must be between 2 and 500"),
    ({"max_venue_size": 501}, "max_venue_size must be between 2 and 500"),
    ({"min_shared": 0}, "min_shared must be between 1 and 100"),
])
def test_out_of_range_parameters_are_refused(kwargs, message):
    with pytest.raises(OneModeError, match=message):
        OneModeParams(("forum",), **kwargs).validate()


def test_the_affiliation_sources_are_actors_in_the_ontology():
    """A future ontology change fails here rather than tying artefacts."""
    actor = {n.key for n in NODE_TYPES if n.category == "ACTOR"}
    for key in ("POSTS_ON", "CONTROLS", "CONFIRMED_CONTROL_OF"):
        assert set(_ET[key].src_node_types) <= actor, key
    assert set(_ET["PAID"].src_node_types) == {"IDENTITY", "WALLET"}
    assert set(_ET["PAID"].dst_node_types) == {"IDENTITY", "WALLET"}


def test_the_coverage_is_canonical_under_any_row_order():
    nodes = {**_FLOW, "C": "IDENTITY", "W3": "WALLET", "F": "FORUM", "G": "CHANNEL"}
    rows = _FLOW_ROWS + [("C", "CONTROLS", "W3"), ("W3", "TX_INPUT", "T"),
                         ("A", "POSTS_ON", "F"), ("B", "POSTS_ON", "F"),
                         ("C", "POSTS_ON", "F"), ("A", "POSTS_ON", "G"),
                         ("C", "POSTS_ON", "G")]
    seen = set()
    for seed in (None, 1, 2, 3):
        sub, _ids, p = _world(nodes, rows, families=("forum", "wallet"), order_seed=seed)
        seen.add((json.dumps(sub.one_mode, sort_keys=True),
                  graph_hash(sub, p, AnalyticsParams()).hex()))
    assert len(seen) == 1


def test_every_user_visible_string_obeys_the_copy_rules():
    texts = [affiliation.SIZE_NOTE, affiliation.READING, str(OneModeTooLarge(5))]
    for kwargs in ({"weighting": "X"}, {"max_venue_size": 0}, {"min_shared": 0}):
        with pytest.raises(OneModeError) as exc:
            OneModeParams(("forum",), **kwargs).validate()
        texts.append(str(exc.value))
    with pytest.raises(OneModeError) as exc:
        OneModeParams(("x",)).validate()
    texts.append(str(exc.value))
    for text in texts:
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in text, text
