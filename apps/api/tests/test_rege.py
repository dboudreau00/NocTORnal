"""REGE regular equivalence, the Regular roles card's maths (ROADMAP-REMAINING
phase 3, 2026-10-02), without a database.

The implementation is held to an independent one written here from the
published formula (Borgatti and Everett 1993; the classic REGE of the
blockmodeling package): plain loops over every i, j, k and m, the relation
matrices built from the ontology by this file rather than by the module.
They must agree on the textbook shapes (a star both ways, a directed chain,
actors and forums, Wasserman and Faust's small hierarchy) and on random
graphs, weighted and not, through both kernel paths and with chunks of one
row. The average-linkage cut is held to a naive one that recomputes every
cluster pair's mean similarity from the original matrix.

Every fixture spells its ties as (src, edge_type, dst) with ids
UUID(int=k), so a failure reproduces. Pure: no database.
"""
from __future__ import annotations

import json
import math
import os
import random
import re
import subprocess
import sys
import time
from pathlib import Path
from uuid import UUID

import numpy
import pytest
from noctornal_ontology.definition import EDGE_TYPES

from noctornal_api import rege
from noctornal_api.analytics import AnalyticsError, AnalyticsParams
from noctornal_api.projections import Projection, Subgraph

CASE = UUID(int=1)
_ET = {t.key: t for t in EDGE_TYPES}


def _sub(names, ties, types=None, *, weights=None, review=None, truncated=False,
         seed=None, uuid_seed=None) -> tuple[Subgraph, dict]:
    """`uuid_seed` gives every name a random-looking id (the same ones for
    the same seed), as real ids are; the default ids ascend with the names,
    which also happens to be the order a set of them iterates in."""
    ids = {n: UUID(int=100 + i) for i, n in enumerate(names)}
    if uuid_seed is not None:
        rng = random.Random(uuid_seed)
        ids = {n: UUID(int=rng.getrandbits(128)) for n in names}
    nodes = [{"id": ids[n], "label": n, "node_type": (types or {}).get(n, "IDENTITY")}
             for n in names]
    edges = [{"id": UUID(int=1000 + k), "edge_type": et, "src_node_id": ids[s],
              "dst_node_id": ids[t], "sign": _ET[et].default_sign,
              "weight": (weights or {}).get(k, 1.0),
              "valid_from": None, "valid_to": None,
              "review": (review or {}).get(k, "ACCEPTED"), "has_evidence": False}
             for k, (s, et, t) in enumerate(ties)]
    if seed is not None:
        random.Random(seed).shuffle(nodes)
        random.Random(seed).shuffle(edges)
    return Subgraph(nodes, edges, truncated=truncated), ids


def _run(sub, roles=4, weighting="presence") -> dict:
    return rege.rege(sub, Projection(case_id=CASE), AnalyticsParams(), roles=roles,
                     weighting=weighting)


def _roles(out) -> list[set]:
    return [{m["label"] for m in r["members"]} for r in out["rege"]["roles"]]


# --------------------------------------------------------------------------
# The independent reference
# --------------------------------------------------------------------------

def _naive_relations(names, ties, weights=None, weighting="presence"):
    """One matrix per valence present, built here from the ontology: a
    directed tie fills [src][dst], an undirected one both cells; presence
    caps a cell at 1, weight sums positive weights."""
    tied = {s for s, _e, _t in ties} | {t for _s, _e, t in ties}
    order = sorted((n for n in names if n in tied),
                   key=lambda n: str(UUID(int=100 + names.index(n))))
    at = {n: i for i, n in enumerate(order)}
    n = len(order)
    out: dict[int, list[list[float]]] = {}
    for k, (s, et, t) in enumerate(ties):
        sign = _ET[et].default_sign
        m = out.setdefault(sign, [[0.0] * n for _ in range(n)])
        w = (weights or {}).get(k, 1.0)
        cells = [(at[s], at[t])] + ([] if _ET[et].is_directed else [(at[t], at[s])])
        for i, j in cells:
            if weighting == "weight":
                if w > 0:
                    m[i][j] += w
            else:
                m[i][j] = 1.0
    return order, [out[s] for s in (1, -1, 0) if s in out]


def _naive_rege(mats, iterations=3, tolerance=1e-6):
    """The formula, term by term."""
    n = len(mats[0])
    e = [[1.0] * n for _ in range(n)]
    rounds = 0
    for _ in range(iterations):
        new = [[1.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                num = 0.0
                for k in range(n):
                    best_ij = best_ji = 0.0
                    for m in range(n):
                        ij = sum(min(x[i][k], x[j][m]) + min(x[k][i], x[m][j]) for x in mats)
                        ji = sum(min(x[j][k], x[i][m]) + min(x[k][j], x[m][i]) for x in mats)
                        best_ij = max(best_ij, e[k][m] * ij)
                        best_ji = max(best_ji, e[k][m] * ji)
                    num += best_ij + best_ji
                den = sum(x[i][v] + x[j][v] + x[v][i] + x[v][j] for x in mats for v in range(n))
                new[i][j] = new[j][i] = num / den if den else 1.0
        change = max(abs(new[i][j] - e[i][j]) for i in range(n) for j in range(n))
        e = new
        rounds += 1
        if change <= tolerance:
            break
    return numpy.array(e), rounds


def _naive_linkage(sim):
    """Average linkage by brute force: every step recomputes each pair of
    clusters' mean similarity from the original matrix, and takes the most
    alike, the pair with the smaller least members first among equals."""
    clusters = [[i] for i in range(len(sim))]
    merges = []
    while len(clusters) > 1:
        best = None
        for x in range(len(clusters)):
            for y in range(x + 1, len(clusters)):
                a, b = clusters[x], clusters[y]
                level = sum(sim[i][j] for i in a for j in b) / (len(a) * len(b))
                key = (level, -min(min(a), min(b)), -max(min(a), min(b)))
                if best is None or key > best[0]:
                    best = (key, x, y)
        (level, _lo, _hi), x, y = best
        a, b = clusters[x], clusters[y]
        merges.append((min(min(a), min(b)), max(min(a), min(b)), level))
        clusters[x] = sorted(a + b)
        del clusters[y]
    return merges


def _check_against_naive(names, ties, weights=None, weighting="presence"):
    sub, _ids = _sub(names, ties, weights=weights)
    _verts, rels, _w, _u = rege.build_values(sub, weighting)
    got, rounds, _conv, _change = rege.rege_matrix([r[2] for r in rels])
    _order, mats = _naive_relations(names, ties, weights, weighting)
    for mine, theirs in zip([r[2] for r in rels], mats, strict=True):
        assert numpy.allclose(mine, numpy.array(theirs), rtol=0, atol=1e-12)
    want, want_rounds = _naive_rege(mats)
    assert rounds == want_rounds
    assert got == pytest.approx(want, abs=1e-12)
    return got


# --------------------------------------------------------------------------
# Textbook shapes
# --------------------------------------------------------------------------

_STAR = ["hub", "l1", "l2", "l3", "l4"]


def _star(etype):
    return [("hub", etype, x) for x in ("l1", "l2", "l3", "l4")]


def test_a_directed_star_is_a_hub_and_its_leaves():
    _check_against_naive(_STAR, _star("VOUCHED_FOR"))
    out = _run(_sub(_STAR, _star("VOUCHED_FOR"))[0])
    assert _roles(out) == [{"l1", "l2", "l3", "l4"}, {"hub"}]
    g = out["rege"]
    assert g["similarity"][0][1] == 0.0 and g["roles"][0]["cohesion"] == 1.0
    # The leaves' role receives from the hub's in every member: a regular
    # block one way and nothing back.
    assert g["density"]["positive"][1][0] == 1.0 and g["regular"]["positive"][1][0] == 1
    assert g["density"]["positive"][0][1] == 0.0 and g["regular"]["positive"][0][1] == 0
    assert g["image"]["positive"][1][0] == 1


def test_an_undirected_star_is_one_role_and_the_card_says_why():
    """On ties of one kind with no direction every tied entity is regularly
    equivalent: the right answer, and a useless one, so it is said."""
    _check_against_naive(_STAR, _star("COMMUNICATES_WITH"))
    out = _run(_sub(_STAR, _star("COMMUNICATES_WITH"))[0])
    g = out["rege"]
    assert _roles(out) == [set(_STAR)]
    assert g["roles_found"] == 1 and g["cut"]["fewer_than_asked"] is True
    assert g["rounds"] == 1 and g["converged"] is True
    assert any("no direction" in t for t in g["limits"])


_CHAIN = ["a", "b", "c", "d", "e"]


def test_a_directed_chain_separates_its_source_and_its_sink():
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(_CHAIN, _CHAIN[1:], strict=False)]
    sim = _check_against_naive(_CHAIN, ties)
    assert sim[0, 4] == 0.0             # nothing sent against nothing received
    out = _run(_sub(_CHAIN, ties)[0], roles=3)
    assert _roles(out) == [{"b", "c", "d"}, {"a"}, {"e"}]
    # Three rounds look three steps along a chain: the interior is alike
    # but not identical, so the approximation is said.
    assert out["rege"]["converged"] is False
    assert "stopped after 3 rounds" in out["rege"]["limits"][0]
    # Three asked, three found: nothing was joined that the number did not
    # ask for. (Only the two "fewer" cases said so before, which a constant
    # True also passes: 2026-10-02.)
    assert out["rege"]["roles_found"] == 3
    assert out["rege"]["cut"]["fewer_than_asked"] is False


def test_asking_for_more_roles_than_there_are_entities_is_not_fewer_than_asked():
    """Three entities, eight roles asked: three roles is every one there can
    be, so the card must not say the cut fell short."""
    names = ["a", "b", "c"]
    out = _run(_sub(names, [("a", "VOUCHED_FOR", "b"), ("b", "VOUCHED_FOR", "c")])[0],
               roles=8)
    assert out["rege"]["roles_found"] == 3
    assert out["rege"]["cut"]["fewer_than_asked"] is False


def test_a_role_reports_how_alike_its_members_are_on_average_and_at_the_least():
    """The chain's interior is alike but not identical, so the mean and the
    least differ: a `least_alike` that was the mean, or the greatest, passed
    every test that held a role of one or of identical members (2026-10-02)."""
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(_CHAIN, _CHAIN[1:], strict=False)]
    sim = _check_against_naive(_CHAIN, ties)
    out = _run(_sub(_CHAIN, ties)[0], roles=3)
    interior = next(r for r in out["rege"]["roles"] if r["size"] == 3)
    assert {m["label"] for m in interior["members"]} == {"b", "c", "d"}
    pairs = [sim[1, 2], sim[1, 3], sim[2, 3]]
    assert min(pairs) < sum(pairs) / 3 < 1.0
    assert interior["cohesion"] == pytest.approx(sum(pairs) / 3, abs=1e-6)
    assert interior["least_alike"] == pytest.approx(min(pairs), abs=1e-6)
    # And each member's fit is its mean similarity to the other two.
    rows = {n["label"]: n for n in out["nodes"]}
    assert rows["b"]["fit"] == pytest.approx((sim[1, 2] + sim[1, 3]) / 2, abs=1e-6)
    assert rows["c"]["fit"] == pytest.approx((sim[1, 2] + sim[2, 3]) / 2, abs=1e-6)
    assert rows["d"]["fit"] == pytest.approx((sim[1, 3] + sim[2, 3]) / 2, abs=1e-6)
    assert rows["b"]["fit"] != rows["c"]["fit"]


_TWO_MODE = {"F": "FORUM", "G": "FORUM"}


def test_actors_and_forums_actors_alike_by_kind_not_by_venue():
    """i0 and i1 post on F, i2 and i3 on G, i0 on both: CONCOR's structural
    equivalence splits them by forum; every one of them posts on a forum,
    so regular equivalence puts them in one role, and the forums take part
    without being placed."""
    names = ["i0", "i1", "i2", "i3", "F", "G"]
    ties = [("i0", "POSTS_ON", "F"), ("i1", "POSTS_ON", "F"), ("i2", "POSTS_ON", "G"),
            ("i3", "POSTS_ON", "G"), ("i0", "POSTS_ON", "G")]
    _check_against_naive(names, ties)
    out = _run(_sub(names, ties, _TWO_MODE)[0])
    assert _roles(out) == [{"i0", "i1", "i2", "i3"}]
    assert out["rege"]["profile_only"] == {"count": 2, "types": ["FORUM"]}
    # Two of them also vouch for each other: now two kinds of poster.
    more = ties + [("i1", "VOUCHED_FOR", "i2"), ("i2", "VOUCHED_FOR", "i1")]
    _check_against_naive(names, more)
    out = _run(_sub(names, more, _TWO_MODE)[0], roles=2)
    assert _roles(out) == [{"i0", "i3"}, {"i1", "i2"}]


_WF = list("ABCDEFGHI")
_WF_TIES = [(p, "VOUCHED_FOR", c) for p, c in
            ("AB", "AC", "AD", "BE", "BF", "CG", "DH", "DI")]


def test_wasserman_and_fausts_hierarchy_cuts_into_its_three_levels():
    _check_against_naive(_WF, _WF_TIES)
    out = _run(_sub(_WF, _WF_TIES)[0], roles=4)
    g = out["rege"]
    assert _roles(out) == [set("EFGHI"), set("BCD"), {"A"}]
    # Asked for four: perfectly alike entities are never split to make up
    # the number, so three, and the payload says so.
    assert g["roles_asked"] == 4 and g["roles_found"] == 3
    assert g["cut"]["fewer_than_asked"] is True and g["cut"]["held_at"] == 1.0
    assert 0 < g["cut"]["next_merge"] < 1
    out = _run(_sub(_WF, _WF_TIES)[0], roles=2)
    assert _roles(out) == [set("EFGHI"), set("ABCD")]


def test_the_weighting_can_change_the_roles_and_each_says_so():
    """Two hubs with two leaves each, one hub's ties five times the other's.
    Counted as present they are one kind of hub; counted by weight a weak
    tie only partly matches a strong one."""
    names = ["H1", "H2", "a", "b", "c", "d"]
    ties = [("H1", "VOUCHED_FOR", "a"), ("H1", "VOUCHED_FOR", "b"),
            ("H2", "VOUCHED_FOR", "c"), ("H2", "VOUCHED_FOR", "d")]
    weights = {2: 5.0, 3: 5.0}
    _check_against_naive(names, ties, weights, "weight")
    sub = _sub(names, ties, weights=weights)[0]
    present = _run(sub, weighting="presence")
    weighted = _run(sub, weighting="weight")
    assert _roles(present) == [{"a", "b", "c", "d"}, {"H1", "H2"}]
    assert present["rege"]["similarity"][1][1] == 1.0
    assert _roles(weighted) == [{"a", "b"}, {"c", "d"}, {"H1"}, {"H2"}]
    # A third of a match after one round, and each round multiplies in how
    # alike the leaves were the round before: (1/3) cubed after three.
    assert weighted["rege"]["similarity"][2][3] == pytest.approx(1 / 27, abs=1e-6)
    assert "Ties count as present or absent." in present["rege"]["limits"][1]
    assert "Ties count by weight" in weighted["rege"]["limits"][1]
    assert weighted["rege"]["weighting"] == "weight"


def test_a_tie_with_no_positive_weight_counts_as_absent_by_weight_and_is_counted():
    names = ["H1", "H2", "a", "b"]
    ties = [("H1", "VOUCHED_FOR", "a"), ("H2", "VOUCHED_FOR", "b"),
            ("H2", "VOUCHED_FOR", "a")]
    sub = _sub(names, ties, weights={2: 0.0})[0]
    weighted = _run(sub, weighting="weight")
    assert weighted["rege"]["weightless_ties"] == 1
    # By weight H2 sends to b alone, as H1 sends to a alone: alike.
    assert _roles(weighted)[1] == {"H1", "H2"}
    assert _run(sub)["rege"]["weightless_ties"] == 0
    _check_against_naive(names, ties, {2: 0.0}, "weight")
    # Every entity here still has a counted tie, so none is called alike for
    # having nothing to match, and the card has no such sentence to print.
    assert weighted["rege"]["weightless_entities"] == 0
    assert not any("none that count by weight" in t for t in weighted["rege"]["limits"])


def test_entities_left_with_no_counted_tie_are_one_role_and_the_card_says_so():
    """x -> y -> z carry no positive weight, h sends to a, b and c with weight
    one. Counted by weight x, y and z have nothing to match, so they are alike
    one another (the zero-denominator rule) and come out as one role of
    cohesion 1: a perfect role that says nothing. The first card printed the
    count of weightless ties and not this (2026-10-02)."""
    names = ["x", "y", "z", "h", "a", "b", "c"]
    ties = [("x", "VOUCHED_FOR", "y"), ("y", "VOUCHED_FOR", "z"),
            ("h", "VOUCHED_FOR", "a"), ("h", "VOUCHED_FOR", "b"), ("h", "VOUCHED_FOR", "c")]
    sub = _sub(names, ties, weights={0: 0.0, 1: 0.0})[0]
    weighted = _run(sub, roles=4, weighting="weight")["rege"]
    assert {"x", "y", "z"} in [{m["label"] for m in r["members"]} for r in weighted["roles"]]
    held = next(r for r in weighted["roles"] if {m["label"] for m in r["members"]} == set("xyz"))
    assert held["cohesion"] == 1.0 and held["least_alike"] == 1.0
    assert weighted["weightless_ties"] == 2 and weighted["weightless_entities"] == 3
    said = [t for t in weighted["limits"] if "none that count by weight" in t]
    assert said == ["3 entities have ties but none that count by weight. With nothing to "
                    "match, they are all called alike and share one role: that says nothing "
                    "about how they sit in this view."]
    # One such entity: p's only tie carries no weight, q still has a counted
    # one. It is told so in the singular and is not called "all alike".
    lone = _sub(["p", "q", "r"], [("p", "VOUCHED_FOR", "q"), ("q", "VOUCHED_FOR", "r")],
                weights={0: 0.0})[0]
    single = _run(lone, roles=2, weighting="weight")["rege"]
    assert single["weightless_entities"] == 1
    assert [t for t in single["limits"] if "none that count by weight" in t] == [
        "1 entity has ties but none that count by weight, so it has nothing to match: the "
        "role it falls in says nothing about how it sits in this view."]
    # Counted as present every tie counts, so no entity is ever left without one.
    assert _run(sub, roles=4)["rege"]["weightless_entities"] == 0
    assert not any("none that count by weight" in t for t in _run(sub)["rege"]["limits"])


# --------------------------------------------------------------------------
# The role-to-role blocks: density, tied, regular
# --------------------------------------------------------------------------
#
# The star's only blocks are fully dense or fully empty, which every reading
# of "tied" and of "regular" agrees on. These hold the blocks in between: a
# threshold and a regularity test the star cannot tell apart from a wrong
# one (2026-10-02).

def test_a_chain_has_tied_blocks_that_are_not_regular():
    """Source, interior and sink of a chain of five. Three blocks hold a
    third of the ties they could (more than the view's 0.2, so tied) and none
    is regular: the interior's last member sends nothing into the interior,
    and its middle one receives nothing from the source."""
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(_CHAIN, _CHAIN[1:], strict=False)]
    g = _run(_sub(_CHAIN, ties)[0], roles=3)["rege"]
    assert [[m["label"] for m in r["members"]] for r in g["roles"]] == [
        ["b", "c", "d"], ["a"], ["e"]]
    third = pytest.approx(1 / 3, abs=1e-6)
    assert g["alpha"]["positive"] == pytest.approx(0.2, abs=1e-6)
    assert g["density"]["positive"] == [[third, 0.0, third], [third, None, 0.0],
                                        [0.0, 0.0, None]]
    assert g["image"]["positive"] == [[1, 0, 1], [1, 0, 0], [0, 0, 0]]
    assert g["regular"]["positive"] == [[0, 0, 0], [0, 0, 0], [0, 0, 0]]


def test_a_block_with_some_but_not_all_of_its_ties_can_be_regular():
    """Two sources each feeding two of four sinks: half the ties the block
    could hold, and every source sends and every sink receives."""
    names = ["s1", "s2", "t1", "t2", "t3", "t4"]
    ties = [("s1", "VOUCHED_FOR", "t1"), ("s1", "VOUCHED_FOR", "t2"),
            ("s2", "VOUCHED_FOR", "t3"), ("s2", "VOUCHED_FOR", "t4")]
    g = _run(_sub(names, ties)[0], roles=2)["rege"]
    assert [[m["label"] for m in r["members"]] for r in g["roles"]] == [
        ["t1", "t2", "t3", "t4"], ["s1", "s2"]]
    assert g["alpha"]["positive"] == pytest.approx(4 / 30, abs=1e-6)
    assert g["density"]["positive"] == [[0.0, 0.0], [0.5, 0.0]]
    assert g["image"]["positive"] == [[0, 0], [1, 0]]
    assert g["regular"]["positive"] == [[0, 0], [1, 0]]


def test_a_block_exactly_as_dense_as_the_view_is_tied():
    """A directed ring of four is one role holding a third of the ordered
    pairs, the view's own density: tied counts the equal case, which only
    `>=` does."""
    ring = ["a", "b", "c", "d"]
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(ring, ring[1:] + ring[:1], strict=True)]
    g = _run(_sub(ring, ties)[0], roles=2)["rege"]
    assert g["roles_found"] == 1
    assert g["alpha"]["positive"] == pytest.approx(1 / 3, abs=1e-6)
    assert g["density"]["positive"] == [[pytest.approx(1 / 3, abs=1e-6)]]
    assert g["image"]["positive"] == [[1]] and g["regular"]["positive"] == [[1]]


def test_ties_only_to_venues_mark_no_block_tied():
    """No tie joins two entities, so the view's density is zero and every
    block's is too: zero is not "at least zero". A venue is not an entity."""
    names = ["i0", "i1", "F"]
    ties = [("i0", "POSTS_ON", "F"), ("i1", "POSTS_ON", "F")]
    g = _run(_sub(names, ties, {"F": "FORUM"})[0])["rege"]
    (key,) = g["density"]
    assert g["alpha"][key] == 0.0
    assert g["density"][key] == [[0.0]]
    assert g["image"][key] == [[0]] and g["regular"][key] == [[0]]


def _close(got, want, tol=1e-6) -> bool:
    """Equal as nested lists and dicts, numbers within `tol`, None only to
    None (pytest.approx takes neither a None nor a list of lists)."""
    if isinstance(want, dict):
        return got.keys() == want.keys() and all(_close(got[k], want[k], tol) for k in want)
    if isinstance(want, list):
        return len(got) == len(want) and all(_close(g, w, tol) for g, w in zip(got, want, strict=True))
    if want is None or got is None:
        return got is None and want is None
    return abs(got - want) <= tol


def _blocks_by_hand(names, ties, out):
    """Alpha, density, image and regular, and the role-to-role mean
    similarity, recomputed from the payload's own roles with plain loops over
    the tie list and the reference REGE, sharing no code with the module."""
    groups = [[m["label"] for m in r["members"]] for r in out["rege"]["roles"]]
    actors = [n for g in groups for n in g]
    k = len(actors)
    cells: dict[str, set] = {}
    for s, et, t in ties:
        sign = _ET[et].default_sign
        key = "positive" if sign > 0 else ("negative" if sign < 0 else "neutral")
        have = cells.setdefault(key, set())
        have.add((s, t))
        if not _ET[et].is_directed:
            have.add((t, s))
    order, mats = _naive_relations(names, ties)
    sim = _naive_rege(mats)[0]
    at = {n: i for i, n in enumerate(order)}
    want = {"alpha": {}, "density": {}, "image": {}, "regular": {}}
    for key, have in cells.items():
        among = {(u, v) for (u, v) in have if u in actors and v in actors and u != v}
        alpha = len(among) / (k * (k - 1))
        want["alpha"][key] = alpha
        dens, img, reg = [], [], []
        for gx in groups:
            drow, irow, rrow = [], [], []
            for gy in groups:
                pairs = [(u, v) for u in gx for v in gy if u != v]
                d = (sum(1 for p in pairs if p in among) / len(pairs)) if pairs else None
                drow.append(d)
                irow.append(int(d is not None and d > 0 and d >= alpha - 1e-12))
                rrow.append(int(bool(pairs)
                                and all(any((u, v) in among for v in gy if v != u) for u in gx)
                                and all(any((u, v) in among for u in gx if u != v)
                                        for v in gy)))
            dens.append(drow)
            img.append(irow)
            reg.append(rrow)
        want["density"][key], want["image"][key], want["regular"][key] = dens, img, reg
    similarity = []
    for x, gx in enumerate(groups):
        row = []
        for y, gy in enumerate(groups):
            vals = [sim[at[u], at[v]] for u in gx for v in gy if x != y or u != v]
            row.append(sum(vals) / len(vals) if vals else None)
        similarity.append(row)
    return want, similarity


@pytest.mark.parametrize("seed", range(10))
def test_the_blocks_agree_with_a_recomputation_from_the_roles(seed):
    names, ties, _weights = _random_world(300 + seed, n=9, density=0.28)
    sub, _ids = _sub(names, ties)
    out = _run(sub, roles=3)
    want, similarity = _blocks_by_hand(names, ties, out)
    g = out["rege"]
    for part in ("alpha", "density"):
        assert _close(g[part], want[part]), (seed, part, g[part], want[part])
    assert g["image"] == want["image"] and g["regular"] == want["regular"], seed
    assert _close(g["similarity"], similarity), (seed, g["similarity"], similarity)


def test_the_random_worlds_hold_every_kind_of_block_the_flags_can_tell_apart():
    """The recomputation test is only as good as the blocks it sees: across
    its worlds there must be partly dense blocks that are regular, partly
    dense blocks that are not, tied ones that are not regular and regular
    ones that are not tied."""
    seen = set()
    for seed in range(10):
        names, ties, _weights = _random_world(300 + seed, n=9, density=0.28)
        g = _run(_sub(names, ties)[0], roles=3)["rege"]
        for key in g["density"]:
            for dr, ir, rr in zip(g["density"][key], g["image"][key], g["regular"][key],
                                  strict=True):
                for d, i, r in zip(dr, ir, rr, strict=True):
                    if d is not None and 0 < d < 1:
                        seen.add(("partial", bool(r), bool(i)))
    assert {("partial", True, True), ("partial", False, True),
            ("partial", False, False)} <= seen, seen


# --------------------------------------------------------------------------
# Random graphs, both weightings, both kernel paths, chunks of one row
# --------------------------------------------------------------------------

_KINDS = ["VOUCHED_FOR", "ACCUSED_SCAM", "POSTS_ON", "COMMUNICATES_WITH", "RIVAL_OF"]


def _random_world(seed, n=8, density=0.3):
    rng = random.Random(seed)
    names = [f"v{i}" for i in range(n)]
    ties, weights = [], {}
    for a in names:
        for b in names:
            if a != b and rng.random() < density:
                weights[len(ties)] = float(rng.randint(1, 4))
                ties.append((a, rng.choice(_KINDS), b))
    return names, ties, weights


@pytest.mark.parametrize("seed", range(8))
def test_random_graphs_agree_with_the_reference_counting_presence(seed):
    names, ties, _weights = _random_world(seed)
    _check_against_naive(names, ties)


@pytest.mark.parametrize("seed", range(8))
def test_random_graphs_agree_with_the_reference_counting_weight(seed):
    names, ties, weights = _random_world(100 + seed)
    _check_against_naive(names, ties, weights, "weight")


@pytest.mark.parametrize("seed", range(3))
def test_the_kernel_computed_per_chunk_agrees_too(monkeypatch, seed):
    """The table is skipped above PATTERN_TABLE_MAX patterns; forced here,
    with chunks of a single comparison row."""
    monkeypatch.setattr(rege, "PATTERN_TABLE_MAX", 0)
    monkeypatch.setattr(rege, "CHUNK_ELEMENTS", 1)
    names, ties, weights = _random_world(200 + seed, n=7)
    _check_against_naive(names, ties, weights, "weight")
    _check_against_naive(names, ties)


@pytest.mark.parametrize("seed", range(4))
def test_average_linkage_agrees_with_the_brute_force_one(seed):
    rng = numpy.random.default_rng(seed)
    k = 12
    x = rng.random((k, k))
    sim = (x + x.T) / 2
    numpy.fill_diagonal(sim, 1.0)
    got = rege.average_linkage(sim)
    want = _naive_linkage(sim.tolist())
    assert [(a, b) for a, b, _ in got] == [(a, b) for a, b, _ in want]
    assert [lv for _, _, lv in got] == pytest.approx([lv for _, _, lv in want], abs=1e-12)


def test_average_linkage_breaks_ties_by_the_vertices_order():
    sim = numpy.ones((5, 5))
    sim[3, 4] = sim[4, 3] = 0.5
    assert rege.average_linkage(sim) == [(0, 1, 1.0), (0, 2, 1.0), (0, 3, 1.0),
                                         (0, 4, 0.875)]
    assert rege.average_linkage(sim) == _naive_linkage(sim.tolist())


def test_the_cut_never_splits_alike_entities_or_falls_inside_a_level():
    merges = [(0, 1, 1.0), (2, 3, 0.8), (4, 5, 0.8), (0, 2, 0.5), (0, 4, 0.2)]
    # Asked for five of six: (0, 1) are perfectly alike, so they join.
    assert rege.cut_point(merges, 6, 5) == 1
    # Asked for four: the cut would fall between two merges at 0.8.
    assert rege.cut_point(merges, 6, 4) == 3
    assert rege.cut_point(merges, 6, 3) == 3
    assert rege.cut_point(merges, 6, 2) == 4
    assert rege.groups(merges, 6, 3) == [[0, 1], [2, 3], [4, 5]]
    # More roles than entities: each alone, unless perfectly alike.
    assert rege.cut_point([(0, 1, 0.3)], 2, 8) == 0
    assert rege.cut_point([(0, 1, 1.0)], 2, 8) == 1


def test_the_linkage_searches_few_rows_again_when_every_similarity_is_one(monkeypatch):
    """Every row's best partner is the pair just merged; searching every
    such row again made a 1,000-entity undirected view take eleven seconds
    in the cut alone. Counted through the one place rows are re-searched."""
    searched = []
    real = numpy.nonzero

    def counting(a, *args, **kw):
        out = real(a, *args, **kw)
        searched.append(len(out[0]))
        return out

    k = 60
    sim = numpy.ones((k, k))
    monkeypatch.setattr(rege.numpy, "nonzero", counting)
    merges = rege.average_linkage(sim)
    monkeypatch.undo()
    assert [m[:2] for m in merges] == [(0, j) for j in range(1, k)]
    assert sum(searched) <= 2 * k, sum(searched)       # was about k * k / 2


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------

def test_the_answer_does_not_depend_on_row_order():
    """Real ids are random, so the same graph can arrive with its rows in any
    order and its ids in no order at all: ids are random here, and only the
    rows move."""
    ties = _WF_TIES + [("E", "ACCUSED_SCAM", "G"), ("H", "COMMUNICATES_WITH", "I")]
    base = _run(_sub(_WF, ties, uuid_seed=7)[0], roles=4)
    for seed in (1, 2, 3, 4):
        again = _run(_sub(_WF, ties, uuid_seed=7, seed=seed)[0], roles=4)
        assert again["rege"] == base["rege"] and again["nodes"] == base["nodes"]


def test_the_vertices_are_taken_in_id_order_not_in_the_order_a_set_holds_them():
    """The step that makes the answer a function of the graph: the entities
    are sorted by id. With ids that ascend with the names a set iterates in
    that order anyway, so a fixture of them cannot see the step go missing
    (2026-10-02); with random ones it does, and the
    precondition says so."""
    ring = [f"v{i}" for i in range(14)]
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(ring, ring[1:] + ring[:1], strict=True)]
    sub, _ids = _sub(ring, ties, uuid_seed=3)
    held = {n["id"] for n in sub.nodes}
    assert list(held) != sorted(held, key=str), "the fixture cannot tell the two orders apart"
    verts, _rels, _weightless, _usable = rege.build_values(sub)
    assert verts == sorted(verts, key=str)


def test_a_cell_summed_from_parallel_ties_is_exact_whatever_the_order(monkeypatch):
    """Counted by weight a cell is the sum of its ties' weights, and the ties
    arrive in any order. Added one after another, 0.1, 0.2 and 0.3 make
    0.6000000000000001 in that order and 0.6 in the other; every order must
    give the exact sum, bit for bit, and through `math.fsum`. Since Python
    3.12 the built-in `sum` compensates too and agrees with `fsum` on every
    positive list tried, so a value check cannot tell the two apart: the call
    is pinned as well. (The test that stood here summed single ties, so any
    sum passed: 2026-10-02.)"""
    def one_by_one(values):
        total = 0.0
        for v in values:
            total += v
        return total

    assert one_by_one([0.1, 0.2, 0.3]) != one_by_one([0.3, 0.2, 0.1])
    exact = math.fsum([0.1, 0.2, 0.3])
    summed = []
    real = math.fsum
    monkeypatch.setattr(rege.math, "fsum", lambda values: summed.append(list(values))
                        or real(values))
    for order in ([0.1, 0.2, 0.3], [0.3, 0.2, 0.1], [0.2, 0.3, 0.1]):
        ties = [("a", "VOUCHED_FOR", "b")] * 3
        sub = _sub(["a", "b"], ties, weights=dict(enumerate(order)))[0]
        _verts, rels, _weightless, _usable = rege.build_values(sub, "weight")
        assert rels[0][2][0, 1] == exact, order
        assert rels[0][3] == 3
        assert order in summed, "the cell was not summed by math.fsum"


def test_a_weighted_answer_does_not_depend_on_the_order_ties_are_summed():
    """With parallel ties in some cells, so there is something to sum."""
    names, ties, _ = _random_world(7, n=9)
    ties = ties + [(s, et, t) for s, et, t in ties[::2]] + [(s, et, t) for s, et, t in ties[::3]]
    weights = {k: 0.1 * (k % 7) + 0.3 for k in range(len(ties))}
    base = _run(_sub(names, ties, weights=weights)[0], weighting="weight")
    for seed in (5, 6):
        again = _run(_sub(names, ties, weights=weights, seed=seed)[0], weighting="weight")
        assert again["rege"] == base["rege"] and again["nodes"] == base["nodes"]


def test_equally_good_cuts_depend_on_the_ids_and_the_card_says_so():
    """A chain of seven cut into two roles has two cuts exactly as good as
    each other, and which one is returned follows the entities' ids: the same
    structure under another assignment is cut the other way. Fixed for a
    graph, not for a structure, and the limits say exactly that (2026-10-02: docs/03 had
    said the same graph always gives the same
    roles, which reads as the same structure)."""
    chain = list("abcdefg")
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(chain, chain[1:], strict=False)]
    cuts = set()
    for uuid_seed in range(12):
        out = _run(_sub(chain, ties, uuid_seed=uuid_seed)[0], roles=2)
        cuts.add(tuple(sorted(tuple(sorted(r)) for r in _roles(out))))
        # Whatever the ids, the same ids give the same cut.
        again = _run(_sub(chain, ties, uuid_seed=uuid_seed)[0], roles=2)
        assert again["rege"] == out["rege"]
    assert len(cuts) > 1, "the same structure was cut one way under every id assignment"
    limits = _payload()["rege"]["limits"]
    said = [t for t in limits if "internal identifiers" in t]
    assert len(said) == 1
    assert "not on the structure" in said[0]
    assert "The same graph always gives the same roles" in said[0]


def test_two_processes_with_different_hash_seeds_give_the_same_payload():
    code = ("import json, test_rege as t; "
            "out = t._run(t._sub(t._WF, t._WF_TIES)[0], roles=3); "
            "out.pop('engine'); print(json.dumps(out, sort_keys=True, default=str))")
    here = os.path.dirname(os.path.abspath(__file__))
    outs = []
    for seed in ("1", "2"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        env["PYTHONPATH"] = here + os.pathsep + env.get("PYTHONPATH", "")
        res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             env=env, timeout=120, cwd=here)
        assert res.returncode == 0, res.stderr
        outs.append(res.stdout)
    assert outs[0] == outs[1]


# --------------------------------------------------------------------------
# Refusals
# --------------------------------------------------------------------------

def test_the_entity_cap_refuses_before_any_matrix_is_allocated(monkeypatch):
    monkeypatch.setattr(rege, "REGE_MAX_NODES", 3)
    calls = []
    real = numpy.zeros
    monkeypatch.setattr(rege.numpy, "zeros", lambda *a, **kw: calls.append(a) or real(*a, **kw))
    with pytest.raises(AnalyticsError, match="regular equivalence is capped at 3 entities "
                                             "with ties; this view has 5. Narrow"):
        _run(_sub(_STAR, _star("VOUCHED_FOR"))[0])
    assert calls == []


def test_the_pairs_cap_refuses_and_names_itself(monkeypatch):
    monkeypatch.setattr(rege, "REGE_MAX_PAIRS", 3)
    ties = _star("VOUCHED_FOR") + [("l1", "COMMUNICATES_WITH", "hub")]
    with pytest.raises(AnalyticsError, match="capped at 3 tied pairs; this view has 4"):
        rege.precheck(_sub(_STAR, ties)[0])


def _directions_text(cap: int, directions: int, ties: int) -> str:
    """The ties-cap refusal as the analyst reads it, escaped for `match`."""
    return re.escape(
        f"capped at {cap} tie directions (a tie with no direction runs both ways, and ties "
        f"of one kind repeating one direction between two entities count once); this view "
        f"has {directions}, from {ties} ties. Narrow the view first.")


@pytest.mark.parametrize("name, at, over, text", [
    ("REGE_MAX_NODES", 5, 4, "capped at 4 entities with ties; this view has 5"),
    ("REGE_MAX_PAIRS", 4, 3, "capped at 3 tied pairs; this view has 4"),
    ("REGE_MAX_TIES", 4, 3, _directions_text(3, 4, 4))],
    ids=["entities", "pairs", "tie-directions"])
def test_each_cap_admits_exactly_its_limit_and_refuses_one_more(monkeypatch, name, at, over,
                                                               text):
    """The refusals read `>`, so a view AT a cap is computed and one over is
    refused: a `>=` would refuse the view the cap names (2026-10-02)."""
    sub = _sub(_STAR, _star("VOUCHED_FOR"))[0]           # five entities, four pairs, four ties
    monkeypatch.setattr(rege, name, at)
    rege.precheck(sub)
    assert _roles(_run(sub)) == [{"l1", "l2", "l3", "l4"}, {"hub"}]
    monkeypatch.setattr(rege, name, over)
    with pytest.raises(AnalyticsError, match=text):
        rege.precheck(sub)


def test_a_tie_with_no_direction_fills_two_directions_of_the_ties_cap(monkeypatch):
    """The same four pairs as an undirected star hold eight directions, one
    for each way each tie runs: a cap of eight admits it and seven refuses it,
    where a directed star of four ties is under both (2026-10-02: cost follows the cells a
    round reads, and a tie both ways
    is two of them)."""
    sub = _sub(_STAR, _star("COMMUNICATES_WITH"))[0]
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 8)
    rege.precheck(sub)
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 7)
    with pytest.raises(AnalyticsError, match=_directions_text(7, 8, 4)):
        rege.precheck(sub)
    rege.precheck(_sub(_STAR, _star("VOUCHED_FOR"))[0])


def test_the_ties_cap_is_checked_after_the_entity_and_pair_caps_and_before_any_matrix(
        monkeypatch):
    """A view over every cap names the entities first, as before, and a view
    over the ties cap alone is refused before any matrix is allocated."""
    sub = _sub(_STAR, _star("VOUCHED_FOR") + _star("ACCUSED_SCAM"))[0]
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 7)
    calls = []
    real = numpy.zeros
    monkeypatch.setattr(rege.numpy, "zeros", lambda *a, **kw: calls.append(a) or real(*a, **kw))
    with pytest.raises(AnalyticsError, match="capped at 7 tie directions"):
        _run(sub)
    assert calls == []
    monkeypatch.setattr(rege, "REGE_MAX_NODES", 3)
    monkeypatch.setattr(rege, "REGE_MAX_PAIRS", 2)
    with pytest.raises(AnalyticsError, match="capped at 3 entities"):
        rege.precheck(sub)
    monkeypatch.setattr(rege, "REGE_MAX_NODES", 1000)
    with pytest.raises(AnalyticsError, match="capped at 2 tied pairs"):
        rege.precheck(sub)


def test_the_caps_as_shipped_are_the_ones_the_docs_state():
    """1,000 entities with ties, 2,500 tied pairs and 5,000 tie directions
    (docs/03, decision 157), by the shipped constants and not a patched copy:
    a view at each passes the precheck and one over is refused. Nothing is
    computed here. And the docs are read, so a number edited on either side
    alone fails (2026-10-03: this test pinned the constants
    only and never opened the page it is named for)."""
    names = [f"v{i}" for i in range(75)]
    every = [(names[i], "VOUCHED_FOR", names[j]) for i in range(75) for j in range(i + 1, 75)]
    rege.precheck(_sub(names, every[:2500])[0])
    with pytest.raises(AnalyticsError, match="capped at 2500 tied pairs; this view has 2501"):
        rege.precheck(_sub(names, every[:2501])[0])
    chain = [f"c{i}" for i in range(1001)]
    ties = [(x, "VOUCHED_FOR", y) for x, y in zip(chain, chain[1:], strict=False)]
    rege.precheck(_sub(chain[:1000], ties[:999])[0])
    with pytest.raises(AnalyticsError, match="capped at 1000 entities with ties; this view "
                                             "has 1001"):
        rege.precheck(_sub(chain, ties)[0])
    # Each of 2,500 pairs vouched for both ways is 5,000 directions; one
    # direction more (an accusation on a pair) is over, with the pairs still
    # at their cap.
    both = [tie for (a, e, b) in every[:2500] for tie in ((a, e, b), (b, e, a))]
    rege.precheck(_sub(names, both)[0])
    with pytest.raises(AnalyticsError, match=_directions_text(5000, 5001, 5001)):
        rege.precheck(_sub(names, both + [(every[0][0], "ACCUSED_SCAM", every[0][2])])[0])
    # Pinned to the page: the docs state the shipped numbers, in their words.
    docs = Path(__file__).resolve().parents[3] / "docs" / "03-graph-analytics.md"
    page = " ".join(docs.read_text(encoding="utf-8").split())
    stated = (f"Capped at {rege.REGE_MAX_NODES:,} entities with ties, "
              f"{rege.REGE_MAX_PAIRS:,} tied pairs and {rege.REGE_MAX_TIES:,} tie directions")
    assert stated in page, f"docs/03 does not say: {stated}"


def test_parallel_ties_fill_one_direction_of_the_ties_cap(monkeypatch):
    """Ties repeating a cell (the same kind of tie in the same direction
    between the same two entities) collapse into one before any round runs,
    so they are one direction, not many (2026-10-03: the cap
    counted tie rows, and a one-mode view has one derived tie per pair and
    venue). The star of four has four directions however often each is
    repeated; a reverse tie, another kind of tie, or another pair is a new
    one."""
    star = _star("VOUCHED_FOR")
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 4)
    rege.precheck(_sub(_STAR, star * 5)[0])                     # 20 ties, 4 directions
    reverse = [(t, "VOUCHED_FOR", "hub") for _h, _e, t in star]
    for extra in (reverse, _star("ACCUSED_SCAM"), [("l1", "VOUCHED_FOR", "l2")]):
        with pytest.raises(AnalyticsError, match=_directions_text(4, 5 if len(extra) == 1 else 8,
                                                                  len(star * 5 + extra))):
            rege.precheck(_sub(_STAR, star * 5 + extra)[0])
    # An undirected tie is two directions, and a directed tie that repeats
    # one of them adds none: COMMUNICATES_WITH and VOUCHED_FOR are both
    # positive.
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 2)
    rege.precheck(_sub(["a", "b"], [("a", "COMMUNICATES_WITH", "b"), ("b", "VOUCHED_FOR", "a"),
                                    ("a", "VOUCHED_FOR", "b"), ("b", "COMMUNICATES_WITH", "a")])[0])
    # What the cap counts is the cells the matrices hold, whatever the data.
    _tied, _usable, _pairs, directions = rege._usable(_sub(_STAR, star * 5)[0])
    assert directions == 4 and len(_usable) == 20


def test_directions_counted_are_the_cells_the_matrices_hold():
    """The cap's count is the nonzero cells `build_values` builds, to the
    number, over random views with parallel, reverse, undirected and
    weightless ties, counted by presence and by weight (a tie with no
    positive weight fills no cell by weight, and one by presence)."""
    types = ("VOUCHED_FOR", "ACCUSED_SCAM", "POSTS_ON", "COMMUNICATES_WITH", "RIVAL_OF",
             "SHARED_INFRA", "MEMBER_OF")
    for seed in range(25):
        rng = random.Random(seed)
        names = [f"n{i}" for i in range(rng.randint(3, 9))]
        ties, weights = [], {}
        for k in range(rng.randint(2, 60)):
            a, b = rng.sample(names, 2)
            ties.append((a, rng.choice(types), b))
            weights[k] = rng.choice([0.0, 0.0, 0.5, 1.0, 2.5])
        sub = _sub(names, ties, weights=weights)[0]
        for weighting in ("presence", "weight"):
            try:
                _verts, rels, _w, _u = rege.build_values(sub, weighting)
            except AnalyticsError:
                continue                    # no positive weight anywhere: refused, as it should be
            built = sum(int((mat > 0).sum()) for _k, _l, mat, _c in rels)
            assert rege._usable(sub, weighting)[3] == built, (seed, weighting)


def test_weightless_ties_fill_no_direction_when_counted_by_weight(monkeypatch):
    """Counted by weight a tie with no positive weight is absent, so it adds
    no cell; counted as present it adds one. The same view is admitted by
    weight where it is refused by presence, and never the other way."""
    ties = _star("VOUCHED_FOR") + [("l1", "VOUCHED_FOR", "l2"), ("l2", "VOUCHED_FOR", "l3")]
    sub = _sub(_STAR, ties, weights={4: 0.0, 5: 0.0})[0]
    monkeypatch.setattr(rege, "REGE_MAX_TIES", 4)
    rege.precheck(sub, weighting="weight")
    with pytest.raises(AnalyticsError, match=_directions_text(4, 6, 6)):
        rege.precheck(sub, weighting="presence")


def _crew_over_forums(entities: int, forums: int, seed: int = 3):
    """What a one-mode projection of `entities` identities all posting on
    `forums` forums hands the analysis: one derived undirected tie per pair
    and forum, carrying a venue weight (affiliation.py)."""
    rng = random.Random(seed)
    nodes = [{"id": UUID(int=900 + i), "label": f"e{i}", "node_type": "IDENTITY"}
             for i in range(entities)]
    edges = [{"id": None, "derived": True, "directed": False, "edge_type": "CO_POSTED_IN",
              "family": "forum", "src_node_id": nodes[i]["id"], "dst_node_id": nodes[j]["id"],
              "sign": 1, "weight": round(rng.uniform(0.1, 1.0), 3), "review": "ACCEPTED"}
             for i in range(entities) for j in range(i + 1, entities) for _ in range(forums)]
    return Subgraph(nodes, edges, truncated=False)


def test_a_close_knit_crew_over_many_forums_is_admitted_and_computed():
    """The view measured on 2026-10-03: 40 entities, every pair sharing the same 15
    forums, is 780 tied pairs, 11,700 derived ties (23,400 slots, over the
    5,000 cap when rows were counted) but 1,560 directions, and runs in a
    fraction of a second. Admitted by presence and by weight at the shipped
    caps; a view that really is over a cap is still refused."""
    sub = _crew_over_forums(40, 15)
    assert len(sub.edges) == 11700
    tied, _ties, pairs, directions = rege._usable(sub)
    assert (len(tied), pairs, directions) == (40, 780, 1560)
    assert 2 * len(sub.edges) > rege.REGE_MAX_TIES, "the rows alone are over the cap"
    for weighting in ("presence", "weight"):
        started = time.process_time()
        out = _run(sub, roles=4, weighting=weighting)
        assert time.process_time() - started < 5.5
        assert out["node_count"] == 40 and out["rege"]["relations"] == [
            {"key": "positive", "label": "positive ties", "ties": 11700}]
        assert 1 <= out["rege"]["roles_found"] <= 4
    # 100 entities all tied is 4,950 pairs: still over the PAIRS cap, whatever
    # the forums: the pairs and directions caps each still refuse.
    big = _crew_over_forums(100, 1)
    with pytest.raises(AnalyticsError, match="capped at 2500 tied pairs; this view has 4950"):
        rege.precheck(big)


def test_fewer_than_two_tied_entities_is_refused():
    sub, _ids = _sub(["i0", "F", "i9"], [("i0", "POSTS_ON", "F")], {"F": "FORUM"})
    with pytest.raises(AnalyticsError, match="at least two entities with ties"):
        _run(sub)
    with pytest.raises(AnalyticsError):
        rege.precheck(sub)


@pytest.mark.parametrize("roles", [1, 9, True, 2.0])
def test_a_number_of_roles_outside_two_to_eight_is_refused(roles):
    with pytest.raises(AnalyticsError, match="between 2 and 8"):
        rege.precheck(_sub(_STAR, _star("VOUCHED_FOR"))[0], roles=roles)


def test_counting_by_weight_with_no_positive_weight_is_refused_not_one_role():
    """Every pair would have nothing to match and be called alike."""
    sub = _sub(_STAR, _star("VOUCHED_FOR"), weights={k: 0.0 for k in range(4)})[0]
    with pytest.raises(AnalyticsError, match="no tie in this view carries a positive "
                                             "weight; count ties as present or absent"):
        rege.precheck(sub, weighting="weight")
    rege.precheck(sub)                  # counted as present, the ties are there
    assert _roles(_run(sub)) == [{"l1", "l2", "l3", "l4"}, {"hub"}]


def test_an_unknown_weighting_is_refused():
    with pytest.raises(AnalyticsError, match="presence or by weight"):
        _run(_sub(_STAR, _star("VOUCHED_FOR"))[0], weighting="decayed")


# --------------------------------------------------------------------------
# Cost
# --------------------------------------------------------------------------

def _directed_world(entities, pairs, *, both_ways=False, seed=11):
    """Names, ties and weights for a view at a size: every tied pair carries
    the three valences (positive, negative, neutral), each in a random
    direction (or, `both_ways`, in both with a weight of its own), with random
    weights. The dearest shapes of the measurements of 2026-10-02."""
    rng = random.Random(seed)
    order = list(range(entities))
    rng.shuffle(order)
    seen = {frozenset(p) for p in zip(order, order[1:], strict=False)}
    tied = [tuple(p) for p in zip(order, order[1:], strict=False)]
    while len(tied) < pairs:
        a, b = rng.randrange(entities), rng.randrange(entities)
        if a != b and frozenset((a, b)) not in seen:
            seen.add(frozenset((a, b)))
            tied.append((a, b))
    names = [f"n{i}" for i in range(entities)]
    ties, weights = [], {}

    def add(a, b, et):
        weights[len(ties)] = round(rng.uniform(0.1, 9.0), 3)
        ties.append((names[a], et, names[b]))

    for a, b in tied:
        for et in ("VOUCHED_FOR", "ACCUSED_SCAM", "POSTS_ON"):
            if both_ways:
                add(a, b, et)
                add(b, a, et)
            elif rng.random() < 0.85:
                if rng.random() < 0.5:
                    add(a, b, et)
                else:
                    add(b, a, et)
                if rng.random() < 0.4:
                    if ties[-1][0] == names[a]:
                        add(b, a, et)
                    else:
                        add(a, b, et)
    return names, ties, weights


def test_a_round_reads_only_the_rows_of_m_it_needs(monkeypatch):
    """Each tie-pattern group compares its left ties with the counterparts'
    values M(k, m) for the k it holds. Taking all n rows of M for each of up
    to 63 groups was 2.2 of the 2.7 seconds of a round on three relations in
    random directions (2026-10-02): the rows taken must be
    the group's own k."""
    names, ties, weights = _directed_world(60, 100)
    sub = _sub(names, ties, weights=weights)[0]
    taken = []
    real = numpy.take

    def spy(a, indices, axis=None, **kw):
        if axis == 1:
            taken.append(a.shape[0])
        return real(a, indices, axis=axis, **kw)

    monkeypatch.setattr(rege.numpy, "take", spy)
    out = _run(sub, weighting="weight")
    monkeypatch.undo()
    assert out["rege"]["rounds"] >= 1 and len(taken) > 20
    assert max(taken) < 60, f"a group took {max(taken)} rows of M for 60 entities"
    # And the saving moved no number: a small view of the same shape, held to
    # the reference (the reference is too slow for sixty).
    small = _directed_world(8, 14, seed=3)
    _check_against_naive(*small[:2], small[2], "weight")
    _check_against_naive(*small[:2])


_DIRECTED_KINDS = ("VOUCHED_FOR", "ACCUSED_SCAM", "POSTS_ON")      # positive, negative, neutral


def _world_at_caps(kinds, mode, seed=11):
    """Names, ties and weights for a view AT the shipped caps: 1,000 entities,
    pairs added one at a time (every pair carries each of `kinds`, `mode`
    saying whether both ways or in a random direction with some reciprocated)
    until the next would pass REGE_MAX_PAIRS or REGE_MAX_TIES, each tie with a
    random weight of its own. All the kinds are directed, so a tie is one direction
    and none repeats another."""
    rng = random.Random(seed)
    order = list(range(rege.REGE_MAX_NODES))
    rng.shuffle(order)
    seen = {frozenset(p) for p in zip(order, order[1:], strict=False)}
    pairs = [tuple(p) for p in zip(order, order[1:], strict=False)]
    while len(pairs) < rege.REGE_MAX_PAIRS + 50:
        a, b = rng.randrange(len(order)), rng.randrange(len(order))
        if a != b and frozenset((a, b)) not in seen:
            seen.add(frozenset((a, b)))
            pairs.append((a, b))
    names = [f"n{i}" for i in range(len(order))]
    ties, weights = [], {}
    taken = 0
    for a, b in pairs:
        new = []
        for et in kinds:
            if mode == "both":
                new += [(a, b, et), (b, a, et)]
            elif rng.random() < 0.85:
                one = (a, b, et) if rng.random() < 0.5 else (b, a, et)
                new.append(one)
                if rng.random() < 0.4:
                    new.append((one[1], one[0], et))
        if taken == rege.REGE_MAX_PAIRS or len(ties) + len(new) > rege.REGE_MAX_TIES:
            break
        for x, y, et in new:
            weights[len(ties)] = round(rng.uniform(0.1, 9.0), 3)
            ties.append((names[x], et, names[y]))
        taken += 1
    return names, ties, weights, taken


@pytest.mark.parametrize("kinds, mode", [
    (_DIRECTED_KINDS[:1], "both"), (_DIRECTED_KINDS[:2], "mix"), (_DIRECTED_KINDS, "mix"),
    (_DIRECTED_KINDS, "both")],
    ids=["one-relation-both-ways", "two-relations-random", "three-relations-random",
         "three-relations-both-ways"])
def test_the_dearest_views_at_the_caps_stay_near_two_seconds(kinds, mode):
    """1,000 entities, filled to the pairs cap or the ties cap, whichever
    comes first, counted by weight with every tie's weight its own, three full
    rounds. The shapes are the ones measured on 2026-10-02: one relation tied
    both ways (the first calibration's 'worst', among the cheapest), and
    relations in random directions, which took 7.5 to 8.3 s at 3,000 pairs
    before the caps moved (2026-10-02). Every one is
    measured at 0.9 to 2.1 s of CPU with every core of the build host busy. The
    bound is two and a half times the dearest, so it fails on an order-of-
    magnitude regression and not on noise, and it reads the shipped caps."""
    names, ties, weights, taken = _world_at_caps(kinds, mode)
    assert max(taken / rege.REGE_MAX_PAIRS, len(ties) / rege.REGE_MAX_TIES) > 0.97, (
        taken, len(ties))
    sub = _sub(names, ties, weights=weights)[0]
    started = time.process_time()
    out = _run(sub, weighting="weight")
    spent = time.process_time() - started
    assert out["rege"]["rounds"] == rege.REGE_ITERATIONS, "the view settled early"
    assert out["node_count"] == rege.REGE_MAX_NODES
    assert spent < 5.5, f"{spent:.1f} s of CPU at the caps; the calibration says about 2"


def test_parallel_ties_at_the_caps_cost_what_the_collapsed_view_costs():
    """Counting directions admits views whose raw ties far exceed the cap, so
    the dearest one is measured: the dearest shape at the caps (three relations
    in random directions, 1,000 entities, every weight its own) with every tie
    repeated five times under a weight of its own, which is the same cells
    with five times the rows. Each repeat is a new row of the same cell, so the
    directions are unchanged and the rounds cost what they cost without the
    repeats (1.5 to 1.8 s, not more) plus the linear pass over the rows, a few
    microseconds each (2026-10-03)."""
    names, ties, weights, _taken = _world_at_caps(_DIRECTED_KINDS, "mix")
    rng = random.Random(7)
    repeated, heavier = [], {}
    for k, tie in enumerate(ties):
        for again in range(5):
            heavier[len(repeated)] = weights[k] if again == 0 else round(rng.uniform(0.1, 9.0), 3)
            repeated.append(tie)
    sub = _sub(names, repeated, weights=heavier)[0]
    _tied, _usable, _pairs, directions = rege._usable(sub, "weight")
    assert directions == len(ties) and len(repeated) == 5 * len(ties)
    assert directions / rege.REGE_MAX_TIES > 0.97
    started = time.process_time()
    out = _run(sub, weighting="weight")
    spent = time.process_time() - started
    assert out["rege"]["rounds"] == rege.REGE_ITERATIONS and out["node_count"] == 1000
    assert spent < 5.5, f"{spent:.1f} s of CPU with every tie repeated five times"


def test_the_first_calibrations_dearest_view_is_now_refused_not_computed():
    """Three relations in random directions on 3,000 pairs (shape B of
    2026-10-03: about 10,600 ties) took 7.5 to 8.3 s. It is over the ties cap now
    (and over the pairs cap), refused before any matrix exists."""
    names, ties, weights = _directed_world(1000, 3000)
    assert len(ties) > 10000
    sub = _sub(names, ties, weights=weights)[0]
    with pytest.raises(AnalyticsError, match=r"capped at 2500 tied pairs; this view has 29\d\d"):
        rege.precheck(sub)
    # The first 6,000 of them are on about 1,700 pairs, inside that cap, and
    # over this one (no two of them are the same kind and direction between
    # one pair, so each is its own direction).
    with pytest.raises(AnalyticsError, match=_directions_text(5000, 6000, 6000)):
        rege.precheck(_sub(names, ties[:6000])[0])


# --------------------------------------------------------------------------
# What the payload says
# --------------------------------------------------------------------------

def test_isolates_hold_no_role_and_are_counted():
    out = _run(_sub(_STAR + ["z"], _star("VOUCHED_FOR"))[0])
    assert out["rege"]["no_ties"] == {"count": 1}
    assert "z" not in {n["label"] for n in out["nodes"]}


def test_every_node_row_names_its_role_and_its_fit():
    out = _run(_sub(_WF, _WF_TIES)[0], roles=3)
    rows = {n["label"]: n for n in out["nodes"]}
    assert rows["A"]["role"] == 3 and rows["A"]["fit"] is None
    assert rows["B"]["role"] == 2 and rows["B"]["fit"] == 1.0
    assert {n["block_index"] for n in out["nodes"]} == {0, 1, 2}
    for r in out["rege"]["roles"]:
        assert r["block_index"] == r["role"] - 1


def test_unaccepted_ties_are_counted_and_the_view_is_said_to_decide():
    sub = _sub(_STAR, _star("VOUCHED_FOR"), review={0: "PROPOSED", 1: "DISPUTED"})[0]
    g = _run(sub)["rege"]
    assert g["unaccepted_ties"] == 2
    assert any("Only the ties this view admits" in t for t in g["limits"])


def test_a_run_that_settles_says_more_rounds_would_not_move_it(monkeypatch):
    out = _run(_sub(_STAR, _star("VOUCHED_FOR"))[0])
    assert out["rege"]["converged"] is True and out["rege"]["rounds"] < 3
    assert "settled within" in out["rege"]["limits"][0]


def test_a_run_cut_short_says_so_with_its_last_change(monkeypatch):
    monkeypatch.setattr(rege, "REGE_ITERATIONS", 1)
    g = _run(_sub(_WF, _WF_TIES)[0])["rege"]
    assert g["rounds"] == 1 and g["max_rounds"] == 1 and g["converged"] is False
    assert g["last_change"] > 0
    assert g["limits"][0].startswith("REGE is an approximation: it stopped after 1 round, "
                                     "comparing neighbourhoods 1 step out")


def test_derived_ties_are_flagged():
    from test_affiliation import _world
    sub, _ids, p = _world({"a": "IDENTITY", "b": "IDENTITY", "c": "IDENTITY",
                           "F": "FORUM"},
                          [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"),
                           ("c", "POSTS_ON", "F")])
    out = rege.rege(sub, p, AnalyticsParams(), roles=2)
    assert out["rege"]["derived_ties"] is True
    assert out["one_mode"]["derived_ties"]["forum"] == 3
    assert _run(_sub(_STAR, _star("VOUCHED_FOR"))[0])["rege"]["derived_ties"] is False


def test_a_truncated_view_carries_the_truncation_note():
    out = _run(_sub(_STAR, _star("VOUCHED_FOR"), truncated=True)[0])
    assert out["truncated"] is True and "PARTIAL" in out["truncation_note"]


def test_the_run_is_marked_approximate_at_the_top_level_where_the_service_reads_it():
    """`analytics_runs` stores the top-level flag on the run row and in its
    audit event; REGE had it only inside its own block, so every run was
    recorded as exact (2026-10-02)."""
    out = _run(_sub(_STAR, _star("VOUCHED_FOR"))[0])
    assert out["is_approximate"] is True and out["rege"]["is_approximate"] is True


def test_the_limits_name_what_a_view_leaves_out_and_no_filter_there_is_not():
    """The view filters by type, confidence, date, review state, inference and
    the reader's clearance and compartments. It has no label filter, which the
    first wording named while leaving two of those out."""
    sentence = next(t for t in _payload()["rege"]["limits"]
                    if t.startswith("Only the ties this view admits"))
    for reason in ("type", "confidence", "date", "review state", "inferred", "clearance",
                   "compartments"):
        assert reason in sentence, reason
    assert "label" not in sentence


def _walk(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)
    else:
        yield key, value


def _payload(weighting="presence"):
    ties = _WF_TIES + [("E", "ACCUSED_SCAM", "G"), ("H", "COMMUNICATES_WITH", "I")]
    return _run(_sub(_WF + ["z"], ties)[0], roles=5, weighting=weighting)


@pytest.mark.parametrize("weighting", rege.WEIGHTINGS)
def test_the_payload_serialises_without_nan_and_holds_python_scalars(weighting):
    out = _payload(weighting)
    json.dumps(out, allow_nan=False)
    for key, value in _walk(out):
        assert value is None or type(value) in (int, float, bool, str), (key, type(value))


def test_every_name_in_the_payload_sits_under_a_label_key():
    names = set(_WF)
    for key, value in _walk(_payload()):
        if isinstance(value, str) and value in names:
            assert key == "label", key


def test_the_copy_obeys_the_rules_and_never_calls_a_role_a_person():
    texts = [rege.METHOD, rege.READING]
    for w in rege.WEIGHTINGS:
        texts += _payload(w)["rege"]["limits"]
    texts += rege._limits("presence", 1, False, 0.5)
    texts += rege._limits("weight", 1, False, 0.5, 1) + rege._limits("weight", 1, False, 0.5, 4)
    for call in (lambda: _run(_sub(["i0", "F"], [("i0", "POSTS_ON", "F")],
                                   {"F": "FORUM"})[0]),
                 lambda: _run(_sub(_STAR, _star("VOUCHED_FOR"))[0], roles=12),
                 lambda: _run(_sub(_STAR, _star("VOUCHED_FOR"))[0], weighting="x"),
                 lambda: _run(_sub(_STAR, _star("VOUCHED_FOR"),
                                   weights={k: 0.0 for k in range(4)})[0],
                              weighting="weight")):
        with pytest.raises(AnalyticsError) as exc:
            call()
        texts.append(str(exc.value))
    for text in texts:
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in text, text
    assert "never an attribution" in rege.READING
    assert "not one person" in rege.READING
    assert "A role is a hypothesis, never an attribution." in _payload()["rege"]["limits"]


@pytest.mark.skipif(sys.platform == "darwin",
                    reason="the macOS arm64 numpy wheels use Accelerate, which "
                           "neither threadpoolctl nor OpenBLAS's own call can cap")
def test_importing_rege_alone_caps_blas_to_one_thread():
    """REGE imports blockmodel, whose import takes the cap (decision 88): a
    process that loads only the regular-role analysis is capped too."""
    code = ("import noctornal_api.rege, noctornal_api.blockmodel as b; "
            "print(b.BLAS_CAP, b.blas_threads())")
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env=dict(os.environ), timeout=120)
    assert res.returncode == 0, res.stderr
    method, threads = res.stdout.split()
    assert method in ("threadpoolctl", "openblas") and threads == "1"
