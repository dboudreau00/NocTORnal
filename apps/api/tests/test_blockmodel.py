"""F1: CONCOR structural equivalence, the Roles card's maths (2026-09-24),
without a database.

Every fixture spells out each vertex and each tie as (src, edge_type,
dst), taking sign and directedness from the ontology, with ids
UUID(int=k) so a failure reproduces (with uuid4, one fixture's positions
depended on which vertex sorted first). The expected correlations were
computed independently of the module and are reproduced here by it, and
the pair-excluding correlation is held against a brute-force Pearson over
explicitly deleted entries.

Pure: no database. numpy is a hard dependency of this module.
"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from uuid import UUID

import numpy
import pytest
from noctornal_ontology.definition import EDGE_TYPES
from test_affiliation import _world

from noctornal_api import blockmodel
from noctornal_api.analytics import AnalyticsError, AnalyticsParams
from noctornal_api.projections import Projection, Subgraph

CASE = UUID(int=1)
_ET = {t.key: t for t in EDGE_TYPES}


def _sub(names, ties, types=None, *, truncated=False, seed=None) -> tuple[Subgraph, dict]:
    ids = {n: UUID(int=100 + i) for i, n in enumerate(names)}
    nodes = [{"id": ids[n], "label": n, "node_type": (types or {}).get(n, "IDENTITY")}
             for n in names]
    edges = [{"id": UUID(int=1000 + k), "edge_type": et, "src_node_id": ids[s],
              "dst_node_id": ids[t], "sign": _ET[et].default_sign, "weight": 1.0,
              "valid_from": None, "valid_to": None, "review": "ACCEPTED",
              "has_evidence": False}
             for k, (s, et, t) in enumerate(ties)]
    if seed is not None:
        random.Random(seed).shuffle(nodes)
        random.Random(seed).shuffle(edges)
    return Subgraph(nodes, edges, truncated=truncated), ids


def _corr(sub, ids, a, b) -> float:
    verts, rels = blockmodel.build_relations(sub)
    c = blockmodel.profile_correlation([r[2] for r in rels])
    ix = {v: i for i, v in enumerate(verts)}
    return round(float(c[ix[ids[a]], ix[ids[b]]]), 4)


def _run(sub, depth=1) -> dict:
    return blockmodel.concor(sub, Projection(case_id=CASE), AnalyticsParams(), depth=depth)


def _positions(out) -> list[set]:
    return [{m["label"] for m in p["members"]} for p in out["concor"]["positions"]]


_HUBS = ["H1", "H2", "a", "b", "c", "d"]


def _hub_ties(etype="COMMUNICATES_WITH"):
    return [(h, etype, x) for h in ("H1", "H2") for x in "abcd"]


def test_two_hubs_with_the_same_leaves_share_a_position_and_correlate_at_one():
    sub, ids = _sub(_HUBS, _hub_ties())
    assert _corr(sub, ids, "H1", "H2") == 1.0      # the zero-variance rule
    assert _corr(sub, ids, "a", "b") == 1.0
    assert _corr(sub, ids, "H1", "a") == -1.0
    out = _run(sub)
    assert sorted(_positions(out), key=len) == [{"H1", "H2"}, {"a", "b", "c", "d"}]
    assert out["concor"]["r_squared"]["overall"] == 1.0
    assert out["concor"]["splits"] == [{"block": "1", "sizes": [2, 4], "iterations": 0,
                                        "converged": True}]


def test_directed_hubs_correlate_at_one_too():
    sub, ids = _sub(_HUBS, _hub_ties("VOUCHED_FOR"))
    assert _corr(sub, ids, "H1", "H2") == 1.0
    assert _corr(sub, ids, "a", "b") == 1.0


def test_a_leaf_with_an_extra_tie():
    sub, ids = _sub(_HUBS, _hub_ties() + [("a", "COMMUNICATES_WITH", "b")])
    assert _corr(sub, ids, "a", "b") == 1.0
    assert _corr(sub, ids, "a", "c") == 0.5774
    assert _corr(sub, ids, "c", "d") == 1.0


def test_the_profile_correlation_excludes_the_pair_itself():
    """Against a brute-force Pearson that deletes columns i and j of every
    block explicitly, on a random 40-vertex graph with four relations, one
    of them symmetric."""
    rng = numpy.random.default_rng(20260924)
    n = 40
    mats = []
    for k in range(4):
        r = (rng.random((n, n)) < 0.12).astype(float)
        if k == 0:
            r = numpy.triu(r, 1)
            r = r + r.T
        numpy.fill_diagonal(r, 0.0)
        mats.append(r)
    got = blockmodel.profile_correlation(mats)
    blocks = []
    for r in mats:
        blocks.append(r)
        if not numpy.array_equal(r, r.T):
            blocks.append(r.T)
    stacked = numpy.hstack(blocks)
    for i in range(n):
        for j in range(n):
            if i == j:
                assert got[i, j] == 1.0
                continue
            drop = [b * n + c for b in range(len(blocks)) for c in (i, j)]
            x = numpy.delete(stacked[i], drop)
            y = numpy.delete(stacked[j], drop)
            vx, vy = x.var(), y.var()
            if vx <= 1e-12 and vy <= 1e-12:
                want = 1.0 if abs(x.sum() - y.sum()) < 1e-9 else 0.0
            elif vx <= 1e-12 or vy <= 1e-12:
                want = 0.0
            else:
                want = float(numpy.corrcoef(x, y)[0, 1])
            assert got[i, j] == pytest.approx(want, abs=1e-12), (i, j)


def test_two_constant_profiles_correlate_one_when_equal_and_zero_when_not():
    # a (0) and b (1) each tied to c, d, e (2, 3, 4): equal constant
    # profiles once a and b are left out.
    r = numpy.zeros((5, 5))
    for i in (0, 1):
        for j in (2, 3, 4):
            r[i, j] = r[j, i] = 1.0
    assert blockmodel.profile_correlation([r])[0, 1] == 1.0
    # a (0) tied to b, c, d (1, 2, 3); f (4) tied to c alone. With a and f
    # left out, a's profile is constant and f's varies.
    s = numpy.zeros((5, 5))
    for j in (1, 2, 3):
        s[0, j] = s[j, 0] = 1.0
    s[4, 2] = s[2, 4] = 1.0
    assert blockmodel.profile_correlation([s])[0, 4] == 0.0
    # Two constant profiles that differ: every entry 1 against every entry 0.
    q = numpy.zeros((4, 4))
    q[0, 2] = q[0, 3] = q[2, 0] = q[3, 0] = 1.0
    assert blockmodel.profile_correlation([q])[0, 1] == 0.0


def test_two_disjoint_cliques_split_into_themselves_with_a_perfect_fit():
    names = list("abcdwxyz")
    ties = [(x, "COMMUNICATES_WITH", y) for grp in ("abcd", "wxyz")
            for i, x in enumerate(grp) for y in grp[i + 1:]]
    sub, _ids = _sub(names, ties)
    out = _run(sub, depth=1)
    assert sorted(_positions(out), key=min) == [set("abcd"), set("wxyz")]
    assert out["concor"]["r_squared"]["overall"] == 1.0
    out = _run(sub, depth=2)
    assert out["concor"]["unsplit"] == [
        {"block": "1.1", "size": 4, "reason": "alike"},
        {"block": "1.2", "size": 4, "reason": "alike"}]


def test_signs_are_compared_apart():
    names = ["V1", "V2", "A1", "T", "U"]
    ties = [("V1", "VOUCHED_FOR", "T"), ("V2", "VOUCHED_FOR", "T"),
            ("A1", "ACCUSED_SCAM", "T"), ("T", "VOUCHED_FOR", "U"),
            ("U", "VOUCHED_FOR", "V1")]
    sub, ids = _sub(names, ties)
    assert _corr(sub, ids, "V2", "A1") == -0.0909
    assert _corr(sub, ids, "V1", "A1") == -0.1348
    assert _corr(sub, ids, "V1", "V2") == 0.6742
    sub, ids = _sub(names, [(a, "VOUCHED_FOR", b) for a, _e, b in ties])
    assert _corr(sub, ids, "V2", "A1") == 1.0


def test_direction_is_kept():
    names = ["A", "B", "X", "Y", "Z"]
    ties = [("A", "VOUCHED_FOR", "X"), ("X", "VOUCHED_FOR", "B"),
            ("Y", "VOUCHED_FOR", "X"), ("B", "VOUCHED_FOR", "Z")]
    sub, ids = _sub(names, ties)
    assert _corr(sub, ids, "A", "B") == -0.3162
    assert _corr(sub, ids, "A", "Y") == 1.0
    sub, ids = _sub(names, [(a, "COMMUNICATES_WITH", b) for a, _e, b in ties])
    assert _corr(sub, ids, "A", "B") == 0.5
    assert _corr(sub, ids, "A", "Y") == 1.0


_TWO_MODE = {"F": "FORUM", "G": "FORUM", "H": "FORUM"}


def test_on_a_two_mode_view_forums_shape_profiles_but_hold_no_position():
    names = ["i0", "i1", "i2", "F", "G"]
    ties = [("i0", "POSTS_ON", "F"), ("i1", "POSTS_ON", "F"),
            ("i1", "POSTS_ON", "G"), ("i2", "POSTS_ON", "G")]
    sub, ids = _sub(names, ties, _TWO_MODE)
    assert _corr(sub, ids, "i0", "i1") == 0.6325
    assert _corr(sub, ids, "i0", "i2") == -0.2
    out = _run(sub)
    assert out["concor"]["profile_only"] == {"count": 2, "types": ["FORUM"]}
    assert {m["label"] for p in out["concor"]["positions"] for m in p["members"]} \
        == {"i0", "i1", "i2"}
    # i1 sits exactly between i0 and i2 here, so which side it lands on is
    # noise. A third forum shared by i1 and i2 only breaks
    # the tie, and the split settles.
    sub, ids = _sub(names + ["H"], ties + [("i1", "POSTS_ON", "H"),
                                           ("i2", "POSTS_ON", "H")], _TWO_MODE)
    assert _corr(sub, ids, "i0", "i1") == 0.488
    assert _corr(sub, ids, "i0", "i2") == -0.2182
    for seed in range(5):
        out = _run(_sub(names + ["H"], ties + [("i1", "POSTS_ON", "H"),
                                               ("i2", "POSTS_ON", "H")],
                        _TWO_MODE, seed=seed)[0])
        assert sorted(_positions(out), key=len) == [{"i0"}, {"i1", "i2"}]
        assert out["concor"]["all_converged"] is True


def test_derived_ties_use_their_own_direction_flag():
    flow = {"A": "IDENTITY", "B": "IDENTITY", "C": "IDENTITY", "W1": "WALLET",
            "W2": "WALLET", "T": "TRANSACTION"}
    rows = [("A", "CONTROLS", "W1"), ("W1", "TX_INPUT", "T"),
            ("T", "TX_OUTPUT", "W2"), ("B", "CONTROLS", "W2"),
            ("C", "COMMUNICATES_WITH", "A")]
    sub, ids, _p = _world(flow, rows, families=("wallet",))
    rows_ = {(r[2], r[3]) for r in blockmodel.direction_rows(sub)}
    assert ("ONE_MODE:wallet_flow", "d") in rows_
    assert ("COMMUNICATES_WITH", "u") in rows_
    verts, rels = blockmodel.build_relations(sub)
    ix = {v: i for i, v in enumerate(verts)}
    neutral = dict((k, m) for k, _l, m, _c in rels)["neutral"]
    assert neutral[ix[ids["A"]], ix[ids["B"]]] == 1.0
    assert neutral[ix[ids["B"]], ix[ids["A"]]] == 0.0


def test_isolates_hold_no_position_and_are_counted():
    sub, _ids = _sub(_HUBS + ["z"], _hub_ties())
    out = _run(sub)
    assert out["concor"]["no_ties"] == {"count": 1}
    assert "z" not in {n["label"] for n in out["nodes"]}


def test_the_answer_does_not_depend_on_row_order():
    ties = _hub_ties() + [("a", "COMMUNICATES_WITH", "b"), ("c", "VOUCHED_FOR", "d")]
    base = _run(_sub(_HUBS, ties)[0], depth=2)
    for seed in (1, 2, 3):
        again = _run(_sub(_HUBS, ties, seed=seed)[0], depth=2)
        assert again["concor"] == base["concor"] and again["nodes"] == base["nodes"]


def test_equivalent_pairs_exclude_tied_pairs_and_thin_profiles():
    sub, _ids = _sub(_HUBS + ["e"], _hub_ties() + [("a", "COMMUNICATES_WITH", "b"),
                                                   ("e", "COMMUNICATES_WITH", "c")])
    out = _run(sub)
    pairs = {(p["a"]["label"], p["b"]["label"]) for p in out["concor"]["equivalent_pairs"]}
    assert ("H1", "H2") in pairs
    assert ("a", "b") not in pairs and ("b", "a") not in pairs     # tied
    assert not any("e" in pair for pair in pairs)                   # one tie only
    for p in out["concor"]["equivalent_pairs"]:
        assert p["correlation"] >= blockmodel.EQUIVALENCE_LEAD_MIN


def test_the_cap_refuses_before_any_matrix_is_allocated(monkeypatch):
    monkeypatch.setattr(blockmodel, "CONCOR_MAX_NODES", 3)
    calls = []
    real = numpy.zeros
    monkeypatch.setattr(blockmodel.numpy, "zeros",
                        lambda *a, **kw: calls.append(a) or real(*a, **kw))
    with pytest.raises(AnalyticsError, match="capped at 3 entities with ties; this "
                                             "view has 6"):
        _run(_sub(_HUBS, _hub_ties())[0])
    assert calls == []


def test_fewer_than_two_tied_entities_is_an_error_not_a_partition():
    sub, _ids = _sub(["i0", "F", "i9"], [("i0", "POSTS_ON", "F")], {"F": "FORUM"})
    with pytest.raises(AnalyticsError, match="at least two entities with ties"):
        _run(sub)
    with pytest.raises(AnalyticsError):
        blockmodel.precheck(sub)


@pytest.mark.parametrize("depth", [0, 5])
def test_a_depth_outside_one_to_four_is_refused(depth):
    with pytest.raises(AnalyticsError, match="between 1 and 4"):
        _run(_sub(_HUBS, _hub_ties())[0], depth=depth)


def test_a_split_that_does_not_settle_is_made_and_reported(monkeypatch):
    monkeypatch.setattr(blockmodel, "CONCOR_MAX_ITER", 1)
    names = ["i0", "i1", "i2", "F", "G", "H"]
    ties = [("i0", "POSTS_ON", "F"), ("i1", "POSTS_ON", "F"), ("i1", "POSTS_ON", "G"),
            ("i2", "POSTS_ON", "G"), ("i1", "POSTS_ON", "H"), ("i2", "POSTS_ON", "H")]
    out = _run(_sub(names, ties, _TWO_MODE)[0])
    (split,) = out["concor"]["splits"]
    assert split["converged"] is False and split["iterations"] == 1
    assert out["concor"]["all_converged"] is False
    assert len(out["concor"]["positions"]) == 2


def _walk(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)
    else:
        yield key, value


def _payload():
    ties = _hub_ties() + [("a", "COMMUNICATES_WITH", "b"), ("c", "ACCUSED_SCAM", "d")]
    return _run(_sub(_HUBS + ["z"], ties)[0], depth=3)


def test_the_payload_serialises_without_nan():
    json.dumps(_payload(), allow_nan=False)


def test_every_value_is_a_python_scalar():
    for _key, value in _walk(_payload()):
        assert value is None or type(value) in (int, float, bool, str), (_key, type(value))


def test_every_name_in_the_payload_sits_under_a_label_key():
    names = set(_HUBS)
    for key, value in _walk(_payload()):
        if isinstance(value, str) and value in names:
            assert key == "label", key


def test_derived_ties_are_flagged_as_counted_whole():
    sub, _ids, p = _world({"a": "IDENTITY", "b": "IDENTITY", "c": "IDENTITY",
                           "F": "FORUM"},
                          [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"),
                           ("c", "POSTS_ON", "F")])
    out = blockmodel.concor(sub, p, AnalyticsParams(), depth=1)
    assert out["concor"]["derived_ties_counted_whole"] is True
    assert out["one_mode"]["derived_ties"]["forum"] == 3
    assert _payload()["concor"]["derived_ties_counted_whole"] is False


def test_a_truncated_view_carries_the_truncation_note():
    out = _run(_sub(_HUBS, _hub_ties(), truncated=True)[0])
    assert out["truncated"] is True and "PARTIAL" in out["truncation_note"]
    assert _run(_sub(_HUBS, _hub_ties())[0])["truncation_note"] is None


def test_the_image_marks_blocks_denser_than_the_relation():
    out = _run(_sub(_HUBS, _hub_ties())[0])
    c = out["concor"]
    hubs = next(i for i, p in enumerate(c["positions"])
                if {m["label"] for m in p["members"]} == {"H1", "H2"})
    leaves = 1 - hubs
    assert c["density"]["positive"][hubs][leaves] == 1.0
    assert c["density"]["positive"][hubs][hubs] == 0.0
    assert c["image"]["positive"][hubs][leaves] == 1
    assert c["image"]["positive"][leaves][leaves] == 0
    assert c["alpha"]["positive"] == pytest.approx(16 / 30, abs=1e-6)


@pytest.mark.skipif(sys.platform == "darwin",
                    reason="the macOS arm64 numpy wheels use Accelerate, which "
                           "neither threadpoolctl nor OpenBLAS's own call can cap; "
                           "production is Linux with OpenBLAS")
def test_blas_is_capped_to_one_thread_on_import():
    """In a fresh process, as a worker starts. At least one OpenBLAS must be
    found and report one thread: a check that passed with nothing to ask
    would stay green on a platform where the cap does nothing."""
    code = ("import noctornal_api.blockmodel as b; "
            "print(b.BLAS_CAP, b.blas_threads())")
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         env=dict(os.environ), timeout=120)
    assert res.returncode == 0, res.stderr
    method, threads = res.stdout.split()
    assert method in ("threadpoolctl", "openblas")
    assert threads == "1"


def test_the_copy_obeys_the_rules():
    texts = [blockmodel.METHOD, blockmodel.READING]
    for sub in (_sub(["i0", "F"], [("i0", "POSTS_ON", "F")], {"F": "FORUM"})[0],):
        with pytest.raises(AnalyticsError) as exc:
            _run(sub)
        texts.append(str(exc.value))
    with pytest.raises(AnalyticsError) as exc:
        _run(_sub(_HUBS, _hub_ties())[0], depth=9)
    texts.append(str(exc.value))
    for text in texts:
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in text, text
