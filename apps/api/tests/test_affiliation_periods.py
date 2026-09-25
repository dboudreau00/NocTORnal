"""F2: when two memberships count as at the same time, and what that may
cost (2026-09-24), without a database.

core.edge keeps one live row per (src, dst, type, valid_from), so one
entity's membership of one venue, or one wallet's leg of one transaction,
may be recorded by many parallel dated rows, and ANY of them may make two
members contemporaneous. An earlier version did that by trying one interval
from every constituent in every combination, which grows as the product
of the parallel rows and sat outside the derived-tie limit (measured: 50
posters with 100 dated rows each took 6.85 s; one flow leg with 200 rows
on each of its four constituents took 4.29 s, on every one-mode read
route).

Now each constituent's rows are merged once into disjoint periods, two
constituents meet in one linear pass, and `MAX_PERIOD_STEPS` bounds every
pass by arithmetic before any is made. What is tested here:

- the three period helpers against a brute-force reference on a grid of
  half days, over random intervals with open ends, touching ends and
  rows dated to end before they start;
- the two measured worlds finish well inside a second;
- the step bound is a true upper bound on the steps the transform takes,
  over random forum, wallet and payment worlds, and refuses before any
  step or derived tie;
- an undated view at the derived-tie limit never meets the step limit.

Pure: no database.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone

import pytest
from test_affiliation import _FLOW, _derived, _world, d

from noctornal_api import affiliation
from noctornal_api.affiliation import (
    MAX_DERIVED_TIES,
    MAX_PERIOD_STEPS,
    OneModeTooManyPeriods,
    _last_overlap,
    _overlap,
    _periods,
)
from noctornal_api.projections import ProjectionTooLarge

UTC = timezone.utc
BASE = datetime(2020, 1, 1, tzinfo=UTC)
#: Drawn endpoints lie in 0..20 days; an open end reaches past them.
LO, HI = -1, 21


def _t(x):
    return None if x is None else BASE + timedelta(days=x)


def _days(t) -> int:
    return (t - BASE).days


def _cover(periods) -> set[int]:
    """The half days a union covers. Endpoints are whole days, so a gap of
    one day between two periods shows as uncovered odd points and touching
    ends as a shared even one."""
    out: set[int] = set()
    for s, e in periods:
        a = 2 * LO if s is None else 2 * _days(s)
        b = 2 * HI if e is None else 2 * _days(e)
        out.update(range(a, b + 1))
    return out


def _runs(points: set[int]) -> tuple:
    """Maximal runs of covered half days, back as periods, an end at the
    edge of the grid meaning open."""
    runs: list[tuple] = []
    for p in sorted(points):
        if runs and runs[-1][1] == p - 1:
            runs[-1] = (runs[-1][0], p)
        else:
            runs.append((p, p))
    return tuple((None if a == 2 * LO else _t(a // 2), None if b == 2 * HI else _t(b // 2))
                 for a, b in runs)


def _random_intervals(rng: random.Random, n: int) -> list[tuple]:
    out = []
    for _ in range(n):
        s = None if rng.random() < 0.15 else rng.randint(0, 20)
        e = None if rng.random() < 0.15 else rng.randint(0, 20)
        if s is not None and e is not None and rng.random() < 0.8 and s > e:
            s, e = e, s          # mostly well formed, sometimes reversed
        out.append((_t(s), _t(e)))
    return out


def _valid(ivs) -> list[tuple]:
    return [iv for iv in ivs if iv[0] is None or iv[1] is None or iv[0] <= iv[1]]


# ---------------------------------------------------------------------------
# The helpers against a reference
# ---------------------------------------------------------------------------

def test_periods_are_the_union_merged_into_disjoint_sorted_periods():
    rng = random.Random(20260924)
    for _ in range(600):
        ivs = _random_intervals(rng, rng.randint(0, 6))
        got = _periods(ivs)
        assert got == _runs(_cover(_valid(ivs))), ivs
        # Canonical: sorted, and no two periods overlap or touch.
        for (_, e1), (s2, _) in zip(got, got[1:], strict=False):
            assert e1 is not None and s2 is not None and e1 < s2


def test_periods_edge_cases():
    assert _periods([]) == ()
    # Dated to end before it starts: covers no time, as a lone interval
    # intersected with anything did before.
    assert _periods([(_t(5), _t(2))]) == ()
    # Touching closed periods share an instant, so they are one.
    assert _periods([(_t(1), _t(3)), (_t(3), _t(6))]) == ((_t(1), _t(6)),)
    # Open at both ends is all time, the shared fast-path value.
    assert _periods([(_t(1), _t(3)), (None, None)]) is affiliation._ALWAYS
    assert _periods([(None, _t(4)), (_t(2), None)]) is affiliation._ALWAYS


def test_overlap_and_last_overlap_match_the_reference():
    rng = random.Random(7)
    for _ in range(600):
        a = _periods(_random_intervals(rng, rng.randint(0, 5)))
        b = _periods(_random_intervals(rng, rng.randint(0, 5)))
        want = _runs(_cover(a) & _cover(b))
        assert _overlap(a, b) == want, (a, b)
        assert _overlap(b, a) == want, (a, b)
        assert _last_overlap(a, b) == (want[-1] if want else None), (a, b)
        assert _last_overlap(b, a) == (want[-1] if want else None), (a, b)


def test_a_members_overlapping_rows_are_one_period():
    """Two rows of one membership that overlap cover their union, so the
    derived tie spans all of the time both members were there, not the
    piece one row happens to share."""
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F", {"vf": d(2020), "vt": d(2020, 6)}),
                          ("a", "POSTS_ON", "F", {"vf": d(2020, 5), "vt": d(2020, 12)}),
                          ("b", "POSTS_ON", "F", {"vf": d(2020, 3), "vt": d(2021)})])
    (edge,) = _derived(sub, ids).values()
    assert (edge["valid_from"], edge["valid_to"]) == (d(2020, 3), d(2020, 12))


def test_the_latest_shared_period_dates_the_tie():
    sub, ids, _ = _world({"a": "IDENTITY", "b": "IDENTITY", "F": "FORUM"},
                         [("a", "POSTS_ON", "F", {"vf": d(2019), "vt": d(2019, 6)}),
                          ("a", "POSTS_ON", "F", {"vf": d(2022), "vt": d(2022, 6)}),
                          ("b", "POSTS_ON", "F", {"vf": d(2019, 3), "vt": d(2019, 4)}),
                          ("b", "POSTS_ON", "F", {"vf": d(2022, 2)})])
    (edge,) = _derived(sub, ids).values()
    assert (edge["valid_from"], edge["valid_to"]) == (d(2022, 2), d(2022, 6))


def test_a_flow_needs_one_instant_all_four_constituents_share():
    """The two legs and A's control share one day, which B's control does
    not reach, until a parallel control row of B's does."""
    rows = [("A", "CONTROLS", "W1", {"vf": d(2020), "vt": d(2020, 6)}),
            ("W1", "TX_INPUT", "T", {"vf": d(2020, 5), "vt": d(2020, 9)}),
            ("T", "TX_OUTPUT", "W2", {"vf": d(2020, 3), "vt": d(2020, 5)}),
            ("B", "CONTROLS", "W2", {"vf": d(2020, 7)})]
    sub, ids, _ = _world(_FLOW, rows, families=("wallet",))
    assert ("wallet_flow", "A", "B") not in _derived(sub, ids)
    assert sub.one_mode["flow_legs_not_contemporaneous"] == 1
    sub, ids, _ = _world(_FLOW, rows + [("B", "CONTROLS", "W2",
                                         {"vf": d(2020, 4), "vt": d(2020, 5, 20)})],
                         families=("wallet",))
    edge = _derived(sub, ids)[("wallet_flow", "A", "B")]
    assert (edge["valid_from"], edge["valid_to"]) == (d(2020, 5), d(2020, 5))


# ---------------------------------------------------------------------------
# Cost
# ---------------------------------------------------------------------------

def _dated_posters(posters: int, parallel: int) -> tuple[dict, list]:
    """The measured forum: every poster with `parallel` dated rows,
    windows shifted per poster so pairs meet in different places."""
    nodes = {f"p{i:02d}": "IDENTITY" for i in range(posters)}
    nodes["F"] = "FORUM"
    rows = []
    for i in range(posters):
        for j in range(parallel):
            vf = BASE + timedelta(days=10 * j + i % 7)
            rows.append((f"p{i:02d}", "POSTS_ON", "F",
                         {"vf": vf, "vt": vf + timedelta(days=5 + i % 3)}))
    return nodes, rows


def test_many_parallel_dated_postings_cost_linear_time():
    """50 posters x 100 dated rows: 6.85 s when every combination of rows
    was tried."""
    nodes, rows = _dated_posters(50, 100)
    started = time.perf_counter()
    sub, _ids, _ = _world(nodes, rows)
    elapsed = time.perf_counter() - started
    cov = sub.one_mode
    assert cov["derived_ties"]["forum"] + cov["pairs_not_contemporaneous"] == 50 * 49 // 2
    assert elapsed < 1.5, elapsed


def test_a_flow_leg_with_many_parallel_dated_rows_costs_linear_time():
    """One leg, 200 dated rows on each of its four constituents: 4.29 s
    when every combination was tried, and growing as the cube."""
    rows = []
    for (s, et, t), shift in ((("A", "CONTROLS", "W1"), 0), (("W1", "TX_INPUT", "T"), 1),
                              (("T", "TX_OUTPUT", "W2"), 2), (("B", "CONTROLS", "W2"), 3)):
        for j in range(200):
            vf = BASE + timedelta(days=j + shift)
            rows.append((s, et, t, {"vf": vf, "vt": vf + timedelta(days=200)}))
    started = time.perf_counter()
    sub, ids, _ = _world(_FLOW, rows, families=("wallet",))
    elapsed = time.perf_counter() - started
    assert ("wallet_flow", "A", "B") in _derived(sub, ids)
    assert elapsed < 1.5, elapsed


def _steps_bound(monkeypatch, *world_args, **world_kwargs) -> int:
    """The pre-count's step bound, read from the refusal it raises when
    the limit is below everything."""
    monkeypatch.setattr(affiliation, "MAX_PERIOD_STEPS", -1)
    with pytest.raises(ProjectionTooLarge) as exc:
        _world(*world_args, **world_kwargs)
    monkeypatch.setattr(affiliation, "MAX_PERIOD_STEPS", MAX_PERIOD_STEPS)
    assert isinstance(exc.value.__cause__, OneModeTooManyPeriods)
    return exc.value.__cause__.bound


def test_the_step_limit_refuses_before_any_step_or_tie(monkeypatch):
    built, merged = [], []
    real_init = affiliation._Derived.__init__

    def spy_init(self, *a, **kw):
        built.append(a)
        real_init(self, *a, **kw)

    monkeypatch.setattr(affiliation._Derived, "__init__", spy_init)
    monkeypatch.setattr(affiliation, "_overlap",
                        lambda *a: merged.append(a) or _overlap(*a))
    monkeypatch.setattr(affiliation, "_last_overlap",
                        lambda *a: merged.append(a) or _last_overlap(*a))
    monkeypatch.setattr(affiliation, "MAX_PERIOD_STEPS", 5)
    nodes, rows = _dated_posters(3, 3)
    with pytest.raises(ProjectionTooLarge,
                       match="up to 18 comparisons of dated periods, over the limit of 5"):
        _world(nodes, rows)
    assert built == [] and merged == []


def test_an_undated_view_at_the_tie_limit_is_well_inside_the_step_limit(monkeypatch):
    """316 undated posters draw 49,770 ties, just inside the tie limit, and
    need 99,540 steps: the step limit only ever binds on dated rows."""
    nodes = {f"p{i:03d}": "IDENTITY" for i in range(316)}
    nodes["F"] = "FORUM"
    rows = [(f"p{i:03d}", "POSTS_ON", "F") for i in range(316)]
    assert 316 * 315 // 2 <= MAX_DERIVED_TIES
    steps = _steps_bound(monkeypatch, nodes, rows, max_venue_size=500)
    assert steps == 315 * 316
    assert steps * 10 <= MAX_PERIOD_STEPS


def _random_world(rng: random.Random) -> tuple[dict, list]:
    """Posters on two forums, controllers of four wallets, two transactions
    and a few payments, every row dated or not at random and some
    memberships recorded several times."""
    nodes = {f"e{i}": "IDENTITY" for i in range(7)}
    nodes.update({"F": "FORUM", "G": "CHANNEL", "T1": "TRANSACTION", "T2": "TRANSACTION"})
    nodes.update({f"W{i}": "WALLET" for i in range(4)})

    def dated() -> dict:
        (s, e), = _random_intervals(rng, 1)
        return {"vf": s, "vt": e} if rng.random() < 0.7 else {}

    rows = []

    def add(src, et, dst):
        for _ in range(rng.choice((1, 1, 2, 3))):
            rows.append((src, et, dst, dated()))

    for i in range(7):
        for venue in ("F", "G"):
            if rng.random() < 0.6:
                add(f"e{i}", "POSTS_ON", venue)
        for w in range(4):
            if rng.random() < 0.3:
                add(f"e{i}", "CONTROLS", f"W{w}")
    for t in ("T1", "T2"):
        for w in range(4):
            roll = rng.random()
            if roll < 0.35:
                add(f"W{w}", "TX_INPUT", t)
            elif roll < 0.7:
                add(t, "TX_OUTPUT", f"W{w}")
    for _ in range(rng.randint(0, 3)):
        src = rng.choice([f"W{w}" for w in range(4)] + ["e0", "e1"])
        dst = rng.choice([f"W{w}" for w in range(4)])
        add(src, "PAID", dst)
    return nodes, rows


def test_the_step_bound_is_an_upper_bound_on_the_steps_taken(monkeypatch):
    """Every merge takes at most len(a) + len(b) steps; summed over every
    merge the transform makes, that never exceeds what the pre-count
    refused on. Checked over random forum, wallet and payment worlds."""
    rng = random.Random(24)
    took: list[int] = []
    monkeypatch.setattr(affiliation, "_overlap",
                        lambda a, b: took.append(len(a) + len(b)) or _overlap(a, b))
    monkeypatch.setattr(affiliation, "_last_overlap",
                        lambda a, b: took.append(len(a) + len(b)) or _last_overlap(a, b))
    exercised = 0
    for _ in range(150):
        nodes, rows = _random_world(rng)
        kwargs = {"families": ("forum", "wallet"), "preset": "all"}
        bound = _steps_bound(monkeypatch, nodes, rows, **kwargs)
        took.clear()
        _world(nodes, rows, **kwargs)
        assert sum(took) <= bound, (sum(took), bound)
        exercised += bool(took)
    assert exercised > 100


def test_the_period_refusal_is_worded_by_the_copy_rules():
    text = str(OneModeTooManyPeriods(1_234_567))
    assert "1,234,567" in text and f"{MAX_PERIOD_STEPS:,}" in text
    for bad in ("—", "–", " -- ", "(s)"):
        assert bad not in text
