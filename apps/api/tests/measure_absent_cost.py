"""Time a hidden id against a missing one, route by route (decision 230). Evidence, not a gate.

    python apps/api/tests/measure_absent_cost.py [--family NAME]... [--pairs 60] [--warmup 10]
                                                 [--assert-within MS]

Asks each route of `absent_families.FAMILIES` in process, through the test client, with the id
hidden from the caller and the id that names nothing, in interleaved pairs (hidden, missing, hidden,
missing, ...) after a warm-up, with the garbage collector off around each request. It prints, per
route, the median of each, the median of the paired differences and a 95 per cent bootstrap interval
for it (1,000 resamples, a fixed seed), and exits 0 unless `--assert-within MS` is given and a
route's median difference is further than MS from zero.

Needs the suite's database and environment (DATABASE_URL, NOCTORNAL_APP_DB_ROLE and the rest; the
row security tests' set-up), and asks as the request role. The name has no `test_` prefix, so pytest
never collects it: CI fails on a skipped test, and a timing is not a verdict. What the two ids send
and record is pinned by `test_absent_element_work_pg.py`; this says what that costs on this host.
"""
from __future__ import annotations

import argparse
import gc
import random
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path

#: Interval and resample count, fixed so a run reproduces its own figures.
RESAMPLES = 1000
SEED = 230


@dataclass(frozen=True)
class Summary:
    """One route's figures, in milliseconds."""
    hidden_ms: float
    missing_ms: float
    difference_ms: float
    low_ms: float
    high_ms: float


def summarise(hidden_ns: list[int], missing_ns: list[int], *,
              resamples: int = RESAMPLES, seed: int = SEED) -> Summary:
    """The medians of two paired series of request times in nanoseconds, the median of their
    differences (hidden less missing) and its 95 per cent bootstrap interval."""
    if not hidden_ns or len(hidden_ns) != len(missing_ns):
        raise ValueError("the two series must be paired and not empty")
    diffs = [(h - m) / 1e6 for h, m in zip(hidden_ns, missing_ns, strict=True)]
    rng = random.Random(seed)
    boot = sorted(statistics.median(rng.choices(diffs, k=len(diffs)))
                  for _ in range(resamples))
    return Summary(
        hidden_ms=statistics.median(hidden_ns) / 1e6,
        missing_ms=statistics.median(missing_ns) / 1e6,
        difference_ms=statistics.median(diffs),
        low_ms=boot[round(0.025 * (resamples - 1))],
        high_ms=boot[round(0.975 * (resamples - 1))])


def _timed(client, call, headers) -> int:
    method, url, body = call
    gc.collect()
    gc.disable()
    try:
        started = time.perf_counter_ns()
        client.request(method, url, headers=headers, json=body)
        return time.perf_counter_ns() - started
    finally:
        gc.enable()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--family", action="append", default=[],
                        help="a route's name in FAMILIES; every route when left out")
    parser.add_argument("--pairs", type=int, default=60)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--assert-within", type=float, default=None, metavar="MS")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import os

    import absent_families as af
    import rls_support as s
    from noctornal_api.db import ASSUME_ROLE_ENV

    if not (os.environ.get("DATABASE_URL") and s.APP_ROLE):
        parser.error("DATABASE_URL and NOCTORNAL_APP_DB_ROLE are needed, as for the "
                     "row security tests")
    os.environ[ASSUME_ROLE_ENV] = "1"
    families = [f for f in af.FAMILIES if not args.family or f.name in args.family]
    if not families:
        parser.error(f"no route is named {args.family}")
    owner = s.owner_conn()
    worst = 0.0
    try:
        world = af.World(owner)
        client = af.make_client()
        for family in families:
            headers = world.headers(getattr(world, family.who))
            ids = family.probes(world)
            hidden = family.call(world, ids["hidden"])
            missing = family.call(world, ids["missing"])
            for _ in range(args.warmup):
                _timed(client, hidden, headers)
                _timed(client, missing, headers)
            times: dict[str, list[int]] = {"hidden": [], "missing": []}
            for _ in range(args.pairs):
                times["hidden"].append(_timed(client, hidden, headers))
                times["missing"].append(_timed(client, missing, headers))
            got = summarise(times["hidden"], times["missing"])
            worst = max(worst, abs(got.difference_ms))
            print(f"{family.name:44} hidden {got.hidden_ms:7.2f} ms  "
                  f"missing {got.missing_ms:7.2f} ms  "
                  f"paired difference {got.difference_ms:+6.2f} ms  "
                  f"95% [{got.low_ms:+6.2f}, {got.high_ms:+6.2f}]", flush=True)
    finally:
        af.cleanup(owner)
        owner.close()
    if args.assert_within is not None and worst > args.assert_within:
        print(f"a median difference of {worst:.2f} ms is outside "
              f"{args.assert_within:.2f} ms")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
