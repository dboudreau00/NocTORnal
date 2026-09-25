"""The cron entry under the collection foundation (2026-09-24): it polls
as the system, counts blocked, rate-limited, held and too-long sources,
exits 1 when a person is needed, and reserves a long
poll's budget without changing how RSS passes are clocked. Run for real
against stand-ins, as test_collection_poll_script.py does. No database.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "scripts" / "collection_poll.py"


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("collection_poll_held", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(monkeypatch, capsys, *, sources, outcome=None, seconds=None,
         held=0, argv=(), step=10.0):
    module = _load()
    clock = [1000.0]
    calls = []

    class Service:
        def __init__(self, _conn):
            pass

        def due_sources(self):
            return [{"id": s, "due_at": None, "health": "OK",
                     "consecutive_failures": 0} for s in sources]

        def held_count(self):
            return held

        def poll_seconds(self, source_id):
            return (seconds or {}).get(source_id, 0)

        def run_once(self, source_id, *, actor_id):
            calls.append((source_id, actor_id))
            clock[0] += step
            status = (outcome or {}).get(source_id, "OK")
            return SimpleNamespace(items_seen=1, items_new=1, watch_hits=0,
                                   warnings=[], run_id=f"run-{source_id}",
                                   status=status,
                                   error=None if status == "OK" else "why")

    monkeypatch.setattr(module, "connect", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(module, "blocking_failures", lambda _c: [])
    monkeypatch.setattr(module, "CollectionService", Service)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr("sys.argv", ["collection_poll.py", *argv])
    code = module.main()
    return code, capsys.readouterr().out, calls


def test_the_pass_polls_as_the_system(monkeypatch, capsys):
    _code, _out, calls = _run(monkeypatch, capsys, sources=["a", "b"])
    assert [actor for _s, actor in calls] == [None, None]


def test_the_counters_line_keeps_its_order_and_adds_blocked_rate_limited_and_held(
        monkeypatch, capsys):
    _code, out, _calls = _run(monkeypatch, capsys, sources=["a", "b", "c"],
                              outcome={"b": "BLOCKED", "c": "RATE_LIMITED"}, held=4)
    line = [ln for ln in out.splitlines() if ln.startswith("due=")][0]
    keys = [part.split("=")[0] for part in line.split()]
    assert keys == ["due", "selected", "polled", "skipped", "deferred", "failed",
                    "blocked", "rate_limited", "held", "too_long", "items_seen",
                    "items_new", "watch_hits", "warnings"]
    assert "polled=1 skipped=0 deferred=0 failed=0 blocked=1 rate_limited=1 held=4" in line


def test_a_blocked_poll_exits_one_and_a_rate_limited_one_does_not(monkeypatch, capsys):
    blocked, out, _ = _run(monkeypatch, capsys, sources=["a"], outcome={"a": "BLOCKED"})
    assert blocked == 1 and "blocked a  run run-a" in out
    limited, _out, _ = _run(monkeypatch, capsys, sources=["a"],
                            outcome={"a": "RATE_LIMITED"})
    assert limited == 0


def test_held_sources_never_make_the_exit_non_zero(monkeypatch, capsys):
    code, _out, _ = _run(monkeypatch, capsys, sources=[], held=3)
    assert code == 0


def test_the_pass_clock_reserves_a_long_polls_budget(monkeypatch, capsys):
    code, out, calls = _run(monkeypatch, capsys, sources=["f1", "f2"],
                            seconds={"f1": 90, "f2": 90},
                            argv=["--max-seconds", "150"], step=90.0)
    assert [s for s, _a in calls] == ["f1"], "90 s spent plus 90 s needed passes 150"
    assert "deferred=1" in out and code == 0


def test_the_first_poll_of_a_pass_always_starts(monkeypatch, capsys):
    _code, _out, calls = _run(monkeypatch, capsys, sources=["f1"],
                              seconds={"f1": 140}, argv=["--max-seconds", "150"])
    assert [s for s, _a in calls] == ["f1"]


def test_a_source_longer_than_the_pass_is_counted_too_long_and_exits_one(
        monkeypatch, capsys):
    code, out, calls = _run(monkeypatch, capsys, sources=["long", "rss"],
                            seconds={"long": 300}, argv=["--max-seconds", "150"])
    assert [s for s, _a in calls] == ["rss"], "never started, even first"
    assert "too_long long  needs 300 seconds" in out and "too_long=1" in out
    assert code == 1


def test_no_clock_means_no_limit(monkeypatch, capsys):
    code, out, calls = _run(monkeypatch, capsys, sources=["long"],
                            seconds={"long": 300}, argv=["--max-seconds", "0"])
    assert [s for s, _a in calls] == ["long"] and "too_long=0" in out and code == 0


def test_rss_passes_are_clocked_as_before(monkeypatch, capsys):
    _code, out, calls = _run(monkeypatch, capsys, sources=["s0", "s1", "s2", "s3"],
                             argv=["--max-seconds", "150"], step=100.0)
    assert [s for s, _a in calls] == ["s0", "s1"]
    assert "selected=4 polled=2 skipped=0 deferred=2 failed=0" in out


def test_the_pass_reads_the_schedule_once_for_due_and_held(monkeypatch, capsys):
    """2026-09-25: due then held was two readings, and the
    first moves a source resting outside its persona's hours, so the
    second under-counted `held`. A service offering due_and_held is asked
    once, and neither of the two single readings is."""
    module = _load()
    asked = []

    class Service:
        def __init__(self, _conn):
            pass

        def due_and_held(self):
            asked.append("due_and_held")
            return ([{"id": "a", "due_at": None, "health": "OK",
                      "consecutive_failures": 0}],
                    [{"id": "resting"}, {"id": "uncovered"}])

        def due_sources(self):
            asked.append("due_sources")
            return []

        def held_count(self):
            asked.append("held_count")
            return 0

        def run_once(self, source_id, *, actor_id):
            return SimpleNamespace(items_seen=0, items_new=0, watch_hits=0,
                                   warnings=[], run_id="run-a", status="OK",
                                   error=None)

    monkeypatch.setattr(module, "connect", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(module, "blocking_failures", lambda _c: [])
    monkeypatch.setattr(module, "CollectionService", Service)
    monkeypatch.setattr("sys.argv", ["collection_poll.py"])
    assert module.main() == 0
    assert asked == ["due_and_held"]
    line = [ln for ln in capsys.readouterr().out.splitlines()
            if ln.startswith("due=")][0]
    assert "due=1 selected=1 polled=1" in line and "held=2" in line
