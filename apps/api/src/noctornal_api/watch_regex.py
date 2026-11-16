"""Watch regexes, run under a bound the collector enforces.

A watch carries regular expressions an investigator wrote, and the text they run over is written by
the people under investigation. Python's `re` is a backtracking engine with no timeout that holds
the interpreter lock while it matches, so a thread cannot interrupt it: a pattern with a nested
repeat (`(a+)+$`) over a crafted post spins instead of raising, and inside the persist transaction
it would wedge a source's poll, its transaction and its lock.

The only bound that holds is a process the parent can kill. Each pattern is matched in a child
(`python -m noctornal_api.watch_regex`, started through lab_triage's bounded runner, as the forum
parser is; in production the isolated analysis worker) that limits its own CPU and memory before it
reads a byte, and that the parent kills when its wall clock runs out. Three clocks can end a
pattern, and a run reports all three in the same words, as a pattern that did not finish within its
time limit.

1. The child's CPU limit, CHILD_CPU_S: 5 seconds of CPU time from the start of the child process,
   so interpreter start-up counts. The kernel ends the child with SIGXCPU at the soft limit and the
   runner reads that as a timeout. This is what ends a pattern that spins, on Linux and macOS,
   usually before the wall clock does. Windows has no such limit.
2. The parent's wall clock for one batch of texts, PATTERN_WALL_S plus STARTUP_S: 8 seconds in all.
   STARTUP_S pays for starting the interpreter, which this clock also counts, so a pattern killed
   this way costs up to 8 seconds and not 5. It ends a child that is not using CPU (blocked, or on
   a host so loaded that its CPU time accrues slowly) and, on Windows, is the only thing that ends
   one.
3. The run's budget, RUN_BUDGET_S: 30 seconds for every pattern of one run together. A child is
   given the lesser of its 8 seconds and what is left of the budget, so the last pattern started
   may be stopped sooner. A pattern the budget never reached is reported as that and is not matched
   in the run at all.

A pattern is matched once per run for every watch that carries it, over every item's text, and is
tried again on the next run. One that never finishes therefore costs its seconds on every poll
until its watch is edited or stopped, and fails for every watch that carries it. A pattern with
more text than one batch (BATCH_BYTES) runs in one child per batch, each with its own clocks.

A pattern that does not finish is abandoned for the run and REPORTED (a WATCH_PATTERN warning, so
the run reads PARTIAL), never silently skipped: a dead watch that reads like a quiet one is worse
than a noisy one.

The collector asks for every verdict before it opens the persist transaction
(`CollectionService._regex_verdicts`), so the database holds no transaction or row lock while a
hostile pattern is being stopped. The poll's advisory lock is held through this phase. The budget
bounds the matching; it does not count the wait for a slot at the isolated worker
(`analysis_runner.QUEUE_WAIT_S`, 30 seconds) or the transfers to and from it, which are the worker
client's own bounds.

Not closed here: a memory-safety defect in the interpreter's own matcher, and the cost of a pattern
that is slow but finishes inside its limits. That one is not reported: it holds the run for as long
as it takes, up to the clocks above. A collection manager writes patterns through the console
(`POST /cases/{case_id}/collection/watches`, behind `watch.manage` and the case). That route bounds
a pattern's length and their number and only parses one; it never matches one, so this child is the
only place a pattern meets text.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field

#: The wall clock for one pattern over one batch of texts, before the allowance below. A pattern
#: that spins is ended sooner than this by CHILD_CPU_S on Linux and macOS; this is the bound for a
#: child that is not using CPU, and the only bound on Windows.
PATTERN_WALL_S = 5.0
#: Added to that for starting the child's interpreter, which the runner's wall clock also counts.
#: A pattern killed on the wall clock costs PATTERN_WALL_S plus STARTUP_S (8 seconds), and
#: RUN_BUDGET_S caps the sum.
STARTUP_S = 3.0
#: Every pattern of one run together. A run with many slow patterns stops
#: matching rather than holding its poll lock for ever. A child is given the lesser of its own
#: clock and what is left of this, so the last pattern started may be stopped sooner.
RUN_BUDGET_S = 30.0
#: The child's own CPU limit, in seconds of CPU time counted from the start of its process,
#: interpreter start-up included. It is set as a soft limit with a hard limit one second above
#: (lab_static.apply_limits): at the soft limit the kernel sends SIGXCPU, which the runner reads as
#: a timeout and never as a crash. Linux and macOS only.
CHILD_CPU_S = 5
CHILD_MEMORY_BYTES = 768 * 1024 * 1024
#: A batch of texts sent to one child. A single text larger than this goes
#: alone, whole: the text is never cut, because a match past a cut is a hit
#: the watch would silently miss.
BATCH_BYTES = 16 * 1024 * 1024
#: The child reads at most this much after its header.
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024
#: The child's answer is one boolean per text.
STDOUT_CAP = 4 * 1024 * 1024
_HEADER_CAP = 64 * 1024

#: The child. A module attribute so a test can point it at one that never
#: answers.
CHILD_ARGV: list[str] = [sys.executable, "-m", "noctornal_api.watch_regex"]
#: Its kind for `analysis_runner`: in production the isolated worker starts
#: the module this names (`analysis_worker.KIND_ARGV`), and a request that
#: named any other kind ran lab_static, which refuses the header.
CHILD_KIND = "watch_regex"

#: Why a pattern was not matched, by kind. `compile`: it is not a valid
#: expression. `limit`: it did not finish, or the child could not run.
COMPILE = "compile"
LIMIT = "limit"

_LIMIT_SENTENCES = {
    "timeout": ("it did not finish within its time limit on this run's text "
                "and was stopped, and it is tried again, at the same cost, on "
                "every run until its watch is edited or stopped"),
    "output_too_large": "its answer passed its cap and it was stopped",
    "start_failed": "the matching process could not be started",
    "crashed": "the matching process stopped without an answer",
    "bad_output": "the matching process's answer could not be read",
    "budget": ("this run's time for watch patterns was used up before it was "
               "reached, so it matched nothing in this run"),
}


@dataclass
class Verdicts:
    """What the bounded run established.

    `hits` maps (pattern, text) to whether the pattern matched that text.
    `failed` maps a pattern to (kind, reason) for one that was not matched:
    its texts have no entry in `hits`, so a lookup that finds none knows the
    pattern was reported, not evaluated."""

    hits: dict[tuple[str, str], bool] = field(default_factory=dict)
    failed: dict[str, tuple[str, str]] = field(default_factory=dict)


def _batches(texts: list[str]) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    size = 0
    for text in texts:
        weight = len(text) * 2 + 16
        if current and size + weight > BATCH_BYTES:
            batches.append(current)
            current, size = [], 0
        current.append(text)
        size += weight
    if current:
        batches.append(current)
    return batches


def _encode(pattern: str, texts: list[str]) -> bytes:
    # surrogatepass: a text with a lone surrogate (an undecodable byte kept
    # by an adapter) is data, not an error, and must reach the matcher.
    return json.dumps({"pattern": pattern, "texts": texts},
                      ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8", "surrogatepass")


def run(jobs: dict[str, list[str]], *, argv: list[str] | None = None,
        wall_s: float | None = None,
        budget_s: float | None = None) -> Verdicts:
    """Match each pattern against its texts in a bounded child.

    `jobs` maps a pattern to the texts to try it on. A pattern with no texts
    starts nothing. Patterns run one after another, each batch in its own
    child, so one that never finishes costs `wall_s` and not the others'
    verdicts."""
    import time

    from noctornal_api import lab_triage
    from noctornal_api.pinned_http import redact

    wall = PATTERN_WALL_S if wall_s is None else wall_s
    budget = RUN_BUDGET_S if budget_s is None else budget_s
    out = Verdicts()
    deadline = time.monotonic() + budget
    for pattern, texts in jobs.items():
        unique = list(dict.fromkeys(texts))
        if not pattern or not unique:
            continue
        for batch in _batches(unique):
            remaining = deadline - time.monotonic()
            if remaining <= 0.05:
                out.failed[pattern] = (LIMIT, _LIMIT_SENTENCES["budget"])
                break
            header = {"mode": "watch_regex", "cpu_s": CHILD_CPU_S,
                      "memory_bytes": CHILD_MEMORY_BYTES}
            result = lab_triage.run_child(
                header, (_encode(pattern, batch),),
                wall_s=max(0.5, min(wall + STARTUP_S, remaining)),
                stdout_cap=STDOUT_CAP, argv=argv or CHILD_ARGV,
                kind=CHILD_KIND)
            if not result.ok:
                # The sandbox's own state (no worker, a busy one, an answer that is not one) says
                # nothing about the pattern, and is never reported as a crashed matcher.
                sentence = (f"{lab_triage.CHILD_FAILURES[result.failure]}, so it "
                            f"was not matched on this run"
                            if result.failure in lab_triage.CHILD_FAILURES
                            and result.failure not in _LIMIT_SENTENCES
                            else _LIMIT_SENTENCES.get(result.failure or "crashed",
                                                      _LIMIT_SENTENCES["crashed"]))
                out.failed[pattern] = (LIMIT, sentence)
                break
            try:
                answer = json.loads(result.output.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                answer = None
            if not isinstance(answer, dict):
                out.failed[pattern] = (LIMIT, _LIMIT_SENTENCES["bad_output"])
                break
            if answer.get("compile_error") is not None:
                out.failed[pattern] = (
                    COMPILE, redact(str(answer["compile_error"]))[:200])
                break
            verdict = answer.get("hits")
            if (answer.get("ok") is not True or not isinstance(verdict, list)
                    or len(verdict) != len(batch)
                    or not all(isinstance(v, bool) for v in verdict)):
                out.failed[pattern] = (LIMIT, _LIMIT_SENTENCES["bad_output"])
                break
            for text, hit in zip(batch, verdict, strict=True):
                out.hits[(pattern, text)] = hit
        else:
            continue
        # A pattern that failed part-way keeps none of its earlier verdicts:
        # half an answer would make the watch fire on some posts and not
        # others, which reads as a quiet watch.
        for key in [k for k in out.hits if k[0] == pattern]:
            del out.hits[key]
    return out


def _child_main() -> int:
    """`python -m noctornal_api.watch_regex`: one header line (JSON: the
    limits), then one JSON document: the pattern and its texts. Answers one
    JSON document on stdout: a boolean per text, or `compile_error`. Errors
    are reported by CLASS, never by message: a message can quote the text."""
    from noctornal_api import lab_static

    stdin = sys.stdin.buffer
    line = stdin.readline(_HEADER_CAP + 1)
    try:
        header = json.loads(line.decode("utf-8"))
        lab_static.apply_limits(int(header.get("memory_bytes") or CHILD_MEMORY_BYTES),
                                int(header.get("cpu_s") or CHILD_CPU_S))
        body = stdin.read(MAX_PAYLOAD_BYTES + 1)
        if len(body) > MAX_PAYLOAD_BYTES:
            raise ValueError("payload over its cap")
        doc = json.loads(body.decode("utf-8", "surrogatepass"))
        pattern, texts = doc["pattern"], doc["texts"]
        if not isinstance(pattern, str) or not isinstance(texts, list):
            raise TypeError("malformed")
        try:
            compiled = re.compile(pattern, re.I)
        except re.error as exc:
            answer = {"ok": False, "compile_error": str(exc)[:200]}
        else:
            answer = {"ok": True,
                      "hits": [compiled.search(t) is not None for t in texts]}
    except Exception as exc:  # noqa: BLE001 - reported by class, never by text
        answer = {"ok": False, "error": type(exc).__name__[:64]}
    sys.stdout.buffer.write(json.dumps(answer, separators=(",", ":")).encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the collector
    sys.exit(_child_main())
