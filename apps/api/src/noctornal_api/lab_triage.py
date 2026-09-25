"""Static triage: the queue, the bounded runner and what a run writes (F11,
with F12's YARA step and compile queue), 2026-09-24.

## Shape

A machine step that runs AFTER submission, outside the upload request:
`submit()` enqueues a run in its insert transaction, a cron pass
(`scripts/lab_triage.py`) drains the queue, and an analyst's "run it now"
enqueues and, when a slot is free, starts the run after the response
(`run_queued_detached`). Decision 30 holds: functions you call, no
resident worker. A run writes nothing to `core.*` or `collect.*` and
raises no proposal: machines propose only when an analyst clicks.

## One run, in this order

1. CLAIM, one transaction: the next QUEUED run whose sample has none
   RUNNING, by priority (an analyst's request, then submissions and
   retries, then retrohunts and backfills) then age, FOR
   UPDATE SKIP LOCKED. Refusals end it SKIPPED having read nothing. The
   per-run session lock is taken INSIDE this transaction, before COMMIT,
   so a sweep can never see the run RUNNING with its lock free.
2. MATERIALISE with no transaction open: `samples._verified_plaintext`,
   which decrypts, verifies and, on a mismatch, commits the tamper alarm
   on its own and raises. A failed check is FAILED and never retried.
3. CUSTODY, committed, only after verification and before a byte leaves
   this process: one SCANNED row per person whose request caused the read
   and one SYSTEM row when a scheduled trigger did. The detail
   names the run and the byte count, never the steps or the trigger, so
   custody says who caused a read and not what a hidden rule set hunts.
4. CHILDREN, one per step, each bounded (`lab_static`, `run_child`).
5. RESULTS, one transaction: the sample re-read FOR UPDATE; a sample
   rejected, excluded or whose case closed meanwhile has its findings
   discarded. Otherwise the hashes, the gaps for the steps this run
   covered, QUARANTINED to TRIAGED, the machine rows, the run DONE (only
   while it is still RUNNING) and the audit row LAST. A failure here marks
   the run FAILED on its own, retried only for a lock timeout.
6. The plaintext reference is dropped and both locks released.

## Liveness without a clock

A run's owner holds a session advisory lock for it. `sweep_abandoned`
takes that lock for each RUNNING run: getting it proves the owner is gone,
so the run is ABANDONED and re-queued as a RETRY under `MAX_ATTEMPTS`,
carrying its requesters (a requested read never becomes SYSTEM on retry).
The cron pass and the on-demand path both sweep first, so a restart
cannot leave a permanent "already running". Compile jobs have the same
idiom. Slots, also advisory locks, bound the runs in the
whole deployment (API workers and cron together).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import fuzzyhash, lab_static
from noctornal_api.config import DEFAULT_UPLOAD_CAP, SAMPLE_CAP_ENV, parse_size

log = logging.getLogger("noctornal.lab_triage")

MIB = 1 << 20
GIB = 1 << 30

# ---------------------------------------------------------------------------
# Settings (one reader: the runner, readiness and the boot check)
# ---------------------------------------------------------------------------

MEMORY_ENV = "NOCTORNAL_SAMPLE_ANALYSIS_MEMORY"
MAX_BYTES_ENV = "NOCTORNAL_SAMPLE_ANALYSIS_MAX_BYTES"
FUZZY_MAX_ENV = "NOCTORNAL_SAMPLE_FUZZY_MAX_BYTES"
TIMEOUT_ENV = "NOCTORNAL_SAMPLE_ANALYSIS_TIMEOUT_S"
CONCURRENCY_ENV = "NOCTORNAL_SAMPLE_ANALYSIS_CONCURRENCY"
SETTINGS_ENV = (MEMORY_ENV, MAX_BYTES_ENV, FUZZY_MAX_ENV, TIMEOUT_ENV,
                CONCURRENCY_ENV)

#: What a parser and the interpreter take beside the sample in the child.
PARSER_OVERHEAD = 512 * MIB

MAX_ATTEMPTS = 3
CHILD_STDOUT_CAP = 8 * MIB
STDERR_KEPT = 4 * 1024
#: The parent's wall clock beyond the child's own CPU limit.
WALL_GRACE_S = 10

STEPS = ("pe", "fuzzy", "yara")
#: The stored gap each step settles.
STEP_GAPS = {"pe": ("imphash", "rich_header_hash"),
             "fuzzy": ("ssdeep", "tlsh"), "yara": ("yara",)}

TRIGGER_PRIORITY = {"ON_DEMAND": 0, "SUBMIT": 1, "RETRY": 1, "RETROHUNT": 2,
                    "BACKFILL": 2}
#: The triggers nobody asked for in person.
SCHEDULED = ("SUBMIT", "BACKFILL", "RETRY")


@dataclass(frozen=True)
class AnalysisSettings:
    memory_bytes: int
    max_bytes: int
    fuzzy_max_bytes: int
    timeout_s: int
    concurrency: int


def _size(env, name: str) -> tuple[int | None, str | None]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return None, None
    try:
        return parse_size(raw), None
    except ValueError:
        return None, (f"{name} is not a size (bytes, or a whole number with a "
                      f"binary K, M or G, such as 2GiB)")


def _whole(env, name: str, low: int, high: int, default: int,
           unit: str) -> tuple[int | None, str | None]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default, None
    if not raw.isdigit() or not low <= int(raw) <= high:
        return None, f"{name} must be a whole number {unit} from {low} to {high}"
    return int(raw), None


def analysis_settings(env=None) -> tuple[AnalysisSettings | None, str | None]:
    """`(settings, None)` or `(None, problem)`. The problem names the
    variable and never its value (it reaches a boot log and readiness)."""
    env = os.environ if env is None else env
    memory, problem = _size(env, MEMORY_ENV)
    if problem:
        return None, problem
    memory = memory or 2 * GIB
    if not 256 * MIB <= memory <= 64 * GIB:
        return None, f"{MEMORY_ENV} must be between 256 MiB and 64 GiB"
    room = (memory - PARSER_OVERHEAD) // 3
    declared, problem = _size(env, MAX_BYTES_ENV)
    if problem:
        return None, problem
    if declared is not None:
        if declared < 1 or declared > room:
            return None, (f"{MAX_BYTES_ENV} is larger than a third of what "
                          f"{MEMORY_ENV} leaves after the parser, so the "
                          f"analysis child could not hold a sample this large "
                          f"with its parser")
        max_bytes = declared
    else:
        try:
            cap = parse_size(env.get(SAMPLE_CAP_ENV) or "") \
                if (env.get(SAMPLE_CAP_ENV) or "").strip() else DEFAULT_UPLOAD_CAP
        except ValueError:
            cap = DEFAULT_UPLOAD_CAP
        max_bytes = min(cap, room)
    fuzzy, problem = _size(env, FUZZY_MAX_ENV)
    if problem:
        return None, problem
    if fuzzy is not None:
        if fuzzy < 1 or fuzzy > max_bytes:
            return None, (f"{FUZZY_MAX_ENV} must be at most the analysis "
                          f"maximum ({MAX_BYTES_ENV})")
    else:
        fuzzy = min(32 * MIB, max_bytes)
    timeout, problem = _whole(env, TIMEOUT_ENV, 10, 3600, 300, "of seconds")
    if problem:
        return None, problem
    concurrency, problem = _whole(env, CONCURRENCY_ENV, 1, 8, 1, "of runs")
    if problem:
        return None, problem
    return AnalysisSettings(memory, max_bytes, fuzzy, timeout, concurrency), None


def settings_or_default() -> AnalysisSettings:
    """For a development process with an unusable setting: the defaults,
    so a typo stops nothing locally. Production refuses to start on the
    same problem (config.verify_environment)."""
    settings, _problem = analysis_settings()
    return settings or analysis_settings({})[0]


def limits_words(settings: AnalysisSettings, kind: str | None = None) -> dict:
    """The limits line the run row, the card and readiness show."""
    kind = kind or lab_static.limits_kind()
    return {"kind": kind, "words": lab_static.LIMITS_WORDS[kind],
            "memory_bytes": settings.memory_bytes if kind == "rlimit" else None,
            "timeout_s": settings.timeout_s}


# ---------------------------------------------------------------------------
# The child
# ---------------------------------------------------------------------------

#: How the child is started. A module attribute so a test can point it at
#: a script that floods its output or never returns.
CHILD_ARGV: list[str] = [sys.executable, "-m", "noctornal_api.lab_static"]


def _package_root() -> str:
    import noctornal_api
    return os.path.dirname(os.path.dirname(os.path.abspath(
        noctornal_api.__file__)))


def child_env() -> dict[str, str]:
    """The child's whole environment: a PATH, what Windows needs to start
    an interpreter, a locale, two flags that stop it writing, and where
    THIS process's code is, so parent and child run the same module. No
    NOCTORNAL_*, DATABASE_URL, MINIO_*, SAMPLE_*, PRESERVE_*, REDIS_URL or
    SMTP_*: the data key and the KEK never reach a child. (See
    `lab_static`'s docstring for what it can still read on Linux.)"""
    env = {"PATH": os.environ.get("PATH", os.defpath),
           "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1",
           "PYTHONPATH": _package_root()}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if os.environ.get(name):
                env[name] = os.environ[name]
    return env


@dataclass
class ChildResult:
    ok: bool
    output: bytes = b""
    #: None, or: start_failed | timeout | output_too_large | crashed
    failure: str | None = None
    returncode: int | None = None


#: The sentence for each way a child can fail, by kind.
CHILD_FAILURES = {
    "start_failed": "the analysis process could not be started",
    "timeout": "the step did not finish within its time limit and was stopped",
    "output_too_large": ("the step's output passed its cap and the process was "
                         "stopped"),
    "crashed": "the analysis process stopped without an answer",
    "bad_output": "the analysis process's answer could not be read",
    "version_mismatch": ("the analysis process reported a different parser "
                         "version from this server's"),
}


def run_child(header: dict, payloads: tuple[bytes, ...] = (), *,
              wall_s: float, stdout_cap: int = CHILD_STDOUT_CAP,
              argv: list[str] | None = None) -> ChildResult:
    """Start one child, feed it over stdin, read its answer under a cap
    and a wall clock, and never let it outlive either.

    The sample is written 1 MiB at a time by a writer thread, never as one
    concatenated frame; stdout is read incrementally and the child killed
    the moment it passes `stdout_cap`; stderr is drained so a chatty child
    cannot block, and its first `STDERR_KEPT` bytes go to this server's
    log only. Never `preexec_fn`, which is unsafe in a threaded server: a
    new session (POSIX) or process group (Windows) instead, so the kill
    takes the whole group."""
    line = json.dumps({"protocol": lab_static.PROTOCOL, **header},
                      separators=(",", ":")).encode() + b"\n"
    if len(line) > lab_static.HEADER_CAP:
        raise ValueError("header too large")
    extra: dict = {}
    if os.name == "posix":
        extra["start_new_session"] = True
    else:
        extra["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP
                                  | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        proc = subprocess.Popen(argv or CHILD_ARGV, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=child_env(), close_fds=True, **extra)
    except OSError:
        log.warning("the static triage child could not be started",
                    exc_info=True)
        return ChildResult(False, failure="start_failed")
    parts: list[bytes] = []
    state = {"n": 0, "over": False}
    err = bytearray()

    def kill() -> None:
        try:
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except (OSError, ProcessLookupError):
            pass

    def writer() -> None:
        try:
            proc.stdin.write(line)
            for payload in payloads:
                view = memoryview(payload)
                for i in range(0, len(view), MIB):
                    proc.stdin.write(view[i:i + MIB])
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def reader() -> None:
        while True:
            try:
                chunk = proc.stdout.read1(1 << 16)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            state["n"] += len(chunk)
            if state["n"] > stdout_cap:
                state["over"] = True
                kill()
                break
            parts.append(chunk)

    def drain() -> None:
        while True:
            try:
                chunk = proc.stderr.read1(1 << 16)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            if len(err) < STDERR_KEPT:
                err.extend(chunk[:STDERR_KEPT - len(err)])

    threads = [threading.Thread(target=t, daemon=True)
               for t in (writer, reader, drain)]
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(timeout=wall_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill()
        proc.wait()
    for t in threads:
        t.join(timeout=5)
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        try:
            pipe.close()
        except (OSError, ValueError):
            pass
    if err:
        # The server log, never the UI, the audit chain or the run row: a
        # parser's message can quote hostile bytes.
        log.info("static triage child stderr (first %d bytes): %r",
                 len(err), bytes(err))
    if state["over"]:
        return ChildResult(False, failure="output_too_large",
                           returncode=proc.returncode)
    if timed_out:
        return ChildResult(False, failure="timeout", returncode=proc.returncode)
    if proc.returncode != 0:
        return ChildResult(False, b"".join(parts), failure="crashed",
                           returncode=proc.returncode)
    return ChildResult(True, b"".join(parts), returncode=0)


def _parent_versions() -> dict:
    return {"pefile": lab_static._version("pefile"),
            "yara_x": lab_static._version("yara-x")}


def _child_json(result: ChildResult) -> tuple[dict | None, str | None]:
    """The child's JSON answer, or the failure kind."""
    if not result.ok:
        return None, result.failure or "crashed"
    try:
        out = json.loads(result.output.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "bad_output"
    if not isinstance(out, dict) or not out.get("ok"):
        return None, "bad_output"
    if out.get("versions") != _parent_versions():
        return None, "version_mismatch"
    return out, None


def selftest(settings: AnalysisSettings, *, probe: dict | None = None,
             wall_s: float = 10) -> dict:
    """Start a child in selftest mode: what it can run, its limits, the
    environment keys it sees, and what it could reach (lab_static
    docstring). Raises RuntimeError with a fixed sentence on failure."""
    result = run_child({"mode": "selftest",
                        "limits": {"memory_bytes": settings.memory_bytes,
                                   "cpu_s": 10},
                        "probe": probe or {}}, wall_s=wall_s)
    out, failure = _child_json(result)
    if out is None:
        raise RuntimeError(CHILD_FAILURES.get(failure, CHILD_FAILURES["crashed"]))
    return out


# ---------------------------------------------------------------------------
# The queue
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EnqueueResult:
    run_id: UUID | None
    merged: bool = False
    refused: str | None = None


#: How a request merges into the sample's one queued run. Shared by
#: `enqueue` and the RETRY a sweep queues, so both merge the same way: the
#: verifier of 2026-09-24 found the RETRY path unioned the steps but not
#: the rule set versions, so a retried yara-scoped request merged into a
#: queued run lost its versions or had its scope widened (F11). Steps are
#: unioned; an empty version list on a run that includes the yara step
#: means every open activation at run time and absorbs a list; the merged
#: run takes the highest priority it absorbs, with that request's trigger
#: and person.
_MERGE_INTO_QUEUED = """ON CONFLICT (sample_id) WHERE status = 'QUEUED' DO UPDATE SET
              requests = r.requests || EXCLUDED.requests,
              priority = least(r.priority, EXCLUDED.priority),
              trigger = CASE WHEN EXCLUDED.priority < r.priority
                             THEN EXCLUDED.trigger ELSE r.trigger END,
              requested_by = CASE WHEN EXCLUDED.priority < r.priority
                                   AND EXCLUDED.requested_by IS NOT NULL
                                  THEN EXCLUDED.requested_by
                                  ELSE coalesce(r.requested_by,
                                                EXCLUDED.requested_by) END,
              steps = ARRAY(SELECT DISTINCT x FROM unnest(r.steps
                             || EXCLUDED.steps) AS x ORDER BY x),
              yara_version_ids = CASE
                WHEN ('yara' = ANY(r.steps)
                      AND cardinality(r.yara_version_ids) = 0)
                  OR ('yara' = ANY(EXCLUDED.steps)
                      AND cardinality(EXCLUDED.yara_version_ids) = 0)
                THEN '{}'::uuid[]
                ELSE ARRAY(SELECT DISTINCT x FROM unnest(r.yara_version_ids
                            || EXCLUDED.yara_version_ids) AS x) END"""


def enqueue(conn: psycopg.Connection, sample_id: UUID, *, trigger: str,
            requested_by: UUID | None = None, steps: tuple[str, ...] = STEPS,
            yara_version_ids: tuple = (), via: str | None = None,
            priority: int | None = None) -> EnqueueResult:
    """Queue a run, or merge the request into the sample's queued run.

    Steps are unioned; version lists are unioned, and an empty list on a
    request that includes the yara step (every open activation at run
    time) absorbs a list. The merged run takes the highest priority it
    absorbs, and its trigger and named person are the highest-priority
    request's. EVERY request is appended to `requests`, with its person
    and trigger, because custody names each person whose request caused
    the read. Nothing is inserted for a rejected sample or one
    the Lab's exclusions hold back. Runs inside the caller's transaction
    when there is one (submit's), and on its own otherwise."""
    from noctornal_api.samples import lab_exclusions_sql
    if trigger not in TRIGGER_PRIORITY:
        raise ValueError(f"unknown trigger {trigger!r}")
    if trigger in ("ON_DEMAND", "RETROHUNT") and requested_by is None:
        raise ValueError("a requested run names the person who asked")
    steps = tuple(sorted(set(steps)))
    if not steps or not set(steps) <= set(STEPS):
        raise ValueError("unknown static triage step")
    prio = TRIGGER_PRIORITY[trigger] if priority is None else priority
    request = {"trigger": trigger,
               "requested_by": str(requested_by) if requested_by else None}
    if via:
        request["via"] = via
    row = conn.execute(
        f"""INSERT INTO lab.static_run AS r
                (sample_id, trigger, requested_by, requests, priority, steps,
                 yara_version_ids)
            SELECT s.id, %(trigger)s, %(by)s,
                   jsonb_build_array(%(request)s::jsonb
                                     || jsonb_build_object('at', now())),
                   %(prio)s, %(steps)s::text[], %(vids)s::uuid[]
              FROM lab.sample s
             WHERE s.id = %(sample)s AND s.state <> 'REJECTED'
               AND {lab_exclusions_sql('s')}
            {_MERGE_INTO_QUEUED}
            RETURNING r.id, (r.xmax::text <> '0')""",
        {"trigger": trigger, "by": requested_by, "request": Json(request),
         "prio": prio, "steps": list(steps),
         "vids": [str(v) for v in yara_version_ids], "sample": sample_id}
    ).fetchone()
    if row is None:
        return EnqueueResult(None, refused="rejected_or_excluded")
    return EnqueueResult(row[0], merged=bool(row[1]))


def running_run(conn: psycopg.Connection, sample_id: UUID) -> UUID | None:
    row = conn.execute(
        "SELECT id FROM lab.static_run WHERE sample_id = %s "
        "AND status = 'RUNNING'", (sample_id,)).fetchone()
    return row[0] if row else None


# -- locks -------------------------------------------------------------------

SLOT_LOCK = "noctornal.static_triage.slot"


def take_slot(conn: psycopg.Connection, concurrency: int) -> int | None:
    """The first free slot below `concurrency`, held by this session."""
    for n in range(concurrency):
        if conn.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, %s))",
                        (SLOT_LOCK, n)).fetchone()[0]:
            return n
    return None


def release_slot(conn: psycopg.Connection, n: int) -> None:
    conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, %s))",
                 (SLOT_LOCK, n))


def slot_free(conn: psycopg.Connection, concurrency: int) -> bool:
    """A hint for the route's answer: whether a slot is free right now."""
    n = take_slot(conn, concurrency)
    if n is None:
        return False
    release_slot(conn, n)
    return True


def _run_lock(conn, fn: str, run_id) -> bool:
    return bool(conn.execute(
        f"SELECT {fn}(hashtextextended('noctornal.static_run:' || %s::text, 0))",
        (str(run_id),)).fetchone()[0])


# -- gaps --------------------------------------------------------------------

PENDING_REASON = "static triage has not run yet; it runs after submission"
ABANDONED_REASON = "the process running it stopped before it finished"
INTEGRITY_REASON = ("integrity check failed: the stored bytes do not match "
                    "the recorded SHA-256; nothing was analysed")
MATERIALISE_REASON = "the sample's bytes could not be read for triage"
DISCARDED_REASON = ("rejected, withdrawn or closed while triage ran; findings "
                    "discarded")
RESULTS_REASON = "the findings could not be written"
TOO_LARGE_REASON = (f"larger than {MAX_BYTES_ENV}; static triage did not "
                    f"read it")
ENGINE_ABSENT_REASON = ("the YARA engine (yara-x) is not installed in this "
                        "deployment: install noctornal-api[yara]")


def _rewrite_gaps(gaps: list, updates: dict[str, dict | None], *,
                  only_pending: bool = False) -> list:
    """`gaps` with each named step replaced (a dict) or removed (None).
    Steps not named are left as they were; with `only_pending` a step is
    touched only while its stored entry is still pending."""
    out = []
    seen = set()
    for g in gaps or []:
        step = g.get("step") if isinstance(g, dict) else None
        if step in updates:
            seen.add(step)
            if only_pending and g.get("status") != "pending":
                out.append(g)
                continue
            if updates[step] is not None:
                out.append({"step": step, **updates[step]})
            continue
        out.append(g)
    if not only_pending:
        for step, entry in updates.items():
            if step not in seen and entry is not None:
                out.append({"step": step, **entry})
    return out


def _gap_steps(steps) -> list[str]:
    return [g for s in steps for g in STEP_GAPS.get(s, ())]


def _set_gaps(conn, sample_id, updates: dict[str, dict | None], *,
              only_pending: bool = False) -> None:
    row = conn.execute("SELECT triage_gaps FROM lab.sample WHERE id = %s "
                       "FOR UPDATE", (sample_id,)).fetchone()
    if row is None:
        return
    conn.execute("UPDATE lab.sample SET triage_gaps = %s WHERE id = %s",
                 (Json(_rewrite_gaps(row[0], updates,
                                     only_pending=only_pending)), sample_id))


# -- sweep -------------------------------------------------------------------

def _requeue(conn, run: dict, attempt: int) -> None:
    """A RETRY of `run`, carrying its requesters, steps, versions and
    priority. Merged into a queued run when there is one, by the same
    rule `enqueue` merges by (`_MERGE_INTO_QUEUED`), and never queued for
    a sample the Lab's exclusions now hold back."""
    from noctornal_api.samples import lab_exclusions_sql
    conn.execute(
        f"""INSERT INTO lab.static_run AS r
               (sample_id, trigger, requested_by, requests, priority, steps,
                yara_version_ids, attempt)
           SELECT s.id, 'RETRY', %(by)s, %(requests)s::jsonb, %(prio)s,
                  %(steps)s::text[], %(vids)s::uuid[], %(attempt)s
             FROM lab.sample s
            WHERE s.id = %(sample)s AND s.state <> 'REJECTED'
              AND {lab_exclusions_sql('s')}
           {_MERGE_INTO_QUEUED}""",
        {"by": run["requested_by"], "requests": Json(run["requests"]),
         "prio": run["priority"], "steps": list(run["steps"]),
         "vids": [str(v) for v in run["yara_version_ids"]],
         "attempt": attempt, "sample": run["sample_id"]})


_RUN_COLUMNS = ("id, sample_id, trigger, requested_by, requests, priority, "
                "steps, yara_version_ids, attempt")


def _run_dict(row) -> dict:
    return dict(zip(("id", "sample_id", "trigger", "requested_by", "requests",
                     "priority", "steps", "yara_version_ids", "attempt"), row, strict=True))


def sweep_abandoned(conn: psycopg.Connection) -> int:
    """ABANDON every RUNNING run whose owner is gone, proved by getting
    its lock; its pending gaps become failed; a RETRY is queued while
    attempts remain. Returns how many were abandoned."""
    rows = conn.execute(
        f"SELECT {_RUN_COLUMNS} FROM lab.static_run WHERE status = 'RUNNING'"
    ).fetchall()
    swept = 0
    for row in rows:
        run = _run_dict(row)
        if not _run_lock(conn, "pg_try_advisory_lock", run["id"]):
            continue
        try:
            with conn.transaction():
                done = conn.execute(
                    """UPDATE lab.static_run
                          SET status = 'ABANDONED', finished_at = now(),
                              failure = %s
                        WHERE id = %s AND status = 'RUNNING' RETURNING id""",
                    (ABANDONED_REASON, run["id"])).fetchone()
                if done is None:
                    continue
                _set_gaps(conn, run["sample_id"],
                          {g: {"status": "failed", "reason": ABANDONED_REASON}
                           for g in _gap_steps(run["steps"])},
                          only_pending=True)
                if run["attempt"] < MAX_ATTEMPTS:
                    _requeue(conn, run, run["attempt"] + 1)
                _audit_run(conn, run, "FAILED", {"status": "ABANDONED"})
            swept += 1
        finally:
            _run_lock(conn, "pg_advisory_unlock", run["id"])
    return swept


# -- claim -------------------------------------------------------------------

@dataclass
class Claimed:
    id: UUID
    sample_id: UUID
    trigger: str
    requested_by: UUID | None
    requests: list
    priority: int
    steps: list
    yara_version_ids: list
    attempt: int
    byte_size: int
    #: set when the claim ended the run instead of starting it
    skipped: str | None = None


def _open_versions(conn, wanted: list) -> list[tuple]:
    """(version_id, ruleset_id, key, version) of every open activation in
    scope: the run's list, or every open one when the list is empty."""
    return conn.execute(
        """SELECT a.version_id, a.ruleset_id, r.key, v.version
             FROM lab.yara_activation a
             JOIN lab.yara_ruleset r ON r.id = a.ruleset_id
             JOIN lab.yara_ruleset_version v ON v.id = a.version_id
            WHERE a.deactivated_at IS NULL
              AND (cardinality(%s::uuid[]) = 0 OR a.version_id = ANY(%s::uuid[]))
            ORDER BY r.key""",
        ([str(v) for v in wanted], [str(v) for v in wanted])).fetchall()


def claim(conn: psycopg.Connection, settings: AnalysisSettings, *,
          run_id: UUID | None = None,
          among: tuple | list | None = None) -> tuple[Claimed | None, int]:
    """The next run to do, RUNNING and locked by this session, and how
    many runs the claim ended SKIPPED on the way (each read nothing).

    `run_id` claims that run or nothing (an analyst's request); `among`
    claims only the runs of those samples, in the usual order (the demo
    seed's own samples, and a test's)."""
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    from noctornal_api.samples import lab_exclusions_sql, policy_declared
    from noctornal_api.yara_rules import engine_version
    skipped = 0
    while True:
        with conn.transaction():
            row = conn.execute(
                f"""SELECT r.id, r.sample_id, r.trigger, r.requested_by,
                           r.requests, r.priority, r.steps, r.yara_version_ids,
                           r.attempt, s.byte_size, s.state,
                           octet_length(s.data_key_ciphertext) = 0,
                           c.status, ({lab_exclusions_sql('s')})
                      FROM lab.static_run r
                      JOIN lab.sample s ON s.id = r.sample_id
                      LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                     WHERE r.status = 'QUEUED'
                       AND (%(run)s::uuid IS NULL OR r.id = %(run)s::uuid)
                       AND (%(among)s::uuid[] IS NULL
                            OR r.sample_id = ANY(%(among)s::uuid[]))
                       AND NOT EXISTS (SELECT 1 FROM lab.static_run x
                                        WHERE x.sample_id = r.sample_id
                                          AND x.status = 'RUNNING')
                     ORDER BY r.priority, r.queued_at, r.id
                     LIMIT 1
                     FOR UPDATE OF r SKIP LOCKED""",
                {"run": run_id,
                 "among": [str(x) for x in among] if among is not None
                 else None}).fetchone()
            if row is None:
                return None, skipped
            c = Claimed(id=row[0], sample_id=row[1], trigger=row[2],
                        requested_by=row[3], requests=row[4] or [],
                        priority=row[5], steps=list(row[6]),
                        yara_version_ids=list(row[7] or []), attempt=row[8],
                        byte_size=row[9])
            state, key_gone, case_status, kept = row[10], row[11], row[12], row[13]
            declared, _detail = policy_declared()
            refusal = None
            gaps: dict[str, dict] = {}
            if not declared:
                refusal = ("no prohibited-content policy is declared; nothing "
                           "was read")
            elif state == "REJECTED" or not kept:
                refusal = "the sample was rejected before triage ran; nothing was read"
            elif case_status in CONTENT_READ_ONLY_STATES:
                refusal = "the sample's case is closed; nothing was read"
            elif key_gone:
                refusal = "the sample's data key is destroyed; nothing was read"
            elif c.byte_size > settings.max_bytes:
                refusal = TOO_LARGE_REASON
                gaps = {g: {"status": "skipped", "reason": TOO_LARGE_REASON}
                        for g in _gap_steps(c.steps)}
            elif c.steps == ["yara"] and (
                    engine_version() is None
                    or not _open_versions(conn, c.yara_version_ids)):
                # Nothing left to scan with: end it before decrypting.
                # Said without naming the step, which a reader
                # who cannot see the rule set must not learn from the card.
                refusal = "there was nothing left to run; nothing was read"
                if engine_version() is None:
                    gaps = {"yara": {"status": "unavailable",
                                     "reason": ENGINE_ABSENT_REASON}}
            if refusal is not None:
                conn.execute(
                    """UPDATE lab.static_run
                          SET status = 'SKIPPED', finished_at = now(),
                              failure = %s
                        WHERE id = %s""", (refusal, c.id))
                if gaps:
                    _set_gaps(conn, c.sample_id, gaps)
                skipped += 1
                if run_id is not None:
                    return None, skipped
                continue
            conn.execute(
                """UPDATE lab.static_run SET status = 'RUNNING',
                          started_at = now() WHERE id = %s""", (c.id,))
            # The run's lock, BEFORE the commit: session scope,
            # so it outlives this transaction and is what a sweep asks.
            if not _run_lock(conn, "pg_try_advisory_lock", c.id):
                raise RuntimeError("the run's lock is held elsewhere")
        return c, skipped


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------

def _requesters(c: Claimed) -> tuple[list[UUID], bool]:
    """(each distinct person whose request is merged into the run, in
    order; whether a scheduled trigger contributed as well)."""
    people: list[UUID] = []
    system = False
    for entry in c.requests or []:
        who = entry.get("requested_by") if isinstance(entry, dict) else None
        if who:
            uid = UUID(who)
            if uid not in people:
                people.append(uid)
        else:
            system = True
    if c.requested_by and c.requested_by not in people:
        people.insert(0, c.requested_by)
    if not people:
        system = True
    return people, system


def _write_scanned(conn, c: Claimed, nbytes: int) -> None:
    """The custody of a verified read: one SCANNED row per requester and
    one SYSTEM row for scheduled work, committed before any child starts."""
    from noctornal_api.samples import SampleService
    svc = SampleService(conn)
    detail = {"event": "static_triage", "run_id": str(c.id), "bytes": nbytes,
              "sha256_verified": True}
    people, system = _requesters(c)
    with conn.transaction():
        for person in people:
            svc._access(c.sample_id, person, "SCANNED", detail)
        if system:
            svc._access(c.sample_id, None, "SCANNED", detail)


def _audit_run(conn, run, outcome: str, detail: dict) -> None:
    rid = run["id"] if isinstance(run, dict) else run.id
    sample = run["sample_id"] if isinstance(run, dict) else run.sample_id
    by = run["requested_by"] if isinstance(run, dict) else run.requested_by
    trigger = run["trigger"] if isinstance(run, dict) else run.trigger
    steps = run["steps"] if isinstance(run, dict) else run.steps
    conn.execute(
        """INSERT INTO audit.event (actor_id, actor_kind, action, object_type,
                                    object_id, outcome, detail)
           VALUES (%s, %s, 'SAMPLE_STATIC_TRIAGE', 'sample', %s, %s, %s)""",
        (by, "USER" if by else "SYSTEM", sample, outcome,
         Json({"run_id": str(rid), "trigger": trigger, "steps": list(steps),
               **detail})))


def _finish(conn, c: Claimed, status: str, failure: str, *,
            retry: bool, outcome: dict | None = None) -> None:
    """End the run FAILED (or SKIPPED) on its own, its pending gaps
    marked, a RETRY queued when allowed, and the audit row last."""
    with conn.transaction():
        done = conn.execute(
            """UPDATE lab.static_run
                  SET status = %s, finished_at = now(), failure = %s,
                      outcome = %s
                WHERE id = %s AND status = 'RUNNING' RETURNING id""",
            (status, failure, Json(outcome or {}), c.id)).fetchone()
        if done is None:
            return
        _set_gaps(conn, c.sample_id,
                  {g: {"status": "failed", "reason": failure}
                   for g in _gap_steps(c.steps)}, only_pending=True)
        if retry and c.attempt < MAX_ATTEMPTS:
            _requeue(conn, {"requested_by": c.requested_by,
                            "requests": c.requests, "priority": c.priority,
                            "steps": c.steps,
                            "yara_version_ids": c.yara_version_ids,
                            "sample_id": c.sample_id}, c.attempt + 1)
        _audit_run(conn, c, "FAILED", {"status": status, **(outcome or {})})


def _valid(step: str, value) -> str | None:
    """A value a child reported, in canonical form, or None when it is not
    a digest of that kind: nothing a child says is stored unchecked."""
    if not isinstance(value, str) or len(value) > 200:
        return None
    try:
        if step in ("imphash", "rich_header_hash"):
            return fuzzyhash.canonical_imphash(value)
        if step == "ssdeep":
            v = fuzzyhash.canonical_ssdeep(value)
            return None if fuzzyhash.ssdeep_is_degenerate(v) else v
        if step == "tlsh":
            return fuzzyhash.canonical_tlsh(value)
    except ValueError:
        return None
    return None


def _step_entry(step: str, reported) -> tuple[str | None, dict | None]:
    """(stored value, gap entry or None for a success) from what a child
    reported for one step."""
    if not isinstance(reported, dict):
        return None, {"status": "failed",
                      "reason": CHILD_FAILURES["bad_output"]}
    status = reported.get("status")
    if status == "done":
        value = _valid(step, reported.get("value"))
        if value is None:
            return None, {"status": "failed",
                          "reason": CHILD_FAILURES["bad_output"]}
        return value, None
    if status in ("not_applicable", "skipped"):
        reason = lab_static.REASONS.get(reported.get("code"))
        if reason is None:
            return None, {"status": "failed",
                          "reason": CHILD_FAILURES["bad_output"]}
        return None, {"status": status, "reason": reason}
    return None, {"status": "failed",
                  "reason": lab_static.failure_reason(reported.get("error"))}


def _step_child(mode: str, data: bytes, settings: AnalysisSettings,
                gap_names: tuple[str, ...]) -> dict:
    """Run one pe or fuzzy child: `{values, gaps, facts, timing_ms}`."""
    started = time.monotonic()
    result = run_child(
        {"mode": mode, "sample_len": len(data),
         "fuzzy_max_bytes": settings.fuzzy_max_bytes,
         "limits": {"memory_bytes": settings.memory_bytes,
                    "cpu_s": settings.timeout_s}},
        (data,), wall_s=settings.timeout_s + WALL_GRACE_S)
    out, failure = _child_json(result)
    timing = int((time.monotonic() - started) * 1000)
    if out is None:
        reason = CHILD_FAILURES.get(failure, CHILD_FAILURES["crashed"])
        return {"values": {}, "gaps": {g: {"status": "failed", "reason": reason}
                                       for g in gap_names},
                "facts": None, "timing_ms": timing, "failure": failure}
    values: dict = {}
    gaps: dict = {}
    steps = out.get("steps") if isinstance(out.get("steps"), dict) else {}
    for g in gap_names:
        value, entry = _step_entry(g, steps.get(g))
        values[g] = value
        gaps[g] = entry
    facts = None
    pe = out.get("pe")
    if mode == "pe" and isinstance(pe, dict):
        facts = {"machine": pe.get("machine") if isinstance(pe.get("machine"), int) else None,
                 "is_dll": pe.get("is_dll") is True,
                 "is_dotnet": pe.get("is_dotnet") is True}
    return {"values": values, "gaps": gaps, "facts": facts,
            "timing_ms": timing}


# -- the YARA step -----------------------------------------------------------

YARA_ERRORS = {
    "rules_not_compiled": "the rule set has no usable build for this engine yet",
    "timeout": "the scan did not finish within its time limit",
    "crashed": "the scanning process stopped without an answer",
    "output_too_large": "the scan's output passed its cap",
    "engine_error": "the engine refused to scan this input",
    "rules_rejected": "the build could not be loaded and is being rebuilt",
}


def _text(value, limit: int = lab_static.META_TEXT) -> str:
    return str(value)[:limit]


def _clean_rules(rules) -> list[dict]:
    """A child's match list, rebuilt field by field under the same bounds
    the child applied: nothing it says is stored unchecked."""
    out = []
    for r in (rules if isinstance(rules, list) else [])[:lab_static.MAX_RULES_REPORTED]:
        if not isinstance(r, dict):
            continue
        meta = r.get("metadata") if isinstance(r.get("metadata"), dict) else {}
        clean_meta = {}
        for k, v in list(meta.items())[:50]:
            if isinstance(v, bool) or isinstance(v, (int, float)):
                clean_meta[_text(k)] = v
            else:
                clean_meta[_text(k)] = _text(v)
        patterns = []
        for p in (r.get("patterns") if isinstance(r.get("patterns"), list) else [])[:50]:
            if not isinstance(p, dict):
                continue
            offsets = [o for o in (p.get("offsets") or [])
                       if isinstance(o, int) and o >= 0][:lab_static.MAX_OFFSETS]
            hits = p.get("hits") if isinstance(p.get("hits"), int) else len(offsets)
            patterns.append({"identifier": _text(p.get("identifier", "")),
                             "hits": max(0, hits), "offsets": offsets})
        out.append({"namespace": _text(r.get("namespace", "")),
                    "identifier": _text(r.get("identifier", "")),
                    "tags": [_text(t) for t in (r.get("tags") or [])][:50],
                    "metadata": clean_meta, "patterns": patterns})
    return out


def _yara_step(conn, c: Claimed, data: bytes) -> dict:
    """One child per open version in scope: `{engine, rows}` where each
    row is what `record_machine_analysis` writes, or `{engine: None}`
    without the engine."""
    from noctornal_api.yara_rules import (RulesetService, build_key,
                                          engine_version, yara_settings)
    key = build_key()
    if key is None:
        return {"engine": None, "rows": []}
    ysettings, _problem = yara_settings()
    timeout = ysettings.scan_timeout_s if ysettings else 60
    rulesets = RulesetService(conn)
    rows = []
    for version_id, ruleset_id, set_key, number in _open_versions(
            conn, c.yara_version_ids):
        base = {"ruleset": {"id": str(ruleset_id), "key": set_key,
                            "version": number},
                "engine": key.engine, "platform": key.platform}
        build = rulesets.usable_build(version_id, key)
        if build is None or build["status"] == "FAILED":
            if build is None:
                rulesets.queue_compile(version_id, key)
            rows.append({"version_id": version_id, "set_key": set_key,
                         "findings": {**base, "matched": 0, "truncated": False,
                                      "rules": [],
                                      "error": "rules_not_compiled"}})
            continue
        result = run_child({"mode": "yara_scan", "sample_len": len(data),
                            "rules_len": len(build["blob"]),
                            "timeout_s": timeout,
                            "limits": {"memory_bytes": _memory(),
                                       "cpu_s": timeout + 5}},
                           (data, build["blob"]),
                           wall_s=timeout + WALL_GRACE_S)
        out, failure = _child_json(result)
        error = None
        if out is None:
            error = failure if failure in YARA_ERRORS else "crashed"
        elif out.get("error"):
            error = out["error"] if out["error"] in YARA_ERRORS else "engine_error"
            if error == "rules_rejected":
                rulesets.reject_build(UUID(build["id"]), version_id,
                                      "undecodable")
        findings = {**base, "matched": 0, "truncated": False, "rules": []}
        if error:
            findings["error"] = error
        else:
            rules = _clean_rules(out.get("rules"))
            findings.update(matched=int(out.get("matched") or 0)
                            if isinstance(out.get("matched"), int) else len(rules),
                            truncated=out.get("truncated") is True, rules=rules)
        rows.append({"version_id": version_id, "set_key": set_key,
                     "findings": findings})
    return {"engine": key.engine, "engine_version": engine_version(),
            "rows": rows}


def _memory() -> int:
    return settings_or_default().memory_bytes


# -- results -----------------------------------------------------------------

STATIC_TOOL = "noctornal static triage"


class _Discard(Exception):
    """The run is no longer this process's to finish."""


def _write_results(conn, c: Claimed, pe: dict | None, fz: dict | None,
                   yara: dict | None, nbytes: int,
                   settings: AnalysisSettings) -> str:
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    from noctornal_api.samples import (REJECT_LOCK_TIMEOUT, SampleService,
                                       lab_exclusions_sql)
    svc = SampleService(conn)
    limits = limits_words(settings)
    with conn.transaction():
        conn.execute("SELECT set_config('lock_timeout', %s, true)",
                     (REJECT_LOCK_TIMEOUT,))
        row = conn.execute(
            f"""SELECT s.state, c.status, s.triage_gaps,
                       ({lab_exclusions_sql('s')})
                  FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                 WHERE s.id = %s FOR UPDATE OF s""", (c.sample_id,)).fetchone()
        if (row is None or row[0] == "REJECTED" or not row[3]
                or row[1] in CONTENT_READ_ONLY_STATES):
            done = conn.execute(
                """UPDATE lab.static_run
                      SET status = 'SKIPPED', finished_at = now(), failure = %s
                    WHERE id = %s AND status = 'RUNNING' RETURNING id""",
                (DISCARDED_REASON, c.id)).fetchone()
            if done is None:
                raise _Discard()
            _audit_run(conn, c, "FAILED", {"status": "SKIPPED",
                                           "reason": "discarded", "bytes": nbytes})
            return "SKIPPED"
        values: dict = {}
        gaps: dict = {}
        for part in (pe, fz):
            if part:
                values.update(part["values"])
                gaps.update(part["gaps"])
        if yara is not None:
            gaps["yara"] = (None if yara["engine"] else
                            {"status": "unavailable",
                             "reason": ENGINE_ABSENT_REASON})
        sets = []
        params: dict = {"id": c.sample_id}
        # A step that failed keeps whatever an earlier run found; one that
        # succeeded, or does not apply, says so.
        for col in ("imphash", "rich_header_hash", "ssdeep", "tlsh"):
            if col not in values:
                continue
            entry = gaps.get(col)
            if entry is not None and entry["status"] in ("failed", "skipped"):
                continue
            sets.append(f"{col} = %({col})s")
            params[col] = values[col]
            if col == "ssdeep":
                sets.append("ssdeep_tokens = %(tokens)s")
                params["tokens"] = (fuzzyhash.ssdeep_tokens(values[col])
                                    if values[col] else None)
            if col == "tlsh":
                sets.append("tlsh_lvalue = %(lvalue)s")
                params["lvalue"] = (fuzzyhash.tlsh_lvalue(values[col])
                                    if values[col] else None)
        sets.append("triage_gaps = %(gaps)s")
        params["gaps"] = Json(_rewrite_gaps(row[2], gaps))
        sets.append("state = CASE WHEN state = 'QUARANTINED' THEN 'TRIAGED'"
                    "::lab.sample_state ELSE state END")
        conn.execute(f"UPDATE lab.sample SET {', '.join(sets)} WHERE id = %(id)s",
                     params)
        if pe or fz:
            facts = (pe or {}).get("facts")
            imphash = values.get("imphash")
            findings = {
                "imphash": imphash,
                "rich_header_hash": values.get("rich_header_hash"),
                "ssdeep": values.get("ssdeep"), "tlsh": values.get("tlsh"),
                "pe": facts, "limits": limits,
                "timings_ms": {k: v["timing_ms"] for k, v in
                               (("pe", pe), ("fuzzy", fz)) if v},
                "gaps": {k: v for k, v in gaps.items()
                         if k != "yara" and v is not None}}
            if imphash in fuzzyhash.COMMON_IMPHASHES:
                findings["imphash_common"] = fuzzyhash.COMMON_IMPHASHES[imphash]
            versions = _parent_versions()
            why = {"imphash": f"computed by pefile {versions['pefile']}",
                   "rich_header_hash": f"computed by pefile {versions['pefile']}",
                   "ssdeep": f"computed by {fuzzyhash.SSDEEP_IMPLEMENTATION}",
                   "tlsh": f"computed by {fuzzyhash.TLSH_IMPLEMENTATION}"}
            kinds = {"imphash": "IMPHASH", "rich_header_hash": "RICH_HEADER",
                     "ssdeep": "SSDEEP", "tlsh": "TLSH"}
            selectors = [{"selector_type": kinds[k], "value": values[k],
                          "why": why[k]}
                         for k in ("imphash", "rich_header_hash", "ssdeep", "tlsh")
                         if values.get(k)]
            svc.record_machine_analysis(
                c.sample_id, kind="STATIC", tool=STATIC_TOOL,
                tool_version=(f"pefile {versions['pefile']}; noctornal-tlsh 1; "
                              f"noctornal-ssdeep 1"),
                findings=findings, extracted_selectors=selectors,
                run_id=c.id)
        yara_failed = 0
        for yrow in (yara or {}).get("rows", []):
            f = yrow["findings"]
            yara_failed += 1 if f.get("error") else 0
            hits = [f"{yrow['set_key']}/{r['namespace']}:{r['identifier']}"
                    for r in f.get("rules", [])]
            svc.record_machine_analysis(
                c.sample_id, kind="YARA", tool="yara-x",
                tool_version=(yara or {}).get("engine_version"),
                findings=f, yara_hits=hits, run_id=c.id,
                yara_ruleset_version_id=yrow["version_id"])
        statuses = {g: ("done" if gaps.get(g) is None else gaps[g]["status"])
                    for g in ("imphash", "rich_header_hash", "ssdeep", "tlsh")
                    if g in gaps or g in values}
        outcome = {"statuses": statuses, "limits": limits, "bytes": nbytes,
                   "yara": {"versions": len((yara or {}).get("rows", [])),
                            "failed": yara_failed}}
        done = conn.execute(
            """UPDATE lab.static_run
                  SET status = 'DONE', finished_at = now(), outcome = %s
                WHERE id = %s AND status = 'RUNNING' RETURNING id""",
            (Json(outcome), c.id)).fetchone()
        if done is None:
            raise _Discard()
        # The audit row LAST in the transaction (final review C7).
        _audit_run(conn, c, "SUCCESS", outcome)
    return "DONE"


def run_claimed(conn: psycopg.Connection, storage, c: Claimed,
                settings: AnalysisSettings) -> str:
    """Steps 2 to 6 for one claimed run. Returns its final status."""
    from noctornal_api.samples import SampleIntegrityError, SampleService
    data = None
    try:
        try:
            data = SampleService(conn, storage)._verified_plaintext(
                c.sample_id, actor_id=c.requested_by,
                max_bytes=settings.max_bytes, extra={"run_id": str(c.id)})
        except SampleIntegrityError:
            # The alarm is already committed; a tamper is never retried.
            _finish(conn, c, "FAILED", INTEGRITY_REASON, retry=False)
            return "FAILED"
        except Exception as exc:  # noqa: BLE001 - every failure is a verdict
            log.warning("static triage run %s could not read its sample",
                        c.id, exc_info=True)
            _finish(conn, c, "FAILED",
                    f"{MATERIALISE_REASON} ({type(exc).__name__})", retry=True)
            return "FAILED"
        nbytes = len(data)
        _write_scanned(conn, c, nbytes)
        pe = fz = yara = None
        if "pe" in c.steps:
            pe = _step_child("pe", data, settings, STEP_GAPS["pe"])
        if "fuzzy" in c.steps:
            if nbytes > settings.fuzzy_max_bytes:
                skip = {"status": "skipped",
                        "reason": lab_static.REASONS["fuzzy_cap"]}
                fz = {"values": {}, "gaps": {"ssdeep": dict(skip),
                                             "tlsh": dict(skip)},
                      "facts": None, "timing_ms": 0}
            else:
                fz = _step_child("fuzzy", data, settings, STEP_GAPS["fuzzy"])
        if "yara" in c.steps:
            yara = _yara_step(conn, c, data)
        data = None
        try:
            return _write_results(conn, c, pe, fz, yara, nbytes, settings)
        except _Discard:
            return "ABANDONED"
        except psycopg.errors.LockNotAvailable:
            _finish(conn, c, "FAILED", f"{RESULTS_REASON} (the sample was busy)",
                    retry=True)
            return "FAILED"
        except Exception as exc:  # noqa: BLE001
            log.warning("static triage run %s could not write its findings",
                        c.id, exc_info=True)
            _finish(conn, c, "FAILED",
                    f"{RESULTS_REASON} ({type(exc).__name__})", retry=False)
            return "FAILED"
    finally:
        data = None
        try:
            _run_lock(conn, "pg_advisory_unlock", c.id)
        except psycopg.Error:
            pass


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------

def run_due(conn: psycopg.Connection, storage, *,
            settings: AnalysisSettings | None = None, limit: int = 20,
            max_seconds: float = 90, budget_s: float | None = None) -> dict:
    """One pass: sweep, compile what is queued for this host, then run
    up to `limit` runs, starting none after `max_seconds`. With
    `budget_s` a compile or a run starts only when its worst case (its
    children's wall limits added up) still fits, so a pass sharing a loop
    with other work cannot overrun it (2026-09-24).
    The deadline is taken before the sweep, so the sweep's own time counts
    against it too."""
    from noctornal_api.samples import policy_declared
    counts = {"queued": 0, "done": 0, "failed": 0, "skipped": 0,
              "abandoned": 0, "left": 0, "compiled": 0, "compile_failed": 0}
    declared, detail = policy_declared()
    if not declared:
        counts["refused"] = detail
        return counts
    settings = settings or settings_or_default()
    started = time.monotonic()
    counts["abandoned"] = sweep_abandoned(conn)
    counts["queued"] = queue_depth(conn)
    compiled, failed = compile_pending(
        conn, settings, until=None if budget_s is None else started + budget_s)
    counts["compiled"], counts["compile_failed"] = compiled, failed
    open_n = conn.execute("SELECT count(*) FROM lab.yara_activation "
                          "WHERE deactivated_at IS NULL").fetchone()[0]
    worst = run_worst_s(settings, open_n)
    ran = 0
    while ran < limit and time.monotonic() - started < max_seconds:
        if budget_s is not None and (time.monotonic() - started + worst
                                     > budget_s):
            break
        slot = take_slot(conn, settings.concurrency)
        if slot is None:
            break
        try:
            claimed, skipped = claim(conn, settings)
            counts["skipped"] += skipped
            if claimed is None:
                break
            status = run_claimed(conn, storage, claimed, settings)
            key = status.lower()
            counts[key] = counts.get(key, 0) + 1
            ran += 1
        finally:
            release_slot(conn, slot)
    counts["left"] = queue_depth(conn)
    return counts


def queue_depth(conn) -> int:
    return conn.execute("SELECT count(*) FROM lab.static_run "
                        "WHERE status = 'QUEUED'").fetchone()[0]


def run_queued_detached(run_id: UUID) -> None:
    """After an analyst's request has been answered: open a connection
    and the sample store, sweep, and run THAT run if a slot is free. The
    request never waits for a child."""
    # The worker's own connection is a system one (S1, 2026-09-25):
    # triage reads and records every sample it is handed, whoever asked.
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.samples import SampleStorage
    try:
        conn = connect_system(SystemPurpose.LAB_TRIAGE)
    except Exception:  # noqa: BLE001
        log.warning("static triage could not open a connection", exc_info=True)
        return
    try:
        settings = settings_or_default()
        try:
            storage = SampleStorage()
        except Exception:  # noqa: BLE001 - the next pass will say so
            log.warning("static triage: the sample store is not configured")
            return
        sweep_abandoned(conn)
        slot = take_slot(conn, settings.concurrency)
        if slot is None:
            return
        try:
            claimed, _skipped = claim(conn, settings, run_id=run_id)
            if claimed is not None:
                run_claimed(conn, storage, claimed, settings)
        finally:
            release_slot(conn, slot)
    except Exception:  # noqa: BLE001 - a background task has no caller
        log.warning("static triage run %s failed in the background", run_id,
                    exc_info=True)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The compile queue (F12)
# ---------------------------------------------------------------------------

def _job_lock(conn, fn: str, version_id, key) -> bool:
    return bool(conn.execute(
        f"SELECT {fn}(hashtextextended('noctornal.yara_compile:' || %s || '|' "
        f"|| %s || '|' || %s || '|' || %s, 0))",
        (str(version_id), key.engine, key.platform, key.fingerprint)
    ).fetchone()[0])


COMPILE_TRANSIENT = ("timeout", "crashed", "output_too_large", "bad_output",
                     "start_failed", "version_mismatch", "error")


def sweep_compile_jobs(conn, key) -> int:
    """Return every RUNNING job of this host whose owner is gone to the
    queue, one attempt more (FAILED after the third)."""
    rows = conn.execute(
        """SELECT version_id FROM lab.yara_compile_job
            WHERE status = 'RUNNING' AND engine = %s AND platform = %s
              AND fingerprint = %s""",
        (key.engine, key.platform, key.fingerprint)).fetchall()
    n = 0
    for (version_id,) in rows:
        if not _job_lock(conn, "pg_try_advisory_lock", version_id, key):
            continue
        try:
            conn.execute(
                """UPDATE lab.yara_compile_job
                      SET attempts = attempts + 1,
                          status = CASE WHEN attempts + 1 >= %s THEN 'FAILED'
                                        ELSE 'QUEUED' END,
                          last_error = 'abandoned', updated_at = now()
                    WHERE version_id = %s AND engine = %s AND platform = %s
                      AND fingerprint = %s AND status = 'RUNNING'""",
                (MAX_ATTEMPTS, version_id, key.engine, key.platform,
                 key.fingerprint))
            n += 1
        finally:
            _job_lock(conn, "pg_advisory_unlock", version_id, key)
    return n


def compile_worst_s(settings: AnalysisSettings) -> float:
    """The longest one compile can take: its child's wall limit."""
    return settings.timeout_s + WALL_GRACE_S


def run_worst_s(settings: AnalysisSettings, open_versions: int) -> float:
    """The longest one run can take: its pe and fuzzy children and one
    YARA child per open rule set version, each to its wall limit."""
    return (2 + open_versions) * (settings.timeout_s + WALL_GRACE_S)


def compile_pending(conn: psycopg.Connection, settings: AnalysisSettings, *,
                    until: float | None = None, limit: int = 10,
                    version_id: UUID | None = None) -> tuple[int, int]:
    """Compile the queued jobs for THIS host's engine, platform and
    fingerprint (a process never builds for another host), each in a
    child under the analysis limits. A deterministic result is a build
    row; a timeout, crash or cap is transient and writes none. Returns
    (builds written, jobs that failed for good this pass).

    With `until` (a monotonic deadline) a compile starts only when its
    worst case, the child's wall limit, still fits before it: a budgeted
    pass must never START work it cannot finish in time, compiles as
    well as runs (2026-09-24: compiles had started whenever the deadline
    had not yet passed)."""
    from noctornal_api import yara_rules
    key = yara_rules.build_key()
    if key is None:
        return 0, 0
    sweep_compile_jobs(conn, key)
    built = failed = 0
    worst = compile_worst_s(settings)
    for _ in range(limit):
        if until is not None and time.monotonic() + worst > until:
            break
        with conn.transaction():
            job = conn.execute(
                """SELECT j.version_id, j.attempts, v.ruleset_id, v.version,
                          v.source_gz, v.files
                     FROM lab.yara_compile_job j
                     JOIN lab.yara_ruleset_version v ON v.id = j.version_id
                    WHERE j.status = 'QUEUED' AND j.engine = %s
                      AND j.platform = %s AND j.fingerprint = %s
                      AND (%s::uuid IS NULL OR j.version_id = %s::uuid)
                    ORDER BY j.updated_at LIMIT 1
                    FOR UPDATE OF j SKIP LOCKED""",
                (key.engine, key.platform, key.fingerprint, version_id,
                 version_id)).fetchone()
            if job is None:
                break
            vid, attempts, ruleset_id, number, source_gz, files = job
            conn.execute(
                """UPDATE lab.yara_compile_job SET status = 'RUNNING',
                          updated_at = now()
                    WHERE version_id = %s AND engine = %s AND platform = %s
                      AND fingerprint = %s""",
                (vid, key.engine, key.platform, key.fingerprint))
            if not _job_lock(conn, "pg_try_advisory_lock", vid, key):
                raise RuntimeError("the compile job's lock is held elsewhere")
        try:
            outcome = _compile_one(conn, key, vid, ruleset_id, number,
                                   bytes(source_gz), files or [], attempts,
                                   settings)
            if outcome == "built":
                built += 1
            elif outcome == "failed":
                failed += 1
        finally:
            _job_lock(conn, "pg_advisory_unlock", vid, key)
    return built, failed


def _compile_one(conn, key, vid, ruleset_id, number, source_gz, files,
                 attempts, settings) -> str:
    from noctornal_api import yara_rules
    try:
        canonical = yara_rules.stored_canonical(source_gz, files)
    except Exception:  # noqa: BLE001
        canonical = None
    result = None
    if canonical is not None:
        result = run_child(
            {"mode": "yara_compile", "sample_len": len(canonical),
             "limits": {"memory_bytes": settings.memory_bytes,
                        "cpu_s": settings.timeout_s}},
            (canonical,), wall_s=settings.timeout_s + WALL_GRACE_S,
            stdout_cap=yara_rules.MAX_COMPILED_BYTES)
    report = blob = None
    kind = "error" if canonical is None else None
    if result is not None:
        if not result.ok:
            kind = result.failure or "crashed"
        else:
            try:
                report, blob = lab_static.unframe_compile(result.output)
                if report.get("versions") != _parent_versions():
                    kind = "version_mismatch"
                elif report.get("status") not in ("COMPILED", "PARTIAL",
                                                  "FAILED"):
                    kind = "error"
            except (ValueError, UnicodeDecodeError):
                kind = "bad_output"
    if kind is not None:
        # Transient: no build is recorded, the job is tried again up to
        # the limit (a timeout or a memory cap may pass with more room).
        gone = attempts + 1 >= MAX_ATTEMPTS
        conn.execute(
            """UPDATE lab.yara_compile_job
                  SET attempts = attempts + 1,
                      status = %s, last_error = %s, updated_at = now()
                WHERE version_id = %s AND engine = %s AND platform = %s
                  AND fingerprint = %s""",
            ("FAILED" if gone else "QUEUED", kind, vid, key.engine,
             key.platform, key.fingerprint))
        return "failed" if gone else "transient"
    status = report["status"]
    clean = _clean_report(report)
    with conn.transaction():
        if status == "FAILED" or not blob:
            conn.execute(
                """INSERT INTO lab.yara_compiled
                       (version_id, engine, platform, fingerprint, status,
                        rule_count, warning_count, report)
                   VALUES (%s, %s, %s, %s, 'FAILED', 0, %s, %s)""",
                (vid, key.engine, key.platform, key.fingerprint,
                 clean["warning_count"], Json(clean)))
            status = "FAILED"
        else:
            digest, key_id, mac = yara_rules.seal_build(vid, key, blob)
            conn.execute(
                """INSERT INTO lab.yara_compiled
                       (version_id, engine, platform, fingerprint, status,
                        rule_count, warning_count, report, compiled,
                        blob_sha256, mac_key_id, mac)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (vid, key.engine, key.platform, key.fingerprint, status,
                 clean["rule_count"], clean["warning_count"], Json(clean),
                 blob, digest, key_id, mac))
        conn.execute(
            """DELETE FROM lab.yara_compile_job
                WHERE version_id = %s AND engine = %s AND platform = %s
                  AND fingerprint = %s""",
            (vid, key.engine, key.platform, key.fingerprint))
        failed_files = sum(1 for f in clean["files"] if f["status"] == "failed")
        conn.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action,
                                        object_type, object_id, outcome, detail)
               VALUES (NULL, 'SYSTEM', 'YARA_RULESET_COMPILED', 'yara_ruleset',
                       %s, %s, %s)""",
            (ruleset_id, "SUCCESS" if status != "FAILED" else "FAILED",
             Json({"version": number, "engine": key.engine,
                   "platform": key.platform, "status": status,
                   "rule_count": clean["rule_count"],
                   "failed_files": failed_files})))
    if status != "FAILED":
        _rescan_unbuilt(conn, vid)
    return "built" if status != "FAILED" else "failed"


def _clean_report(report: dict) -> dict:
    """What a compile child said, rebuilt under bounds, never quoting a
    rule line (docs/18 D3)."""
    files = []
    for f in (report.get("files") if isinstance(report.get("files"), list)
              else [])[:5000]:
        if not isinstance(f, dict):
            continue
        errors = []
        for e in (f.get("errors") if isinstance(f.get("errors"), list)
                  else [])[:20]:
            if isinstance(e, dict):
                errors.append({
                    "code": _text(e.get("code", ""), 16),
                    "title": _text(e.get("title", ""), 200),
                    "line": e.get("line") if isinstance(e.get("line"), int) else None,
                    "column": e.get("column") if isinstance(e.get("column"), int)
                    else None})
        files.append({"path": _text(f.get("path", ""), 255),
                      "status": "failed" if f.get("status") == "failed"
                      else "compiled", "errors": errors})
    n = report.get("rule_count")
    w = report.get("warning_count")
    return {"files": files, "rule_count": n if isinstance(n, int) else 0,
            "warning_count": w if isinstance(w, int) else 0}


def _rescan_unbuilt(conn, version_id) -> int:
    """When a build lands for a version with an open activation, queue its
    yara step for every sample whose latest row for that version said it
    had no build, or one that would not load, so coverage lost to a missing build comes
    back without anybody asking. SYSTEM: nobody asked."""
    rows = conn.execute(
        """SELECT DISTINCT ON (a.sample_id) a.sample_id,
                  a.findings->>'error'
             FROM lab.sample_analysis a
            WHERE a.yara_ruleset_version_id = %s AND a.origin = 'machine'
              AND EXISTS (SELECT 1 FROM lab.yara_activation x
                           WHERE x.version_id = %s
                             AND x.deactivated_at IS NULL)
            ORDER BY a.sample_id, a.created_at DESC""",
        (version_id, version_id)).fetchall()
    n = 0
    for sample_id, error in rows:
        # Both mean the version had no build this host could load when the
        # sample was scanned: the coverage a missing build cost.
        if error in ("rules_not_compiled", "rules_rejected"):
            if enqueue(conn, sample_id, trigger="BACKFILL", steps=("yara",),
                       yara_version_ids=(version_id,),
                       via="build_landed").run_id:
                n += 1
    return n


def compile_one_detached(version_id: UUID) -> None:
    """After an upload or an activation attempt: compile that version for
    this host, in the background, when a slot is free."""
    # A system connection, as the triage sweep above (S1).
    from noctornal_api.db import SystemPurpose, connect_system
    try:
        conn = connect_system(SystemPurpose.LAB_TRIAGE)
    except Exception:  # noqa: BLE001
        return
    try:
        settings = settings_or_default()
        slot = take_slot(conn, settings.concurrency)
        if slot is None:
            return
        try:
            compile_pending(conn, settings, limit=1, version_id=version_id)
        finally:
            release_slot(conn, slot)
    except Exception:  # noqa: BLE001
        log.warning("compiling YARA version %s failed in the background",
                    version_id, exc_info=True)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Reads for the card and the queue
# ---------------------------------------------------------------------------

_SUMMARY_SQL = """
SELECT DISTINCT ON (r.sample_id)
       r.sample_id, r.id, r.status, r.requested_by, u.display_name, u.email,
       r.queued_at, r.started_at, r.finished_at, r.failure, r.outcome,
       (SELECT count(DISTINCT e->>'requested_by')
          FROM jsonb_array_elements(r.requests) e
         WHERE e->>'requested_by' IS NOT NULL)
  FROM lab.static_run r
  LEFT JOIN iam.app_user u ON u.id = r.requested_by
 WHERE r.sample_id = ANY(%s::uuid[])
 ORDER BY r.sample_id, r.queued_at DESC, r.id DESC"""


def _summary(row) -> dict:
    """What a reader of the sample may know about a run: its status, who
    asked (or that it was scheduled), when, why it failed, and the limits.
    Never its steps, trigger, YARA set identity or YARA counts, so a
    reader cannot learn that a rule set they cannot see ran."""
    outcome = row[10] or {}
    return {"status": row[2].lower(), "run_id": str(row[1]),
            "trigger_kind": "requested" if row[3] else "scheduled",
            "requested_by_name": row[4], "requested_by_email": row[5],
            "requesters": row[11] or 0,
            "queued_at": row[6].isoformat() if row[6] else None,
            "started_at": row[7].isoformat() if row[7] else None,
            "finished_at": row[8].isoformat() if row[8] else None,
            "failure": row[9],
            "limits": outcome.get("limits")}


def static_triage_summaries(conn, ids) -> dict[str, dict]:
    """`{sample id: summary}` for a page of samples, in one query. A
    sample never triaged has no entry (the router says `never`)."""
    wanted = sorted({str(i) for i in ids if i})
    if not wanted:
        return {}
    return {str(r[0]): _summary(r)
            for r in conn.execute(_SUMMARY_SQL, (wanted,)).fetchall()}


def static_runs(conn, sample_id, *, limit: int = 5) -> list[dict]:
    rows = conn.execute(
        """SELECT r.sample_id, r.id, r.status, r.requested_by, u.display_name,
                  u.email, r.queued_at, r.started_at, r.finished_at,
                  r.failure, r.outcome,
                  (SELECT count(DISTINCT e->>'requested_by')
                     FROM jsonb_array_elements(r.requests) e
                    WHERE e->>'requested_by' IS NOT NULL)
             FROM lab.static_run r
             LEFT JOIN iam.app_user u ON u.id = r.requested_by
            WHERE r.sample_id = %s
            ORDER BY r.queued_at DESC, r.id DESC LIMIT %s""",
        (sample_id, limit)).fetchall()
    return [_summary(r) for r in rows]


# ---------------------------------------------------------------------------
# Retrohunt (F12 F)
# ---------------------------------------------------------------------------

def retrohunt(conn: psycopg.Connection, version_id: UUID, *, ruleset_id: UUID,
              number: int, actor_id: UUID, clearance: str,
              compartments) -> dict:
    """Queue the yara step with one ACTIVE version for every sample the
    caller can see (their lab gate), that is not rejected, whose case is
    not closed and that is within the analysis maximum. The runs name the
    caller, so each read's custody names them; the answer counts only
    the caller's own view. A version
    with no open activation is refused rather than decrypting samples to
    scan with nothing (2026-09-24)."""
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    from noctornal_api.samples import gate_params, lab_gate
    from noctornal_api.yara_rules import RulesetError
    if not conn.execute(
            "SELECT 1 FROM lab.yara_activation WHERE version_id = %s "
            "AND deactivated_at IS NULL", (version_id,)).fetchone():
        raise RulesetError("that version is not active, so a rescan would "
                           "scan with nothing; activate it first",
                           code="not_active")
    settings = settings_or_default()
    rows = conn.execute(
        f"""SELECT s.id, s.state, s.byte_size, c.status
              FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
             WHERE {lab_gate()}
             ORDER BY s.submitted_at""",
        gate_params(clearance, compartments)).fetchall()
    counts = {"queued": 0, "merged": 0,
              "skipped": {"rejected": 0, "case_read_only": 0, "too_large": 0}}
    with conn.transaction():
        for sample_id, state, size, case_status in rows:
            if state == "REJECTED":
                counts["skipped"]["rejected"] += 1
                continue
            if case_status in CONTENT_READ_ONLY_STATES:
                counts["skipped"]["case_read_only"] += 1
                continue
            if size > settings.max_bytes:
                counts["skipped"]["too_large"] += 1
                continue
            result = enqueue(conn, sample_id, trigger="RETROHUNT",
                             requested_by=actor_id, steps=("yara",),
                             yara_version_ids=(version_id,))
            if result.run_id is None:
                counts["skipped"]["rejected"] += 1
            elif result.merged:
                counts["merged"] += 1
            else:
                counts["queued"] += 1
        conn.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action,
                                        object_type, object_id, outcome, detail)
               VALUES (%s, 'USER', 'YARA_RETROHUNT_QUEUED', 'yara_ruleset', %s,
                       'SUCCESS', %s)""",
            (actor_id, ruleset_id, Json({"version": number, **counts})))
    return counts


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------

def backfill(conn: psycopg.Connection, *, host_user: str | None,
             settings: AnalysisSettings | None = None) -> int:
    """Queue a BACKFILL run for every held sample that has never been
    triaged: not rejected or excluded, no DONE run, its case not closed,
    within the analysis maximum. Decrypting every held sample is the
    operator's decision, recorded as theirs: a SYSTEM audit row naming the
    command and the host user, and the same `via` on every request
    (2026-09-24)."""
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    from noctornal_api.samples import lab_exclusions_sql
    settings = settings or settings_or_default()
    via = "lab_triage.py --backfill"
    rows = conn.execute(
        f"""SELECT s.id FROM lab.sample s
              LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
             WHERE s.state <> 'REJECTED' AND {lab_exclusions_sql('s')}
               AND s.byte_size <= %s
               AND (c.status IS NULL OR NOT (c.status = ANY(%s)))
               AND NOT EXISTS (SELECT 1 FROM lab.static_run r
                                WHERE r.sample_id = s.id AND r.status = 'DONE')
             ORDER BY s.submitted_at""",
        (settings.max_bytes, list(CONTENT_READ_ONLY_STATES))).fetchall()
    n = 0
    with conn.transaction():
        for (sample_id,) in rows:
            if enqueue(conn, sample_id, trigger="BACKFILL", via=via).run_id:
                n += 1
        conn.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action,
                                        object_type, outcome, detail)
               VALUES (NULL, 'SYSTEM', 'SAMPLE_STATIC_TRIAGE_BACKFILL',
                       'sample', 'SUCCESS', %s)""",
            (Json({"via": via, "host_user": host_user, "count": n}),))
    return n


__all__ = [
    "AnalysisSettings", "CHILD_ARGV", "Claimed", "EnqueueResult",
    "MAX_ATTEMPTS", "SETTINGS_ENV", "analysis_settings", "backfill", "claim",
    "compile_pending", "enqueue", "limits_words", "queue_depth", "run_child",
    "run_claimed", "run_due", "run_queued_detached", "running_run",
    "selftest", "slot_free", "static_runs", "static_triage_summaries",
    "sweep_abandoned",
]
