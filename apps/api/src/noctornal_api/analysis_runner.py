"""Where hostile bytes are parsed: a bounded child process on this host,
or the same bounded child inside the isolated analysis worker (docs/17
F42, 2026-10-02).

## Why two runners, and one child

Static triage (`lab_triage`, every step in `lab_static`) and forum
parsing (`forum_parse`, one page at a time) read bytes written by the
people under investigation. Since 2026-09-24 each read happens in a child
process that starts without the deployment's secrets and is bounded by a
wall clock and, on Linux, rlimits. That bounds a parser; it does not
confine one. On Linux the child can read `/proc/<pid>/environ` of every
process of the same user, which hold every secret in secrets.env, and it
shares its container's network with the database. The owner decided on
2026-10-02 to close that with a container of its own: no secrets, no
network, a read-only root, no capabilities, a pids and memory limit and a
user of its own (infra/production/compose.yml, `analysis-worker`).

So there are two runners and exactly one child. `run_local` is the
bounded subprocess this module has always started (development, Windows,
and a production deployment that says out loud it accepts the residual).
`run_isolated` hands the same request to the worker over a Unix socket on
a volume only the application containers mount, and the worker starts
the child with `run_local`, the same function, so the parsers, their
limits and their failure kinds never fork into two implementations. (In
the worker the child also runs as a uid of its own, under a task limit;
analysis_worker's docstring says why.)

## Choosing one (`runner_choice`)

NOCTORNAL_ANALYSIS_SOCKET names the worker's socket: isolated. Unset,
development runs locally. Unset in PRODUCTION is not a fallback: every
analysis is refused, nothing is decrypted or parsed, and the readiness
row `sample_static_analysis` says why, until the socket is set or
NOCTORNAL_ANALYSIS_LOCAL=1 accepts the local child explicitly (which the
row then reports as not ready). A worker that does not answer is refused
the same way and never replaced by a local child: a silent fallback
would put the hostile bytes back beside the secrets on the day the
sandbox broke, which is the day nobody is looking.

## Production reports a missing worker; it does not refuse to boot

config.verify_environment refuses a value SET and unusable, as it
refuses every malformed setting. It does not refuse an UNSET socket, for
three reasons (decided 2026-10-02). The boot check reads one environment
and the runner is a per-process fact: secrets.env makes every application
container production, the sample origin and lab-cron parse nothing and
are given no socket, and the cron loop's collection poll, which does
parse, never runs the boot check at all; a boot rule would stop processes
that never analyse and miss one that does. The worker can also stop after
everything has booted, so the refusal at the point of use and the
readiness row are needed regardless, and a boot rule would be a second
reader of the same fact. And refusing the console, its case work and its
evidence intake over the sandbox of two features is the disproportionate
refusal config.py warns teaches operators to switch refusals off;
refusing exactly those two features, by name, is the proportionate one.

## The wire

One request per connection. Both directions start with a frame: four
bytes of magic, a big-endian u32 length and that many bytes of JSON, at
most `FRAME_HEADER_CAP`. A request's frame names its id, its kind, the
child's wall clock, the output cap and each payload's length, and the
payloads follow raw; a reply's frame echoes the id and names the outcome
and the output's length, and the output follows. Every read is capped
before it is made and bounded by a deadline, an idle limit included, so
neither side can be held by a slow or lying peer. Nothing the worker says
is believed beyond its shape: an unknown failure, a wrong id or an output
longer than was asked for is `worker_bad_answer`.

This is not an outbound connection: a Unix socket on a volume, never an
address (test_egress_single_exit names this module for that reason).
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

log = logging.getLogger("noctornal.analysis")

MIB = 1 << 20

# ---------------------------------------------------------------------------
# The choice
# ---------------------------------------------------------------------------

SOCKET_ENV = "NOCTORNAL_ANALYSIS_SOCKET"
LOCAL_ENV = "NOCTORNAL_ANALYSIS_LOCAL"
#: sun_path is 108 bytes on Linux and 104 on macOS; a path that does not
#: fit is refused by name rather than truncated by the kernel.
SOCKET_PATH_MAX = 100

#: Whether this platform has Unix sockets at all (Windows' CPython does
#: not). A module attribute so a test can stand a TCP pair in for one.
HAS_UNIX = hasattr(socket, "AF_UNIX")

NOT_CONFIGURED = (
    "No isolated analysis worker is configured (NOCTORNAL_ANALYSIS_SOCKET), "
    "and this production deployment does not parse hostile input beside its "
    "own secrets, so nothing was analysed; run the analysis-worker service, "
    "or set NOCTORNAL_ANALYSIS_LOCAL=1 to parse in a local child on this "
    "host, beside those secrets")
NO_UNIX = (
    "NOCTORNAL_ANALYSIS_SOCKET is set and this platform has no Unix sockets, "
    "so the isolated analysis worker cannot be reached; unset it to analyse "
    "in a local child (development only)")
WORKER_SILENT = (
    "The isolated analysis worker did not answer on its socket "
    "(NOCTORNAL_ANALYSIS_SOCKET), so nothing was analysed; start the "
    "analysis-worker service and read its log")


@dataclass(frozen=True)
class RunnerChoice:
    #: local | isolated | refused
    mode: str
    socket_path: str | None = None
    #: NOCTORNAL_ANALYSIS_LOCAL=1 chose the local child.
    explicit_local: bool = False
    production: bool = False
    #: Why `refused`, in a sentence that names variables and never a value.
    reason: str | None = None


def _production(env: Mapping[str, str]) -> bool:
    # The mode's one spelling is config's (ENV_VAR, PRODUCTION); read the
    # same way egress._production reads it.
    from noctornal_api.config import ENV_VAR, PRODUCTION
    return env.get(ENV_VAR, "").strip().lower() == PRODUCTION


def setting_problem(env: Mapping[str, str] | None = None) -> str | None:
    """Why the two settings, as SET, cannot be used; None when they can or
    are unset. The one reader of their shape: the runner refuses on it and
    a production boot refuses on it (config.verify_environment). Whether an
    UNSET socket is acceptable is `runner_choice`'s question, not this."""
    env = os.environ if env is None else env
    raw = env.get(SOCKET_ENV, "")
    local = env.get(LOCAL_ENV, "").strip()
    if local and local != "1":
        return f"{LOCAL_ENV} must be 1 or unset"
    if raw.strip() and local:
        return (f"{SOCKET_ENV} and {LOCAL_ENV} are both set, so it is not "
                f"said whether analysis runs in the isolated worker or here")
    path = raw.strip()
    if not path:
        return None
    if path != raw or "\x00" in path or not path.startswith("/"):
        return f"{SOCKET_ENV} must be an absolute path to the worker's socket"
    if len(path.encode("utf-8")) > SOCKET_PATH_MAX:
        return (f"{SOCKET_ENV} is longer than {SOCKET_PATH_MAX} bytes, which a "
                f"Unix socket address cannot hold")
    return None


def runner_choice(env: Mapping[str, str] | None = None) -> RunnerChoice:
    """Which runner analyses here, and why. Fails closed: a setting that
    is unusable, or production with neither setting, is `refused`."""
    env = os.environ if env is None else env
    production = _production(env)
    problem = setting_problem(env)
    if problem:
        return RunnerChoice("refused", production=production, reason=problem)
    path = env.get(SOCKET_ENV, "").strip()
    if path:
        if not HAS_UNIX:
            return RunnerChoice("refused", production=production, reason=NO_UNIX)
        return RunnerChoice("isolated", socket_path=path, production=production)
    explicit = env.get(LOCAL_ENV, "").strip() == "1"
    if production and not explicit:
        return RunnerChoice("refused", production=True, reason=NOT_CONFIGURED)
    return RunnerChoice("local", explicit_local=explicit, production=production)


# ---------------------------------------------------------------------------
# What a run answers
# ---------------------------------------------------------------------------

@dataclass
class ChildResult:
    ok: bool
    #: bytes, or the bytearray the local runner filled (one copy of a
    #: large output, not two; `run` hands the application bytes).
    output: bytes | bytearray = b""
    #: None, or: start_failed | timeout | output_too_large | crashed, or one
    #: of the runner's own: isolation_refused | worker_unavailable |
    #: worker_bad_answer | worker_refused | worker_busy
    failure: str | None = None
    returncode: int | None = None


#: What a child itself can fail with, wherever it ran.
CHILD_FAILURE_KINDS = ("start_failed", "timeout", "output_too_large", "crashed")
#: What the worker may answer instead of running a child.
WORKER_FAILURE_KINDS = ("worker_refused", "worker_busy")
#: The runner's own failures: no child ran, or none answered through the
#: sandbox, so they say nothing about the page or the sample. Every caller
#: reads them as the sandbox's state: never parser drift, never a crashed
#: step, never an attempt spent (F42 review, 2026-10-02).
SANDBOX_FAILURES = ("isolation_refused", "worker_unavailable",
                    "worker_bad_answer", "worker_refused", "worker_busy")

# ---------------------------------------------------------------------------
# The local child (moved here from lab_triage.run_child, F42 2026-10-02, so
# the worker runs exactly this)
# ---------------------------------------------------------------------------

STDERR_KEPT = 4 * 1024
#: How long `run_local` waits for the threads that attend a child once the
#: child and what it left behind are stopped. A module attribute so a test
#: can shrink it.
PIPE_GRACE_S = 5.0


def package_root() -> str:
    import noctornal_api
    return os.path.dirname(os.path.dirname(os.path.abspath(
        noctornal_api.__file__)))


def child_env() -> dict[str, str]:
    """The child's whole environment: a PATH, what Windows needs to start
    an interpreter, a locale, two flags that stop it writing, and where
    THIS process's code is, so parent and child run the same module. No
    NOCTORNAL_*, DATABASE_URL, MINIO_*, SAMPLE_*, PRESERVE_*, REDIS_URL or
    SMTP_*: the data key and the KEK never reach a child. (In the isolated
    worker there is nothing of the kind to leave out in the first place.)"""
    env = {"PATH": os.environ.get("PATH", os.defpath),
           "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1",
           "PYTHONNOUSERSITE": "1",
           "PYTHONPATH": package_root()}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if os.environ.get(name):
                env[name] = os.environ[name]
    return env


def child_line(header: dict) -> bytes:
    """The header line a child reads first. ValueError when it is larger
    than the child reads, on both runners alike."""
    from noctornal_api import lab_static
    line = json.dumps({"protocol": lab_static.PROTOCOL, **header},
                      separators=(",", ":")).encode() + b"\n"
    if len(line) > lab_static.HEADER_CAP:
        raise ValueError("header too large")
    return line


#: Run by the child's own uid between the fork and the child's program,
#: when the worker gives the child a uid of its own (F42 review,
#: 2026-10-02): a task limit, then the highest OOM score, then the
#: program. RLIMIT_NPROC counts every process and thread of the REAL uid,
#: and a slot's uid is that slot's alone, so the count is exactly the
#: child's; set before the program's first instruction, it binds a child
#: that never applies limits of its own as well. The OOM score makes the
#: kernel pick a child, never the worker, when the container's memory
#: runs out. Never `preexec_fn` (unsafe in a threaded server): a small
#: program that execs the real one, and a limit it cannot set ends the
#: run, so a child never starts unbounded.
_LAUNCHER = (
    "import os, resource, sys\n"
    "n = int(sys.argv[1])\n"
    "resource.setrlimit(resource.RLIMIT_NPROC, (n, n))\n"
    "try:\n"
    "    with open('/proc/self/oom_score_adj', 'w') as f:\n"
    "        f.write('1000')\n"
    "except OSError:\n"
    "    pass\n"
    "os.execv(sys.argv[2], sys.argv[2:])\n")


def launch_argv(argv: list[str], max_tasks: int) -> list[str]:
    """`argv` behind the launcher: at most `max_tasks` processes and
    threads for the child's uid. `-I -S`: the launcher reads no setting
    and imports no site, so nothing in the environment changes it."""
    return [sys.executable, "-I", "-S", "-c", _LAUNCHER, str(int(max_tasks)),
            *argv]


def _wait(proc, seconds: float) -> None:
    try:
        proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        # Killed and still not gone: logged, and the worker's purge of the
        # slot's uid answers for it (analysis_worker.purge_user).
        log.warning("an analysis child did not exit after it was killed")


def _close_quietly(pipe) -> None:
    try:
        pipe.close()
    except (OSError, ValueError):
        pass


def _reap_quietly(reap) -> None:
    """Run the caller's `reap`; an error in it is logged and never ends the
    run (the worker purges the slot's uid again before it frees the slot,
    and retires the slot when it cannot)."""
    if reap is None:
        return
    try:
        reap()
    except Exception:  # noqa: BLE001 - the answer does not depend on it
        log.warning("an analysis child's leftovers could not be stopped",
                    exc_info=True)


def run_local(header: dict, payloads: tuple = (), *, wall_s: float,
              stdout_cap: int, argv: list[str], user: int | None = None,
              max_tasks: int | None = None, reap=None) -> ChildResult:
    """Start one child, feed it over stdin, read its answer under a cap
    and a wall clock, and never let it outlive either.

    The sample is written 1 MiB at a time by a writer thread, never as one
    concatenated frame; stdout is read incrementally and the child killed
    the moment it passes `stdout_cap`; stderr is drained so a chatty child
    cannot block, and its first `STDERR_KEPT` bytes go to this process's
    log only. Never `preexec_fn`, which is unsafe in a threaded server: a
    new session (POSIX) or process group (Windows) instead, so the kill
    takes the whole group.

    `user` (POSIX, the isolated worker only) runs the child as that uid
    and gid with no supplementary group, behind `launch_argv` when
    `max_tasks` is given. A child that cannot be attended (no thread to
    feed or read it) is killed, never left running.

    What the child leaves running (F42 verify 1, 2026-10-03). A process the
    child started can keep its stdout, stderr or stdin open after the child
    has gone, and a pipe held open is a read that never ends. Closing such
    a pipe from here waits for the lock the blocked read holds, which
    wedged the worker's slot, and the request with it, for as long as the
    helper lived. So each thread closes its own pipe when its read or write
    ends, and nothing here closes a pipe a thread may still be using. Once
    the child has exited, or been killed at its wall clock, this stops what
    it left BEFORE it waits on any pipe: the child's whole group (a normal
    exit used to leave it alone), then `reap`, which the worker uses to
    empty the slot's uid (every process of it, in any group or session).
    Only then are the threads joined, and for at most PIPE_GRACE_S: a
    helper nothing here can stop (one that left the session when there is
    no uid to purge, or any helper on Windows) is not waited for, and what
    it writes after this returns is never added to the answer."""
    line = child_line(header)
    extra: dict = {}
    if os.name == "posix":
        extra["start_new_session"] = True
        if user is not None:
            extra.update(user=user, group=user, extra_groups=[])
            if max_tasks is not None:
                argv = launch_argv(argv, max_tasks)
    else:
        if user is not None:
            raise RuntimeError("a child of a uid of its own needs POSIX")
        extra["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP
                                  | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=child_env(), close_fds=True, **extra)
    except OSError:
        log.warning("an analysis child could not be started", exc_info=True)
        return ChildResult(False, failure="start_failed")
    # One buffer, grown as the child writes: a large output is held once,
    # not once in parts and again joined (F42 review, 2026-10-02). `lock`
    # and state["done"] keep a thread that is still blocked after this
    # function has returned from writing into what it handed back.
    out = bytearray()
    state = {"over": False, "done": False}
    err = bytearray()
    lock = threading.Lock()

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
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            _close_quietly(proc.stdin)

    def reader() -> None:
        try:
            while True:
                try:
                    chunk = proc.stdout.read1(1 << 16)
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                with lock:
                    if state["done"]:
                        break
                    over = len(out) + len(chunk) > stdout_cap
                    if over:
                        state["over"] = True
                    else:
                        out.extend(chunk)
                if over:
                    kill()
                    break
        finally:
            _close_quietly(proc.stdout)

    def drain() -> None:
        try:
            while True:
                try:
                    chunk = proc.stderr.read1(1 << 16)
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                with lock:
                    if state["done"]:
                        break
                    if len(err) < STDERR_KEPT:
                        err.extend(chunk[:STDERR_KEPT - len(err)])
        finally:
            _close_quietly(proc.stderr)

    pipes = (proc.stdin, proc.stdout, proc.stderr)
    threads = [threading.Thread(target=t, daemon=True)
               for t in (writer, reader, drain)]
    started = []
    try:
        for t in threads:
            t.start()
            started.append(t)
    except RuntimeError:
        # No thread to be had (the tasks of this process's container are
        # spent): a child nobody feeds or reads would run unbounded, so it
        # is killed and the run is a start failure (F42 review, 2026-10-02).
        log.warning("an analysis child could not be attended, and was stopped")
        kill()
        _wait(proc, 30)
        _reap_quietly(reap)
        for t in started:
            t.join(timeout=PIPE_GRACE_S)
        # A thread that never started cannot close its pipe; one that did
        # closes its own.
        for t, pipe in zip(threads, pipes, strict=True):
            if t not in started:
                _close_quietly(pipe)
        return ChildResult(False, failure="start_failed",
                           returncode=proc.returncode)
    timed_out = False
    try:
        proc.wait(timeout=wall_s)
    except subprocess.TimeoutExpired:
        timed_out = True
    # Whatever the child left running may hold its pipes open, and a pipe
    # held open is a read that does not end: stop all of it first. The group
    # is killed on a normal exit too (a helper started without setsid is in
    # it); a group with no member left is a signal to nothing, and while one
    # member lives the kernel does not hand its id to another process.
    kill()
    if timed_out:
        _wait(proc, 30)
    _reap_quietly(reap)
    end = time.monotonic() + PIPE_GRACE_S
    for t in threads:
        t.join(timeout=max(0.0, end - time.monotonic()))
    with lock:
        state["done"] = True
        left = sum(t.is_alive() for t in threads)
        kept = bytes(err)
    if left:
        log.warning("an analysis child left a process holding %d of its pipes "
                    "after it was stopped; the run is answered without waiting "
                    "for it", left)
    if kept:
        # The process log, never the UI, the audit chain or the run row: a
        # parser's message can quote hostile bytes.
        log.info("analysis child stderr (first %d bytes): %r", len(kept), kept)
    if state["over"]:
        return ChildResult(False, failure="output_too_large",
                           returncode=proc.returncode)
    if timed_out:
        return ChildResult(False, failure="timeout", returncode=proc.returncode)
    if proc.returncode != 0:
        return ChildResult(False, out, failure="crashed",
                           returncode=proc.returncode)
    return ChildResult(True, out, returncode=0)


# ---------------------------------------------------------------------------
# The wire
# ---------------------------------------------------------------------------

WIRE_VERSION = 1
MAGIC = b"NAW1"
FRAME_HEADER_CAP = 64 * 1024
#: The child modules the worker starts, by name. A peer names a kind; it
#: never names a program.
#: `lab_archive_child` is archive expansion's (phase 8, merged 2026-10-03):
#: it reads an archive from stdin and answers its members, with no path
#: written, under the same limits and failure kinds as the others.
KINDS = ("lab_static", "forum_parse", "lab_archive_child")
HELLO = "hello"
MAX_PAYLOADS = 4
#: The largest output the worker hands back, whatever a request asks: the
#: archive child's members (its default 256 MiB of them, and a line of report
#: for each, `lab_archive.stdout_cap`) are the largest answer any child
#: gives, above a compiled YARA build (yara_rules). `lab_archive.
#: archive_settings` refuses a setting that would ask for more, by name.
MAX_OUTPUT_BYTES = 320 * MIB
MAX_WALL_S = 3700.0
CONNECT_TIMEOUT_S = 5.0
#: The longest either side waits for the next byte of something it was
#: promised. Module attributes so a test can shrink them.
IDLE_S = 10.0
TRANSFER_BASE_S = 30.0
#: The slowest rate a transfer is allowed, in bytes a second, on top of
#: TRANSFER_BASE_S: 8 MiB/s is far below a local socket's.
MIN_RATE = 8 * MIB
#: How long a request may wait for one of the worker's slots.
QUEUE_WAIT_S = 30.0
#: How long `unavailable` waits for the worker's hello (twice this, for
#: the whole exchange), and how long its verdict is believed. Callers ask
#: once per forum source in a source list and on every schedule pass, so
#: a worker that accepts and never answers must cost one wait, not one per
#: source (F42 review, 2026-10-02). Module attributes so a test can
#: shrink them.
HELLO_TIMEOUT_S = CONNECT_TIMEOUT_S
VERDICT_TTL_S = 5.0
_ID = re.compile(r"[0-9a-f]{32}")


class WireError(Exception):
    """A frame that did not arrive whole and well formed. `kind` is closed
    (the peer hung up), timeout, malformed or oversize."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def pack_frame(header: dict) -> bytes:
    body = json.dumps(header, separators=(",", ":")).encode("utf-8")
    if len(body) > FRAME_HEADER_CAP:
        raise ValueError("frame header too large")
    return MAGIC + struct.pack(">I", len(body)) + body


def _remaining(deadline: float, idle: bool = True) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise WireError("timeout")
    return min(IDLE_S, left) if idle else left


def recv_exact(sock, n: int, deadline: float, *, idle: bool = True,
               mutable: bool = False) -> bytes | bytearray:
    """Exactly `n` bytes, or WireError. Grown as bytes arrive, never
    allocated up front, so a peer that declares much and sends little
    costs what it sent. `idle=False` waits for the bytes until the
    deadline alone: a reply starts only once its child has finished.
    `mutable` hands back the buffer itself rather than a bytes copy of
    it, so the worker holds a payload once while it arrives, not twice
    (F42 review, 2026-10-02)."""
    buf = bytearray()
    while len(buf) < n:
        sock.settimeout(_remaining(deadline, idle))
        try:
            chunk = sock.recv(min(n - len(buf), MIB))
        except TimeoutError:
            raise WireError("timeout") from None
        except OSError:
            raise WireError("closed") from None
        if not chunk:
            raise WireError("closed")
        buf += chunk
    return buf if mutable else bytes(buf)


def send_all(sock, data, deadline: float) -> None:
    view = memoryview(data)
    for i in range(0, len(view), MIB):
        sock.settimeout(_remaining(deadline))
        try:
            sock.sendall(view[i:i + MIB])
        except TimeoutError:
            raise WireError("timeout") from None
        except OSError:
            raise WireError("closed") from None


def read_frame(sock, deadline: float, *, wait: bool = False) -> dict:
    """One frame. With `wait`, its first bytes may take until the deadline
    (a caller waiting while the worker's child runs); the rest of it, and
    every frame without `wait`, must keep coming within IDLE_S."""
    head = recv_exact(sock, 8, deadline, idle=not wait)
    if head[:4] != MAGIC:
        raise WireError("malformed")
    (n,) = struct.unpack(">I", head[4:])
    if n == 0 or n > FRAME_HEADER_CAP:
        raise WireError("oversize")
    raw = recv_exact(sock, n, deadline)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise WireError("malformed") from None
    if not isinstance(value, dict):
        raise WireError("malformed")
    return value


def transfer_deadline(started: float, nbytes: int) -> float:
    return started + TRANSFER_BASE_S + nbytes / MIN_RATE


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------

class WorkerUnavailable(Exception):
    """The worker did not answer, or answered something that is not an
    answer. The message is a fixed word, never what the peer sent."""


def _connect_unix(path: str):
    """A connection to the worker's socket. The path must BE a socket
    (lstat, so a symlink is refused): the worker alone writes the volume,
    and a client never follows a name somewhere else."""
    st = os.lstat(path)
    if not stat.S_ISSOCK(st.st_mode):
        raise OSError("not a socket")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT_S)
    try:
        sock.connect(path)
    except OSError:
        sock.close()
        raise
    return sock


def _valid_reply(reply: dict, rid: str, stdout_cap: int) -> bool:
    if reply.get("v") != WIRE_VERSION or reply.get("id") != rid:
        return False
    ok = reply.get("ok")
    n = reply.get("output_len")
    failure = reply.get("failure")
    code = reply.get("returncode")
    if not isinstance(ok, bool) or isinstance(n, bool) or not isinstance(n, int):
        return False
    if not 0 <= n <= stdout_cap:
        return False
    if ok and failure is not None:
        return False
    if not ok and failure not in CHILD_FAILURE_KINDS + WORKER_FAILURE_KINDS:
        return False
    if code is not None and (isinstance(code, bool) or not isinstance(code, int)
                             or not -2 ** 31 <= code < 2 ** 31):
        return False
    return True


def run_isolated(path: str, kind: str, header: dict, payloads: tuple = (), *,
                 wall_s: float, stdout_cap: int, connect=None) -> ChildResult:
    """One request to the worker, answered as `run_local` answers. The
    worker's own failures are `worker_unavailable` (no connection, the
    connection ended, or no answer by the deadline) and
    `worker_bad_answer`; what it says it refused is `worker_refused` or
    `worker_busy`. Never a local child instead."""
    if kind not in KINDS:
        raise ValueError("unknown analysis kind")
    child_line(header)
    rid = uuid.uuid4().hex
    sizes = [len(p) for p in payloads]
    request = {"v": WIRE_VERSION, "id": rid, "kind": kind,
               "wall_s": float(wall_s), "stdout_cap": int(stdout_cap),
               "payloads": sizes, "child": header}
    frame = pack_frame(request)
    started = time.monotonic()
    # The child's own wall clock, a wait for a slot and the transfers both
    # ways: past this the worker is not answering, whatever it is doing.
    deadline = (started + float(wall_s) + QUEUE_WAIT_S + 2 * TRANSFER_BASE_S
                + (sum(sizes) + int(stdout_cap)) / MIN_RATE)
    try:
        sock = (connect or _connect_unix)(path)
    except OSError:
        log.warning("analysis request %s: the worker could not be reached", rid)
        return ChildResult(False, failure="worker_unavailable")
    try:
        try:
            send_all(sock, frame, deadline)
            for payload in payloads:
                send_all(sock, payload, deadline)
        except WireError:
            # The worker may have refused and hung up mid-send: its
            # refusal, when it sent one, is the better answer.
            pass
        reply = read_frame(sock, deadline, wait=True)
        if not _valid_reply(reply, rid, int(stdout_cap)):
            log.warning("analysis request %s: the worker's answer is not one", rid)
            return ChildResult(False, failure="worker_bad_answer")
        output = recv_exact(sock, reply["output_len"], deadline) \
            if reply["output_len"] else b""
    except WireError as exc:
        kind_ = "worker_bad_answer" if exc.kind in ("malformed", "oversize") \
            else "worker_unavailable"
        log.warning("analysis request %s: %s from the worker (%s)", rid,
                    kind_, exc.kind)
        return ChildResult(False, failure=kind_)
    finally:
        sock.close()
    return ChildResult(reply["ok"], output, failure=reply.get("failure"),
                       returncode=reply.get("returncode"))


def hello(path: str, *, connect=None, timeout_s: float = CONNECT_TIMEOUT_S) -> dict:
    """The worker's account of itself (`Worker.status`). Raises
    WorkerUnavailable. Short: `unavailable` asks it before a pass or a
    forum poll (remembering the answer briefly), readiness and the
    healthcheck ask it every time, and a worker that cannot answer this
    quickly is not one to hand a sample to."""
    rid = uuid.uuid4().hex
    deadline = time.monotonic() + 2 * timeout_s
    try:
        sock = (connect or _connect_unix)(path)
    except OSError:
        raise WorkerUnavailable("unreachable") from None
    try:
        send_all(sock, pack_frame({"v": WIRE_VERSION, "id": rid,
                                   "kind": HELLO}), deadline)
        reply = read_frame(sock, deadline)
    except WireError as exc:
        raise WorkerUnavailable(exc.kind) from None
    finally:
        sock.close()
    status = reply.get("status")
    if (reply.get("v") != WIRE_VERSION or reply.get("id") != rid
            or reply.get("ok") is not True or not isinstance(status, dict)):
        raise WorkerUnavailable("bad_answer")
    return status


def run(kind: str, header: dict, payloads: tuple = (), *, wall_s: float,
        stdout_cap: int, argv: list[str], env: Mapping[str, str] | None = None,
        connect=None) -> ChildResult:
    """THE dispatch: the chosen runner, or a refusal. `argv` is the local
    child's; the worker starts only the modules it knows by `kind`."""
    choice = runner_choice(env)
    if choice.mode == "refused":
        log.warning("analysis refused: %s", choice.reason)
        return ChildResult(False, failure="isolation_refused")
    if choice.mode == "isolated":
        return run_isolated(choice.socket_path, kind, header, payloads,
                            wall_s=wall_s, stdout_cap=stdout_cap, connect=connect)
    result = run_local(header, payloads, wall_s=wall_s, stdout_cap=stdout_cap,
                       argv=argv)
    if isinstance(result.output, bytearray):
        # The application reads bytes, as from the worker; only the worker
        # keeps the buffer it filled.
        result.output = bytes(result.output)
    return result


#: socket path -> (monotonic expiry, verdict). See VERDICT_TTL_S.
_verdicts: dict[str, tuple[float, str | None]] = {}
_verdict_lock = threading.Lock()


def forget_verdicts() -> None:
    """Drop every remembered verdict (a test changes the worker under the
    same socket path)."""
    with _verdict_lock:
        _verdicts.clear()


def unavailable(env: Mapping[str, str] | None = None, *, connect=None) -> str | None:
    """Why nothing can be analysed from here right now, in a sentence, or
    None. Callers ask BEFORE they decrypt a sample or fetch a page, so a
    missing worker costs a pass and never a sample's attempts.

    The worker's answer is remembered for VERDICT_TTL_S, and asked by one
    caller at a time: the others wait for that answer rather than each
    asking (F42 review, 2026-10-02). The cost against a worker that accepts
    and never answers is therefore one wait of at most 2 * HELLO_TIMEOUT_S
    (10 seconds) per VERDICT_TTL_S window, however many forum sources ask,
    where it was 10 seconds for every source. A worker that stops inside that
    window costs the request that finds out, which every caller handles
    as the sandbox's state (SANDBOX_FAILURES). Readiness and the
    healthcheck call `hello` and are never answered from memory."""
    choice = runner_choice(env)
    if choice.mode == "refused":
        return choice.reason
    if choice.mode == "local":
        return None
    path = choice.socket_path
    with _verdict_lock:
        known = _verdicts.get(path)
        if known is not None and time.monotonic() < known[0]:
            return known[1]
        try:
            hello(path, connect=connect, timeout_s=HELLO_TIMEOUT_S)
            verdict = None
        except WorkerUnavailable:
            verdict = WORKER_SILENT
        _verdicts[path] = (time.monotonic() + VERDICT_TTL_S, verdict)
        return verdict


# ---------------------------------------------------------------------------
# What the worker may hold
# ---------------------------------------------------------------------------

#: The worker's own settings (read in analysis_worker).
CONCURRENCY_ENV = "NOCTORNAL_ANALYSIS_WORKER_CONCURRENCY"
MAX_BYTES_ENV = "NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES"
#: The worker's own settings, by exact name. Until the F42 review
#: (2026-10-02) any NOCTORNAL_ANALYSIS_ name passed, so a secret that
#: happened to carry the prefix would have too.
WORKER_OWN_ENV = frozenset({SOCKET_ENV, CONCURRENCY_ENV, MAX_BYTES_ENV})
#: The only variables the worker's environment may carry: what the base
#: image and Docker set (GPG_KEY is the python image's release signing key
#: fingerprint, public by design), and the worker's own settings. An
#: allow-list, not a deny-list: a variable nobody named is refused, so a
#: credential added to the service later stops it rather than riding in.
WORKER_ALLOWED_ENV = frozenset({
    "PATH", "HOME", "HOSTNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ",
    "container", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256",
    "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
    "PYTHONPATH", "PIP_DISABLE_PIP_VERSION_CHECK"}) | WORKER_OWN_ENV


def foreign_environment(keys) -> list[str]:
    """The names in `keys` the worker must not hold, sorted. Names only:
    a value never reaches this function."""
    return sorted(k for k in keys if isinstance(k, str)
                  and k not in WORKER_ALLOWED_ENV)


__all__ = [
    "ChildResult", "HAS_UNIX", "KINDS", "LOCAL_ENV", "RunnerChoice",
    "SANDBOX_FAILURES", "SOCKET_ENV", "WORKER_OWN_ENV", "WorkerUnavailable",
    "child_env", "foreign_environment", "forget_verdicts", "hello",
    "launch_argv", "run", "run_isolated", "run_local", "runner_choice",
    "setting_problem", "unavailable",
]
