"""Where hostile bytes are parsed: a bounded child process on this host, or the same bounded child
inside the isolated analysis worker.

Static triage (`lab_triage`, `lab_static`) and forum parsing (`forum_parse`) read bytes written by
the people under investigation. A child that starts without the deployment's secrets, bounded by a
wall clock and, on Linux, rlimits, bounds a parser but does not confine it: it can read
`/proc/<pid>/environ` of every process of its user and shares the container's network with the
database. The worker confines it: no secrets, no network, a read-only root, no capabilities, pids
and memory limits and a user of its own (infra/production/compose.yml, `analysis-worker`).

Two runners, one child. `run_local` is the bounded subprocess; `run_isolated` hands the same
request to the worker over a Unix socket on a volume only the application containers mount, and
the worker starts the child with `run_local`, so the parsers, their limits and their failure kinds
never fork. In the worker the child also runs as a uid of its own, under a task limit
(analysis_worker says why).

`runner_choice`: NOCTORNAL_ANALYSIS_SOCKET (a Unix socket) or NOCTORNAL_ANALYSIS_ADDR (TCP with
mutual TLS 1.3, below) set means isolated; unset, development runs locally.
Unset in production is not a fallback: every analysis is refused, nothing is decrypted or parsed,
and the readiness row `sample_static_analysis` says why, until one is set or
NOCTORNAL_ANALYSIS_LOCAL=1 accepts the local child (reported as not ready). A worker that does not
answer is refused the same way, never replaced by a local child: a silent fallback would put the
hostile bytes back beside the secrets on the day the sandbox broke. config.verify_environment
refuses a socket set and unusable but not an unset one: the runner is a per-process fact, a worker
can stop after boot, and refusing the whole console over two features would be disproportionate,
so the refusal is made at the point of use.

The wire: one request per connection, each direction a frame (four bytes of magic, a big-endian u32
length, that much JSON, at most `FRAME_HEADER_CAP`) followed by raw payloads or output. Every read
is capped before it is made and bounded by a deadline and an idle limit, and nothing the worker
says is believed beyond its shape: an unknown failure, a wrong id or an overlong output is
`worker_bad_answer`. A Unix socket on a volume is not an outbound connection
(test_egress_single_exit names this module for that reason).

The second transport is for a worker that is a pod of its own, where no volume is shared (decision
239): the same frames over TCP under mutual TLS 1.3 (NOCTORNAL_ANALYSIS_ADDR for a caller,
NOCTORNAL_ANALYSIS_LISTEN for the worker, each with a certificate, a key and a CA path). It carries
decrypted sample bytes and is a connection that is neither HTTP through the egress proxy nor a
volume, so a caller fences it three ways: it dials only an address that is loopback or inside the
deployment's declared networks (`egress_policy.internal_networks`), and dials the address it checked,
never a second lookup; it trusts the channel's own CA and never the system roots; and it requires TLS
1.3 with a client certificate. There is no plaintext form. Any certificate the CA issued may call the
worker, so that CA is the channel's alone.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass

from noctornal_api import egress_policy
from noctornal_api.egress_policy import hostport

log = logging.getLogger("noctornal.analysis")

MIB = 1 << 20

# ---------------------------------------------------------------------------
# The choice
# ---------------------------------------------------------------------------

SOCKET_ENV = "NOCTORNAL_ANALYSIS_SOCKET"
LOCAL_ENV = "NOCTORNAL_ANALYSIS_LOCAL"
#: The TCP transport: a caller's HOST:PORT, the worker's own address to listen on, and the three files
#: both sides hold (absolute paths). Mutual TLS 1.3 is the only form; see the module docstring.
ADDR_ENV = "NOCTORNAL_ANALYSIS_ADDR"
LISTEN_ENV = "NOCTORNAL_ANALYSIS_LISTEN"
TLS_CERT_ENV = "NOCTORNAL_ANALYSIS_TLS_CERT"
TLS_KEY_ENV = "NOCTORNAL_ANALYSIS_TLS_KEY"
TLS_CA_ENV = "NOCTORNAL_ANALYSIS_TLS_CA"
TLS_ENV = (TLS_CERT_ENV, TLS_KEY_ENV, TLS_CA_ENV)
#: The longest a TLS handshake may take in all, on either side. A module attribute so a test can shrink it.
HANDSHAKE_TIMEOUT_S = 5.0
#: sun_path is 108 bytes on Linux and 104 on macOS; a path that does not
#: fit is refused by name rather than truncated by the kernel.
SOCKET_PATH_MAX = 100

#: Whether this platform has Unix sockets at all (Windows' CPython does
#: not). A module attribute so a test can stand a TCP pair in for one.
HAS_UNIX = hasattr(socket, "AF_UNIX")

NOT_CONFIGURED = (
    "No isolated analysis worker is configured (NOCTORNAL_ANALYSIS_SOCKET, or "
    "NOCTORNAL_ANALYSIS_ADDR for a worker reached over mutual TLS), "
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
WORKER_SILENT_TCP = (
    "The isolated analysis worker did not answer over mutual TLS "
    "(NOCTORNAL_ANALYSIS_ADDR), so nothing was analysed; start the "
    "analysis-worker and read its log, and check that its certificate and "
    "this process's were issued by the one CA both hold")


@dataclass(frozen=True)
class TcpTarget:
    """A worker reached over TCP with mutual TLS: where, and the three files this side presents and
    trusts. `own_listener` is the worker's own `--check` dialling the listener it just opened, where no
    network fence and no name check apply (nothing is reached that the worker is not)."""
    host: str
    port: int
    cert: str
    key: str
    ca: str
    own_listener: bool = False

    def __str__(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


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
    #: The worker reached over mutual TLS, when NOCTORNAL_ANALYSIS_ADDR chose it.
    address: TcpTarget | None = None

    @property
    def target(self) -> str | TcpTarget | None:
        """What `run_isolated` and `hello` dial: the socket's path, or the TCP target."""
        return self.address if self.address is not None else self.socket_path


def _production(env: Mapping[str, str]) -> bool:
    # The mode has one reader, config's.
    from noctornal_api.config import is_production
    return is_production(env)


def tls_problem(env: Mapping[str, str], variable: str) -> str | None:
    """Why the three TLS paths, as set, cannot serve the transport `variable` names: one of them
    missing, or not an absolute path. None when all three are. The sentence names the variables and
    never a value."""
    missing = [name for name in TLS_ENV if not env.get(name, "").strip()]
    if missing:
        return (f"{variable} is set and {', '.join(missing)} "
                f"{'is' if len(missing) == 1 else 'are'} not: the channel is mutual TLS and has no "
                f"plaintext form, so it needs {', '.join(TLS_ENV)} together")
    for name in TLS_ENV:
        value = env[name]
        if value != value.strip() or "\x00" in value or not os.path.isabs(value):
            return f"{name} must be an absolute path to a file"
    return None


def setting_problem(env: Mapping[str, str] | None = None) -> str | None:
    """Why the settings, as SET, cannot be used; None when they can or
    are unset. The one reader of their shape: the runner refuses on it and
    a production boot refuses on it (config.verify_environment). Whether an
    UNSET socket is acceptable is `runner_choice`'s question, not this.

    At most one of the socket, the address (the TCP transport) and the local child is set, and an
    address comes with the three TLS paths."""
    env = os.environ if env is None else env
    raw = env.get(SOCKET_ENV, "")
    addr = env.get(ADDR_ENV, "")
    local = env.get(LOCAL_ENV, "").strip()
    if local and local != "1":
        return f"{LOCAL_ENV} must be 1 or unset"
    if raw.strip() and local:
        return (f"{SOCKET_ENV} and {LOCAL_ENV} are both set, so it is not "
                f"said whether analysis runs in the isolated worker or here")
    if addr.strip() and local:
        return (f"{ADDR_ENV} and {LOCAL_ENV} are both set, so it is not "
                f"said whether analysis runs in the isolated worker or here")
    if addr.strip() and raw.strip():
        return (f"{SOCKET_ENV} and {ADDR_ENV} are both set, so it is not "
                f"said which transport reaches the isolated worker")
    if addr.strip():
        if addr != addr.strip() or hostport(addr) is None:
            return (f"{ADDR_ENV} must be HOST:PORT, a DNS name or an IP address and a "
                    f"port (an IPv6 address in square brackets)")
        return tls_problem(env, ADDR_ENV)
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
    addr = env.get(ADDR_ENV, "").strip()
    if addr:
        host, port = hostport(addr)
        return RunnerChoice("isolated", production=production, address=TcpTarget(
            host, port, env[TLS_CERT_ENV], env[TLS_KEY_ENV], env[TLS_CA_ENV]))
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
#: The runner's own failures: no child ran, or none answered through the sandbox, so they say
#: nothing about the page or the sample. Every caller reads them as the sandbox's state: never
#: parser drift, never a crashed step, never an attempt spent.
SANDBOX_FAILURES = ("isolation_refused", "worker_unavailable",
                    "worker_bad_answer", "worker_refused", "worker_busy")

# ---------------------------------------------------------------------------
# The local child (the worker runs exactly this)
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
    NOCTORNAL_*, DATABASE_URL, OBJECT_STORE_*, MINIO_*, SAMPLE_*, PRESERVE_*,
    REDIS_URL or SMTP_*: the data key and the KEK never reach a child. (In the isolated
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


#: Run by the child's own uid between the fork and the child's program, when the worker gives the
#: child a uid of its own: a task limit, then the highest OOM score, then the program.
#: RLIMIT_NPROC counts every process and thread of the real uid, and a slot's uid is that slot's
#: alone, so the count is exactly the child's, set before its first instruction. The OOM score
#: makes the kernel pick a child, never the worker. Never `preexec_fn` (unsafe in a threaded
#: server): a small program that execs the real one, and a limit it cannot set ends the run.
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

    A process the child started can hold its pipes open after it has gone, and closing such a pipe
    from here would wait on the lock a blocked read holds. So each thread closes its own pipe when
    its read or write ends, and once the child has exited or been killed this stops what it left
    before it waits on any pipe: the child's whole group, then `reap`, which the worker uses to
    empty the slot's uid. Only then are the threads joined, for at most PIPE_GRACE_S; a helper
    nothing here can stop is not waited for, and what it writes after this returns is never added
    to the answer."""
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
    # One buffer, grown as the child writes, so a large output is held once, not in parts and again
    # joined. `lock` and state["done"] keep a thread still blocked after this function has returned
    # from writing into what it handed back.
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
        # No thread to be had (the container's tasks are spent): a child nobody feeds or reads
        # would run unbounded, so it is killed and the run is a start failure.
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
    xcpu = getattr(signal, "SIGXCPU", None)
    if timed_out or (xcpu is not None and proc.returncode == -xcpu):
        # The child's own CPU-time limit ending it is a time limit as much as
        # the wall clock is, never a crash (lab_static.apply_limits).
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
#: The child modules the worker starts, by name. A peer names a kind; it never names a program.
#: `lab_archive_child` reads an archive from stdin and answers its members, with no path written,
#: under the same limits and failure kinds as the others. `watch_regex` matches a watch's regular
#: expressions against collected text (watch_regex.py); sent as `lab_static` instead, it is
#: answered `bad_header` and every pattern reads as failed.
KINDS = ("lab_static", "forum_parse", "lab_archive_child", "watch_regex")
HELLO = "hello"
MAX_PAYLOADS = 4
#: The largest output the worker hands back, whatever a request asks: the archive child's members
#: (256 MiB by default, plus a report line each, `lab_archive.stdout_cap`) are the largest answer
#: any child gives. `lab_archive.archive_settings` refuses a setting that would ask for more.
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
#: How long `unavailable` waits for the worker's hello (twice this, for the whole exchange), and
#: how long its verdict is believed: callers ask once per forum source and on every schedule pass,
#: so a worker that accepts and never answers must cost one wait, not one per source. Module
#: attributes so a test can shrink them.
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
    it, so the worker holds a payload once while it arrives, not twice."""
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


def _no_constant(name: str):
    raise ValueError(f"{name} is not JSON")


def loads_child_json(raw):
    """JSON a child (or the worker) sent, read the way every parent check of an answer needs it
    read: a ValueError for anything that is not an answer this process can store. That is a text
    that is not UTF-8, one nested so deep that the decoder raises RecursionError (no ValueError,
    so callers' `except ValueError` would miss it), and the constants NaN, Infinity and -Infinity,
    which Python's decoder accepts and PostgreSQL's jsonb refuses."""
    try:
        return json.loads(str(raw, "utf-8") if not isinstance(raw, str) else raw,
                          parse_constant=_no_constant)
    except RecursionError:
        raise ValueError("nested too deeply") from None


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
        value = loads_child_json(raw)
    except ValueError:
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


def _stop_socket(sock) -> None:
    """End a connection from another thread, so a read or a handshake blocked on it returns. The
    base class's shutdown, because an SSLSocket's own would drop its TLS state under a thread that
    is using it."""
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except OSError:
        pass


#: How long a handshake that can be cancelled waits for its peer before it looks at the flag again.
HANDSHAKE_POLL_S = 0.02


def tls_handshake(context: ssl.SSLContext, raw, *, server_side: bool,
                  server_hostname: str | None = None, cancelled=None):
    """`raw` wrapped in `context` with its handshake finished within HANDSHAKE_TIMEOUT_S in all, not
    per read: a peer that trickles one byte at a time is ended at the deadline. Raises OSError
    (`ssl.SSLError` is one) and closes `raw` when it fails.

    `cancelled`, when given, is a function the handshake asks every HANDSHAKE_POLL_S: when it answers
    True the handshake ends with a ConnectionAbortedError. It is how the worker makes room for a newer
    connection (`analysis_worker.Worker._admit`): the thread ends its own handshake, as no thread has to
    shut a socket under another's read, which wakes a blocked read on Linux and not everywhere."""
    raw.settimeout(HANDSHAKE_TIMEOUT_S)
    tls = None
    try:
        tls = context.wrap_socket(raw, server_side=server_side, server_hostname=server_hostname,
                                  do_handshake_on_connect=False)
        if cancelled is not None:
            end = time.monotonic() + HANDSHAKE_TIMEOUT_S
            tls.settimeout(HANDSHAKE_POLL_S)
            while True:
                if cancelled():
                    raise ConnectionAbortedError("the handshake was ended to make room")
                if time.monotonic() >= end:
                    raise TimeoutError("the TLS handshake did not finish in time")
                try:
                    tls.do_handshake()
                    break
                except (TimeoutError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    continue
            tls.settimeout(HANDSHAKE_TIMEOUT_S)
            return tls
        timer = threading.Timer(HANDSHAKE_TIMEOUT_S, _stop_socket, args=(tls,))
        timer.daemon = True
        timer.start()
        try:
            tls.do_handshake()
        finally:
            timer.cancel()
        return tls
    except BaseException:
        for sock in (tls, raw):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        raise


def client_context(target: TcpTarget) -> ssl.SSLContext:
    """The caller's side of the channel. Built directly and not with `create_default_context`, which
    would load the system roots: the only certificate authority trusted is the channel's own, so a
    certificate any public CA issued is refused whatever name it carries. TLS 1.3 at least, the
    worker's certificate and its name checked, and this side's certificate presented."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = not target.own_listener
    context.load_verify_locations(cafile=target.ca)
    context.load_cert_chain(target.cert, target.key)
    return context


def server_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    """The worker's side: TLS 1.3 at least, its own certificate, and a client certificate required
    that the channel's CA issued (no other CA, and none from the system's roots)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=ca)
    context.load_cert_chain(cert, key)
    return context


def _connect_tcp(target: TcpTarget, *, env: Mapping[str, str] | None = None):
    """A TLS connection to the worker, or OSError. The fence of a connection that is neither HTTP
    through the egress proxy nor a volume: the name is resolved ONCE and every answer must be loopback
    or inside the deployment's declared networks, or nothing is dialled; the address that was checked
    is the one dialled (a second lookup could be answered otherwise); the certificate must chain to
    the channel's own CA and name the configured host. A worker's own `--check` (`own_listener`)
    dials only the listener it just opened and is not fenced."""
    env = os.environ if env is None else env
    infos = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
    if not target.own_listener:
        try:
            networks = egress_policy.internal_networks(env, production=_production(env))
        except ValueError:
            raise OSError("the declared networks are unusable") from None
        for info in infos:
            address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
            if not egress_policy.is_own_address(address, networks):
                raise OSError("outside the deployment's own networks")
    if not infos:
        raise OSError("no address")
    context = client_context(target)
    last: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in infos:
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(CONNECT_TIMEOUT_S)
        try:
            raw.connect(sockaddr)
            return tls_handshake(context, raw, server_side=False,
                                 server_hostname=target.host)
        except OSError as exc:
            raw.close()
            last = exc
    raise last if last is not None else OSError("no address")


def _connector(target, connect):
    """The function that opens a connection to `target`: the caller's own (a test's), else this
    module's, looked up now so a test can replace either."""
    if connect is not None:
        return connect
    return _connect_tcp if isinstance(target, TcpTarget) else _connect_unix


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


def run_isolated(path: str | TcpTarget, kind: str, header: dict, payloads: tuple = (), *,
                 wall_s: float, stdout_cap: int, connect=None) -> ChildResult:
    """One request to the worker (at a socket's path, or a TcpTarget), answered as `run_local` answers. The
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
        sock = _connector(path, connect)(path)
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


def hello(path: str | TcpTarget, *, connect=None, timeout_s: float = CONNECT_TIMEOUT_S) -> dict:
    """The worker's account of itself (`Worker.status`). Raises
    WorkerUnavailable. Short: `unavailable` asks it before a pass or a
    forum poll (remembering the answer briefly), readiness and the
    healthcheck ask it every time, and a worker that cannot answer this
    quickly is not one to hand a sample to."""
    rid = uuid.uuid4().hex
    deadline = time.monotonic() + 2 * timeout_s
    try:
        sock = _connector(path, connect)(path)
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


def worker_request_cap(env: Mapping[str, str] | None = None, *,
                       connect=None) -> int | None:
    """The most payload bytes the isolated worker takes in one request, as
    it reports them (`Worker.status`, `max_request_bytes`), or None: no
    worker is in use (the local runner has no such limit), or it did not
    answer, or it did not say. A fresh question each time; the caller asks
    only after the worker has refused a request."""
    choice = runner_choice(env)
    if choice.mode != "isolated":
        return None
    try:
        status = hello(choice.target, connect=connect, timeout_s=HELLO_TIMEOUT_S)
    except WorkerUnavailable:
        return None
    cap = status.get("max_request_bytes")
    if isinstance(cap, bool) or not isinstance(cap, int) or cap < 1:
        return None
    return cap


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
        return run_isolated(choice.target, kind, header, payloads,
                            wall_s=wall_s, stdout_cap=stdout_cap, connect=connect)
    result = run_local(header, payloads, wall_s=wall_s, stdout_cap=stdout_cap,
                       argv=argv)
    if isinstance(result.output, bytearray):
        # The application reads bytes, as from the worker; only the worker
        # keeps the buffer it filled.
        result.output = bytes(result.output)
    return result


#: where the worker is (a socket path, or host:port) -> (monotonic expiry, verdict). See VERDICT_TTL_S.
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

    The worker's answer is remembered for VERDICT_TTL_S and asked by one caller at a time, the
    others waiting for that answer, so a worker that accepts and never answers costs one wait of at
    most 2 * HELLO_TIMEOUT_S per window, however many forum sources ask. A worker that stops inside
    the window costs the request that finds out, which every caller handles as the sandbox's state
    (SANDBOX_FAILURES). Readiness and the healthcheck call `hello` and are never answered from
    memory."""
    choice = runner_choice(env)
    if choice.mode == "refused":
        return choice.reason
    if choice.mode == "local":
        return None
    target = choice.target
    key = str(target)
    with _verdict_lock:
        known = _verdicts.get(key)
        if known is not None and time.monotonic() < known[0]:
            return known[1]
        try:
            hello(target, connect=connect, timeout_s=HELLO_TIMEOUT_S)
            verdict = None
        except WorkerUnavailable:
            verdict = WORKER_SILENT_TCP if choice.address is not None else WORKER_SILENT
        _verdicts[key] = (time.monotonic() + VERDICT_TTL_S, verdict)
        return verdict


# ---------------------------------------------------------------------------
# What the worker may hold
# ---------------------------------------------------------------------------

#: The worker's own settings (read in analysis_worker).
CONCURRENCY_ENV = "NOCTORNAL_ANALYSIS_WORKER_CONCURRENCY"
MAX_BYTES_ENV = "NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES"
#: The pids limit the worker is told it runs under, for a pod, whose limit is on the pod's cgroup and
#: reads as "max" from inside a container (decision 239). Used only where the cgroup gives no number.
PIDS_LIMIT_ENV = "NOCTORNAL_ANALYSIS_PIDS_LIMIT"
#: The worker's own settings, by exact name: a prefix match would let through a secret that
#: happened to carry the prefix.
#: The address a caller dials (ADDR_ENV) is a CALLER's setting and is not here: a worker holding it is
#: refused like any foreign name.
WORKER_OWN_ENV = frozenset({SOCKET_ENV, CONCURRENCY_ENV, MAX_BYTES_ENV, LISTEN_ENV, PIDS_LIMIT_ENV,
                            *TLS_ENV})
#: What a Kubernetes kubelet puts in every container of a pod once enableServiceLinks is false: the
#: address of the cluster's API server, which it injects even then (the `kubernetes` master service),
#: and the downward API's POD_IP when a manifest asks for it. With the default (true) it adds a set per
#: Service of the namespace too (POSTGRES_SERVICE_HOST and the rest), which are not here and are
#: refused: the worker's pod must set enableServiceLinks: false. By exact name, never a prefix (a prefix
#: would let a service account token variable through). None is a secret, and the child never
#: inherits one (`child_env` builds its environment from nothing). Without them the worker would
#: refuse to start in every cluster.
KUBELET_ENV = frozenset({
    "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT",
    "KUBERNETES_SERVICE_PORT_HTTPS", "KUBERNETES_PORT", "KUBERNETES_PORT_443_TCP",
    "KUBERNETES_PORT_443_TCP_ADDR", "KUBERNETES_PORT_443_TCP_PORT",
    "KUBERNETES_PORT_443_TCP_PROTO", "POD_IP"})
#: The only variables the worker's environment may carry: what the base
#: image and Docker set (GPG_KEY is the python image's release signing key
#: fingerprint, public by design), the kubelet's, and the worker's own settings. An
#: allow-list, not a deny-list: a variable nobody named is refused, so a
#: credential added to the service later stops it rather than riding in.
WORKER_ALLOWED_ENV = frozenset({
    "PATH", "HOME", "HOSTNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ",
    "container", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256",
    "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
    "PYTHONPATH", "PIP_DISABLE_PIP_VERSION_CHECK"}) | WORKER_OWN_ENV | KUBELET_ENV


def foreign_environment(keys) -> list[str]:
    """The names in `keys` the worker must not hold, sorted. Names only:
    a value never reaches this function."""
    return sorted(k for k in keys if isinstance(k, str)
                  and k not in WORKER_ALLOWED_ENV)


__all__ = [
    "ADDR_ENV", "ChildResult", "HAS_UNIX", "KINDS", "KUBELET_ENV", "LISTEN_ENV", "LOCAL_ENV",
    "PIDS_LIMIT_ENV", "RunnerChoice", "SANDBOX_FAILURES", "SOCKET_ENV", "TLS_CA_ENV",
    "TLS_CERT_ENV", "TLS_ENV", "TLS_KEY_ENV", "TcpTarget", "WORKER_OWN_ENV", "WorkerUnavailable",
    "child_env",
    "client_context", "foreign_environment", "forget_verdicts", "hello", "hostport",
    "launch_argv", "run", "run_isolated", "run_local", "runner_choice", "server_context",
    "setting_problem", "tls_handshake", "tls_problem", "unavailable",
]
