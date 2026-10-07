"""The isolated analysis worker: a container with no secrets and no
network that runs the bounded analysis children for the application
(docs/17 F42, 2026-10-02).

    python -m noctornal_api.analysis_worker               serve
    python -m noctornal_api.analysis_worker --check       the compose healthcheck
    python -m noctornal_api.analysis_worker --shared-uid  serve, development only

## What it is, and what it is not

Not a task worker: there is no queue, nothing is scheduled here, and no
state outlives a request: a child can create no file, shared memory,
semaphore or message queue that a later request could find ("State a child
could leave behind" below; decision 30 stands; the owner decided this
sandbox on 2026-10-02, and CONVENTIONS' "no worker container" means a
queue's worker). A caller in the API, the cron loop or the lab-triage
loop connects, hands over one request, and waits for its answer; the
worker starts the child with `analysis_runner.run_local`, the very
function those callers would otherwise use, so the parsers run the same
code under the same limits either way.

## Why it can be trusted with hostile bytes

It is started with an environment it can name and nothing else
(`analysis_runner.WORKER_ALLOWED_ENV`) and refuses to start holding any
other variable. compose.yml gives it no env_file, no network
(network_mode none), a read-only root with a tmpfs only root can write,
no private IPC objects a child could use (below), no-new-privileges, pids
and memory limits, and of the capabilities only the three it needs to
keep its children apart (below). Its one channel is
a Unix socket on a tmpfs volume that only the application containers
mount, read-only. A parser exploit in a child can therefore read an
environment that holds nothing, and reach nothing beyond its own pipes.

## Each child is a user of its own (F42 review, 2026-10-02)

The review showed, in a container with these settings, that a child
running as the worker's own user could unlink the worker's socket and
bind its own at the same name; that a process it detached with setsid
outlived the request's kill and then answered every later request in the
worker's place; and that a child could spend the container's pids until
the worker could not start a thread for anybody.

So the worker is a supervisor. It starts as root holding only the kill,
setgid and setuid capabilities, behind no-new-privileges (so no setuid
program hands a capability back to a child), and refuses to start
otherwise. Slot N's child runs as uid CHILD_UID_BASE + N, gid the same,
with no supplementary group:

* the socket's directory is root's and closed to that user, so the child
  cannot unlink, bind or even connect there;
* it cannot signal or trace the worker or another slot's child, whatever
  kernel.yama.ptrace_scope says, because none of them is its user;
* RLIMIT_NPROC, set before its program starts
  (`analysis_runner.launch_argv`), holds it and everything it starts to
  CHILD_MAX_TASKS processes and threads, and the service's pids limit
  must leave the worker room beside every slot at that limit
  (`start_problems` checks);
* before the request is answered, every process of the slot's uid is
  killed (`purge_user`), so nothing a child started outlives its request.
  The purge runs inside `run_local`, once the child has gone and BEFORE
  anything waits on the child's pipes: a process the child left holding
  its stdout or stderr open (with or without setsid) used to wedge the
  request, and its slot for good, until the helper died on its own, because
  the purge ran only after `run_local` returned (F42 verify 1,
  2026-10-03). A slot whose uid cannot be emptied, or whose purge fails,
  is not used again; with none left the worker exits so Docker restarts it
  clean. init: true reaps them.

Why this and not the other ways: a pid namespace per request needs
CAP_SYS_ADMIN or a user namespace, which Docker's default seccomp profile
refuses; killing every process of one shared child uid after a request
would kill another request's child; and a root-owned socket directory
alone still leaves a child of the worker's uid able to kill or trace the
worker. The cost is a root process, with three capabilities, in a
container with no network, no secret and a read-only root, which parses
nothing hostile itself: it moves bytes, bounded, between the socket and a
child's pipes.

`--shared-uid` keeps the old shape for development and the tests: every
child runs as this process's own user, which must then not be root. The
hello says so, and readiness reports such a worker as not isolated.

## State a child could leave behind (F42 verify 2, 2026-10-03)

Killing a uid's processes does not remove what they made in the kernel or
on a writable filesystem. The review showed SysV shared memory a child
creates survives every process of the uid, is charged to the container's
memory limit until the worker itself is killed for it, and is readable by
a child of another slot; POSIX shared memory (/dev/shm, Docker's default
64 MiB tmpfs), POSIX message queues and files in /tmp did the same. The
worker, holding no capability that overrides ownership, can remove none of
it. So it is closed at the source instead, and the worker refuses to start
(and readiness fails) unless it can see for itself that it is:

* `ipc: none` gives the container no /dev/shm at all;
* sysctls kernel.shmmax 0, kernel.msgmni 0, kernel.sem "0 0 0 0" and
  fs.mqueue.queues_max 0 leave a child unable to create a SysV segment,
  queue or semaphore set or a POSIX queue (shmget answers EINVAL, msgget and
  mq_open ENOSPC, semget EINVAL: measured on 2026-10-03). They are the
  container's own, in its IPC namespace;
* /tmp is a tmpfs of root's with mode 0755, so no child's uid can write in
  it, and nothing a child runs needs to (the code is on the read-only
  root).

`state_left_open` reads each of those from the running process, and the
hello carries the names of any that is open.

## Bounds

A request's frame is read under `FRAME_HEADER_CAP` and an idle limit;
its declared payloads must fit `NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES`
before a byte of them is read, and are read only once a slot is free, so
at most `NOCTORNAL_ANALYSIS_WORKER_CONCURRENCY` requests are held in
memory; a request that waits longer than QUEUE_WAIT_S for a slot is
answered busy. The answer is sent while the slot is still held, so a
slot's memory is its payload, its child and its output, and nothing is
held beside the slots. Connections beyond `MAX_CONNECTIONS` are closed at
once, and so is one no thread can be started for. The child's wall clock
is the request's, clamped to MAX_WALL_S, and its output cap the
request's, clamped to MAX_OUTPUT_BYTES. A broken request is answered
`worker_refused` and logged by its request id, never by its content.

## What the hello reports

`Worker.status` is what readiness judges, and it reports what this
process IS rather than what a file says it should be: its uid, its
effective capabilities, no-new-privileges, whether its root is read-only,
its network interfaces, its pids limit, the state a child could leave
behind (`state_left_open`), the NAMES of its environment (never a value),
how its children are kept apart, how many slots it has retired, and its
parser versions. Until the F42 review (2026-10-02) it did not report its
capabilities, no-new-privileges or a read-only root, and the compose
file's cap_drop, security_opt and read_only were held by text tests alone;
until the verify round (2026-10-03) the docstring named the pids limit and
the hello did not carry it, so an absent or enormous limit started
silently (`pids_problem` is now the one reader, for the start and for
readiness).

## What remains (F42 review, 2026-10-02)

* The state a child could leave behind is closed by the container's
  settings, which the worker checks from inside; what it cannot see is a
  runtime that ignores them. A kernel object of another kind that a plain
  uid can create (a kernel keyring, which Docker's default seccomp profile
  refuses; a container started with no seccomp profile is outside this
  claim) is not covered.
* A slot's uid is reused by later requests, after the purge. Nothing of
  one request is in the next one's memory, processes, files or IPC.
* The local runner (development, and NOCTORNAL_ANALYSIS_LOCAL=1) has no
  uid to purge: a helper that left the child's session keeps the child's
  pipes and survives the run. The run no longer waits for it (it is
  answered after PIPE_GRACE_S at most) and what it writes later is never
  added to the answer, but the process lives until it exits or is killed.
* RLIMIT_NPROC counts a uid's tasks over the whole host, not per
  container: uids CHILD_UID_BASE to CHILD_UID_BASE + 15 must own nothing
  else on the host, a second analysis worker included
  (infra/production/README.md, Analysis worker).
* kernel.yama.ptrace_scope does not matter here: a child holds no
  capability and shares no uid with the worker or with a child of another
  slot, so it cannot trace or read them at any setting. It matters under
  --shared-uid (development), where every child shares the worker's uid
  and at scope 0 could read a concurrent request's payload; readiness
  reports such a worker as not isolated.
* Memory: infra/production/README.md has the sizing and what was measured.
  A child ranks first for the kernel's OOM killer, so a container limit
  that is too small costs a crashed step, never the worker.
* A kernel or container-runtime escape from the worker's container is not
  addressed (docs/17 F42); a compromised child can still return false
  findings, which the parent validates by shape only.
"""
from __future__ import annotations

import argparse
import logging
import os
import queue
import signal
import socket
import stat
import sys
import threading
import time
from collections.abc import Mapping

from noctornal_api import analysis_runner as ar

log = logging.getLogger("noctornal.analysis.worker")

CONCURRENCY_ENV = ar.CONCURRENCY_ENV
MAX_BYTES_ENV = ar.MAX_BYTES_ENV
DEFAULT_CONCURRENCY = 2
DEFAULT_MAX_BYTES = 1 << 30
MAX_CONNECTIONS = 32

#: Slot N's child runs as this uid plus N, gid the same: 10100 to 10115,
#: above the application's 10001, owning nothing in the image. They must
#: own nothing on the host either (infra/production/README.md, Analysis
#: worker): RLIMIT_NPROC counts a uid's processes host-wide.
CHILD_UID_BASE = 10100
#: Processes and threads one child may hold, itself included. A YARA scan
#: needs two (yara-x keeps a timer thread; measured 2026-10-02, and a
#: compile of 3000 rules started none); the rest is room.
CHILD_MAX_TASKS = 16
#: What the worker needs beside its children: a thread per connection,
#: init, itself and a healthcheck, with room.
WORKER_TASKS = MAX_CONNECTIONS + 8
#: Per slot: the child's tasks and the three threads that attend it.
TASKS_PER_SLOT = CHILD_MAX_TASKS + 4
#: The capabilities a supervising worker holds, and no other.
SUPERVISOR_CAPABILITIES = frozenset({"kill", "setgid", "setuid"})
#: How long a slot's uid may take to empty after its request.
PURGE_S = 5.0
#: Linux's SIGKILL; a name Windows' signal module lacks, where the purge
#: never runs but its tests do.
_SIGKILL = getattr(signal, "SIGKILL", 9)

#: The child each kind starts. A module attribute so a test can point a
#: kind at a child that hangs, floods or runs out of memory.
KIND_ARGV: dict[str, list[str]] = {
    "lab_static": [sys.executable, "-m", "noctornal_api.lab_static"],
    "forum_parse": [sys.executable, "-m", "noctornal_api.forum_parse"],
    # Archive expansion's child (phase 8, merged 2026-10-03): it writes no
    # path, so the worker's tmpfs of one MiB and its read-only root are all
    # it needs.
    "lab_archive_child": [sys.executable, "-m", "noctornal_api.lab_archive_child"],
    # A watch's regular expressions (watch_regex): text in, one boolean per
    # text out, no path, no network.
    "watch_regex": [sys.executable, "-m", "noctornal_api.watch_regex"],
}


# ---------------------------------------------------------------------------
# What this process is (Linux; None where a fact cannot be read)
# ---------------------------------------------------------------------------

#: Linux's capability numbers, as names.
CAP_NAMES = (
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill",
    "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service",
    "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time",
    "sys_tty_config", "mknod", "lease", "audit_write", "audit_control",
    "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
    "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore")


def capability_names(mask: int) -> list[str]:
    """The names of the bits set in a capability mask, sorted; a bit this
    list does not know is `capN`, never dropped."""
    out = []
    bit = 0
    while mask >> bit:
        if mask >> bit & 1:
            out.append(CAP_NAMES[bit] if bit < len(CAP_NAMES) else f"cap{bit}")
        bit += 1
    return sorted(out)


#: The container's pids limit may not be more than this many times what its
#: slots need (F42 verify 3, 2026-10-03). The limit is the second wall: the
#: first is each child's task limit, and the second is what is left when a
#: task limit does not hold. A limit of 100000 holds nothing, and so does
#: none at all, which the kernel reports as "max".
PIDS_CEILING_FACTOR = 4


def pids_needed(concurrency: int) -> int:
    return WORKER_TASKS + concurrency * TASKS_PER_SLOT


def pids_ceiling(concurrency: int) -> int:
    return PIDS_CEILING_FACTOR * pids_needed(concurrency)


def pids_problem(pids_max, concurrency: int) -> str | None:
    """Why this pids limit, as the running process reads it, is not one a
    worker with `concurrency` slots may serve under; None when it is a whole
    number from what the slots need up to the ceiling. The one reader: the
    worker refuses to start on it and readiness fails on it, so the
    compose file's pids_limit is judged on the running process and not on
    its text (F42 verify 3, 2026-10-03: the hello did not report it, and an
    absent or enormous limit started silently)."""
    need = pids_needed(concurrency)
    if isinstance(pids_max, bool) or not isinstance(pids_max, int):
        return ("The analysis worker's container has no pids limit it can "
                f"read, so nothing bounds its tasks but each child's own: set "
                f"pids_limit on the service ({need} to {pids_ceiling(concurrency)} "
                f"for {concurrency} slots).")
    if pids_max < need:
        return (f"The service's pids limit is {pids_max}, and {concurrency} "
                f"slots need {need} (each child may hold {CHILD_MAX_TASKS}): "
                f"raise pids_limit or lower {CONCURRENCY_ENV}.")
    if pids_max > pids_ceiling(concurrency):
        return (f"The service's pids limit is {pids_max}, above the "
                f"{pids_ceiling(concurrency)} that {concurrency} slots are "
                f"allowed ({PIDS_CEILING_FACTOR} times the {need} they need), "
                f"so it bounds nothing: lower pids_limit.")
    return None


def _pids_candidates(root: str, cgroup_file: str):
    """Where this process's cgroup keeps its pids limit: the cgroup the
    container sees as its root (cgroup v2, then v1), then the path
    /proc/self/cgroup names, for a runtime that does not give the container
    a cgroup namespace of its own."""
    yield os.path.join(root, "pids.max")
    yield os.path.join(root, "pids", "pids.max")
    try:
        with open(cgroup_file, encoding="ascii", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        rel = [p for p in parts[2].split("/") if p]
        if not rel or ".." in rel or "." in rel:
            continue
        yield os.path.join(root, *rel, "pids.max")
        yield os.path.join(root, "pids", *rel, "pids.max")


def read_pids_max(*, root: str = "/sys/fs/cgroup",
                  cgroup_file: str = "/proc/self/cgroup") -> int | None:
    """The pids limit of this process's cgroup as a whole number, or None
    when there is none ("max") or it cannot be read."""
    for path in _pids_candidates(root, cgroup_file):
        try:
            with open(path, encoding="ascii") as f:
                raw = f.read().strip()
        except OSError:
            continue
        return int(raw) if raw.isdigit() else None
    return None


#: What a child's uid can create that outlives its processes, and the
#: setting that closes each (F42 verify 2, 2026-10-03). Each is read from
#: the running process, in the container's own IPC namespace, by
#: `state_left_open`. SysV shared memory, a message queue or a semaphore
#: set, and a POSIX message queue, stay until the container is removed, are
#: charged to its memory limit, and cannot be removed by a worker holding
#: no capability that overrides ownership; /dev/shm is the same for POSIX
#: shared memory, and a file in /tmp is the same for any child that can
#: write one.
IPC_SYSCTLS = ("kernel.shmmax", "kernel.msgmni", "fs.mqueue.queues_max")
#: The directories a child's uid could write to if their mode and mount let
#: it: left there, a file is read by the next request's child.
CHILD_SCRATCH_DIRS = ("/tmp", "/var/tmp", "/dev/shm")


def _sysctl_ints(name: str, root: str) -> list[int] | None:
    try:
        with open(os.path.join(root, *name.split(".")), encoding="ascii") as f:
            return [int(v) for v in f.read().split()]
    except (OSError, ValueError):
        return None


def _writable_by_others(mode: int, readonly: bool) -> bool:
    """Whether a user that is neither the owner nor in the group could write
    in a directory of this mode on a filesystem that is, or is not,
    read-only. A child's uid is in neither: its gid is its own and it has no
    supplementary group."""
    return stat.S_ISDIR(mode) and not readonly and bool(mode & 0o002)


def _others_can_write(path: str) -> bool:
    """`_writable_by_others` for the directory at `path`. False for a path
    that is not there; a path that cannot be examined is open, because
    nothing shows it closed."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        readonly = bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (AttributeError, OSError):
        readonly = False
    return _writable_by_others(st.st_mode, readonly)


def state_left_open(*, sys_root: str = "/proc/sys",
                    dirs: tuple[str, ...] = CHILD_SCRATCH_DIRS) -> list[str]:
    """The ways a child could leave state behind that this process can see
    are open, as names, sorted; empty when none is. A setting that cannot be
    read is open (nothing shows it closed)."""
    left = []
    for name in IPC_SYSCTLS:
        if _sysctl_ints(name, sys_root) != [0]:
            left.append(name)
    # kernel.sem is SEMMSL SEMMNS SEMOPM SEMMNI: a set may hold no semaphore
    # when the first is 0, which closes SysV semaphores.
    sem = _sysctl_ints("kernel.sem", sys_root)
    if sem is None or len(sem) != 4 or sem[0] != 0:
        left.append("kernel.sem")
    left.extend(path for path in dirs if _others_can_write(path))
    return sorted(left)


def process_facts() -> dict:
    """This process's user, pid, effective capabilities, no-new-privileges
    flag, whether its root is read-only, its container's pids limit and the
    state a child could leave behind. What the worker decides on at start
    and reports in its hello, so readiness judges the running process, not
    the compose file."""
    facts: dict = {"euid": os.geteuid() if hasattr(os, "geteuid") else None,
                   "pid": os.getpid(), "capabilities": None,
                   "no_new_privileges": None, "read_only_root": None,
                   "pids_max": None, "state_left_open": None}
    try:
        with open("/proc/self/status", encoding="ascii", errors="replace") as f:
            for line in f:
                key, _, value = line.partition(":")
                if key == "CapEff":
                    facts["capabilities"] = capability_names(int(value.strip(), 16))
                elif key == "NoNewPrivs":
                    facts["no_new_privileges"] = value.strip() == "1"
    except (OSError, ValueError):
        pass
    try:
        facts["read_only_root"] = bool(os.statvfs("/").f_flag & os.ST_RDONLY)
    except (AttributeError, OSError):
        pass
    facts["pids_max"] = read_pids_max()
    facts["state_left_open"] = state_left_open()
    return facts


# ---------------------------------------------------------------------------
# Settings and the start refusals
# ---------------------------------------------------------------------------

def worker_settings(env: Mapping[str, str]) -> tuple[dict | None, str | None]:
    """`({path, concurrency, max_bytes}, None)` or `(None, problem)`."""
    from noctornal_api.config import parse_size
    problem = ar.setting_problem(env)
    if problem:
        return None, problem
    path = env.get(ar.SOCKET_ENV, "").strip()
    if not path:
        return None, f"{ar.SOCKET_ENV} is not set: it names the socket to listen on"
    raw = env.get(CONCURRENCY_ENV, "").strip()
    concurrency = DEFAULT_CONCURRENCY
    if raw:
        if not raw.isdigit() or not 1 <= int(raw) <= 16:
            return None, f"{CONCURRENCY_ENV} must be a whole number from 1 to 16"
        concurrency = int(raw)
    raw = env.get(MAX_BYTES_ENV, "").strip()
    max_bytes = DEFAULT_MAX_BYTES
    if raw:
        try:
            max_bytes = parse_size(raw)
        except ValueError:
            return None, (f"{MAX_BYTES_ENV} is not a size (bytes, or a whole "
                          f"number with a binary K, M or G, such as 1GiB)")
        if not ar.MIB <= max_bytes <= 64 << 30:
            return None, f"{MAX_BYTES_ENV} must be between 1 MiB and 64 GiB"
    return {"path": path, "concurrency": concurrency, "max_bytes": max_bytes}, None


def start_problems(env: Mapping[str, str], *, shared: bool = False,
                   facts: dict | None = None) -> list[str]:
    """Every reason this process must not serve, as sentences that name a
    variable or a setting and never a value. `facts` is
    `process_facts()`'s shape, injectable so the rules can be tested."""
    facts = process_facts() if facts is None else facts
    problems = []
    foreign = ar.foreign_environment(env)
    if foreign:
        problems.append(
            "The analysis worker must hold no setting but its own, and its "
            "environment carries " + ", ".join(foreign) + ": it parses hostile "
            "input, so anything it holds a parser exploit holds too. Remove "
            "them from the service (no env_file).")
    if not ar.HAS_UNIX:
        problems.append("This platform has no Unix sockets, so the analysis "
                        "worker has nothing to listen on.")
    settings, problem = worker_settings(env)
    if problem:
        problems.append(problem + ".")
    euid = facts.get("euid")
    if shared:
        if euid == 0:
            problems.append(
                "With --shared-uid every child runs as this process's own "
                "user, so the analysis worker must not run as root: set a "
                "user on the service.")
        return problems
    caps = facts.get("capabilities")
    if euid != 0 or caps is None or set(caps) != SUPERVISOR_CAPABILITIES:
        held = ("capabilities it cannot read" if caps is None else
                "the capabilities " + ", ".join(caps) if caps else
                "no capability")
        problems.append(
            "The analysis worker runs each child as a user of its own, so it "
            "must start as root holding the kill, setgid and setuid "
            "capabilities and no other (compose.yml: user 0:10001, cap_drop "
            f"ALL, cap_add KILL, SETGID and SETUID); it runs as uid {euid} "
            f"with {held}. --shared-uid runs every child as this process's "
            "own user instead, for development only.")
    if facts.get("no_new_privileges") is not True:
        problems.append(
            "The analysis worker must run with no-new-privileges "
            "(security_opt), so no child can take a capability back through "
            "a setuid program.")
    if facts.get("pid") == 1:
        problems.append(
            "The analysis worker must not be PID 1: set init: true on the "
            "service, so the processes killed after each request are reaped.")
    concurrency = settings["concurrency"] if settings else DEFAULT_CONCURRENCY
    # F42 verify 3 (2026-10-03): a limit that is absent, unreadable or
    # enormous used to start silently; only one that was too small refused.
    pids = pids_problem(facts.get("pids_max"), concurrency)
    if pids:
        problems.append(pids)
    # F42 verify 2 (2026-10-03): state a child leaves behind outlives its
    # request, which the purge of its uid cannot reach.
    left = facts.get("state_left_open")
    if not isinstance(left, list):
        problems.append(
            "The analysis worker could not read whether a child can leave "
            "state behind that outlives its request (shared memory, "
            "semaphores, message queues, files), so it does not serve.")
    elif left:
        problems.append(
            "The analysis worker's container lets a child leave state behind "
            "that outlives its request, and nothing here can remove it: "
            + ", ".join(str(n) for n in left[:10]) + ". Set ipc: none, "
            "sysctls kernel.shmmax 0, kernel.msgmni 0, kernel.sem \"0 0 0 0\" "
            "and fs.mqueue.queues_max 0, and a /tmp that only root can write "
            "(compose.yml, analysis-worker).")
    return problems


def socket_directory_problem(st, *, euid: int) -> str | None:
    """Why the socket's directory, as `os.stat` saw it, would let a child
    put something at the socket's name: it must be this process's own and
    closed to every other user but its group's read and search."""
    if st.st_uid != euid or stat.S_IMODE(st.st_mode) & 0o027:
        return (f"The directory of {ar.SOCKET_ENV} must belong to the "
                f"analysis worker's user with mode 0750 or tighter, so no "
                f"child can put anything at the socket's name; it does not "
                f"(compose.yml mounts analysis-socket as uid 0, gid 10001, "
                f"mode 0750).")
    return None


def bind_unix(path: str):
    """Listen on `path`. A stale socket from an earlier run is replaced;
    anything else at that name is refused rather than removed."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        st = None
    if st is not None:
        if not stat.S_ISSOCK(st.st_mode):
            raise RuntimeError(f"{ar.SOCKET_ENV} names something that is not a "
                               f"socket; refusing to replace it")
        os.unlink(path)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o077)
    try:
        sock.bind(path)
    finally:
        os.umask(old)
    # Group connect: the application runs as the volume's group, and the
    # directory is the worker's (compose.yml, analysis-socket).
    os.chmod(path, 0o660)
    sock.listen(64)
    return sock


# ---------------------------------------------------------------------------
# Emptying a slot's uid (F42 review, 2026-10-02)
# ---------------------------------------------------------------------------

def tasks_of(uid: int, *, proc: str = "/proc") -> list[int]:
    """Every process whose real, effective or saved uid is `uid`, in any
    state, zombies included: a slot is empty only when none is left."""
    out = []
    try:
        names = os.listdir(proc)
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(os.path.join(proc, name, "status"), encoding="ascii",
                      errors="replace") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        if str(uid) in line.split()[1:4]:
                            out.append(int(name))
                        break
        except OSError:
            continue
    return out


def purge_user(uid: int, *, within: float = PURGE_S, proc: str = "/proc",
               kill=os.kill) -> bool:
    """Kill every process of `uid` until none is left, or `within` seconds
    pass; whether none is left. A process killed here can fork no more,
    and RLIMIT_NPROC bounds how many there can be, so the rounds end. A
    zombie leaves when init reaps it (a zombie leader whose threads live
    on is killed too, which ends them)."""
    end = time.monotonic() + within
    while True:
        found = tasks_of(uid, proc=proc)
        if not found:
            return True
        for pid in found:
            try:
                kill(pid, _SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                log.error("the analysis worker may not stop a process of uid "
                          "%d: it lacks the kill capability", uid)
        if time.monotonic() > end:
            log.error("uid %d still holds %d processes after %.0f seconds",
                      uid, len(found), within)
            return False
        time.sleep(0.01)


# ---------------------------------------------------------------------------
# The worker
# ---------------------------------------------------------------------------

def _interfaces() -> list[str] | None:
    try:
        return sorted(name for _i, name in socket.if_nameindex())[:50]
    except (AttributeError, OSError):
        return None


class Worker:
    """Serves requests from one listening socket until stopped.

    `child_uids`, one per slot, runs each slot's child as that uid and
    empties it before the answer (a supervising worker); None runs every
    child as this process's own user (--shared-uid, and the tests)."""

    def __init__(self, listener, *, concurrency: int = DEFAULT_CONCURRENCY,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 child_uids: list[int] | None = None):
        if child_uids is not None and len(child_uids) != concurrency:
            raise ValueError("one child uid per slot")
        self.listener = listener
        self.concurrency = concurrency
        self.max_bytes = max_bytes
        self.child_uids = list(child_uids) if child_uids is not None else None
        # The slots, by number: a request takes one, and gives it back only
        # once its uid holds nothing.
        self._free: queue.Queue[int] = queue.Queue()
        for slot in range(concurrency):
            self._free.put(slot)
        self._connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.retired = 0
        #: Set when no slot is left; main exits non-zero so Docker restarts.
        self.failed = False

    def status(self) -> dict:
        """What `analysis_runner.hello` answers: the wire, the parsers,
        the environment's NAMES, the user, how children are kept apart,
        the effective capabilities, no-new-privileges, a read-only root, the
        network interfaces, its pids limit and the state a child could leave
        behind, so readiness can see for itself what this process is rather
        than read the compose file (F42 review, 2026-10-02; the pids limit
        and the state, which the docstring named and the hello did not
        carry, F42 verify 2 and 3, 2026-10-03)."""
        from noctornal_api import lab_static
        facts = process_facts()
        own = self.child_uids is not None
        return {"protocol": ar.WIRE_VERSION, "child_protocol": lab_static.PROTOCOL,
                "kinds": list(ar.KINDS),
                "versions": {"pefile": lab_static._version("pefile"),
                             "yara_x": lab_static._version("yara-x")},
                "environment_keys": sorted(os.environ)[:200],
                # So a list cut at 200 is never read as the whole of it.
                "environment_count": len(os.environ),
                "uid": facts["euid"],
                "children": {"isolation": "own_uid" if own else "shared_uid",
                             "uids": list(self.child_uids) if own else None,
                             "max_tasks": CHILD_MAX_TASKS if own else None},
                "capabilities": facts["capabilities"],
                "no_new_privileges": facts["no_new_privileges"],
                "read_only_root": facts["read_only_root"],
                "pids_max": facts["pids_max"],
                "state_left_open": facts["state_left_open"],
                "network_interfaces": _interfaces(),
                "concurrency": self.concurrency,
                "slots_retired": self.retired,
                "max_request_bytes": self.max_bytes}

    def stop(self) -> None:
        self._stop.set()

    def serve_forever(self) -> None:
        self.listener.settimeout(0.5)
        while not self._stop.is_set():
            try:
                self._accept_one()
            except Exception:  # noqa: BLE001 - nothing one request does ends the loop
                # F42 review (2026-10-02): an error here used to end the
                # loop every other request needs. The pause stops a hot
                # loop when the error repeats.
                log.warning("the analysis worker's accept loop met an error "
                            "and carries on", exc_info=True)
                time.sleep(0.1)

    def _accept_one(self) -> None:
        try:
            conn, _addr = self.listener.accept()
        except TimeoutError:
            return
        except OSError:
            if not self._stop.is_set():
                time.sleep(0.1)
            return
        if not self._connections.acquire(blocking=False):
            # Over the connection cap: closed at once, which the client
            # reads as an unavailable worker.
            conn.close()
            return
        try:
            threading.Thread(target=self._serve_one, args=(conn,),
                             daemon=True).start()
        except Exception:  # noqa: BLE001 - RuntimeError when no thread can start
            # No thread to be had (the container's tasks are spent, which a
            # child at its task limit can no longer cause): this caller is
            # told at once by a closed connection, and the loop goes on
            # (F42 review, 2026-10-02).
            self._connections.release()
            conn.close()
            log.warning("an analysis request was turned away: no thread could "
                        "be started for it")
            time.sleep(0.1)

    def _serve_one(self, conn) -> None:
        try:
            self._handle(conn)
        except Exception:  # noqa: BLE001 - one request never takes the worker down
            log.warning("an analysis request failed in the worker", exc_info=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._connections.release()

    @staticmethod
    def _reply(conn, rid: str, deadline: float, *, ok: bool,
               failure: str | None = None, returncode: int | None = None,
               output: bytes = b"", status: dict | None = None) -> None:
        frame = {"v": ar.WIRE_VERSION, "id": rid, "ok": ok, "failure": failure,
                 "returncode": returncode, "output_len": len(output)}
        if status is not None:
            frame["status"] = status
        try:
            ar.send_all(conn, ar.pack_frame(frame), deadline)
            if output:
                ar.send_all(conn, output, deadline)
        except ar.WireError:
            log.info("analysis request %s: the caller left before its answer", rid)

    def _refuse(self, conn, rid: str, why: str, failure: str = "worker_refused") -> None:
        log.warning("analysis request %s refused: %s", rid or "(no id)", why)
        self._reply(conn, rid, time.monotonic() + ar.TRANSFER_BASE_S,
                    ok=False, failure=failure)
        # The caller may still be sending what it declared. Half-close and
        # read a little of it, briefly, so the refusal is read rather than
        # lost to a reset; never the whole declaration.
        try:
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(0.2)
            end = time.monotonic() + 1.0
            drained = 0
            while time.monotonic() < end and drained < 4 * ar.MIB:
                chunk = conn.recv(ar.MIB)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass

    def _retire(self, slot: int, uid: int | None) -> None:
        with self._lock:
            self.retired += 1
            none_left = self.retired >= self.concurrency
        log.error("analysis slot %d (uid %s) still holds processes after its "
                  "request and is not used again", slot, uid)
        if none_left:
            log.error("no analysis slot is left: the worker stops, so it can "
                      "be restarted clean")
            self.failed = True
            self.stop()

    def _handle(self, conn) -> None:
        started = time.monotonic()
        try:
            req = ar.read_frame(conn, started + ar.TRANSFER_BASE_S)
        except ar.WireError as exc:
            log.warning("an analysis request was dropped before its frame "
                        "was read (%s)", exc.kind)
            return
        rid = req.get("id") if isinstance(req.get("id"), str) \
            and ar._ID.fullmatch(req.get("id")) else ""
        if req.get("v") != ar.WIRE_VERSION or not rid:
            self._refuse(conn, rid, "not this wire's version, or no id")
            return
        kind = req.get("kind")
        if kind == ar.HELLO:
            self._reply(conn, rid, time.monotonic() + ar.TRANSFER_BASE_S,
                        ok=True, status=self.status())
            return
        sizes = req.get("payloads")
        wall_s = req.get("wall_s")
        cap = req.get("stdout_cap")
        child = req.get("child")
        if kind not in ar.KINDS:
            self._refuse(conn, rid, "an unknown kind")
            return
        if (not isinstance(sizes, list) or len(sizes) > ar.MAX_PAYLOADS
                or not all(isinstance(n, int) and not isinstance(n, bool)
                           and n >= 0 for n in sizes)):
            self._refuse(conn, rid, "payload lengths that are not lengths")
            return
        if sum(sizes) > self.max_bytes:
            self._refuse(conn, rid, f"{sum(sizes)} bytes declared, above "
                                    f"{MAX_BYTES_ENV}")
            return
        if (isinstance(wall_s, bool) or not isinstance(wall_s, (int, float))
                or not 0 < wall_s <= ar.MAX_WALL_S):
            self._refuse(conn, rid, "a wall clock out of range")
            return
        if (isinstance(cap, bool) or not isinstance(cap, int)
                or not 0 < cap <= ar.MAX_OUTPUT_BYTES):
            self._refuse(conn, rid, "an output cap out of range")
            return
        if not isinstance(child, dict):
            self._refuse(conn, rid, "no child header")
            return
        try:
            slot = self._free.get(timeout=ar.QUEUE_WAIT_S)
        except queue.Empty:
            self._refuse(conn, rid, "no slot came free", failure="worker_busy")
            return
        uid = self.child_uids[slot] if self.child_uids is not None else None
        # True until a child may have run; from then on only an emptied uid
        # makes it True again (F42 verify 1, 2026-10-03: it used to stay True
        # when the purge itself failed, which freed a slot nobody had
        # emptied).
        clean = True
        purged: list[bool] = []

        def reap() -> None:
            # Called by run_local after the child is gone and BEFORE it waits
            # on the child's pipes: a process the child left holding them is
            # stopped here, where it used to wedge run_local until it died
            # on its own (F42 verify 1, 2026-10-03).
            purged.append(purge_user(uid))

        try:
            deadline = ar.transfer_deadline(time.monotonic(), sum(sizes))
            try:
                payloads = tuple(ar.recv_exact(conn, n, deadline, mutable=True)
                                 for n in sizes)
            except ar.WireError as exc:
                log.warning("analysis request %s: its payload did not arrive "
                            "(%s)", rid, exc.kind)
                return
            clean = uid is None
            try:
                result = ar.run_local(
                    child, payloads, wall_s=float(wall_s), stdout_cap=cap,
                    argv=KIND_ARGV[kind], user=uid,
                    max_tasks=CHILD_MAX_TASKS if uid is not None else None,
                    reap=reap if uid is not None else None)
            except ValueError:
                self._refuse(conn, rid, "a child header larger than a child reads")
                return
            finally:
                payloads = ()
                if uid is not None:
                    # Before the answer: nothing the child started outlives
                    # its request (F42 review, 2026-10-02). The purge that
                    # ran inside run_local is not repeated when it answered.
                    try:
                        clean = purged[-1] if purged else purge_user(uid)
                    except Exception:  # noqa: BLE001 - not emptied is not clean
                        log.error("the analysis worker could not empty uid %d",
                                  uid, exc_info=True)
                        clean = False
            log.info("analysis request %s (%s): %s in %d ms", rid, kind,
                     "ok" if result.ok else result.failure,
                     int((time.monotonic() - started) * 1000))
            # Answered while the slot is held, so the output is counted in
            # the slot's memory and never held beside it.
            self._reply(conn, rid,
                        ar.transfer_deadline(time.monotonic(), len(result.output)),
                        ok=result.ok, failure=result.failure,
                        returncode=result.returncode, output=result.output)
        finally:
            if clean:
                self._free.put(slot)
            else:
                self._retire(slot, uid)


# ---------------------------------------------------------------------------
# The process
# ---------------------------------------------------------------------------

def check(env: Mapping[str, str] | None = None) -> int:
    """The healthcheck: 0 when the worker answers on its socket."""
    env = os.environ if env is None else env
    path = env.get(ar.SOCKET_ENV, "").strip()
    if not path:
        print(f"{ar.SOCKET_ENV} is not set", file=sys.stderr)
        return 1
    try:
        ar.hello(path)
    except ar.WorkerUnavailable:
        print("the analysis worker did not answer", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the isolated analysis worker (docs/17 F42).")
    parser.add_argument("--check", action="store_true",
                        help="exit 0 when the worker answers on its socket")
    parser.add_argument("--shared-uid", action="store_true",
                        help="development only: run every child as this "
                             "process's own user, which readiness reports "
                             "as not isolated")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if args.check:
        return check()
    problems = start_problems(os.environ, shared=args.shared_uid)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 2
    settings, _problem = worker_settings(os.environ)
    child_uids = None
    if not args.shared_uid:
        try:
            st = os.stat(os.path.dirname(settings["path"]))
        except OSError:
            print(f"The directory of {ar.SOCKET_ENV} does not exist.",
                  file=sys.stderr)
            return 2
        problem = socket_directory_problem(st, euid=os.geteuid())
        if problem:
            print(problem, file=sys.stderr)
            return 2
        child_uids = [CHILD_UID_BASE + n for n in range(settings["concurrency"])]
        for uid in child_uids:
            if not purge_user(uid):
                print(f"uid {uid} holds processes that cannot be stopped, so "
                      f"its slot cannot start empty.", file=sys.stderr)
                return 2
    try:
        listener = bind_unix(settings["path"])
    except (OSError, RuntimeError) as exc:
        print(f"The analysis worker could not listen on its socket "
              f"({type(exc).__name__}).", file=sys.stderr)
        return 2
    worker = Worker(listener, concurrency=settings["concurrency"],
                    max_bytes=settings["max_bytes"], child_uids=child_uids)
    # PID 1 in a container ignores SIGTERM unless it says otherwise, and
    # init forwards it here.
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_a: worker.stop())
    log.info("the analysis worker is listening (concurrency %d; %s)",
             settings["concurrency"],
             "each child a user of its own" if child_uids
             else "children share this process's user")
    try:
        worker.serve_forever()
    finally:
        listener.close()
        try:
            os.unlink(settings["path"])
        except OSError:
            pass
    return 3 if worker.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
