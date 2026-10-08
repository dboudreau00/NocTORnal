"""The isolated analysis worker and the runner that chooses it (docs/17
F42, 2026-10-02).

Static triage and forum parsing hand hostile bytes to a bounded child.
In production that child runs in a container with no secrets and no
network, reached over a Unix socket; here the worker is the real
`analysis_worker.Worker` on a loopback TCP listener standing in for the
socket (Windows' CPython has no AF_UNIX), so every test below runs on
every platform. The same wire on a real Unix socket, with the worker as
its own process, is test_analysis_worker_unix.py; the container is
infra/production/compose.yml, held by test_analysis_worker_compose.py.

Covered: the choice and its refusals (production never falls back to a
local child), the same child answering through the worker as here, a
hostile child that hangs, floods or exhausts memory, a worker that dies
mid-request or answers garbage, a slow or malformed peer, oversize frames
both ways, concurrent requests, the slot and connection caps, and that no
secret reaches the worker or its child.

Pure: no database. The children are real processes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import forum_helpers as fh
from lab_static_fixtures import declare_policy, pe_image

from noctornal_api import analysis_runner as ar
from noctornal_api import analysis_worker as aw
from noctornal_api import forum_adapters as fa
from noctornal_api import lab_triage

ROOT = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)
SOCK = "/run/noctornal-analysis/worker.sock"
SECRETS = {"NOCTORNAL_TOTP_KEK": "kek-value-the-worker-must-not-see",
           "DATABASE_URL": "postgresql://u:pw-the-worker-must-not-see@db/x",
           "MINIO_SECRET_KEY": "minio-value-the-worker-must-not-see"}
CHILD_KEYS = {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
              "PYTHONPATH", "SYSTEMROOT", "WINDIR"}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

@contextmanager
def tcp_worker(**kw):
    """The real Worker on a loopback listener, and a connector for it."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    worker = aw.Worker(listener, **kw)
    thread = threading.Thread(target=worker.serve_forever, daemon=True)
    thread.start()
    addr = listener.getsockname()

    def connect(_path):
        return socket.create_connection(addr, timeout=5)

    try:
        yield worker, connect
    finally:
        worker.stop()
        thread.join(5)
        listener.close()


@contextmanager
def stub_peer(behaviour):
    """One connection to a server that does `behaviour(conn)`: a worker
    that dies, lies or never answers."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)

    def serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            behaviour(conn)
        except OSError:
            pass
        finally:
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    addr = listener.getsockname()
    try:
        yield lambda _path: socket.create_connection(addr, timeout=5)
    finally:
        listener.close()
        thread.join(5)


def _read_request(conn) -> dict:
    req = ar.read_frame(conn, time.monotonic() + 10)
    for n in req.get("payloads") or []:
        ar.recv_exact(conn, n, time.monotonic() + 10)
    return req


def _nobody(_path):
    raise ConnectionRefusedError()


def _gone(_path):
    raise FileNotFoundError()


def _closed_by_peer(sock, timeout: float = 10) -> bool:
    """Whether the peer hung up: an orderly end, or (on Windows, where a
    close with unread bytes is a reset) a reset."""
    sock.settimeout(timeout)
    try:
        return sock.recv(64) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True


def _frame(header: dict) -> bytes:
    return ar.pack_frame(header)


def _request(kind="lab_static", **over) -> dict:
    out = {"v": ar.WIRE_VERSION, "id": "a" * 32, "kind": kind, "wall_s": 10.0,
           "stdout_cap": 1 << 20, "payloads": [], "child": {"mode": "selftest"}}
    out.update(over)
    return out


def _reply(sock) -> dict:
    return ar.read_frame(sock, time.monotonic() + 15)


@pytest.fixture(autouse=True)
def fresh_verdicts():
    """`unavailable` remembers the worker's answer by socket path for a few
    seconds, and every test here reuses one path for a different worker."""
    ar.forget_verdicts()
    yield
    ar.forget_verdicts()


#: process_facts() of a worker started as compose.yml starts it.
SUPERVISED = {"euid": 0, "pid": 7, "capabilities": ["kill", "setgid", "setuid"],
              "no_new_privileges": True, "read_only_root": True, "pids_max": 128,
              "state_left_open": []}
#: What a worker started as compose.yml starts it says of itself, beside
#: what the in-process stand-in reports (F42 review, 2026-10-02).
CLEAN_ACCOUNT = {"environment_keys": ["HOME", "PATH", ar.SOCKET_ENV],
                 "environment_count": 3, "uid": 0,
                 "children": {"isolation": "own_uid", "uids": [10100, 10101],
                              "max_tasks": 16},
                 "capabilities": ["kill", "setgid", "setuid"],
                 "no_new_privileges": True, "read_only_root": True,
                 "pids_max": 128, "state_left_open": [],
                 "network_interfaces": ["lo"]}


@pytest.fixture
def settings():
    return lab_triage.settings_or_default()


@pytest.fixture
def isolated(monkeypatch):
    """This process configured for the worker, with the TCP stand-in."""
    def use(connect):
        monkeypatch.setattr(ar, "HAS_UNIX", True)
        monkeypatch.setattr(ar, "_connect_unix", connect)
        monkeypatch.setenv(ar.SOCKET_ENV, SOCK)
        monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    return use


def _script(tmp_path, name, body) -> list[str]:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return [sys.executable, str(path)]


def _pe_header(data, settings):
    return {"mode": "pe", "sample_len": len(data),
            "fuzzy_max_bytes": settings.fuzzy_max_bytes,
            "limits": {"memory_bytes": settings.memory_bytes, "cpu_s": 30}}


def _without_timing(raw: bytes) -> dict:
    out = json.loads(raw)
    out.pop("timing_ms", None)
    return out


# ---------------------------------------------------------------------------
# The choice
# ---------------------------------------------------------------------------

def test_development_with_nothing_set_runs_locally():
    choice = ar.runner_choice({})
    assert (choice.mode, choice.production, choice.explicit_local) == ("local", False, False)


def test_production_with_nothing_set_is_refused_never_local():
    choice = ar.runner_choice({"NOCTORNAL_ENV": "production"})
    assert choice.mode == "refused" and choice.reason == ar.NOT_CONFIGURED
    assert "NOCTORNAL_ANALYSIS_SOCKET" in choice.reason
    assert "NOCTORNAL_ANALYSIS_LOCAL=1" in choice.reason


def test_production_runs_locally_only_when_told_to_out_loud():
    choice = ar.runner_choice({"NOCTORNAL_ENV": " Production ", ar.LOCAL_ENV: "1"})
    assert (choice.mode, choice.explicit_local, choice.production) == ("local", True, True)


def test_a_socket_means_the_worker(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    choice = ar.runner_choice({ar.SOCKET_ENV: SOCK, "NOCTORNAL_ENV": "production"})
    assert (choice.mode, choice.socket_path) == ("isolated", SOCK)


def test_a_socket_on_a_platform_without_unix_sockets_is_refused(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", False)
    choice = ar.runner_choice({ar.SOCKET_ENV: SOCK})
    assert choice.mode == "refused" and choice.reason == ar.NO_UNIX


@pytest.mark.parametrize("env, says", [
    ({ar.SOCKET_ENV: SOCK, ar.LOCAL_ENV: "1"}, "both set"),
    ({ar.LOCAL_ENV: "yes"}, "must be 1 or unset"),
    ({ar.SOCKET_ENV: "run/worker.sock"}, "absolute path"),
    ({ar.SOCKET_ENV: " /run/worker.sock"}, "absolute path"),
    ({ar.SOCKET_ENV: "/run/" + "x" * 120}, "longer than"),
])
def test_an_unusable_setting_is_refused_by_name_never_by_value(monkeypatch, env, says):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    problem = ar.setting_problem(env)
    assert problem and says in problem
    assert "x" * 20 not in problem and "run/worker.sock" not in problem
    choice = ar.runner_choice(env)
    assert choice.mode == "refused" and choice.reason == problem


def test_production_boot_refuses_a_malformed_setting_and_not_an_absent_one():
    """An unset socket refuses every analysis at the point of use and
    readiness says so; it does not stop the console starting. A value SET
    and unusable is refused at boot, by its name (the F42 decision)."""
    from noctornal_api.config import verify_environment
    base = {"NOCTORNAL_ENV": "production"}
    assert not any("NOCTORNAL_ANALYSIS" in p for p in verify_environment(base))
    bad = verify_environment({**base, ar.SOCKET_ENV: "relative/worker.sock"})
    mine = [p for p in bad if ar.SOCKET_ENV in p]
    assert len(mine) == 1 and "relative" not in mine[0]
    assert "refuse every request" in mine[0]
    both = verify_environment({**base, ar.SOCKET_ENV: SOCK, ar.LOCAL_ENV: "1"})
    assert any("both set" in p for p in both)
    assert not any("NOCTORNAL_ANALYSIS" in p for p in verify_environment(
        {**base, ar.SOCKET_ENV: SOCK}))
    assert verify_environment({ar.SOCKET_ENV: "relative"}) == []


def test_a_refused_runner_never_starts_a_child(monkeypatch):
    def forbidden(*_a, **_k):
        raise AssertionError("a local child was started in production")

    monkeypatch.setattr(ar, "run_local", forbidden)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    result = lab_triage.run_child({"mode": "selftest"}, wall_s=5)
    assert not result.ok and result.failure == "isolation_refused"
    assert lab_triage.CHILD_FAILURES["isolation_refused"]


def test_a_silent_worker_is_refused_never_replaced_by_a_local_child(monkeypatch, isolated):
    def forbidden(*_a, **_k):
        raise AssertionError("a local child replaced the worker")

    isolated(_nobody)
    monkeypatch.setattr(ar, "run_local", forbidden)
    result = lab_triage.run_child({"mode": "selftest"}, wall_s=5)
    assert result.failure == "worker_unavailable"
    assert ar.unavailable() == ar.WORKER_SILENT


def test_unavailable_speaks_for_each_mode(monkeypatch):
    assert ar.unavailable({}) is None
    assert ar.unavailable({"NOCTORNAL_ENV": "production"}) == ar.NOT_CONFIGURED
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    monkeypatch.setattr(ar, "_connect_unix", _gone)
    assert ar.unavailable({ar.SOCKET_ENV: SOCK}) == ar.WORKER_SILENT


# ---------------------------------------------------------------------------
# The same child, through the worker
# ---------------------------------------------------------------------------

def test_the_worker_answers_a_pe_step_exactly_as_a_local_child(settings):
    image = pe_image()
    header = _pe_header(image, settings)
    here = ar.run_local(header, (image,), wall_s=40, stdout_cap=1 << 20,
                        argv=lab_triage.CHILD_ARGV)
    with tcp_worker() as (_w, connect):
        there = ar.run_isolated(SOCK, "lab_static", header, (image,), wall_s=40,
                                stdout_cap=1 << 20, connect=connect)
    assert here.ok and there.ok and there.returncode == 0
    assert _without_timing(there.output) == _without_timing(here.output)


def test_a_forum_page_parses_in_the_worker_as_in_this_process(isolated):
    fetched = fh.fetched(fh.XF_THREAD, 200, fh.page("xenforo/thread_page1.html"))
    here = fa.parse_in_process("xenforo", "thread", fetched, config={}, now=NOW,
                               wall_s=10)
    with tcp_worker() as (_w, connect):
        isolated(connect)
        there = fa.parse_bounded("xenforo", "thread", fetched, config={},
                                 now=NOW, wall_s=30)
    assert there == here


def test_triage_steps_run_in_the_worker_and_the_run_says_so(isolated, settings):
    with tcp_worker() as (_w, connect):
        isolated(connect)
        part = lab_triage._step_child("pe", pe_image(), settings,
                                      lab_triage.STEP_GAPS["pe"])
        assert part["gaps"] == {"imphash": None, "rich_header_hash": None}
        assert part["values"]["imphash"]
        assert lab_triage.limits_words(settings)["isolated"] is True


def test_the_local_runner_says_it_is_not_isolated(monkeypatch, settings):
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    assert lab_triage.limits_words(settings)["isolated"] is False


def test_the_worker_starts_only_the_module_a_kind_names(tmp_path):
    """A peer names a kind, never a program: an `argv` in the request is
    not read, and the child that answers is lab_static's."""
    with tcp_worker() as (_w, connect):
        sock = connect(None)
        sock.sendall(_frame(_request(argv=[sys.executable, "-c", "print('owned')"])))
        reply = _reply(sock)
        out = ar.recv_exact(sock, reply["output_len"], time.monotonic() + 10)
        sock.close()
    assert reply["ok"] is True
    answer = json.loads(out)
    assert answer["mode"] == "selftest" and "capabilities" in answer
    assert b"owned" not in out


# ---------------------------------------------------------------------------
# A hostile child, inside the worker
# ---------------------------------------------------------------------------

def test_a_hanging_child_is_killed_at_its_wall_clock_and_the_worker_carries_on(
        tmp_path, monkeypatch):
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(
        tmp_path, "hang.py",
        "import sys, time\nsys.stdin.buffer.readline()\ntime.sleep(60)\n"))
    with tcp_worker() as (_w, connect):
        started = time.monotonic()
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (b"MZ",),
                                 wall_s=1.5, stdout_cap=1 << 20, connect=connect)
        assert result.failure == "timeout" and not result.ok
        assert time.monotonic() - started < 15
        assert ar.hello(SOCK, connect=connect)["protocol"] == ar.WIRE_VERSION


def test_a_child_slower_than_the_idle_limit_is_still_waited_for(tmp_path, monkeypatch):
    """The idle limit is for a frame in flight. A caller waits for the
    reply to START until its deadline, because the reply starts only once
    the child is done: a real step takes minutes, the idle limit seconds."""
    monkeypatch.setattr(ar, "IDLE_S", 0.5)
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(tmp_path, "echo.py", _ECHO))
    with tcp_worker() as (_w, connect):
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe", "hold": 2},
                                 (b"slow",), wall_s=20, stdout_cap=1 << 16,
                                 connect=connect)
    assert result.ok, result
    assert json.loads(result.output)["sha"] == hashlib.sha256(b"slow").hexdigest()


def test_a_flooding_child_is_stopped_at_its_output_cap(tmp_path, monkeypatch):
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(
        tmp_path, "flood.py",
        "import sys\nsys.stdin.buffer.readline()\n"
        "while True:\n    sys.stdout.buffer.write(b'x' * 65536)\n"))
    with tcp_worker() as (_w, connect):
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (),
                                 wall_s=30, stdout_cap=1 << 20, connect=connect)
    assert result.failure == "output_too_large"
    assert len(result.output) <= 1 << 20


@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="RLIMIT_AS is enforced on Linux; elsewhere a child "
                           "that allocates would take the host's memory")
def test_a_child_that_exhausts_its_memory_dies_alone(tmp_path, monkeypatch):
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(
        tmp_path, "hog.py",
        "import sys\nfrom noctornal_api import lab_static\n"
        "sys.stdin.buffer.readline()\n"
        "lab_static.apply_limits(256 << 20, 10)\n"
        "blob = bytearray(1 << 30)\nprint('ALLOCATED')\n"))
    with tcp_worker() as (_w, connect):
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (),
                                 wall_s=20, stdout_cap=1 << 20, connect=connect)
        assert result.failure == "crashed" and b"ALLOCATED" not in result.output
        assert ar.hello(SOCK, connect=connect)


def test_a_child_that_crashes_is_reported_with_its_code(tmp_path, monkeypatch):
    monkeypatch.setitem(aw.KIND_ARGV, "forum_parse", _script(
        tmp_path, "crash.py", "import sys\nsys.stdin.buffer.read()\nsys.exit(3)\n"))
    with tcp_worker() as (_w, connect):
        result = ar.run_isolated(SOCK, "forum_parse", {"mode": "forum"}, (b"<p>",),
                                 wall_s=20, stdout_cap=1 << 20, connect=connect)
    assert (result.failure, result.returncode) == ("crashed", 3)


# ---------------------------------------------------------------------------
# A worker that dies, lies or never answers
# ---------------------------------------------------------------------------

@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(ar, "IDLE_S", 0.5)
    monkeypatch.setattr(ar, "TRANSFER_BASE_S", 0.5)
    monkeypatch.setattr(ar, "QUEUE_WAIT_S", 0.2)


def test_a_worker_that_dies_mid_request_is_unavailable_at_once():
    def die(conn):
        ar.read_frame(conn, time.monotonic() + 5)
        conn.close()

    with stub_peer(die) as connect:
        started = time.monotonic()
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"},
                                 (b"MZ" * 1000,), wall_s=60, stdout_cap=1 << 20,
                                 connect=connect)
        elapsed = time.monotonic() - started
    assert result.failure == "worker_unavailable"
    # Told when the connection ends, not when the 60 second wall clock does.
    assert elapsed < 10


def test_a_worker_that_never_answers_is_given_up_on_by_the_deadline(quick):
    def mute(conn):
        _read_request(conn)
        time.sleep(8)

    with stub_peer(mute) as connect:
        started = time.monotonic()
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (b"MZ",),
                                 wall_s=0.5, stdout_cap=1024, connect=connect)
        elapsed = time.monotonic() - started
    assert result.failure == "worker_unavailable"
    # wall 0.5 + slot wait 0.2 + two transfers of 0.5: about 1.7 seconds.
    assert elapsed < 5


def _lie(build):
    def behaviour(conn):
        req = _read_request(conn)
        conn.sendall(build(req["id"]))
        time.sleep(0.5)
    return behaviour


def _good(rid, **over):
    frame = {"v": ar.WIRE_VERSION, "id": rid, "ok": True, "failure": None,
             "returncode": 0, "output_len": 0}
    frame.update(over)
    return frame


@pytest.mark.parametrize("build, failure", [
    (lambda rid: b"EVIL" + struct.pack(">I", 2) + b"{}", "worker_bad_answer"),
    (lambda rid: ar.MAGIC + struct.pack(">I", ar.FRAME_HEADER_CAP + 1),
     "worker_bad_answer"),
    (lambda rid: ar.MAGIC + struct.pack(">I", 0), "worker_bad_answer"),
    (lambda rid: ar.MAGIC + struct.pack(">I", 9) + b"not json!", "worker_bad_answer"),
    (lambda rid: ar.MAGIC + struct.pack(">I", 2) + b"[]", "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good("b" * 32)), "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, v=2)), "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, output_len=4096)), "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, ok=False, failure="rm -rf")),
     "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, failure="timeout")), "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, ok="yes")), "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, returncode=2 ** 40)), "worker_bad_answer"),
    (lambda rid: ar.pack_frame(_good(rid, output_len=100)) + b"short",
     "worker_unavailable"),
])
def test_nothing_a_worker_says_is_believed_beyond_its_shape(build, failure, quick):
    with stub_peer(_lie(build)) as connect:
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (b"MZ",),
                                 wall_s=1, stdout_cap=1024, connect=connect)
    assert not result.ok and result.failure == failure


def test_a_worker_refusal_is_read_whatever_the_caller_was_still_sending():
    """A busy or refusing worker answers before it has read the payload:
    the caller reads that refusal rather than giving up on its send."""
    def refuse(conn):
        req = ar.read_frame(conn, time.monotonic() + 5)
        conn.sendall(ar.pack_frame({"v": ar.WIRE_VERSION, "id": req["id"],
                                    "ok": False, "failure": "worker_busy",
                                    "returncode": None, "output_len": 0}))
        conn.shutdown(socket.SHUT_WR)
        end = time.monotonic() + 3
        while time.monotonic() < end and conn.recv(1 << 16):
            pass

    with stub_peer(refuse) as connect:
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"},
                                 (b"x" * (4 << 20),), wall_s=5, stdout_cap=1024,
                                 connect=connect)
    assert result.failure == "worker_busy"


# ---------------------------------------------------------------------------
# A slow, malformed or greedy peer, at the worker
# ---------------------------------------------------------------------------

def test_a_silent_peer_is_dropped_and_holds_nobody_else_up(quick):
    with tcp_worker() as (_w, connect):
        idle = connect(None)
        assert ar.hello(SOCK, connect=connect)["protocol"] == ar.WIRE_VERSION
        started = time.monotonic()
        assert _closed_by_peer(idle, 5)
        assert time.monotonic() - started < 4
        idle.close()


def test_a_trickling_payload_is_dropped_at_its_deadline_and_runs_nothing(
        monkeypatch, quick):
    ran = []
    monkeypatch.setattr(ar, "run_local", lambda *a, **k: ran.append(1))
    monkeypatch.setattr(ar, "MIN_RATE", 1 << 30)
    with tcp_worker() as (_w, connect):
        sock = connect(None)
        sock.sendall(_frame(_request(payloads=[64])))
        sock.settimeout(0.2)
        got = None
        for _ in range(30):
            try:
                sock.sendall(b"x")
            except OSError:
                break
            try:
                got = sock.recv(1)
                if got == b"":
                    break
            except TimeoutError:
                continue
        assert got in (b"", None)
        sock.close()
    assert ran == []


@pytest.mark.parametrize("raw", [
    b"EVIL" + struct.pack(">I", 2) + b"{}",
    ar.MAGIC + struct.pack(">I", 1 << 30),
    ar.MAGIC + struct.pack(">I", 0),
    ar.MAGIC + struct.pack(">I", 7) + b"\xff\xfe{}{}{",
    ar.MAGIC + struct.pack(">I", 3) + b"[1]",
])
def test_a_malformed_or_oversize_frame_is_dropped_unread(raw):
    with tcp_worker() as (_w, connect):
        sock = connect(None)
        sock.sendall(raw)
        assert _closed_by_peer(sock)
        sock.close()
        assert ar.hello(SOCK, connect=connect)


@pytest.mark.parametrize("over", [
    {"kind": "shell"},
    {"v": 2},
    {"id": "not-an-id"},
    {"payloads": "lots"},
    {"payloads": [-1]},
    {"payloads": [True]},
    {"payloads": [1, 1, 1, 1, 1]},
    {"wall_s": 0},
    {"wall_s": True},
    {"wall_s": ar.MAX_WALL_S + 1},
    {"stdout_cap": 0},
    {"stdout_cap": ar.MAX_OUTPUT_BYTES + 1},
    {"child": "selftest"},
])
def test_a_request_out_of_shape_is_refused(over):
    with tcp_worker() as (_w, connect):
        sock = connect(None)
        sock.sendall(_frame(_request(**over)))
        reply = _reply(sock)
        sock.close()
    assert reply["ok"] is False and reply["failure"] == "worker_refused"
    assert reply["output_len"] == 0


def test_a_declared_payload_over_the_cap_is_refused_before_a_byte_is_read():
    with tcp_worker(max_bytes=1 << 20) as (_w, connect):
        sock = connect(None)
        sock.sendall(_frame(_request(payloads=[(1 << 20) + 1])))
        reply = _reply(sock)
        sock.close()
    assert reply["failure"] == "worker_refused"


def test_a_child_header_larger_than_a_child_reads_is_refused_both_sides():
    big = {"mode": "pe", "pad": "x" * (64 * 1024)}
    with pytest.raises(ValueError):
        ar.run_isolated(SOCK, "lab_static", big, (), wall_s=1, stdout_cap=10,
                        connect=lambda _p: None)
    with pytest.raises(ValueError):
        ar.run_local(big, (), wall_s=1, stdout_cap=10, argv=lab_triage.CHILD_ARGV)


# ---------------------------------------------------------------------------
# Concurrency and the caps on it
# ---------------------------------------------------------------------------

_ECHO = ("import hashlib, json, sys, time\nline = sys.stdin.buffer.readline()\n"
         "data = sys.stdin.buffer.read()\nhold = json.loads(line).get('hold', 0)\n"
         "time.sleep(hold)\n"
         "sys.stdout.write(json.dumps({'sha': hashlib.sha256(data).hexdigest()}))\n")


def test_concurrent_requests_each_get_their_own_answer(tmp_path, monkeypatch):
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(tmp_path, "echo.py", _ECHO))
    blobs = [bytes([i]) * (50_000 + i) for i in range(6)]
    results: dict[int, ar.ChildResult] = {}
    with tcp_worker(concurrency=3) as (_w, connect):
        def one(i):
            results[i] = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"},
                                         (blobs[i],), wall_s=30,
                                         stdout_cap=1 << 16, connect=connect)
        threads = [threading.Thread(target=one, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
    for i, blob in enumerate(blobs):
        assert results[i].ok, results[i]
        assert json.loads(results[i].output)["sha"] == hashlib.sha256(blob).hexdigest()


def test_requests_beyond_the_slots_wait_and_past_the_wait_are_busy(
        tmp_path, monkeypatch):
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(tmp_path, "echo.py", _ECHO))
    monkeypatch.setattr(ar, "QUEUE_WAIT_S", 0.5)
    out: dict[str, ar.ChildResult] = {}
    with tcp_worker(concurrency=1) as (_w, connect):
        def slow():
            out["slow"] = ar.run_isolated(SOCK, "lab_static", {"mode": "pe",
                                                               "hold": 3},
                                          (b"a",), wall_s=20, stdout_cap=1024,
                                          connect=connect)
        t = threading.Thread(target=slow)
        t.start()
        time.sleep(1.0)
        out["second"] = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"},
                                        (b"b",), wall_s=20, stdout_cap=1024,
                                        connect=connect)
        t.join(30)
    assert out["slow"].ok
    assert out["second"].failure == "worker_busy"


def test_connections_beyond_the_cap_are_closed_at_once(monkeypatch):
    monkeypatch.setattr(aw, "MAX_CONNECTIONS", 1)
    with tcp_worker() as (_w, connect):
        held = connect(None)
        time.sleep(0.3)
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(SOCK, connect=connect)
        held.close()
        for _ in range(50):
            try:
                assert ar.hello(SOCK, connect=connect)
                break
            except ar.WorkerUnavailable:
                time.sleep(0.1)
        else:
            pytest.fail("the worker never freed the held connection's place")


# ---------------------------------------------------------------------------
# No secret reaches the worker, or its child
# ---------------------------------------------------------------------------

def test_the_worker_refuses_to_start_holding_a_credential(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    env = {"PATH": "/usr/bin", "HOME": "/", "GPG_KEY": "7169605F",
           ar.SOCKET_ENV: SOCK, **SECRETS}
    problems = aw.start_problems(env, facts=SUPERVISED)
    assert len(problems) == 1
    for name in SECRETS:
        assert name in problems[0]
    for value in SECRETS.values():
        assert value not in problems[0]
    assert aw.start_problems({k: v for k, v in env.items() if k not in SECRETS},
                             facts=SUPERVISED) == []


def test_the_worker_refuses_a_variable_nobody_named(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    problems = aw.start_problems({ar.SOCKET_ENV: SOCK, "SOMETHING_NEW": "1"},
                                 facts=SUPERVISED)
    assert problems and "SOMETHING_NEW" in problems[0]
    assert ar.foreign_environment(["PATH", "NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES",
                                   "NOCTORNAL_SAMPLE_ORIGIN", "REDIS_URL"]) == \
        ["NOCTORNAL_SAMPLE_ORIGIN", "REDIS_URL"]


def test_a_secret_carrying_the_workers_prefix_is_still_foreign():
    """F42 review (2026-10-02): the allow-list named a prefix, so any
    NOCTORNAL_ANALYSIS_ name passed. It names the three settings now."""
    sneaky = ["NOCTORNAL_ANALYSIS_TOKEN", "NOCTORNAL_ANALYSIS_LOCAL",
              "NOCTORNAL_ANALYSIS_WORKER_SECRET"]
    assert ar.foreign_environment(sneaky + sorted(ar.WORKER_OWN_ENV)) == sorted(sneaky)
    assert ar.WORKER_OWN_ENV == {ar.SOCKET_ENV, aw.CONCURRENCY_ENV, aw.MAX_BYTES_ENV}


def test_the_worker_refuses_a_missing_socket(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    unset = aw.start_problems({}, facts=SUPERVISED)
    assert any(ar.SOCKET_ENV in p for p in unset)


@pytest.mark.parametrize("change, says", [
    ({"euid": 10002}, "must start as root"),
    ({"capabilities": ["kill", "setgid", "setuid", "sys_admin"]}, "sys_admin"),
    ({"capabilities": ["setgid", "setuid"]}, "kill, setgid and setuid"),
    ({"capabilities": None}, "capabilities it cannot read"),
    ({"no_new_privileges": False}, "no-new-privileges"),
    ({"no_new_privileges": None}, "no-new-privileges"),
    ({"pid": 1}, "init: true"),
    ({"pids_max": 64}, "pids limit is 64"),
    # F42 verify 3 (2026-10-03): absent, unreadable or enormous used to start.
    ({"pids_max": None}, "no pids limit it can read"),
    ({"pids_max": 100000}, "above the"),
    # F42 verify 2 (2026-10-03): state a child could leave behind.
    ({"state_left_open": None}, "could not read whether a child can leave"),
    ({"state_left_open": ["kernel.shmmax", "/tmp"]}, "kernel.shmmax, /tmp"),
])
def test_a_supervising_worker_starts_only_as_compose_starts_it(monkeypatch, change,
                                                              says):
    """F42 review (2026-10-02): each child is a user of its own, which
    needs root with setuid and setgid (and kill, to stop a child of
    another uid), no other capability, no-new-privileges so no setuid
    program hands one back, an init to reap, and room for every slot's
    tasks."""
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    env = {ar.SOCKET_ENV: SOCK}
    assert aw.start_problems(env, facts=SUPERVISED) == []
    problems = aw.start_problems(env, facts={**SUPERVISED, **change})
    assert len(problems) == 1 and says in problems[0], problems


def test_the_pids_limit_must_hold_every_slot_at_its_task_limit(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    need = aw.pids_needed(16)
    assert need == aw.WORKER_TASKS + 16 * (aw.CHILD_MAX_TASKS + 4)
    env = {ar.SOCKET_ENV: SOCK, aw.CONCURRENCY_ENV: "16"}
    assert any("lower NOCTORNAL_ANALYSIS_WORKER_CONCURRENCY" in p for p in
               aw.start_problems(env, facts={**SUPERVISED, "pids_max": need - 1}))
    assert aw.start_problems(env, facts={**SUPERVISED, "pids_max": need}) == []
    # compose.yml's 128 holds its two slots, and is under the ceiling.
    assert aw.pids_needed(2) <= 128 <= aw.pids_ceiling(2)
    # F42 verify 3 (2026-10-03): "max" (no limit) is read as None, which
    # used to refuse nothing; an enormous limit did not either. Both do now,
    # and so does the ceiling's edge.
    ceiling = aw.pids_ceiling(16)
    assert aw.start_problems(env, facts={**SUPERVISED, "pids_max": ceiling}) == []
    for bad in (None, ceiling + 1, 38393, True, "128"):
        problems = aw.start_problems(env, facts={**SUPERVISED, "pids_max": bad})
        assert len(problems) == 1 and "pids" in problems[0], (bad, problems)


def test_shared_uid_is_for_a_user_that_is_not_root(monkeypatch):
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    env = {ar.SOCKET_ENV: SOCK}
    plain = {"euid": 10002, "pid": 50, "capabilities": [],
             "no_new_privileges": False, "read_only_root": False, "pids_max": None}
    assert aw.start_problems(env, shared=True, facts=plain) == []
    root = aw.start_problems(env, shared=True, facts={**plain, "euid": 0})
    assert len(root) == 1 and "must not run as root" in root[0]


def test_the_socket_directory_must_be_closed_to_a_childs_user():
    def seen(uid, mode):
        return SimpleNamespace(st_uid=uid, st_mode=0o040000 | mode)

    assert aw.socket_directory_problem(seen(0, 0o750), euid=0) is None
    assert aw.socket_directory_problem(seen(0, 0o700), euid=0) is None
    for uid, mode in ((10002, 0o750), (0, 0o770), (0, 0o755), (0, 0o751),
                      (0, 0o1777)):
        problem = aw.socket_directory_problem(seen(uid, mode), euid=0)
        assert problem and ar.SOCKET_ENV in problem, (uid, oct(mode))


def test_capability_masks_are_read_by_name():
    assert aw.capability_names(0xE0) == ["kill", "setgid", "setuid"]
    assert aw.capability_names(0) == []
    assert aw.capability_names(1 << 21) == ["sys_admin"]
    assert aw.capability_names(1 << 50) == ["cap50"]


@pytest.mark.parametrize("env, says", [
    ({aw.CONCURRENCY_ENV: "0"}, aw.CONCURRENCY_ENV),
    ({aw.CONCURRENCY_ENV: "17"}, aw.CONCURRENCY_ENV),
    ({aw.MAX_BYTES_ENV: "lots"}, aw.MAX_BYTES_ENV),
    ({aw.MAX_BYTES_ENV: "100"}, aw.MAX_BYTES_ENV),
])
def test_the_worker_settings_have_one_reader(env, says):
    settings, problem = aw.worker_settings({ar.SOCKET_ENV: SOCK, **env})
    assert settings is None and says in problem
    settings, problem = aw.worker_settings({ar.SOCKET_ENV: SOCK})
    assert problem is None
    assert (settings["concurrency"], settings["max_bytes"]) == (2, 1 << 30)


def test_the_child_in_the_worker_sees_no_secret_and_the_hello_names_keys_only(
        monkeypatch, settings):
    for name, value in SECRETS.items():
        monkeypatch.setenv(name, value)
    with tcp_worker() as (_w, connect):
        status = ar.hello(SOCK, connect=connect)
        raw = ar.run_isolated(SOCK, "lab_static",
                              {"mode": "selftest",
                               "limits": {"memory_bytes": settings.memory_bytes,
                                          "cpu_s": 10}, "probe": {}},
                              wall_s=20, stdout_cap=1 << 20, connect=connect)
    child = json.loads(raw.output)
    assert set(child["environment_keys"]) <= CHILD_KEYS
    # The hello reports names, never values, so readiness can judge them.
    blob = json.dumps(status)
    assert all(value not in blob for value in SECRETS.values())
    assert set(SECRETS) <= set(status["environment_keys"])
    assert set(ar.foreign_environment(status["environment_keys"])) >= set(SECRETS)


# ---------------------------------------------------------------------------
# The callers ask before they decrypt or fetch
# ---------------------------------------------------------------------------

class _Untouchable:
    def execute(self, *_a, **_k):
        raise AssertionError("the pass touched the database while refused")


def test_a_triage_pass_with_no_worker_touches_nothing(monkeypatch):
    declare_policy(monkeypatch)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    counts = lab_triage.run_due(_Untouchable(), None)
    assert counts["refused"] == ar.NOT_CONFIGURED
    assert counts["done"] == counts["failed"] == 0


def test_an_on_demand_run_and_a_compile_wait_for_the_worker(monkeypatch):
    """Both functions swallow every exception (they run in the background
    with no caller), so a stub that raised could not fail this test: the
    F42 review's mutation removing both refusals passed it. The stub
    records instead, and the control below shows it is reached."""
    from uuid import uuid4

    from noctornal_api import db
    opened = []

    def record(*_a, **_k):
        opened.append(1)
        raise RuntimeError("no database in this test")

    monkeypatch.setattr(db, "connect_system", record)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    lab_triage.run_queued_detached(uuid4())
    lab_triage.compile_one_detached(uuid4())
    assert opened == []
    # The control: with a runner to use, both do open a connection.
    monkeypatch.delenv("NOCTORNAL_ENV")
    lab_triage.run_queued_detached(uuid4())
    lab_triage.compile_one_detached(uuid4())
    assert opened == [1, 1]


def test_a_forum_poll_with_no_worker_is_refused_before_its_first_request(
        monkeypatch, isolated):
    from noctornal_api import forum_parse
    monkeypatch.setattr(forum_parse, "parser_available", lambda: True)
    source = SimpleNamespace(base_url=fh.XF_THREAD, parser_config={})
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    assert fa.XenForoAdapter().refusal(None, source) == ar.NOT_CONFIGURED + "."
    isolated(_nobody)
    assert fa.MyBBAdapter().refusal(None, SimpleNamespace(
        base_url=fh.MB_THREAD, parser_config=dict(fh.MB_CONFIG))) == \
        ar.WORKER_SILENT + "."


def test_the_triage_script_exits_1_before_opening_a_connection(monkeypatch, capsys):
    declare_policy(monkeypatch)
    monkeypatch.setenv(ar.SOCKET_ENV, SOCK)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    monkeypatch.setattr(ar, "_connect_unix", _gone)
    from noctornal_api import db

    def forbidden(*_a, **_k):
        raise AssertionError("a connection was opened while refused")

    monkeypatch.setattr(db, "connect_system", forbidden)
    spec = importlib.util.spec_from_file_location(
        "lab_triage_script", ROOT / "scripts" / "lab_triage.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    assert script.main(["run"]) == 1
    said = capsys.readouterr().out
    assert said.startswith("refused: ")
    assert ar.SOCKET_ENV in said


def test_the_triage_script_exits_1_when_no_policy_is_declared(monkeypatch, capsys):
    """docs/17, "lab_triage and an undeclared policy": the pass printed
    `refused:` and exited 0, where an unusable setting and a silent worker
    exit 1. A queue that was not drained is not a pass that succeeded, and the
    two are not told apart by an alert on the exit code."""
    from noctornal_api import db, samples
    for name in ("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "NOCTORNAL_DESIGNATED_PERSON"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(samples, "policy_declared", lambda: (False, "no policy is declared"))

    def forbidden(*_a, **_k):
        raise AssertionError("a connection was opened while refused")

    monkeypatch.setattr(db, "connect_system", forbidden)
    spec = importlib.util.spec_from_file_location(
        "lab_triage_script_undeclared", ROOT / "scripts" / "lab_triage.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    for command in ("run", "status"):
        assert script.main([command]) == 1
        assert capsys.readouterr().out == "refused: no policy is declared\n"


# ---------------------------------------------------------------------------
# Readiness, where it can answer without the database
# ---------------------------------------------------------------------------

def test_readiness_fails_production_with_no_worker_configured(monkeypatch):
    from noctornal_api import readiness
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv(ar.LOCAL_ENV, raising=False)
    check = readiness._sample_static_analysis(None)
    assert not check.ok
    assert "No isolated analysis worker is configured" in check.evidence
    assert "analysis-worker" in check.action and ar.LOCAL_ENV in check.action


def test_readiness_on_the_sample_origin_says_it_analyses_nothing(monkeypatch):
    """The sample origin is given no socket and parses nothing: its own
    register passes the row rather than showing a red it cannot act on."""
    from noctornal_api import readiness
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example.test")
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", "https://samples.example.test")
    monkeypatch.setenv("NOCTORNAL_BASE_URL", "https://console.example.test")
    check = readiness._sample_static_analysis(None)
    assert check.ok and "sample origin, which analyses nothing" in check.evidence
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", "https://console.example.test")
    assert not readiness._sample_static_analysis(None).ok


def test_readiness_fails_a_malformed_setting_by_name(monkeypatch):
    from noctornal_api import readiness
    monkeypatch.setenv(ar.SOCKET_ENV, "relative.sock")
    check = readiness._sample_static_analysis(None)
    assert not check.ok and ar.SOCKET_ENV in check.evidence
    assert "relative.sock" not in check.evidence


def test_readiness_fails_a_silent_worker(monkeypatch, isolated):
    from noctornal_api import readiness
    isolated(_nobody)
    check = readiness._sample_static_analysis(None)
    assert not check.ok and "did not answer" in check.evidence
    assert "analysis-worker" in check.action


@pytest.mark.parametrize("status, says", [
    ({"environment_keys": ["PATH", "DATABASE_URL"]}, "DATABASE_URL"),
    ({"environment_keys": ["PATH", "NOCTORNAL_ANALYSIS_TOKEN"]},
     "NOCTORNAL_ANALYSIS_TOKEN"),
    ({"environment_count": 500}, "whole environment"),
    ({"versions": {"pefile": "0.0.1", "yara_x": None}}, "different parser versions"),
    ({"max_request_bytes": 1 << 20}, "NOCTORNAL_ANALYSIS_WORKER_MAX_BYTES"),
    # F42 review (2026-10-02): each of these passed, or was never asked.
    ({"network_interfaces": ["eth0", "lo"]}, "besides loopback (eth0)"),
    ({"network_interfaces": None}, "did not report its network interfaces"),
    ({"network_interfaces": "lo"}, "did not report its network interfaces"),
    ({"children": {"isolation": "shared_uid", "uids": None, "max_tasks": None}},
     "--shared-uid"),
    ({"children": None}, "--shared-uid"),
    ({"children": {"isolation": "own_uid", "uids": [0, 10101], "max_tasks": 16}},
     "--shared-uid"),
    ({"children": {"isolation": "own_uid", "uids": [10100, 10100],
                   "max_tasks": 16}}, "--shared-uid"),
    ({"capabilities": ["kill", "setgid", "setuid", "sys_admin"]}, "sys_admin"),
    ({"capabilities": None}, "did not report its capabilities"),
    ({"no_new_privileges": False}, "no-new-privileges"),
    ({"no_new_privileges": None}, "no-new-privileges"),
    ({"read_only_root": False}, "writable"),
    ({"read_only_root": None}, "writable"),
    # F42 verify round (2026-10-03): each of these was claimed and not judged.
    ({"pids_max": None}, "no pids limit it can read"),
    ({"pids_max": 64}, "pids limit is 64"),
    ({"pids_max": 38393}, "above the"),
    ({"pids_max": True}, "no pids limit it can read"),
    ({"concurrency": None}, "how many requests it runs at once"),
    ({"state_left_open": None}, "did not report whether a child can leave state"),
    ({"state_left_open": ["kernel.shmmax", "/dev/shm"]}, "/dev/shm, kernel.shmmax"),
    ({"slots_retired": 1}, "retired 1 of its 2 slots"),
    ({"slots_retired": None}, "how many of its slots it has retired"),
    ({"children": {"isolation": "own_uid", "uids": [10100, 10101],
                   "max_tasks": 1000000}}, "task limit"),
    ({"children": {"isolation": "own_uid", "uids": [10100, 10101],
                   "max_tasks": None}}, "task limit"),
    # Mutation V4 of the verify round: the children's uids may not include
    # the worker's own, whatever else is right.
    ({"uid": 10100}, "--shared-uid"),
])
def test_readiness_judges_the_worker_by_its_own_account(monkeypatch, isolated,
                                                        status, says):
    from noctornal_api import readiness
    real = aw.Worker.status

    def account(self):
        out = real(self)
        out.update(CLEAN_ACCOUNT)
        out.update(status)
        if "environment_count" not in status:
            out["environment_count"] = len(out["environment_keys"])
        return out

    monkeypatch.setattr(aw.Worker, "status", account)
    with tcp_worker() as (_w, connect):
        isolated(connect)
        check = readiness._sample_static_analysis(None)
    assert not check.ok
    assert says in check.evidence + check.action


class _Queue:
    """A connection whose one query, the triage queue's, answers as told:
    readiness asks nothing else of it."""

    def __init__(self, depth=0, oldest=None, last_done=None):
        self.row = (depth, oldest, last_done)

    def execute(self, sql, *_a):
        assert "lab.static_run" in sql
        return SimpleNamespace(fetchone=lambda: self.row)


def _clean_worker(monkeypatch):
    real = aw.Worker.status

    def account(self):
        out = real(self)
        out.update(CLEAN_ACCOUNT)
        return out

    monkeypatch.setattr(aw.Worker, "status", account)
    real_selftest = lab_triage.selftest

    def unreachable(settings, **kw):
        out = real_selftest(settings, **kw)
        out["exposure"] = {"proc_environ_readable": False,
                           "database_reachable": False}
        return out

    monkeypatch.setattr(lab_triage, "selftest", unreachable)


def test_readiness_passes_a_worker_as_compose_starts_it_and_says_so(monkeypatch,
                                                                    isolated):
    """With the queue drained, a worker whose account is clean passes, and
    the row says what was judged (no hedge: the queue is fixed here)."""
    from noctornal_api import readiness
    _clean_worker(monkeypatch)
    with tcp_worker() as (_w, connect):
        isolated(connect)
        check = readiness._sample_static_analysis(_Queue())
    assert check.ok is True, check
    assert check.evidence.startswith(f"Analysis runs in the isolated worker at {SOCK}")
    assert "3 environment variables, none a secret and none a setting but its own" \
        in check.evidence
    assert "each child a user of its own with at most 16 processes and threads" \
        in check.evidence
    assert "no network interface but loopback" in check.evidence
    assert "cannot reach the database host" in check.evidence


def test_readiness_fails_the_same_worker_when_nothing_drains_the_queue(monkeypatch,
                                                                       isolated):
    from datetime import timedelta

    from noctornal_api import readiness
    _clean_worker(monkeypatch)
    old = datetime.now(timezone.utc) - timedelta(hours=3)
    with tcp_worker() as (_w, connect):
        isolated(connect)
        check = readiness._sample_static_analysis(_Queue(4, old, None))
    assert check.ok is False
    assert "schedule scripts/lab_triage.py" in check.action


def test_readiness_fails_a_worker_whose_child_reaches_the_database(monkeypatch, isolated):
    from noctornal_api import readiness
    real = aw.Worker.status

    def clean(self):
        out = real(self)
        out.update(CLEAN_ACCOUNT)
        return out

    monkeypatch.setattr(aw.Worker, "status", clean)
    real_selftest = lab_triage.selftest

    def reaching(settings, **kw):
        out = real_selftest(settings, **kw)
        out["exposure"] = {"proc_environ_readable": True, "database_reachable": True}
        return out

    monkeypatch.setattr(lab_triage, "selftest", reaching)
    with tcp_worker() as (_w, connect):
        isolated(connect)
        check = readiness._sample_static_analysis(None)
    assert not check.ok and "not isolated" in check.evidence
    assert "network_mode" in check.action


# ---------------------------------------------------------------------------
# F42 review (2026-10-02): what a hostile child, or a worker in trouble,
# could do to everybody else
# ---------------------------------------------------------------------------

def test_the_accept_loop_survives_a_thread_that_cannot_start(monkeypatch):
    """A child that spent the container's tasks made Thread.start raise in
    the accept loop, which ended it and the container. The caller is now
    turned away and the loop goes on, with its connection place given
    back (one place here, so a leak would refuse the last hello)."""
    monkeypatch.setattr(aw, "MAX_CONNECTIONS", 1)
    real_start = threading.Thread.start
    with tcp_worker() as (w, connect):
        armed = {"n": 3}

        def start(self):
            if armed["n"] and getattr(self, "_target", None) == w._serve_one:
                armed["n"] -= 1
                raise RuntimeError("can't start new thread")
            return real_start(self)

        monkeypatch.setattr(threading.Thread, "start", start)
        for _ in range(3):
            with pytest.raises(ar.WorkerUnavailable):
                ar.hello(SOCK, connect=connect)
        assert ar.hello(SOCK, connect=connect)["protocol"] == ar.WIRE_VERSION


def test_a_child_nobody_can_attend_is_killed_not_left_running(tmp_path, monkeypatch):
    """No thread to read the child's output: it is killed and reaped, and
    the run is a start failure, rather than an exception that leaves the
    child running unbounded."""
    real_start = threading.Thread.start

    def start(self):
        if getattr(getattr(self, "_target", None), "__name__", "") == "reader":
            raise RuntimeError("can't start new thread")
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    argv = _script(tmp_path, "sleepy.py",
                   "import sys, time\nsys.stdin.buffer.readline()\ntime.sleep(60)\n")
    began = time.monotonic()
    result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=60, stdout_cap=1024,
                          argv=argv)
    assert result.failure == "start_failed"
    assert result.returncode is not None, "the child was killed and reaped"
    assert time.monotonic() - began < 20


def test_the_worker_is_asked_once_for_many_sources_and_briefly(monkeypatch):
    """A source list asks every forum source's refusal, and the schedule
    does too: against a worker that accepts and never answers, each ask
    waited the whole hello. One ask is made, by one caller at a time, and
    its verdict is believed for VERDICT_TTL_S only."""
    monkeypatch.setattr(ar, "HAS_UNIX", True)
    monkeypatch.setattr(ar, "HELLO_TIMEOUT_S", 0.3)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    held = []

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            held.append(conn)

    threading.Thread(target=serve, daemon=True).start()
    addr = listener.getsockname()
    env = {ar.SOCKET_ENV: SOCK}

    def connect(_path):
        return socket.create_connection(addr, timeout=5)

    try:
        began = time.monotonic()
        verdicts = []
        askers = [threading.Thread(target=lambda: verdicts.append(
            ar.unavailable(env, connect=connect))) for _ in range(4)]
        for t in askers:
            t.start()
        for t in askers:
            t.join(10)
        verdicts += [ar.unavailable(env, connect=connect) for _ in range(6)]
        assert verdicts == [ar.WORKER_SILENT] * 10
        assert len(held) == 1, "one hello for ten callers"
        assert time.monotonic() - began < 3
        monkeypatch.setattr(ar, "VERDICT_TTL_S", 0.2)
        ar.forget_verdicts()
        ar.unavailable(env, connect=connect)
        time.sleep(0.3)
        ar.unavailable(env, connect=connect)
        assert len(held) == 3, "a verdict past its time is asked again"
    finally:
        listener.close()
        for conn in held:
            conn.close()


def test_payloads_are_read_only_once_a_slot_is_held(tmp_path, monkeypatch):
    """At most `concurrency` payloads are in memory: a request waiting for
    a slot has had none of its payload read (the F42 review's mutation
    reading it first passed every test)."""
    monkeypatch.setitem(aw.KIND_ARGV, "lab_static", _script(tmp_path, "echo.py", _ECHO))
    reads = []
    real_recv = ar.recv_exact

    def recv(sock, n, deadline, **kw):
        if kw.get("mutable"):
            reads.append(n)
        return real_recv(sock, n, deadline, **kw)

    monkeypatch.setattr(ar, "recv_exact", recv)
    blob = b"p" * 4321
    with tcp_worker(concurrency=1) as (w, connect):
        slot = w._free.get(timeout=5)
        out = {}
        t = threading.Thread(target=lambda: out.update(result=ar.run_isolated(
            SOCK, "lab_static", {"mode": "pe"}, (blob,), wall_s=20,
            stdout_cap=1 << 16, connect=connect)))
        t.start()
        time.sleep(1.0)
        assert reads == [], "the payload was read before a slot was free"
        w._free.put(slot)
        t.join(30)
    assert reads == [4321]
    assert out["result"].ok
    assert json.loads(out["result"].output)["sha"] == hashlib.sha256(blob).hexdigest()


def test_a_peer_that_stalls_mid_frame_is_dropped_at_the_idle_limit(monkeypatch):
    """The idle limit, not the deadline, drops a peer that stops sending:
    the deadline here is 30 seconds and the idle limit half of one (the
    review's mutation removing the idle limit passed every test, because
    they shrank both)."""
    monkeypatch.setattr(ar, "IDLE_S", 0.5)
    assert ar.TRANSFER_BASE_S >= 30
    with tcp_worker() as (_w, connect):
        sock = connect(None)
        sock.sendall(ar.MAGIC)
        began = time.monotonic()
        assert _closed_by_peer(sock, 10)
        assert time.monotonic() - began < 4
        sock.close()


@pytest.mark.parametrize("reason", ar.SANDBOX_FAILURES)
def test_a_worker_failure_during_a_poll_is_not_parser_drift(reason):
    """Busy, gone, garbled, refusing or missing: the sandbox's state. The
    poll stops at that page, BLOCKED (no failure counted, the cursor kept)
    and saying so, never PARTIAL with a ParserDrift."""
    from test_forum_adapters import FakeContext

    from noctornal_api.collection import SourceBlocked

    def parse(*_a, **_k):
        raise fa.ParseAbandoned(reason)

    site = fh.xf_thread_site()
    with pytest.raises(fa.AnalysisUnavailable) as caught:
        fa.XenForoAdapter(parse=parse).fetch(
            base_url=fh.XF_THREAD, context=FakeContext(site, proxied=True))
    assert isinstance(caught.value, SourceBlocked)
    said = str(caught.value)
    assert said.startswith("This poll stopped because ")
    assert "the parser is not at fault" in said
    assert "the next poll reads the same pages again" in said
    assert site.urls() == [fh.XF_THREAD], "nothing more is fetched for nothing"


def test_a_busy_worker_during_a_poll_is_reported_busy_not_drift(monkeypatch, isolated):
    """The review's reproduction: one slot, held; the page goes to the
    worker and the poll ends BLOCKED, saying the worker was busy."""
    from test_forum_adapters import FakeContext
    monkeypatch.setattr(ar, "QUEUE_WAIT_S", 0.5)
    with tcp_worker(concurrency=1) as (w, connect):
        isolated(connect)
        slot = w._free.get(timeout=5)
        try:
            with pytest.raises(fa.AnalysisUnavailable) as caught:
                fa.XenForoAdapter().fetch(
                    base_url=fh.XF_THREAD,
                    context=FakeContext(fh.xf_thread_site(), proxied=True))
        finally:
            w._free.put(slot)
    assert "had no free slot in time" in str(caught.value)


def test_an_abandoned_page_is_still_drift():
    """The control: a child that ran and gave no answer is drift as before."""
    from test_forum_adapters import FakeContext

    def parse(*_a, **_k):
        raise fa.ParseAbandoned("crashed")

    got = fa.XenForoAdapter(parse=parse).fetch(
        base_url=fh.XF_THREAD, context=FakeContext(fh.xf_thread_site(), proxied=True))
    assert [w.kind for w in got.warnings] == ["PARSER_DRIFT"]


class _Pass:
    """run_due's collaborators, recorded."""

    def __init__(self, monkeypatch, *, run_status="DONE", compile_raises=None):
        self.claims = 0
        from noctornal_api import samples
        monkeypatch.setattr(samples, "policy_declared", lambda: (True, ""))
        monkeypatch.setattr(ar, "unavailable", lambda *a, **k: None)
        monkeypatch.setattr(lab_triage, "sweep_abandoned", lambda conn: 0)
        monkeypatch.setattr(lab_triage, "queue_depth", lambda conn: 5)
        monkeypatch.setattr(lab_triage, "take_slot", lambda conn, n: 1)
        monkeypatch.setattr(lab_triage, "release_slot", lambda conn, n: None)

        def compile_pending(*_a, **_k):
            if compile_raises:
                raise lab_triage.AnalysisInterrupted(compile_raises)
            return 0, 0

        def claim(*_a, **_k):
            self.claims += 1
            return SimpleNamespace(id=self.claims), 0

        monkeypatch.setattr(lab_triage, "compile_pending", compile_pending)
        monkeypatch.setattr(lab_triage, "claim", claim)
        monkeypatch.setattr(lab_triage, "run_claimed",
                            lambda *a, **k: run_status)

    @staticmethod
    def execute(_sql, *_a):
        return SimpleNamespace(fetchone=lambda: (0,))


def test_a_pass_stops_at_the_first_interrupted_run(monkeypatch):
    """A run the sandbox interrupted goes back to the queue; the next run
    would meet the same worker, so no further sample is decrypted."""
    done = _Pass(monkeypatch)
    counts = lab_triage.run_due(done, None, limit=5)
    assert done.claims == 5 and counts["done"] == 5, "the control runs them all"
    stopped = _Pass(monkeypatch, run_status=lab_triage.INTERRUPTED)
    counts = lab_triage.run_due(stopped, None, limit=5)
    assert stopped.claims == 1
    assert counts["interrupted"] == 1 and counts["done"] == 0


def test_a_yara_scan_the_worker_never_ran_is_not_a_crashed_scan(monkeypatch):
    """The review: a refused, busy or unreachable worker was stored on the
    sample as a crashed scan. It interrupts the run instead; a child that
    crashed is still a crashed scan."""
    from uuid import uuid4

    from noctornal_api import yara_rules

    class Rulesets:
        def __init__(self, _conn):
            pass

        def usable_build(self, _vid, _key):
            return {"status": "COMPILED", "blob": b"rules", "id": str(uuid4())}

    monkeypatch.setattr(yara_rules, "build_key",
                        lambda: SimpleNamespace(engine="yara-x", platform="p"))
    monkeypatch.setattr(yara_rules, "yara_settings", lambda: (None, None))
    monkeypatch.setattr(yara_rules, "RulesetService", Rulesets)
    monkeypatch.setattr(lab_triage, "_open_versions",
                        lambda _conn, _wanted: [("v1", "r1", "set", 1)])
    claimed = SimpleNamespace(yara_version_ids=[])
    for reason in ar.SANDBOX_FAILURES:
        monkeypatch.setattr(lab_triage, "run_child",
                            lambda *a, _r=reason, **k: ar.ChildResult(False, failure=_r))
        with pytest.raises(lab_triage.AnalysisInterrupted) as caught:
            lab_triage._yara_step(None, claimed, b"MZ")
        assert caught.value.failure == reason
    monkeypatch.setattr(lab_triage, "run_child",
                        lambda *a, **k: ar.ChildResult(False, failure="crashed"))
    rows = lab_triage._yara_step(None, claimed, b"MZ")["rows"]
    assert rows[0]["findings"]["error"] == "crashed"


def test_a_pass_whose_compile_is_interrupted_claims_no_run(monkeypatch):
    stopped = _Pass(monkeypatch, compile_raises="worker_unavailable")
    counts = lab_triage.run_due(stopped, None, limit=5)
    assert stopped.claims == 0
    assert counts["interrupted"] == 1 and counts["left"] == 5


def test_the_triage_script_exits_1_on_an_interrupted_pass(monkeypatch, capsys):
    declare_policy(monkeypatch)
    from noctornal_api import db, samples
    monkeypatch.setattr(db, "connect_system",
                        lambda *_a, **_k: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(samples, "SampleStorage", lambda: None)
    monkeypatch.setattr(lab_triage, "run_due", lambda *a, **k: {
        "queued": 1, "done": 0, "failed": 0, "interrupted": 1})
    spec = importlib.util.spec_from_file_location(
        "lab_triage_script_interrupted", ROOT / "scripts" / "lab_triage.py")
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    assert script.main(["run"]) == 1
    assert "interrupted=1" in capsys.readouterr().out


def _fake_proc(tmp_path, entries: dict[int, str]) -> Path:
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "self").mkdir()
    for pid, uids in entries.items():
        (proc / str(pid)).mkdir()
        (proc / str(pid) / "status").write_text(
            f"Name:\tx\nState:\tS (sleeping)\nUid:\t{uids}\nGid:\t1\t1\t1\t1\n",
            encoding="ascii")
    return proc


def test_a_slots_uid_is_emptied_of_every_process_and_nothing_else(tmp_path):
    """purge_user kills every process whose real, effective or saved uid is
    the slot's (a setsid survivor included), and no other."""
    import shutil
    proc = _fake_proc(tmp_path, {100: "10100\t10100\t10100\t10100",
                                 101: "10001\t10001\t10001\t10001",
                                 102: "5\t5\t10100\t5",
                                 103: "0\t0\t0\t0"})
    killed = []

    def kill(pid, sig):
        killed.append(pid)
        shutil.rmtree(proc / str(pid))

    assert sorted(aw.tasks_of(10100, proc=str(proc))) == [100, 102]
    assert aw.purge_user(10100, proc=str(proc), kill=kill) is True
    assert sorted(killed) == [100, 102]
    assert sorted(int(p.name) for p in proc.iterdir() if p.name.isdigit()) == [101, 103]


def test_a_slot_that_cannot_be_emptied_says_so(tmp_path):
    proc = _fake_proc(tmp_path, {100: "10100\t10100\t10100\t10100"})
    began = time.monotonic()
    assert aw.purge_user(10100, within=0.2, proc=str(proc),
                         kill=lambda pid, sig: None) is False
    assert time.monotonic() - began < 2


def test_a_supervising_worker_runs_each_slot_as_its_uid_and_empties_it_first(
        monkeypatch):
    """Slot N's child runs as its uid under the task limit, and that uid
    is emptied BEFORE the caller hears the answer."""
    events = []

    def run_local(header, payloads=(), **kw):
        events.append(("run", kw["user"], kw["max_tasks"]))
        # run_local calls the worker's reap once the child is gone and before
        # it waits on any pipe (F42 verify 1, 2026-10-03).
        kw["reap"]()
        return ar.ChildResult(True, b'{"ok":true}', returncode=0)

    def purge(uid, **_kw):
        events.append(("purge", uid))
        return True

    monkeypatch.setattr(ar, "run_local", run_local)
    monkeypatch.setattr(aw, "purge_user", purge)
    with tcp_worker(concurrency=1, child_uids=[10100]) as (w, connect):
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (b"MZ",),
                                 wall_s=5, stdout_cap=1024, connect=connect)
        events.append(("answered",))
        status = ar.hello(SOCK, connect=connect)
    assert result.ok
    assert events == [("run", 10100, aw.CHILD_MAX_TASKS), ("purge", 10100),
                      ("answered",)]
    assert status["children"] == {"isolation": "own_uid", "uids": [10100],
                                  "max_tasks": aw.CHILD_MAX_TASKS}


def test_a_slot_whose_uid_cannot_be_emptied_is_never_used_again(monkeypatch):
    """Retired; with no slot left the worker stops (main exits 3, and
    Docker restarts it clean)."""
    monkeypatch.setattr(ar, "run_local",
                        lambda *a, **k: ar.ChildResult(True, b"{}", returncode=0))
    monkeypatch.setattr(aw, "purge_user", lambda uid, **kw: False)
    with tcp_worker(concurrency=1, child_uids=[10100]) as (w, connect):
        ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (b"MZ",), wall_s=5,
                        stdout_cap=1024, connect=connect)
        for _ in range(50):
            if w.failed:
                break
            time.sleep(0.05)
        assert w.failed and w.retired == 1
        assert w._free.empty()


def test_a_worker_with_shared_children_says_so():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        status = aw.Worker(listener).status()
    finally:
        listener.close()
    assert status["children"] == {"isolation": "shared_uid", "uids": None,
                                  "max_tasks": None}
    # F42 verify 3 and 2 (2026-10-03): the pids limit and the state a child
    # could leave behind were named in the docstring and the report, and
    # the hello carried neither.
    for key in ("capabilities", "no_new_privileges", "read_only_root",
                "slots_retired", "pids_max", "state_left_open"):
        assert key in status
    with pytest.raises(ValueError):
        aw.Worker(listener, concurrency=2, child_uids=[10100])


def test_the_pids_limit_is_read_from_the_cgroup_the_container_sees(tmp_path):
    """F42 verify 3 (2026-10-03): the hello now carries the limit, so the
    reading is held: v2 then v1 at the container's own root, then the path
    /proc/self/cgroup names, and "max" is no limit."""
    root = tmp_path / "cg"
    root.mkdir()
    listing = tmp_path / "cgroup"
    listing.write_text("0::/docker/abc\n", encoding="ascii")

    def read():
        return aw.read_pids_max(root=str(root), cgroup_file=str(listing))

    assert read() is None, "nothing readable is no limit it can report"
    (root / "pids.max").write_text("128\n", encoding="ascii")
    assert read() == 128
    (root / "pids.max").write_text("max\n", encoding="ascii")
    assert read() is None
    (root / "pids.max").unlink()
    (root / "pids").mkdir()
    (root / "pids" / "pids.max").write_text("64\n", encoding="ascii")
    assert read() == 64
    (root / "pids" / "pids.max").unlink()
    (root / "docker" / "abc").mkdir(parents=True)
    (root / "docker" / "abc" / "pids.max").write_text("200\n", encoding="ascii")
    assert read() == 200
    # A path that climbs out of the root is never followed.
    listing.write_text("0::/../../etc\n", encoding="ascii")
    (root / "docker" / "abc" / "pids.max").unlink()
    assert read() is None


def _sysctls(tmp_path, **values):
    root = tmp_path / "sys"
    for name, value in values.items():
        path = root.joinpath(*name.split("__"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{value}\n", encoding="ascii")
    return str(root)


_CLOSED = {"kernel__shmmax": 0, "kernel__msgmni": 0,
           "kernel__sem": "0\t0\t0\t0", "fs__mqueue__queues_max": 0}


def test_state_a_child_could_leave_behind_is_read_from_the_running_process(tmp_path):
    """F42 verify 2 (2026-10-03): SysV shared memory, queues and semaphores
    and POSIX queues are closed by sysctls, and each is named when it is
    not, or cannot be read."""
    closed = _sysctls(tmp_path, **_CLOSED)
    assert aw.state_left_open(sys_root=closed, dirs=()) == []
    for name, value, shown in (
            ("kernel__shmmax", 18446744073692774399, "kernel.shmmax"),
            ("kernel__msgmni", 32000, "kernel.msgmni"),
            ("kernel__sem", "32000\t1024000000\t500\t32000", "kernel.sem"),
            ("fs__mqueue__queues_max", 256, "fs.mqueue.queues_max")):
        other = tmp_path / shown
        other.mkdir()
        opened = _sysctls(other, **{**_CLOSED, name: value})
        assert aw.state_left_open(sys_root=opened, dirs=()) == [shown], shown
    # What cannot be read is open: nothing shows it closed.
    nothing = tmp_path / "none"
    nothing.mkdir()
    assert aw.state_left_open(sys_root=str(nothing), dirs=()) == sorted(
        [*aw.IPC_SYSCTLS, "kernel.sem"])
    # One value that is not a whole number is open as well.
    junk = tmp_path / "junk"
    junk.mkdir()
    bad = _sysctls(junk, **{**_CLOSED, "kernel__shmmax": "lots"})
    assert aw.state_left_open(sys_root=bad, dirs=()) == ["kernel.shmmax"]


@pytest.mark.parametrize("mode, readonly, writable", [
    (0o040777, False, True),
    (0o041777, False, True),
    (0o040755, False, False),
    (0o040750, False, False),
    (0o040777, True, False),
    (0o100666, False, False),
])
def test_a_directory_is_open_to_a_child_when_others_can_write_it(mode, readonly,
                                                                  writable):
    assert aw._writable_by_others(mode, readonly) is writable


@pytest.mark.skipif(sys.platform == "win32", reason="directory modes are POSIX's")
def test_the_scratch_directories_are_read_from_the_filesystem(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir()
    loose.chmod(0o1777)
    tight = tmp_path / "tight"
    tight.mkdir()
    tight.chmod(0o755)
    closed = _sysctls(tmp_path, **_CLOSED)
    left = aw.state_left_open(sys_root=closed,
                              dirs=(str(loose), str(tight),
                                    str(tmp_path / "absent")))
    assert left == [str(loose)]


def test_recv_exact_hands_the_buffer_it_filled_over_when_asked():
    """Mutation V22 of the verify round: with `mutable` reverted to a bytes
    copy the 'payload held once' claim of the worker was held by a hand
    measurement alone."""
    a, b = socket.socketpair()
    try:
        b.sendall(b"abcdef")
        deadline = time.monotonic() + 5
        assert type(ar.recv_exact(a, 3, deadline, mutable=True)) is bytearray
        assert type(ar.recv_exact(a, 3, deadline)) is bytes
    finally:
        a.close()
        b.close()


@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="RLIMIT_NPROC and oom_score_adj are Linux's")
def test_the_launcher_limits_tasks_and_ranks_the_child_first_for_the_oom_killer():
    import subprocess
    argv = ar.launch_argv([sys.executable, "-c",
                           "import resource\n"
                           "print(resource.getrlimit(resource.RLIMIT_NPROC))\n"
                           "print(open('/proc/self/oom_score_adj').read().strip())\n"],
                          7)
    out = subprocess.run(argv, capture_output=True, text=True, timeout=30,
                         env={"PATH": "/usr/bin:/bin"})
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["(7,", "7)", "1000"]


def test_the_application_reads_bytes_from_either_runner(monkeypatch, settings):
    monkeypatch.delenv(ar.SOCKET_ENV, raising=False)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    result = lab_triage.run_child({"mode": "selftest", "probe": {},
                                   "limits": {"memory_bytes": settings.memory_bytes,
                                              "cpu_s": 10}}, wall_s=20)
    assert result.ok and type(result.output) is bytes


@pytest.mark.skipif(sys.platform == "win32", reason="a CPU-time limit is POSIX's")
def test_a_child_its_own_cpu_limit_stops_is_a_timeout_not_a_crash(tmp_path):
    """A runaway child meets the CPU-time limit it set itself
    (`lab_static.apply_limits`) before the wall clock. The kernel ends it
    with SIGXCPU, which is the time limit it is, never a crash: a
    catastrophic watch regex was told as a matcher that "stopped without an
    answer" (2026-10-07). With the soft and hard limits equal the kernel
    sends SIGKILL instead, which reads like any other kill."""
    src = str(Path(ar.__file__).resolve().parents[1])
    argv = _script(tmp_path, "spin.py",
                   f"import sys\nsys.path.insert(0, {src!r})\n"
                   "from noctornal_api import lab_static\n"
                   "sys.stdin.buffer.readline()\n"
                   "lab_static.apply_limits(1 << 30, 1)\n"
                   "while True:\n    pass\n")
    result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=30, stdout_cap=1024, argv=argv)
    assert result.failure == "timeout", result
    assert result.returncode == -signal.SIGXCPU, result


@pytest.mark.skipif(sys.platform == "win32", reason="a uid of its own is POSIX's")
def test_a_child_of_a_uid_of_its_own_is_started_as_that_user_behind_the_launcher(
        tmp_path, monkeypatch):
    """The supervised worker's wiring (the switch itself needs root with
    setuid): Popen is wrapped to record what it is asked and to start the
    child without the switch. Removing the user, the group, the empty
    group list, the new session or the launcher from run_local fails this;
    a container shows the switch itself (the review's reproductions, re-run
    on 2026-10-03)."""
    import subprocess
    seen = {}
    real = subprocess.Popen

    def popen(argv, **kw):
        seen["argv"], seen["kw"] = list(argv), dict(kw)
        for name in ("user", "group", "extra_groups"):
            kw.pop(name, None)
        return real(argv, **kw)

    monkeypatch.setattr(ar.subprocess, "Popen", popen)
    argv = _script(tmp_path, "ok.py",
                   "import sys\nsys.stdin.buffer.readline()\nsys.stdout.write('{}')\n")
    # The launcher sets RLIMIT_NPROC to the figure it is given and, run
    # unprivileged here, may not raise the hard limit: ask for no more than
    # this host's (a CI runner's is well under 2**20).
    import resource
    hard = resource.getrlimit(resource.RLIMIT_NPROC)[1]
    tasks = 1 << 20 if hard == resource.RLIM_INFINITY else min(hard, 1 << 20)
    result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=20, stdout_cap=1024,
                          argv=argv, user=10101, max_tasks=tasks)
    assert result.ok, result
    kw = seen["kw"]
    assert (kw["user"], kw["group"], kw["extra_groups"]) == (10101, 10101, [])
    assert kw["start_new_session"] is True
    assert seen["argv"][:4] == [sys.executable, "-I", "-S", "-c"]
    assert seen["argv"][5] == str(tasks) and seen["argv"][6:] == argv
    # The control: with no uid asked for, the child is started as itself
    # and with no launcher, which is every development run.
    ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=20, stdout_cap=1024, argv=argv)
    assert "user" not in seen["kw"] and seen["argv"] == argv


def test_the_workers_allow_list_holds_what_the_dockerfile_sets():
    """The worker is the application image running one more command, and it
    refuses to start holding any variable it cannot name: a variable added
    to the Dockerfile's ENV would make every analysis refuse until the
    list learned it (the F42 review's brittleness finding). This holds the
    two together for what this repository sets; what the base image sets
    (GPG_KEY, PYTHON_VERSION) is listed by hand, and a base-image bump that
    adds one shows as a refused worker on the worker's first start, said
    by name in its log and on the readiness row."""
    import re
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    text = re.sub(r"\\\r?\n", " ", text)
    names = set()
    for line in text.splitlines():
        found = re.match(r"\s*ENV\s+(.*)", line)
        if found:
            names |= set(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=", found.group(1)))
    assert {"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE",
            "PIP_DISABLE_PIP_VERSION_CHECK"} <= names, "the parse found nothing"
    assert ar.foreign_environment(names) == []
    assert ar.foreign_environment(names | {"SSL_CERT_FILE"}) == ["SSL_CERT_FILE"]


def test_the_demo_seeder_stops_at_a_run_the_worker_interrupted(monkeypatch):
    """The seeder claims until nothing is left; a run the worker failed
    under is queued again at the same attempt, so without this it would be
    claimed again for ever."""
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    spec = importlib.util.spec_from_file_location(
        "seed_lab_demo_script", ROOT / "scripts" / "seed_lab_demo.py")
    seed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed)
    claims = []
    statuses = iter([lab_triage.INTERRUPTED])

    def claim(_conn, _settings, among=None):
        claims.append(1)
        return SimpleNamespace(id=len(claims)), 0

    monkeypatch.setattr(lab_triage, "claim", claim)
    monkeypatch.setattr(lab_triage, "run_claimed", lambda *a, **k: next(statuses))
    assert seed.triage_seeded(None, None, None, [object()]) == (1, True)
    assert claims == [1]
    # The control: runs that finish are claimed until the queue is empty.
    left = iter([SimpleNamespace(id=1), SimpleNamespace(id=2), None])
    monkeypatch.setattr(lab_triage, "claim",
                        lambda _c, _s, among=None: (next(left), 0))
    monkeypatch.setattr(lab_triage, "run_claimed", lambda *a, **k: "DONE")
    assert seed.triage_seeded(None, None, None, [object()]) == (2, False)


# ---------------------------------------------------------------------------
# F42 verify round (2026-10-03), finding 1: a process the child leaves
# running that keeps the child's stdout or stderr open
# ---------------------------------------------------------------------------

_LINGER_HELPER = (
    "import os, sys, time\n"
    "pidfile, late, hold = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])\n"
    "with open(pidfile + '.tmp', 'w') as f:\n"
    "    f.write(str(os.getpid()))\n"
    "os.replace(pidfile + '.tmp', pidfile)\n"
    "time.sleep(late)\n"
    "sys.stdout.write('LATE')\n"
    "sys.stdout.flush()\n"
    "time.sleep(hold)\n")
#: What a parser exploit does without any care: it starts a helper that
#: INHERITS the child's stdout and stderr (no redirect), waits until the
#: helper runs, then answers `{}` and exits 0. The stand-ins of the earlier
#: rounds all sent their helpers' stdio to /dev/null, which is why none of
#: them found that a pipe held open wedged the run.
_LINGER_CHILD = (
    "import os, subprocess, sys, time\n"
    "sys.stdin.buffer.readline()\n"
    "helper, pidfile, session, late, hold = sys.argv[1:6]\n"
    "subprocess.Popen([sys.executable, helper, pidfile, late, hold],\n"
    "                 stdout=sys.stdout, stderr=sys.stderr,\n"
    "                 start_new_session=(session == 'session'))\n"
    "end = time.monotonic() + 20\n"
    "while not os.path.exists(pidfile) and time.monotonic() < end:\n"
    "    time.sleep(0.02)\n"
    "sys.stdout.write('{}')\n"
    "sys.stdout.flush()\n")


def _linger(tmp_path, *, session: bool, late: float, hold: float):
    helper = tmp_path / "helper.py"
    helper.write_text(_LINGER_HELPER, encoding="utf-8")
    pidfile = tmp_path / "helper.pid"
    argv = _script(tmp_path, "linger.py", _LINGER_CHILD) + [
        str(helper), str(pidfile), "session" if session else "group",
        str(late), str(hold)]
    return argv, pidfile


def _helper_pid(pidfile) -> int | None:
    try:
        return int(Path(pidfile).read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def _stop_helper(pidfile) -> None:
    pid = _helper_pid(pidfile)
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass


def _helper_gone(pid: int, seconds: float) -> bool:
    """Linux: whether `pid` is gone or a zombie, polled for `seconds`."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        except OSError:
            return True
        if text.rsplit(")", 1)[1].split()[0] in ("Z", "X"):
            return True
        time.sleep(0.05)
    return False


def test_a_helper_left_holding_the_childs_pipes_is_stopped_before_the_run_waits_on_them(
        tmp_path, monkeypatch):
    """The worker's `reap` (the purge of the slot's uid) must run BEFORE
    run_local joins its threads and closes the pipes: a pipe a helper holds
    open blocks the close for as long as the helper lives, and the purge
    that could stop it used to run only after run_local returned. The grace
    is long here, so only an end of file after the reap lets the run finish
    in time."""
    monkeypatch.setattr(ar, "PIPE_GRACE_S", 30.0)
    argv, pidfile = _linger(tmp_path, session=True, late=60, hold=60)
    reaped = []

    def reap():
        reaped.append(_helper_pid(pidfile))
        _stop_helper(pidfile)

    began = time.monotonic()
    try:
        result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=30,
                              stdout_cap=1024, argv=argv, reap=reap)
    finally:
        _stop_helper(pidfile)
    assert result.ok, result
    assert bytes(result.output) == b"{}"
    assert len(reaped) == 1 and reaped[0] is not None
    assert time.monotonic() - began < 20


def test_a_helper_nobody_can_stop_does_not_hold_the_run_or_change_its_answer(
        tmp_path, monkeypatch):
    """The local runner has no uid to purge: a helper that left the child's
    session (and on Windows every helper) keeps the pipes for as long as it
    lives. The run no longer waits for it, and what the helper writes later
    is never added to the answer already handed back."""
    monkeypatch.setattr(ar, "PIPE_GRACE_S", 0.5)
    argv, pidfile = _linger(tmp_path, session=True, late=4, hold=40)
    began = time.monotonic()
    try:
        result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=30,
                              stdout_cap=1024, argv=argv)
        took = time.monotonic() - began
        time.sleep(max(0.0, 5.5 - took))
        answer = bytes(result.output)
    finally:
        _stop_helper(pidfile)
    assert took < 15, f"the run waited {took:.0f} s for a helper"
    assert result.ok and answer == b"{}", (result, answer)


@pytest.mark.skipif(not sys.platform.startswith("linux"),
                    reason="a process group is POSIX's, and /proc is Linux's")
def test_a_helper_left_in_the_childs_own_group_is_killed_by_the_run_itself(
        tmp_path, monkeypatch):
    """A normal exit used to leave the group alone (it was killed only on a
    timeout), so a helper started without setsid outlived the run."""
    monkeypatch.setattr(ar, "PIPE_GRACE_S", 30.0)
    argv, pidfile = _linger(tmp_path, session=False, late=30, hold=30)
    began = time.monotonic()
    try:
        result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=30,
                              stdout_cap=1024, argv=argv)
        pid = _helper_pid(pidfile)
        gone = pid is not None and _helper_gone(pid, 5.0)
    finally:
        _stop_helper(pidfile)
    assert result.ok and bytes(result.output) == b"{}", result
    assert time.monotonic() - began < 20
    assert gone, "the helper outlived the run"


def test_a_reap_that_raises_does_not_end_the_run(tmp_path):
    argv = _script(tmp_path, "ok.py",
                   "import sys\nsys.stdin.buffer.readline()\nsys.stdout.write('{}')\n")

    def reap():
        raise OSError("the purge could not read /proc")

    result = ar.run_local({"mode": "pe"}, (b"MZ",), wall_s=20, stdout_cap=1024,
                          argv=argv, reap=reap)
    assert result.ok and bytes(result.output) == b"{}"


def test_large_payloads_and_outputs_cross_the_pipes_whole(tmp_path):
    """The threads that own the pipes now close them: a payload of several
    writes in and an output of several reads out still arrive whole."""
    data = bytes(range(256)) * (24 * 1024)
    argv = _script(tmp_path, "echo.py", _ECHO)
    result = ar.run_local({"mode": "pe"}, (data[:1 << 20], data[1 << 20:]),
                          wall_s=60, stdout_cap=1 << 16, argv=argv)
    assert result.ok, result
    assert json.loads(result.output)["sha"] == hashlib.sha256(data).hexdigest()
    big = _script(tmp_path, "big.py",
                  "import sys\nsys.stdin.buffer.readline()\n"
                  "sys.stdout.buffer.write(b'y' * (3 << 20))\n")
    result = ar.run_local({"mode": "pe"}, (), wall_s=60, stdout_cap=4 << 20,
                          argv=big)
    assert result.ok and len(result.output) == 3 << 20


def test_a_purge_that_cannot_run_retires_the_slot_and_never_frees_it(monkeypatch):
    """`clean` started True and stayed True when the purge raised, so a
    slot nobody had emptied went back into use."""
    def run_local(*_a, **_k):
        raise RuntimeError("the run failed in the worker")

    def purge(_uid, **_kw):
        raise OSError("/proc could not be read")

    monkeypatch.setattr(ar, "run_local", run_local)
    monkeypatch.setattr(aw, "purge_user", purge)
    with tcp_worker(concurrency=1, child_uids=[10100]) as (w, connect):
        result = ar.run_isolated(SOCK, "lab_static", {"mode": "pe"}, (b"MZ",),
                                 wall_s=5, stdout_cap=1024, connect=connect)
        for _ in range(100):
            if w.failed:
                break
            time.sleep(0.05)
        assert not result.ok
        assert w.failed and w.retired == 1 and w._free.empty()


# ---------------------------------------------------------------------------
# The code
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("module", [ar, aw])
def test_no_child_is_started_with_preexec_fn(module):
    text = Path(module.__file__).read_text(encoding="utf-8")
    assert "preexec_fn" not in text.replace("Never `preexec_fn`", "")
