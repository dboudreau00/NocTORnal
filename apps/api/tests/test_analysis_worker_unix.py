"""The isolated analysis worker as its own process, on a real Unix socket
(docs/17 F42, 2026-10-02).

test_analysis_runner.py drives the same Worker over a loopback stand-in
on every platform; this file is what only a platform with AF_UNIX can
show: the process refusing to start with a secret in its environment,
serving with a clean one, its socket's mode, a stale socket replaced and
anything else at its name refused, the client refusing a name that is not
a socket, the healthcheck, and a caller told at once when the worker is
killed mid-request. Linux CI runs it; Windows' CPython has no AF_UNIX.

Since the F42 review (2026-10-02) the worker gives each child a user of
its own, which needs root with three capabilities: CI has neither, so
these start it with --shared-uid (children as its own user), and one test
shows that without the flag an ordinary user is refused. The supervised
worker itself was shown in a container (the review's reproductions,
re-run on 2026-10-03).

Pure: no database. The worker and its children are real processes.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from noctornal_api import analysis_runner as ar

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"),
                                reason="no Unix sockets on this platform")

CHILD_KEYS = {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
              "PYTHONPATH"}


@pytest.fixture
def where():
    """A short directory: a socket's whole path must fit in 100 bytes, and
    pytest's own temporary paths can be longer."""
    path = tempfile.mkdtemp(prefix="naw-", dir="/tmp")
    yield Path(path)
    shutil.rmtree(path, ignore_errors=True)


def _env(sock: Path, **extra) -> dict:
    return {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": ar.package_root(),
            ar.SOCKET_ENV: str(sock), **extra}


def _start(env: dict, argv=None):
    return subprocess.Popen(argv or [sys.executable, "-m",
                                     "noctornal_api.analysis_worker",
                                     "--shared-uid"],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)


def _wait_for(sock: Path, proc, seconds: float = 15) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if sock.exists() and stat.S_ISSOCK(os.lstat(sock).st_mode):
            return
        if proc.poll() is not None:
            pytest.fail(f"the worker exited {proc.returncode}: "
                        f"{proc.stderr.read().decode(errors='replace')}")
        time.sleep(0.05)
    pytest.fail("the worker never listened")


def _stop(proc) -> int:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(5)
    for pipe in (proc.stdout, proc.stderr):
        pipe.close()
    return proc.returncode


def test_the_worker_serves_with_a_clean_environment_and_holds_nothing_else(where):
    sock = where / "w.sock"
    env = _env(sock)
    proc = _start(env)
    try:
        _wait_for(sock, proc)
        assert stat.S_IMODE(os.lstat(sock).st_mode) == 0o660
        assert subprocess.run([sys.executable, "-m", "noctornal_api.analysis_worker",
                               "--check"], env=env, timeout=30).returncode == 0
        status = ar.hello(str(sock))
        assert set(status["environment_keys"]) == set(env)
        assert status["environment_count"] == len(env)
        assert ar.foreign_environment(status["environment_keys"]) == []
        assert status["uid"] == os.geteuid() and status["uid"] != 0
        # And it says its children share its user, which readiness fails.
        assert status["children"]["isolation"] == "shared_uid"
        result = ar.run_isolated(str(sock), "lab_static",
                                 {"mode": "selftest", "probe": {},
                                  "limits": {"memory_bytes": 1 << 30, "cpu_s": 10}},
                                 wall_s=20, stdout_cap=1 << 20)
        assert result.ok
        assert set(json.loads(result.output)["environment_keys"]) <= CHILD_KEYS
    finally:
        assert _stop(proc) == 0
    assert not sock.exists()


def test_the_worker_will_not_start_holding_a_secret(where):
    sock = where / "w.sock"
    proc = _start(_env(sock, NOCTORNAL_TOTP_KEK="kek-value-never-printed",
                       DATABASE_URL="postgresql://u:pw-never-printed@db/x"))
    out, err = proc.communicate(timeout=30)
    assert proc.returncode == 2
    said = (out + err).decode()
    assert "NOCTORNAL_TOTP_KEK" in said and "DATABASE_URL" in said
    assert "never-printed" not in said
    assert not sock.exists()


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="shows what an ordinary user is told")
def test_an_ordinary_user_is_refused_without_shared_uid(where):
    """The worker this file starts with --shared-uid is development's: as
    compose.yml runs it, it must be root with three capabilities, so each
    child is a user of its own, and it says so by name."""
    sock = where / "w.sock"
    proc = _start(_env(sock), argv=[sys.executable, "-m",
                                    "noctornal_api.analysis_worker"])
    _out, err = proc.communicate(timeout=30)
    assert proc.returncode == 2
    said = err.decode()
    assert "must start as root" in said and "--shared-uid" in said
    assert not sock.exists()


def test_the_healthcheck_fails_with_no_worker(where):
    env = _env(where / "w.sock")
    assert subprocess.run([sys.executable, "-m", "noctornal_api.analysis_worker",
                           "--check"], env=env, capture_output=True,
                          timeout=30).returncode == 1


def test_a_stale_socket_is_replaced_and_anything_else_is_refused(where):
    sock = where / "w.sock"
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(sock))
    stale.close()
    proc = _start(_env(sock))
    try:
        # The stale name is there from the start, so ask until the worker
        # that replaced it answers.
        end = time.monotonic() + 15
        while True:
            try:
                assert ar.hello(str(sock))
                break
            except ar.WorkerUnavailable:
                if time.monotonic() > end or proc.poll() is not None:
                    raise
                time.sleep(0.1)
    finally:
        _stop(proc)
    planted = where / "planted"
    planted.write_bytes(b"not a socket")
    proc = _start(_env(planted))
    _out, err = proc.communicate(timeout=30)
    assert proc.returncode == 2 and b"could not listen" in err
    assert planted.read_bytes() == b"not a socket"


def test_the_client_refuses_a_name_that_is_not_the_socket(where):
    sock = where / "w.sock"
    proc = _start(_env(sock))
    try:
        _wait_for(sock, proc)
        link = where / "link.sock"
        link.symlink_to(sock)
        result = ar.run_isolated(str(link), "lab_static", {"mode": "selftest"},
                                 wall_s=5, stdout_cap=1 << 20)
        assert result.failure == "worker_unavailable"
        plain = where / "plain"
        plain.write_bytes(b"")
        with pytest.raises(ar.WorkerUnavailable):
            ar.hello(str(plain))
        assert ar.hello(str(sock))
    finally:
        _stop(proc)


_LAUNCHER = """
import os, sys
from noctornal_api import analysis_worker
analysis_worker.KIND_ARGV["lab_static"] = [sys.executable, "-c", (
    "import os, sys, time\\n"
    "sys.stdin.buffer.readline()\\n"
    "parent = os.getppid()\\n"
    "while os.getppid() == parent:\\n"
    "    time.sleep(0.1)\\n")]
raise SystemExit(analysis_worker.main(["--shared-uid"]))
"""


def test_a_worker_killed_mid_request_is_unavailable_to_its_caller_at_once(where):
    sock = where / "w.sock"
    launcher = where / "launch.py"
    launcher.write_text(_LAUNCHER, encoding="utf-8")
    proc = _start(_env(sock), argv=[sys.executable, str(launcher)])
    got = {}
    try:
        _wait_for(sock, proc)

        def ask():
            got["result"] = ar.run_isolated(str(sock), "lab_static", {"mode": "pe"},
                                            (b"MZ" * 1000,), wall_s=120,
                                            stdout_cap=1 << 20)
            got["at"] = time.monotonic()

        t = threading.Thread(target=ask)
        t.start()
        time.sleep(1.5)
        killed = time.monotonic()
        os.kill(proc.pid, signal.SIGKILL)
        t.join(30)
    finally:
        proc.wait(10)
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()
    assert got["result"].failure == "worker_unavailable"
    assert got["at"] - killed < 5
