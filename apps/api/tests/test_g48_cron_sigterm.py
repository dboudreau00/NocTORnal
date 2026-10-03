"""The cron loops stop on SIGTERM and finish the pass in progress (infra-11,
2026-10-03).

The four loop services in infra/production/compose.yml (cron, lab-triage,
lab-cron, embed-pass) were `sh -c 'while true; ...'` as PID 1, which has no
handler for SIGTERM, so `docker stop` waited ten seconds and killed the whole
tree mid-pass: between a persona poll's request and its record, a sandbox send
and its row, an email and its ledger entry. The scripts below are the real
ones from the compose file, as the container receives them (`$$` turned into
`$`), with the CA bundle line dropped, the jobs replaced by a stub on PATH and
the naps shortened. The signal goes to the shell alone, as `docker stop`
sends it to PID 1, and the shell's stdout goes to a file, because an orphaned
`sleep` would otherwise hold a pipe open after the shell has gone.

POSIX only: Python on Windows cannot deliver SIGTERM to a child. CI runs on
Linux, where /bin/sh is dash, as in the production image.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from pathlib import Path

import pytest
from test_egress_topology import Reader

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "production" / "compose.yml"
LOOPS = ("cron", "lab-triage", "lab-cron", "embed-pass")

pytestmark = pytest.mark.skipif(os.name != "posix", reason="needs POSIX signals and /bin/sh")


def _loop_script(name: str, nap: str) -> str:
    doc = Reader(COMPOSE.read_text(encoding="utf-8")).document()
    script = doc["services"][name]["command"][-1].replace("$$", "$")
    assert script.lstrip().startswith("cat /etc/ssl/certs/ca-certificates.crt")
    lines = [ln for ln in script.splitlines() if not ln.lstrip().startswith("cat /etc/ssl/certs")]
    return re.sub(r"\bnap \d+\b", f"nap {nap}", "\n".join(lines)) + "\n"


def _start(tmp_path: Path, name: str, job_seconds: float, nap: str = "60"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "jobs.log"
    stub = bin_dir / "python"
    stub.write_text('#!/bin/sh\necho "job-start $1" >> "$LOG"\nsleep "$JOB_SECONDS"\n'
                    'echo "job-end $1" >> "$LOG"\n', encoding="utf-8")
    stub.chmod(0o755)
    script = tmp_path / "loop.sh"
    script.write_text(_loop_script(name, nap), encoding="utf-8")
    out = (tmp_path / "out.txt").open("w")
    proc = subprocess.Popen(
        ["/bin/sh", str(script)], stdout=out, stderr=subprocess.STDOUT, start_new_session=True,
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "LOG": str(log),
             "JOB_SECONDS": str(job_seconds)})
    return proc, log, tmp_path / "out.txt"


def _wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _jobs(log: Path) -> list[str]:
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _finish(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # the orphaned nap, if any
    except ProcessLookupError:
        pass
    proc.wait()


@pytest.mark.parametrize("name", LOOPS)
def test_a_stop_during_a_job_lets_it_finish_and_starts_nothing_else(tmp_path, name):
    proc, log, out = _start(tmp_path, name, job_seconds=1.5)
    try:
        assert _wait_for(lambda: any(j.startswith("job-start") for j in _jobs(log))), "no job ran"
        proc.send_signal(signal.SIGTERM)
        began = time.monotonic()
        assert _wait_for(lambda: proc.poll() is not None, 8.0), "the loop did not stop"
        assert proc.returncode == 0, "a clean stop, not 143 and not 137"
        # It waited for the job: that took the better part of its 1.5 seconds.
        assert time.monotonic() - began > 0.5
    finally:
        _finish(proc)
    jobs = _jobs(log)
    assert [j.split()[0] for j in jobs] == ["job-start", "job-end"], jobs
    assert "stopped on request" in out.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", LOOPS)
def test_a_stop_during_a_nap_ends_the_loop_at_once(tmp_path, name):
    """The naps are 150, 300 and 60 seconds in production. A plain `sleep`
    holds the shell for its whole length; the nap is a `wait`, which a trapped
    signal interrupts."""
    proc, log, out = _start(tmp_path, name, job_seconds=0.2)
    # How many jobs run before the loop's first nap: one, except lab-cron's two.
    before_nap = _loop_script(name, "60").split("nap 60")[0].count("python scripts/")
    try:
        assert _wait_for(lambda: out.read_text(encoding="utf-8").count("exit=0") >= before_nap), \
            "the jobs never ended"
        time.sleep(0.4)  # the loop is napping now
        proc.send_signal(signal.SIGTERM)
        assert _wait_for(lambda: proc.poll() is not None, 5.0), "a nap was not interrupted"
        assert proc.returncode == 0
    finally:
        _finish(proc)
    starts = [j for j in _jobs(log) if j.startswith("job-start")]
    assert len(starts) == before_nap, "a stop during the nap must not start the next job"
    assert "stopped on request" in out.read_text(encoding="utf-8")


def test_without_a_stop_the_cron_loop_runs_every_job_in_order(tmp_path):
    """The other direction: the traps change nothing while no signal comes.
    The naps are shortened so a round trip fits in a test."""
    proc, log, _out = _start(tmp_path, "cron", job_seconds=0.1, nap="0.2")
    try:
        assert _wait_for(lambda: len([j for j in _jobs(log) if j.startswith("job-end")]) >= 4, 15.0)
    finally:
        _finish(proc)
    ends = [j.split()[1] for j in _jobs(log) if j.startswith("job-end")]
    # The collection poll left this loop for the collector service
    # (A collector process, 2026-10-02): two jobs, round and round.
    assert ends[:4] == ["scripts/notify_drain.py", "scripts/lookup_drain.py",
                        "scripts/notify_drain.py", "scripts/lookup_drain.py"], ends
