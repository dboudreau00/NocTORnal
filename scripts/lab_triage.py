"""Drain the static-triage queue once. This is the Lab's cron entry (F11
and F12, 2026-09-24).

There is no worker process in this build (decision 30), and static
triage parses hostile bytes, which cannot happen inside an upload
request. `lab_triage.run_due` is written as a function you CALL, and this
is the honest caller: one process, one connection, one pass, an exit
code. One pass sweeps runs and compile jobs whose process stopped,
compiles the queued YARA rule set versions for THIS host, then runs up to
20 queued runs, starting none after 90 seconds.

    python scripts/lab_triage.py              one pass (the cron entry)
    python scripts/lab_triage.py --backfill   queue every held sample never triaged
    python scripts/lab_triage.py status       how many runs wait, and since when

Run it in a loop of its own, not inside the loop that drains
notifications: a pass finishes the run it started, and one run can take
each of its child processes' full time limit, so sharing that loop would
hold the notification drain back. The production compose file gives it
a service of its own (the lab-triage service). `--budget SECONDS` makes a
pass start a compile or a run only when its worst case still fits, for a
deployment that must share a loop anyway.

Cron, every five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/lab_triage.py >> /var/log/noctornal/lab_triage.log 2>&1

Windows Task Scheduler: the same command, from the same directory, with
the venv's python.exe. `.env.local` at the project root is loaded as every
other script here loads it; an exported DATABASE_URL still wins.

Prints the counters on one line (queued, done, failed, skipped,
abandoned, left, compiled, compile_failed) and exits 1 when a run FAILED
or a compile failed for good in this pass. While no prohibited-content
policy is declared it says so and exits 0 having touched nothing (docs/16
L1): that is the deployment's state, not this pass's failure. When the
isolated analysis worker does not answer, or a production deployment
configures none, it says so and exits 1 having touched nothing (docs/17
F42): that is a fault, and the queue waits for it. When the worker fails
during the pass, the pass stops, prints `interrupted=1` and exits 1; the
run or compile it was on goes back to the queue with no attempt spent. Under
NOCTORNAL_ENV=production an environment this job will not run on exits 2
(`config.JOB_REFUSAL_EXIT`, the code every job gives that refusal, so an alert
can tell a job that would not start from a pass that failed), one line per
problem on stderr led by `lab_triage: refusing to run:`, naming variables and
never a value.

`--backfill` decrypts every held sample in the passes that follow. That is
the operator's decision, never a migration's, and it is recorded as
theirs: an audit row naming the command and this host's user.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()


def _host_user() -> str | None:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - a user name is a courtesy here
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Drain the static-triage queue once.")
    parser.add_argument("command", nargs="?", default="run",
                        choices=("run", "status"))
    parser.add_argument("--backfill", action="store_true",
                        help="queue every held sample that was never triaged")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--max-seconds", type=float, default=90)
    parser.add_argument("--budget", type=float, default=None,
                        help="start a compile or run only if its worst case fits")
    args = parser.parse_args(argv)

    # First, before anything is connected to: the API's whole production list,
    # through the one helper every job calls (config.py). It was
    # `enforce_environment()`, whose RuntimeError made a refusal exit 1 with a
    # traceback; 2 is what every other job gives, and 1 here means a pass ran
    # and failed (2026-10-07).
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment
    # outbound=False: this loop sends nothing out and compose gives it no
    # egress proxy, so lookups or a sandbox switched on in secrets.env, which
    # it reads, are not its refusal (2026-10-07).
    refusals = refuse_unsafe_job_environment("lab_triage", whole_environment=True,
                                             outbound=False)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    from noctornal_api import lab_triage
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.samples import policy_declared

    declared, detail = policy_declared()
    if not declared:
        print(f"refused: {detail}")
        return 0
    settings, problem = lab_triage.analysis_settings()
    if problem:
        print(f"refused: {problem}")
        return 1
    if args.command == "run" and not args.backfill:
        # F42 (2026-10-02): no isolated worker answering, or production
        # with none configured, is a fault an operator must see, so exit 1
        # before a connection is opened; the queue is left as it was.
        from noctornal_api import analysis_runner
        refusal = analysis_runner.unavailable()
        if refusal:
            print(f"refused: {refusal}")
            return 1
    conn = connect_system(SystemPurpose.LAB_TRIAGE)
    try:
        if args.backfill:
            n = lab_triage.backfill(conn, host_user=_host_user(),
                                    settings=settings)
            print(f"queued={n}")
            return 0
        if args.command == "status":
            depth, oldest = conn.execute(
                """SELECT count(*), min(queued_at) FROM lab.static_run
                    WHERE status = 'QUEUED'""").fetchone()
            print(f"queued={depth} oldest="
                  f"{oldest.isoformat() if oldest else 'none'}")
            return 0
        from noctornal_api.samples import SampleStorage
        counters = lab_triage.run_due(
            conn, SampleStorage(), settings=settings, limit=args.limit,
            max_seconds=args.max_seconds, budget_s=args.budget)
    finally:
        conn.close()
    print(" ".join(f"{key}={value}" for key, value in counters.items()))
    # interrupted (F42 review, 2026-10-02): the worker failed mid-pass, a
    # fault an operator must see, as the refusal before a pass is.
    return 1 if (counters.get("failed", 0) or counters.get("compile_failed", 0)
                 or counters.get("interrupted", 0)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
