"""Drain the static-triage queue once: the Lab's cron entry.

Static triage parses hostile bytes, which cannot happen inside an upload request, and there is no
job worker (decision 30), so this script is the caller of `lab_triage.run_due`. A pass sweeps runs
and compile jobs whose process stopped, compiles the queued YARA rule set versions for this host,
then runs up to 20 queued runs, starting none after 90 seconds.

    python scripts/lab_triage.py              one pass (the cron entry)
    python scripts/lab_triage.py --backfill   queue every held sample never triaged
    python scripts/lab_triage.py status       how many runs wait, and since when

Give it a loop of its own (the lab-triage compose service): one run can take each of its child
processes' full time limit and would hold the notification drain back. `--budget SECONDS` starts a
compile or run only when its worst case still fits, for a loop that must be shared. Cron, every
five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/lab_triage.py >> /var/log/noctornal/lab_triage.log 2>&1

Prints the counters on one line. Exits 1 when a run or compile failed for good, when no
prohibited-content policy is declared (docs/16 L1), or when the isolated analysis worker does not
answer or production configures none; those last two touch nothing. A worker that fails mid-pass
stops it with `interrupted=1` and exit 1, and its run or compile goes back to the queue with no
attempt spent. Exits 2 (`config.JOB_REFUSAL_EXIT`) when the production environment is refused.
`--backfill` decrypts every held sample in the passes that follow: the operator's decision, never
a migration's, recorded as an audit row naming the command and this host's user.
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

    # First, before anything is connected to: the API's whole production list, through the helper
    # every job calls. A refusal exits 2, because 1 means a pass ran and failed.
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment
    # outbound=False: this loop sends nothing out and compose gives it no egress proxy, so lookups
    # or a sandbox switched on in secrets.env, which it reads, are not its refusal.
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
        # Exit 1, as for an unusable setting or a silent worker: an undrained queue is not a pass
        # that succeeded, and an alert on the exit code must be able to tell the two apart.
        print(f"refused: {detail}")
        return 1
    settings, problem = lab_triage.analysis_settings()
    if problem:
        print(f"refused: {problem}")
        return 1
    if args.command == "run" and not args.backfill:
        # No isolated worker answering, or production with none configured, is a fault an operator
        # must see: exit 1 before a connection is opened, leaving the queue as it was.
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
    # interrupted: the worker failed mid-pass, a fault an operator must see, like a refusal.
    return 1 if (counters.get("failed", 0) or counters.get("compile_failed", 0)
                 or counters.get("interrupted", 0)) else 0


if __name__ == "__main__":
    raise SystemExit(main())
