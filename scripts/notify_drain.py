"""Drain the notification outbox once: the cron entry.

There is no job worker (decision 30), and the API's POST /notifications/dispatch needs a step-up
that a cron entry cannot give, so this script is the caller of `transports.dispatch_due`. One drain
does three things: the outbox, the review-due sweep, and the escalation of unacknowledged
priority-1 notifications.

    python scripts/notify_drain.py

Cron, every five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/notify_drain.py >> /var/log/noctornal/notify_drain.log 2>&1

Prints the counters on one line, `sent=3 failed=0 ...`, and exits 1 when any delivery failed in
this pass: the exit code is a cron job's one channel back to its operator. A non-zero exit does not
mean the drain stopped: every due delivery was attempted, the failed ones are in the ledger with
their reason (GET /notifications/deliveries?refused_only=true), and the retryable ones are tried
again next run. Exits 2 (`config.JOB_REFUSAL_EXIT`), before any connection, when
`config.refuse_unsafe_job_environment` refuses the production environment.
"""
from __future__ import annotations

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
# `_env` is a sibling. Python adds the script's directory itself when the
# script is RUN; it does not when the module is loaded by path (the test
# does that), so the sibling directory is added explicitly.
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment  # noqa: E402
from noctornal_api.db import SystemPurpose, connect_system  # noqa: E402
from noctornal_api.transports import dispatch_due  # noqa: E402

load_env_local()


def connect():
    """Connect as the system role: a script binds no user, so under row-level security the request
    role would see nothing. Named `connect` because the tests replace it by that name."""
    return connect_system(SystemPurpose.NOTIFY)


def main(argv: list[str] | None = None) -> int:
    # It takes no options, and says so: without a parser `--help` would run a drain and send the
    # outbox.
    argparse.ArgumentParser(
        description="Drain the notification outbox once: the outbox, the "
                    "review-due sweep and the escalation of unacknowledged "
                    "priority-1 notifications.").parse_args(argv or [])
    # First, before anything is connected to: under NOCTORNAL_ENV=production a published
    # credential, the schema owner's or a persona key (the cron loop holds none) refuses the pass.
    # Exit 2, not 1: 1 already means a delivery failed in a pass that ran.
    refusals = refuse_unsafe_job_environment("notify_drain")
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    conn = connect()
    try:
        # A production cron with outbound uses and no egress proxy stops here, as the API does.
        from noctornal_api.egress_routes import enforce_production_egress
        enforce_production_egress(conn)
        counters = dispatch_due(conn)
    finally:
        conn.close()
    print(" ".join(f"{key}={value}" for key, value in counters.items()))
    return 1 if counters.get("failed", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
