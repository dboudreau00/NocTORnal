"""Drain the notification outbox once. This is the cron entry.

N3 (2026-09-02). There is no worker process in this build -- decision 30
set that precedent and `transports.dispatch_due` is written as a function
you CALL. Until now the only thing that called it outside a test was
POST /notifications/dispatch, gated on `integration.manage`, which is a
STEP-UP permission: it wants a human who re-entered their second factor
in the last fifteen minutes. A cron entry cannot do that, so in practice
nothing drained the outbox unless an administrator remembered to press
the button, and an email queued at 17:05 went out when somebody pressed
it the next morning. Priority 1 "overrides quiet hours" only if something
sends it.

This script is the honest worker for this release: one process, one
connection, one drain, an exit code. One drain does three things (see
`dispatch_due`): the outbox, the review-due sweep, and the escalation of
unacknowledged priority-1 notifications.

    python scripts/notify_drain.py

Cron, every five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/notify_drain.py >> /var/log/noctornal/notify_drain.log 2>&1

Windows Task Scheduler: the same command, from the same directory, with
the venv's python.exe. `.env.local` at the project root is loaded exactly
as every other script here loads it (`_env.load_env_local`), so the entry
needs no environment of its own; an exported DATABASE_URL still wins.

Prints the counters on one line, `sent=3 failed=0 ...`, and exits 1 when
any delivery FAILED in this pass. The exit code is the one channel a cron
job has back to its operator, and a drain that failed a delivery and
exited 0 would be a failure reported as nothing at all. A non-zero exit
does NOT mean the drain stopped: every due delivery was attempted, the
failed ones are in the ledger with their reason (GET
/notifications/deliveries?refused_only=true), and the retryable ones will
be tried again next run.

Exits 2, before any connection, when under NOCTORNAL_ENV=production a
credential carries a value this repository publishes, the schema owner's
password or DSN is in the environment (docs/17 F52 and infra-12, 2026-10-02
and 2026-10-03), or the persona key only the collector may hold is (A
collector process, 2026-10-02): the refusal is one line per variable on stderr, `notify_drain:
refusing to run: <NAME> ...`, naming it and never its value. It is the one
helper every job calls first (`config.refuse_unsafe_job_environment`) and the
one code every job gives it (`config.JOB_REFUSAL_EXIT`), 2 and not 1 because 1
already means a delivery failed in a pass that ran.
"""
from __future__ import annotations

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
    """Every script connects as the system role (S1, 2026-09-25). A
    script serves no request and binds no user, so on the request role it
    would see nothing under row-level security; `db.connect_system` refuses
    rather than hand it a connection that silently sees part of the data.
    Named `connect` so the tests that replace it still find it."""
    return connect_system(SystemPurpose.NOTIFY)


def main() -> int:
    # First, before anything is connected to (docs/17 F52 and infra-12,
    # 2026-10-02 and 2026-10-03): under NOCTORNAL_ENV=production a published
    # credential, the schema owner's or a persona key (the cron loop holds
    # none: A collector process, 2026-10-02) refuses the pass, the same
    # refusals every job makes through the one helper (config.py). Exit 2,
    # not 1: 1 already means a delivery failed in a pass that ran.
    refusals = refuse_unsafe_job_environment("notify_drain")
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    conn = connect()
    try:
        # S2, the egress proxy (2026-09-24). A production cron with
        # outbound uses and no egress proxy stops here, as the API does.
        from noctornal_api.egress_routes import enforce_production_egress
        enforce_production_egress(conn)
        counters = dispatch_due(conn)
    finally:
        conn.close()
    print(" ".join(f"{key}={value}" for key, value in counters.items()))
    return 1 if counters.get("failed", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
