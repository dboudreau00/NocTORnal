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
from noctornal_api.db import connect  # noqa: E402
from noctornal_api.transports import dispatch_due  # noqa: E402

load_env_local()


def main() -> int:
    conn = connect()
    try:
        counters = dispatch_due(conn)
    finally:
        conn.close()
    print(" ".join(f"{key}={value}" for key, value in counters.items()))
    return 1 if counters.get("failed", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
