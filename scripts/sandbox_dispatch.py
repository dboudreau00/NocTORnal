"""Send the queued detonations to the configured sandbox, once (F14,
2026-09-24).

    python scripts/sandbox_dispatch.py

One pass (`sandbox.dispatch_due`): the requests whose sign-off lapsed, whose
authoriser can no longer give it, whose sample was withdrawn or whose case
closed are ended; a preflight proves the egress route names the sandbox and
that the sandbox takes the token and refuses every read made without it
(its API and its web interface); then up to five queued requests are sent,
paced to CAPE's own limit, each re-checked in the transaction that records
the send, and the tasks already sent are polled and their reports recorded
as machine SANDBOX analyses. Nothing is ever resent.

The worker holds the sample store's credentials, the key ring and the
sandbox token, and for one sample at a time its plaintext, ciphertext and
archive in memory, so config.enforce_environment runs before anything else.

Run it in a loop of its own, never the notification loop: the production
compose file runs it in the lab-cron service beside
scripts/sample_screen.py. A pass keeps to NOCTORNAL_SANDBOX_PASS_BUDGET_S
(240 seconds by default), except that its first send may take that send's
own deadline, so a large sample is never starved.

Cron, every five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/sandbox_dispatch.py >> /var/log/noctornal/sandbox_dispatch.log 2>&1

Prints the counters on one line. Exits 0 when no sandbox is configured (the
deployment's state, not a failure), and 1 when a setting is unusable, when
the preflight refused (nothing was sent), or when a send failed, was not
sent or lost its answer.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()


def main(argv: list[str] | None = None) -> int:
    from noctornal_api.config import enforce_environment
    enforce_environment()
    from noctornal_api import sandbox
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.samples import SampleService, SampleStorage

    settings, problem = sandbox.sandbox_settings()
    if settings is None:
        print(f"refused: {problem}" if problem else "no sandbox is configured")
        return 1 if problem else 0
    conn = connect_system(SystemPurpose.SANDBOX)
    try:
        counters = sandbox.dispatch_due(
            conn, samples=SampleService(conn, SampleStorage()),
            settings=settings)
    finally:
        conn.close()
    print(sandbox.counters_line(counters))
    if "skipped" in counters:
        return 0
    bad = (counters.get("preflight") or counters.get("failed")
           or counters.get("not_sent") or counters.get("unconfirmed")
           or counters.get("rejected_by_target"))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
