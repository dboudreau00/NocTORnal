"""Send the queued outbound lookups once. This is the cron entry
(F15.4, 2026-09-24).

Unattended egress, so it re-checks every rule at send time and never sends
a lookup that is not NONE: a lookup that sends case material to a vendor
or the public is sent at its sign-off or not at all (docs/00 decision 75), and
the database refuses to queue one. Queued NONE lookups (an interactive one
that met a full window, or a batch) are paced by the provider's windows,
keeping a reserve for interactive work.

    python scripts/lookup_drain.py [--limit N] [--max-seconds S] [--dry-run]

It runs in the cron loop with no sleep of its own, so every job in the loop
keeps its five-minute cadence (infra/production/compose.yml). The
collection poll it followed moved to the collector service on 2026-10-02.
The cadence is a resolution, not a rate: pacing comes from the provider
windows.

Prints, first, the host switch as read (NOCTORNAL_OUTBOUND_LOOKUPS=...), so
an api and a cron that disagree are visible in the cron log; then the
housekeeping counts; then one line per provider. Housekeeping (lapsed
sign-offs, abandoned sends, lapsed exposure changes) runs whatever the
switch says: it sends nothing.

Exit codes: 0 when nothing failed; 1 when a lookup FAILED in this pass or a
provider had no route out (information, like notify_drain.py: every other
row was still attempted); 2 when, under NOCTORNAL_ENV=production, a
credential in the environment carries a published value, the schema
owner's password or DSN is in it (docs/17 F52 and infra-12, 2026-10-02 and
2026-10-03), or the persona key only the collector may hold is (A collector
process, 2026-10-02), before any connection and with one line per variable on stderr,
`lookup_drain: refusing to run: <NAME> ...`, naming it and never its value.
It is the one helper every job calls first
(`config.refuse_unsafe_job_environment`) and the one code every job gives it
(`config.JOB_REFUSAL_EXIT`).
"""
from __future__ import annotations

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()

SWITCH_ENV = "NOCTORNAL_OUTBOUND_LOOKUPS"


def main(argv: list[str] | None = None, *, conn=None, service=None) -> int:
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment

    # First, before the switch is echoed or anything is connected to (docs/17
    # F52 and infra-12, 2026-10-02 and 2026-10-03): the published-value check
    # this script once made on its own, the schema owner's credential beside
    # it, and the persona key (the cron loop holds none: A collector process,
    # 2026-10-02), through the one helper every job calls (config.py).
    refusals = refuse_unsafe_job_environment("lookup_drain")
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    parser = argparse.ArgumentParser(description="Send the queued outbound lookups once.")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--max-seconds", type=float, default=240.0)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    from noctornal_api import lookups, providers
    from noctornal_api.db import SystemPurpose, connect_system

    print(f"{SWITCH_ENV}={os.environ.get(SWITCH_ENV, '')}")
    own = conn is None
    conn = conn or connect_system(SystemPurpose.LOOKUPS)
    try:
        if args.dry_run:
            housekept = {"expired": 0, "abandoned": 0, "changes_expired": 0}
        else:
            housekept = lookups.housekeeping(conn)
        print("housekeeping " + " ".join(f"{k}={v}" for k, v in housekept.items()))
        switch, _raw = providers.outbound_switch()
        if switch != "on":
            print("outbound lookups are off on this host")
            return 0
        report = lookups.drain(conn, limit=args.limit, max_seconds=args.max_seconds,
                               dry_run=args.dry_run, service=service)
    finally:
        if own:
            conn.close()
    for key, counts in report["providers"].items():
        print(f"{key} " + " ".join(f"{k}={v}" for k, v in counts.items()))
    for line in report["no_route"]:
        print(f"no route out: {line}")
    return 1 if report["failed"] or report["no_route"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
