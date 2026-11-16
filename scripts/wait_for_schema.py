"""Wait until the database answers and its schema is at the head of db/migrations, then exit.

    python scripts/wait_for_schema.py                  # ask once
    python scripts/wait_for_schema.py --wait 120       # keep asking, for up to two minutes

The question `GET /readyz` asks (noctornal_api.readyz), for a process that serves no HTTP: an init
container that holds a pod back until the migration Job has finished, in front of the collector, the
cron loop and the Lab's workers. Compose gets the same thing from `depends_on` the migrate service
completing; a pod has no such thing.

It connects with `DATABASE_URL`, the application role's, and never the schema owner's: a process that
holds the owner's DSN or password is refused like every job (`config.refuse_unsafe_job_environment`),
before anything is read or connected to. It prints one line, naming a class of failure
(`schema_not_at_head`, `database_unreachable`, `schema_absent`, `database_url_unusable`,
`migrations_unreadable`) and never a revision, a host or a credential.

Exit 0 when the schema is at head, 1 when `--wait` ran out first, 2 (`config.JOB_REFUSAL_EXIT`) when the
environment is refused.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api import readyz  # noqa: E402
from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment  # noqa: E402

load_env_local()

#: Seconds between two questions while waiting. A module attribute so a test can shrink it.
INTERVAL_S = 2.0
#: The longest a caller may ask it to wait. A pod that needs longer is stuck, and says so by restarting.
MAX_WAIT_S = 3600.0


def main(argv: list[str] | None = None) -> int:
    # Sends nothing out: in a pod it is not asked to name the cluster's networks, which only a process that
    # routes a connection needs (egress_policy.cluster_problem).
    refusals = refuse_unsafe_job_environment("wait_for_schema", outbound=False)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    parser = argparse.ArgumentParser(
        description="Wait until the schema is at the head of db/migrations.")
    parser.add_argument("--wait", type=float, default=0.0, metavar="SECONDS",
                        help="keep asking for up to this long (default: ask once)")
    args = parser.parse_args(argv)
    if not 0 <= args.wait <= MAX_WAIT_S:
        parser.error(f"--wait is from 0 to {MAX_WAIT_S:g} seconds")
    deadline = time.monotonic() + args.wait
    while True:
        reason = readyz.schema_problem()
        if reason is None:
            print("wait_for_schema: the schema is at head")
            return 0
        left = deadline - time.monotonic()
        if left <= 0:
            print(f"wait_for_schema: not ready after {args.wait:g} seconds ({reason})",
                  file=sys.stderr)
            return 1
        time.sleep(min(INTERVAL_S, left))


if __name__ == "__main__":
    raise SystemExit(main())
