"""Prohibited-content screening, from the host (F13, 2026-09-24).

    python scripts/sample_screen.py                  one pass (the cron entry)
    python scripts/sample_screen.py status           the screening state
    python scripts/sample_screen.py import --file PATH --name NAME \\
        --provider PROVIDER --authority LICENCE-REF --category CATEGORY \\
        --as officer@example.org                     a list too large for HTTP

A pass screens every held sample not yet screened against the newest
active list, isolates each match, deletes the entries of lists retired with
their purge asked for, and moves every matched sample's bytes into the
preservation store under a legal hold (`ScreeningService.rescan` with
`move_bytes=True`, 240 seconds of work at most). The list import and the
console's "Start a screening pass" do the database half in the request; the
byte moves are object-store work and belong here.

Run it in a loop of its own, not the notification loop: the production
compose file runs it in the lab-cron service beside
scripts/sandbox_dispatch.py, so a long pass never holds back email
delivery or the escalation of urgent alerts.

Cron, every five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/sample_screen.py >> /var/log/noctornal/sample_screen.log 2>&1

Prints the counters on one line and exits 1 while matched samples still
wait for their bytes to move or samples are behind the newest list (the
readiness row fails on the same facts).

## The import's authority is the host operator

`import` is for a list larger than the console's upload cap. On this path
there is no session, no step-up and no browser: whoever runs the command on
the server is the authority, and the account named with `--as` is
attribution that operator asserts. It must exist, be active and hold
sample.screening.manage, so the record names somebody who could have made
the import in the console; the audit row says the path was the command
line, that step-up does not apply, and which host user ran it. Both recorded
authorities (the ingest policy and NOCTORNAL_HASH_SET_AUTHORITY) are
required exactly as over HTTP. Exit 2 on any refusal.
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

from noctornal_api.screening import PASS_BUDGET_S as PASS_BUDGET_SECONDS  # noqa: E402


def _host_user() -> str | None:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - a user name is a courtesy here
        return None


def asserted_account(conn, email: str):
    """The account the host operator names as the importer, or None.

    NOT an authorisation: IamAdminService.holds_global_permission must not
    authorise a write, and this does not. The authority on this path is the
    operator at the host; this only checks that the name they assert is an
    active account holding sample.screening.manage, so the record names
    somebody who could have made the import in the console."""
    from noctornal_api.screening import MANAGE_PERMISSION
    row = conn.execute(
        """SELECT u.id FROM iam.app_user u
            WHERE lower(u.email) = lower(%s) AND u.is_active
              AND EXISTS (SELECT 1 FROM iam.user_role ur
                            JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                           WHERE ur.user_id = u.id
                             AND rp.permission_key = %s)""",
        (email, MANAGE_PERMISSION)).fetchone()
    return row[0] if row else None


def _stores():
    """The two object stores, each built lazily: a store that cannot be
    opened leaves the byte moves for a later pass and says so, and never
    stops the screening itself."""
    from noctornal_api.samples import PreservationStorage, SampleStorage
    notes = []
    built = []
    for what, make in (("sample store", SampleStorage),
                       ("preservation store", PreservationStorage)):
        try:
            built.append(make())
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            built.append(None)
            notes.append(f"{what}: {type(exc).__name__}")
    return built[0], built[1], notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Screen held samples against the prohibited-content lists.")
    parser.add_argument("command", nargs="?", default="rescan",
                        choices=("rescan", "import", "status"))
    parser.add_argument("--file")
    parser.add_argument("--name")
    parser.add_argument("--provider")
    parser.add_argument("--authority")
    parser.add_argument("--category")
    parser.add_argument("--as", dest="as_email")
    args = parser.parse_args(argv)

    from noctornal_api.config import enforce_environment
    enforce_environment()
    from noctornal_api import screening
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.samples import SampleService

    conn = connect_system(SystemPurpose.SCREENING)
    try:
        if args.command == "status":
            now = screening.state(conn)
            print(f"lists={len(now.active_lists)} "
                  f"authority={'declared' if now.authority else 'not declared'} "
                  f"behind={now.behind} pending={now.pending_preservation} "
                  f"bytes_not_found={now.bytes_not_found} "
                  f"unreviewed={now.unreviewed_matches} "
                  f"purges_pending={now.purges_pending}")
            return 0
        if args.command == "import":
            missing = [flag for flag, value in (
                ("--file", args.file), ("--name", args.name),
                ("--provider", args.provider), ("--authority", args.authority),
                ("--category", args.category), ("--as", args.as_email))
                if not value]
            if missing:
                print(f"refused: {', '.join(missing)} not given")
                return 2
            actor = asserted_account(conn, args.as_email)
            if actor is None:
                print("refused: the account named with --as is not an active "
                      "account holding sample.screening.manage")
                return 2
            with open(args.file, "rb") as stream:
                try:
                    out = screening.ScreeningService(conn).import_list(
                        stream, name=args.name, provider=args.provider,
                        authority_reference=args.authority,
                        category=args.category, actor_id=actor, via="cli",
                        host_user=_host_user(),
                        rescan_budget=PASS_BUDGET_SECONDS)
                except screening.ScreeningError as exc:
                    print(f"refused: {exc}")
                    return 2
            print(f"imported entries={out['entry_count']} "
                  f"algorithms={','.join(out['algorithms'])} "
                  f"matched={out['rescan'].get('matched', 0)}")
            return 0
        storage, preservation, notes = _stores()
        svc = screening.ScreeningService(conn, SampleService(conn, storage,
                                                             preservation))
        counters = svc.rescan(trigger="RESCAN", actor_id=None, move_bytes=True,
                              budget_seconds=PASS_BUDGET_SECONDS)
    finally:
        conn.close()
    line = " ".join(f"{key}={value}" for key, value in counters.items())
    if notes:
        line += " stores_unavailable=" + ";".join(n.replace(" ", "_") for n in notes)
    print(line)
    if "skipped" in counters:
        return 0
    return 1 if counters.get("pending", 0) or counters.get("behind", 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
