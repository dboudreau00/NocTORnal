"""Sweep what no case governs and is past its retention clock, once. An operator runs this;
nothing schedules it.

Collected documents (a Telegram group's messages, a forum's posts), dead letters and ingest
records attached to no case have retention clocks but no case-scoped route that can reach them.
This calls the purge every other family uses (`RetentionService.purge_due`, with its legal hold
checks on the document and on every case that cites it, its locks, its markup deletion and its
tombstone) for those three families only. A record attached to a case is that case's, with its
clock and its hold.

    python scripts/retention_sweep.py                      # a dry run, the default
    python scripts/retention_sweep.py --apply --actor you@example.org

A dry run changes and writes nothing and needs no declaration: it counts what is past its clock,
what a hold keeps and what a sweep would destroy. A real run needs `--apply` and a declared
authority in NOCTORNAL_RETENTION_SWEEP_AUTHORITY, a reference an auditor can follow to the
schedule, instruction or ticket the destruction rests on; the software records it and cannot
verify it (docs/16 L1), and refuses a missing one, a placeholder or an answer that is not a
reference. A real run also names the account that answers for it (`--actor` or
NOCTORNAL_RETENTION_SWEEP_ACTOR): an active holder of retention.purge, recorded on every tombstone.

It is not part of the production cron loop and must not be added to one by default: who runs it,
how often and under which authority is the owner's decision (docs/16 L4; scheduling is in
infra/production/README.md, Retention sweep). Prints the counters on one line, then any warnings.
A real run writes one RETENTION_SWEEP audit event of counts, and clears a backlog bigger than one
pass in the same run, up to --max-passes.

Exit 0 when the run did what it was asked; 1 when a real run left something it could have
destroyed (a store refused a document's markup, or the pass limit was reached), so read the
warnings and run it again; 2 when it refused to run: a missing or placeholder authority, no named
account, no store for collected markup, or under NOCTORNAL_ENV=production, dry run included, an
environment every job refuses (`config.refuse_unsafe_job_environment`). Nothing is destroyed on a
2 before any pass began; what a pass destroyed before a refusal stays destroyed and is on its
tombstone.
"""
from __future__ import annotations

import argparse
import getpass
import os
import platform
import socket
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()

VIA = "scripts/retention_sweep.py"

#: Stands for "build the store from the environment", so a test can hand in
#: a store, or None for "none configured", and the real run builds its own.
_FROM_ENVIRONMENT = object()


def _where() -> dict:
    """Where the run happened, for the audit row: the script, the host and
    the operating-system account. Never a credential."""
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - the name is a courtesy
        os_user = None
    return {"via": VIA, "host": socket.gethostname() or platform.node(),
            "os_user": os_user}


def _refuse(message: str) -> int:
    print(f"refused: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None, *, conn=None,
         document_raw=_FROM_ENVIRONMENT) -> int:
    parser = argparse.ArgumentParser(
        description="Sweep collected documents, dead letters and ingest "
                    "records attached to no case that are past their "
                    "retention clock. A dry run unless --apply is given.")
    parser.add_argument("--apply", action="store_true",
                        help="destroy what is past its clock and not held; "
                             "needs a declared authority and a named account")
    parser.add_argument("--actor", default=None,
                        help="email of the active account that holds "
                             "retention.purge and answers for this run")
    parser.add_argument("--max-passes", type=int, default=None,
                        help="the most passes of 500 of each kind one run makes")
    args = parser.parse_args(argv)

    from noctornal_api import retention_sweep as rs
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment
    from noctornal_api.db import SystemPurpose, connect_system

    max_passes = args.max_passes if args.max_passes is not None else rs.DEFAULT_MAX_PASSES
    if max_passes < 1:
        parser.error("--max-passes must be at least 1")

    # The refusal every job makes first, before anything is connected to, dry run included: a
    # published credential, the schema owner's, or the persona key only the collector holds.
    refusals = refuse_unsafe_job_environment("retention_sweep")
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT

    authority = None
    if args.apply:
        try:
            authority = rs.declared_authority()
        except rs.SweepRefused as exc:
            return _refuse(str(exc))

    own = conn is None
    # The system role: on the request role, row-level security would show a sweep only some
    # documents and it would report success.
    conn = conn or connect_system(SystemPurpose.RETENTION)
    try:
        actor_id = None
        if args.apply:
            try:
                actor_id = rs.resolve_actor(
                    conn, args.actor or os.environ.get(rs.ACTOR_ENV))
            except rs.SweepRefused as exc:
                return _refuse(str(exc))
        if document_raw is _FROM_ENVIRONMENT:
            from noctornal_api.rawstore import default_document_raw_store
            document_raw = default_document_raw_store()
        try:
            report = rs.sweep(
                conn, apply=args.apply, actor_id=actor_id, authority=authority,
                document_raw=document_raw, max_passes=max_passes,
                where=_where())
        except rs.SweepRefused as exc:
            return _refuse(str(exc))
    finally:
        if own:
            conn.close()

    print(report.counters())
    for line in report.warnings:
        print(f"warning: {line}")
    if report.stopped:
        print(f"stopped: {report.stopped}")
    if not args.apply:
        if report.sweepable_total:
            print("dry run: nothing was changed. Run with --apply under a "
                  "declared authority to destroy what is past its clock.")
        return 0
    if report.refused:
        return 2
    return 1 if report.remaining else 0


if __name__ == "__main__":
    raise SystemExit(main())
