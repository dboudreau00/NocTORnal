"""Sweep the collected documents that are past their retention clock, once
(F30, 2026-10-02). An operator runs this; nothing schedules it for you.

A Telegram group's messages and a forum's posts are collected documents
with a retention clock, and no case-scoped route can reach them, so until
this script nothing destroyed them when the clock ran out. It calls the same
purge every other family uses (`RetentionService.purge_due`, with its legal
hold checks on the document and on every case that cites it, its locks, its
markup deletion and its tombstone), for collected documents only. Exhibits,
ingest records and the rest keep their own routes.

    python scripts/retention_sweep.py                      # a dry run, the default
    python scripts/retention_sweep.py --apply --actor you@example.org

A dry run changes nothing, writes nothing and needs no declaration: it
counts what is past its clock, what a hold keeps and what a sweep would
destroy. A real run needs `--apply` AND a declared authority, a reference
an auditor can follow to the schedule, instruction or ticket the destruction
rests on, in NOCTORNAL_RETENTION_SWEEP_AUTHORITY. The software records the
reference and cannot verify it (docs/16 L1), and refuses a missing one, a
placeholder and a word that is an answer rather than a reference. A real run
also names the account that answers for it, with `--actor` or
NOCTORNAL_RETENTION_SWEEP_ACTOR: an active account that holds
retention.purge, recorded on every tombstone.

It is not part of the production cron loop and must not be added to one by
default. Who runs it, how often and under which authority is the owner's
decision (docs/16 L4); infra/production/README.md, Retention sweep, says how
to schedule it once that is made.

Prints the counters on one line, first, then any warnings. One real run
writes one RETENTION_SWEEP audit event of counts, and the purge writes its
tombstones as it always does. A backlog bigger than one pass is cleared in
the same run, up to --max-passes.

Exit codes: 0 when the run did what it was asked (a dry run always, a real run
that left nothing it could destroy); 1 when a real run left documents it could
have destroyed (a store refused their markup, or the pass limit was reached),
so run it again after reading the warnings; 2 when it refused to run: a missing
or placeholder authority, no named account, no store for collected markup, or,
under NOCTORNAL_ENV=production and for a dry run as well, an environment every
job refuses (`config.refuse_unsafe_job_environment`: a credential that carries a
published value, the schema owner's password or DSN, or the persona key), one
line per variable on stderr led by `retention_sweep: refusing to run:`. Nothing
was destroyed on a 2 before any pass began, and what a pass destroyed before a
refusal stays destroyed and is on its tombstone.
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
        description="Sweep collected documents past their retention clock. "
                    "A dry run unless --apply is given.")
    parser.add_argument("--apply", action="store_true",
                        help="destroy what is past its clock and not held; "
                             "needs a declared authority and a named account")
    parser.add_argument("--actor", default=None,
                        help="email of the active account that holds "
                             "retention.purge and answers for this run")
    parser.add_argument("--max-passes", type=int, default=None,
                        help="the most passes of 500 documents one run makes")
    args = parser.parse_args(argv)

    from noctornal_api import retention_sweep as rs
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment
    from noctornal_api.db import SystemPurpose, connect_system

    max_passes = args.max_passes if args.max_passes is not None else rs.DEFAULT_MAX_PASSES
    if max_passes < 1:
        parser.error("--max-passes must be at least 1")

    # The one refusal every job makes first, before anything is connected to
    # (config.refuse_unsafe_job_environment): a published credential, the
    # schema owner's, or the persona key only the collector holds. Until the
    # beta 1 gates (2026-10-07) this script asked for the first alone, and
    # only on --apply, so a dry run, or a real run holding the owner's DSN
    # or the persona key, started where every other job refused.
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
    # The system role: on the request role under row-level security a sweep
    # would see only some documents and report success (S1, 2026-09-25).
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
        if report.sweepable:
            print("dry run: nothing was changed. Run with --apply under a "
                  "declared authority to destroy what is past its clock.")
        return 0
    if report.refused:
        return 2
    return 1 if report.remaining else 0


if __name__ == "__main__":
    raise SystemExit(main())
