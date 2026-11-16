"""Re-lodge mirrored exhibits and preserved samples into an object store that never held them, once. An
operator runs this; nothing schedules it.

A backup mirror (`mc mirror`, infra/production/README.md) keeps the bytes of an object and not the
version the store gave them, and an exhibit names the version it was lodged as, so evidence restored into a
new store reads as missing and raises an integrity alarm; a preserved sample's retrieval reads a version of
the preservation bucket the same way. This puts each exhibit's mirrored bytes into the new store under a
COMPLIANCE lock after proving they are the exhibit's, and records where they now live as one hash-chained
`RESTORED` custody row. A preserved sample's mirrored ciphertext goes into the preservation bucket under a
legal hold, set in the put and read back, after it opens to the sample's own size and digests, and is
recorded as one `RESTORED` access row. Nothing on the exhibit or the sample is rewritten, and no hash is
loosened.

    python scripts/restore_object_versions.py --evidence-mirror /backup/evidence          # a dry run
    python scripts/restore_object_versions.py --evidence-mirror /backup/evidence \\
        --preserved-mirror /backup/preserved --apply --actor you@example.org --authority TICKET-1234

A dry run, the default, reads the store and the mirror (and, for a preserved sample, opens its key) and
writes nothing anywhere, and needs no declaration: it says what a run would restore, what is already in
place and what it would refuse and why. A COMPLIANCE lock and a legal hold cannot be taken back by this tool
or by the account it runs as, so a real run needs `--apply`, the account that answers
for it (`--actor`: an active holder of retention.manage through a global role, recorded on every custody and
audit row) and the authority it ran under (`--authority`: a restore ticket or incident reference an auditor
can follow, recorded and not verifiable). It runs as the system role, never the schema owner's, and with the
restore account's store credentials in the variables the API reads (OBJECT_STORE_* or MINIO_*, and PRESERVE_*
for the preservation bucket); the account's policy grants no delete and no change to a lock or a hold
(infra/production/README.md).

Per exhibit, in a stable order: the version a read asks for is probed first, and an exhibit already in place
writes nothing; the mirror file is found without leaving the mirror's root (no link, no `..`), hashed with
SHA-256 and BLAKE3 and compared with the exhibit's row and its hash-chained ACQUIRED row, and a difference
refuses it with nothing written; a version of the key already in the store whose bytes verify is adopted
instead of putting a second locked one; otherwise the object is put, read back by its own version id and
re-hashed, and only then is the database written. A purged exhibit is never restored. A preserved sample
goes the same way, with the proof that its ciphertext opens under its own data key to the size and the
SHA-256 (and the SHA-1 and MD5, where recorded) of the row; a sample has no BLAKE3, and the plaintext exists
in memory for the length of the hashes. It is put only into the bucket its row names. `--no-adopt` is for a
restore account that may not list versions, and says what it risks.

Exit 0 when the run did what it was asked; 1 when something is left (a mirror file missing, a digest that
differs, a store that refused), so read the report and run again; 2 when it refused to run: a missing or
placeholder authority, no named account, a store that is not configured, another restore running, or under
NOCTORNAL_ENV=production an environment every job refuses (`config.refuse_unsafe_job_environment`, dry run
included). `--report FILE` writes the per-object outcomes as JSON, mode 0600, counts and words and no
secret.
"""
from __future__ import annotations

import argparse
import getpass
import os
import platform
import socket
import sys
from uuid import UUID

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()

VIA = "scripts/restore_object_versions.py"

#: Stands for "build the store from the environment", so a test can hand in a store, or None for "none
#: configured", and the real run builds its own.
_FROM_ENVIRONMENT = object()


def _where() -> dict:
    """Where the run happened, for the custody and audit rows: the script, the host and the operating-system
    account. Never a credential."""
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - the name is a courtesy
        os_user = None
    return {"via": VIA, "host": socket.gethostname() or platform.node(), "os_user": os_user}


def _refuse(message: str) -> int:
    print(f"refused: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None, *, conn=None, evidence=_FROM_ENVIRONMENT,
         preserved=_FROM_ENVIRONMENT, now=None, lock_until=None) -> int:
    parser = argparse.ArgumentParser(
        description="Re-lodge mirrored exhibits and preserved samples into a new object store after "
                    "verifying them, and record the new version in the custody ledger. A dry run "
                    "unless --apply is given.")
    parser.add_argument("--evidence-mirror", metavar="DIR",
                        help="the directory `mc mirror` wrote the evidence bucket to")
    parser.add_argument("--preserved-mirror", metavar="DIR",
                        help="the directory `mc mirror` wrote the preservation bucket to")
    parser.add_argument("--case", action="append", default=[], metavar="ID",
                        help="restore only this case's exhibits and samples (repeatable)")
    parser.add_argument("--limit", type=int, default=None, metavar="N",
                        help="the most exhibits, and the most preserved samples, one run restores, "
                             "in a stable order; an object already in place, refused or failed does "
                             "not use the limit up, so each run goes on from the last")
    parser.add_argument("--apply", action="store_true",
                        help="put the verified bytes under a COMPLIANCE lock (a legal hold for a "
                             "sample) and record them; needs --actor and --authority")
    parser.add_argument("--actor", default=None,
                        help="email of the active account that holds retention.manage and answers "
                             "for this run")
    parser.add_argument("--authority", default=None,
                        help="the restore ticket or incident reference the run rests on")
    parser.add_argument("--no-adopt", action="store_true",
                        help="do not look for a version an interrupted run left: for a restore account "
                             "that may not list versions")
    parser.add_argument("--report", default=None, metavar="FILE",
                        help="write the per-object outcomes as JSON (mode 0600, never over a file)")
    args = parser.parse_args(argv)

    from noctornal_api import restore as rs
    from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment
    from noctornal_api.db import SystemPurpose, connect_system

    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")
    if not (args.evidence_mirror or args.preserved_mirror):
        parser.error("name what to restore: --evidence-mirror DIR, --preserved-mirror DIR, or both")
    try:
        cases = [UUID(c) for c in args.case]
    except ValueError:
        parser.error("--case takes a case id (a UUID)")

    # The refusal every job makes first, before anything is connected to, dry run included: the Lab's
    # whole list, because this holds the store's credentials and the key ring.
    refusals = refuse_unsafe_job_environment("restore_object_versions", whole_environment=True)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT

    authority = None
    if args.apply:
        try:
            authority = rs.validate_authority(args.authority)
        except rs.RestoreRefused as exc:
            return _refuse(str(exc))
    if args.report and os.path.exists(args.report):
        return _refuse("--report names a file that exists, and a report is never written over one. "
                       "Nothing was restored.")

    if not args.evidence_mirror:
        evidence = None
    elif evidence is _FROM_ENVIRONMENT:
        from noctornal_api.evidence import EvidenceError, EvidenceStorage
        try:
            evidence = EvidenceStorage()
        except EvidenceError as exc:
            return _refuse(f"the evidence object store is not usable: {exc}. Nothing was restored.")
    if not args.preserved_mirror:
        preserved = None
    elif preserved is _FROM_ENVIRONMENT:
        from noctornal_api.samples import PreservationStorage, SampleError
        try:
            preserved = PreservationStorage()
        except SampleError as exc:
            return _refuse(f"the preservation object store is not usable: {exc}. Nothing was "
                           f"restored.")

    own = conn is None
    # The system role: on the request role, row-level security would show a restore only some exhibits
    # and it would report success.
    conn = conn or connect_system(SystemPurpose.SCRIPT)
    try:
        actor_id = None
        if args.apply:
            try:
                actor_id = rs.resolve_actor(conn, args.actor)
            except rs.RestoreRefused as exc:
                return _refuse(str(exc))
        try:
            run = rs.Restore(
                conn, apply=args.apply, actor_id=actor_id, authority=authority, where=_where(),
                evidence=evidence, evidence_mirror=args.evidence_mirror, preserved=preserved,
                preserved_mirror=args.preserved_mirror, cases=cases, limit=args.limit, adopt=not args.no_adopt, now=now, lock_until=lock_until)
            report = run.run()
        except rs.RestoreRefused as exc:
            return _refuse(str(exc))
    finally:
        if own:
            conn.close()

    print(report.counters())
    for line in report.warnings:
        print(f"warning: {line}")
    for outcome in report.outcomes:
        if outcome.code in rs.LEFT:
            print(f"left: {outcome.kind} {outcome.id}: {outcome.code.lower()} "
                  f"({outcome.reason or 'see the report'})")
    if args.report:
        rs.write_report(args.report, report)
    if not args.apply:
        if report.count(rs.WOULD_RESTORE):
            print("dry run: nothing was changed. Run with --apply, --actor and --authority to "
                  "restore what verified.")
        return 1 if report.left else 0
    return 1 if report.left else 0


if __name__ == "__main__":
    raise SystemExit(main())
