"""Verify the audit and custody chains from a shell, and keep their tail anchor
(evidence-chain-no-anchor, 2026-10-03). An operator runs this; nothing
schedules it for you.

    python scripts/audit_verify.py
    python scripts/audit_verify.py --anchor-file /secure/ledger-anchors.jsonl --record

Every check on both ledgers compares a row with the rows around it, so none
of them can see rows removed from the END, or rows edited and re-chained with
fresh hashes (plain SHA-256). Both need the database owner's credentials. The
defence is an anchor recorded where this system cannot write: the newest row's
number and hash, handed back on a later run. With `--anchor-file` the last
anchor in that file is compared first, and a row that was removed, rewritten
or renumbered since is reported and exits 1. With `--record` a run that found
nothing wrong appends the tails it saw, one JSON line, to the same file.

The file is the operator's. Keep it on another host, on write-once storage or
in a ticket: a file this system could rewrite protects nothing, and the
script cannot tell. It writes the file and never reads another path.

A held anchor vouches for every row up to it and says nothing about the rows
written after it, so record regularly. A run with no anchor file is no better
protected than `GET /audit/verify` and says so.

`--record` refuses `--limit`: an anchor vouches for every row up to it, and a
run that read only the newest N events vouches for none of the older ones
(g49v-record-with-limit, 2026-10-03).

Exit codes: 0 when both chains verify (and the anchors, when given, are held);
1 when a break or a failed anchor was found; 2 when it could not run or could
not finish: bad arguments, an unreadable or unwritable anchor file, no usable
database connection, a database that did not answer. Only 1 means tampering. A
scheduler that reads the status can tell an outage from a break, and must
alert on both (g49v-script-exit-codes, 2026-10-03).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()

CAVEAT = ("Not checked by any run: rows removed from the end of a ledger, or "
          "edited and re-chained with fresh hashes. Record the tails with "
          "--anchor-file and --record, and compare them on the next run.")


def _refuse(message: str) -> int:
    print(f"refused: {message}", file=sys.stderr)
    return 2


def _said(exc: BaseException) -> str:
    """One line about a failure: its class and the first line of its message,
    which for a failed connection names the host and never the password."""
    lines = str(exc).strip().splitlines()
    return f"{type(exc).__name__}: {lines[0] if lines else 'no message'}"


def read_last_anchor(path: str) -> dict | None:
    """The newest line of the anchor file, or None when the file does not
    exist or holds none. A line that is not an anchor is an error, not a
    reason to compare against nothing."""
    from noctornal_api.audit_verify import ChainAnchor
    from noctornal_api.custody_verify import CustodyAnchor

    if not os.path.exists(path):
        return None
    last = None
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if row.get("audit") is not None:
                    ChainAnchor(int(row["audit"]["seq"]), row["audit"]["row_hash"])
                if row.get("custody") is not None:
                    CustodyAnchor(int(row["custody"]["id"]),
                                  row["custody"]["row_hash"])
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise ValueError(f"{path} line {number} is not an anchor") from exc
            last = row
    return last


def append_anchor(path: str, audit, custody, *, now=None) -> dict:
    """Append one line holding the tails just seen."""
    row = {
        "recorded_at": (now or datetime.now(timezone.utc)).isoformat(),
        "audit": ({"seq": audit.tail_seq, "row_hash": audit.tail_row_hash}
                  if audit.tail_row_hash else None),
        "custody": ({"id": custody.tail_id, "row_hash": custody.tail_row_hash}
                    if custody.tail_row_hash else None),
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def check(conn, *, limit: int | None = None, previous: dict | None = None):
    """(audit report, custody report, lines to print, exit status)."""
    from noctornal_api.audit_verify import ChainAnchor, verify_chain
    from noctornal_api.custody_verify import CustodyAnchor, verify_custody_chain

    audit_anchor = custody_anchor = None
    if previous and previous.get("audit"):
        audit_anchor = ChainAnchor(previous["audit"]["seq"],
                                   previous["audit"]["row_hash"])
    if previous and previous.get("custody"):
        custody_anchor = CustodyAnchor(previous["custody"]["id"],
                                       previous["custody"]["row_hash"])
    audit = verify_chain(conn, limit=limit, anchor=audit_anchor)
    custody = verify_custody_chain(conn, anchor=custody_anchor)

    lines = [
        f"audit chain: {'INTACT' if audit.intact else 'BROKEN'}, "
        f"{audit.checked} events checked, tail seq {audit.tail_seq}, "
        f"hash {audit.tail_row_hash}",
        *(f"  {b.kind} at seq {b.seq} ({b.action})" for b in audit.breaks),
        f"custody ledger: {'INTACT' if custody.intact else 'BROKEN'}, "
        f"{custody.checked} rows checked, tail id {custody.tail_id}, "
        f"hash {custody.tail_row_hash}",
        *(f"  {b.kind} at id {b.id} ({b.action})" for b in custody.breaks),
    ]
    for name, report in (("audit", audit), ("custody", custody)):
        if report.anchor is not None:
            held = report.anchor.status == "HELD"
            lines.append(
                f"{name} anchor: {report.anchor.status}"
                + (f", {report.anchor.rows_since} rows written since" if held else ""))
    if audit_anchor is None and custody_anchor is None:
        lines.append("no anchor was compared, so this run cannot see a removed "
                     "tail or a re-chained edit")
    lines.append(CAVEAT)
    return audit, custody, lines, 0 if audit.intact and custody.intact else 1


def main(argv: list[str] | None = None, *, conn=None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the audit and custody chains and keep their tail "
                    "anchor.")
    parser.add_argument("--limit", type=int, default=None,
                        help="check only the most recent N audit events; the "
                             "custody ledger is always checked whole")
    parser.add_argument("--anchor-file", default=None,
                        help="compare the last anchor in this file first")
    parser.add_argument("--record", action="store_true",
                        help="append the tails just seen to --anchor-file, "
                             "when nothing was found wrong")
    args = parser.parse_args(argv)
    if args.record and not args.anchor_file:
        parser.error("--record needs --anchor-file")
    if args.record and args.limit is not None:
        # An anchor is read back as "every row up to it is unchanged"
        # (routers/audit.py, _ANCHOR_NOTES); a run that checked only the
        # newest N events cannot say that of the older ones
        # (g49v-record-with-limit, 2026-10-03).
        parser.error("--record cannot be used with --limit: an anchor "
                     "vouches for every row up to it, and a partial run "
                     "checked only the newest events")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1")

    try:
        previous = read_last_anchor(args.anchor_file) if args.anchor_file else None
    except ValueError as exc:
        return _refuse(str(exc))

    import psycopg

    from noctornal_api.db import (
        SystemContextUnavailable,
        SystemPurpose,
        connect_system,
    )

    own = conn is None
    # Everything that can go wrong before there is a verdict is exit 2, never
    # the 1 that means a break: a scheduler reading the status must be able to
    # tell a database that did not answer from a ledger that was altered
    # (g49v-script-exit-codes, 2026-10-03).
    try:
        # The system role: a verifier that sees part of a chain reports
        # breaks that are not there (S1, 2026-09-25).
        conn = conn or connect_system(SystemPurpose.AUDIT_VERIFY)
        try:
            audit, custody, lines, status = check(
                conn, limit=args.limit, previous=previous)
        finally:
            if own:
                conn.close()
    except SystemContextUnavailable as exc:
        return _refuse(f"no usable system database connection ({exc}); "
                       "nothing was verified")
    except (psycopg.Error, RuntimeError, OSError) as exc:
        return _refuse(f"could not read the database ({_said(exc)}); "
                       "nothing was verified")
    except Exception:  # noqa: BLE001 - a bug is not a break either
        traceback.print_exc()
        return _refuse("the check did not complete; nothing was verified")
    for line in lines:
        print(line)
    if args.record:
        if status != 0:
            print("not recorded: this run found something wrong, and an anchor "
                  "taken now would vouch for it")
        else:
            try:
                append_anchor(args.anchor_file, audit, custody)
            except OSError as exc:
                return _refuse(f"could not write {args.anchor_file} "
                               f"({_said(exc)}); the tails were not recorded")
            print(f"recorded the tails in {args.anchor_file}. Keep that file "
                  "where this system cannot write.")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
