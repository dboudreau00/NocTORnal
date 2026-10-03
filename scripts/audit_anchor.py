"""Record the audit log's tail, and check a recorded one still holds.

    python scripts/audit_anchor.py                      # print the anchor
    python scripts/audit_anchor.py --check '{"seq": 41, "row_hash": "ab..."}'
    python scripts/audit_anchor.py --check anchor.json  # the same, from a file

Why this exists (evidence-chain-no-anchor, 2026-10-03). The chain verifier
(`GET /audit/verify`, `audit_verify.verify_chain`) is relative: it asks
whether each row agrees with its predecessor. Rows removed from the end of
the log leave nothing to disagree, and a rewrite that recomputes every later
hash agrees with itself, because the hash is unkeyed and whoever owns the
database can recompute it. The one defence is a record kept where the
database cannot reach.

Run this on a schedule and keep the line it prints somewhere else (a ticket,
a signed message, a ledger kept by someone other than the database's
operator). Later, `--check` takes one of those lines and says whether the
log still holds that row: it does not if the log was cut back below it, or
rewritten through it.

Exit 0 when printing, or when the anchor holds; 1 when it does not; 2 when
the argument is not an anchor.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from _env import load_env_local  # noqa: E402

load_env_local()


def _load(argument: str) -> tuple[int, str]:
    text = argument
    if os.path.isfile(argument):
        with open(argument, encoding="utf-8") as handle:
            text = handle.read()
    try:
        data = json.loads(text)
        return int(data["seq"]), str(data["row_hash"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"not an anchor ({exc}): expected "
                         '{"seq": N, "row_hash": "64 hex characters"}') from exc


def main() -> int:
    from noctornal_api.audit_verify import verify_chain
    from noctornal_api.db import SystemPurpose, connect_system

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", metavar="ANCHOR",
                        help="an anchor line, or a file holding one, to check "
                             "against the log")
    args = parser.parse_args()
    anchor = None
    try:
        if args.check:
            anchor = _load(args.check)
        conn = connect_system(SystemPurpose.SCRIPT)
        try:
            # limit=1: the walk is not what is asked here, the tail and the
            # anchor are, and both are whole-table reads.
            report = verify_chain(conn, limit=1, anchor=anchor)
        finally:
            conn.close()
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    if anchor is None:
        print(json.dumps({"seq": report.tail_seq, "row_hash": report.tail_row_hash,
                          "rows": report.rows}))
        return 0
    if report.anchor is not None and report.anchor.held:
        print(f"the log still holds seq {anchor[0]}")
        return 0
    print(f"the log does NOT hold seq {anchor[0]} with that hash: it has been cut "
          "back below it, or rewritten through it", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
