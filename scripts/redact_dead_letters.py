"""Redact the dead-letter fragments recorded before the redactor existed.

docs/17 F15(d). `ingest.dead_letter` held verbatim fragments in a table
with no classification, no compartments and no retention, and the route in
was routine rather than adversarial -- a partner whose schema drifts
dead-letters their whole feed, and `categorise` sends anything with
top-level `email` + `password` down that path.

Migration 0040 labelled the table, put every row on a clock and made new
rows redacted by construction. It deliberately did NOT rewrite the rows
already there: redaction is not reversible and this project's rule is that
a migration is. This is the irreversible half, so a human runs it
deliberately and sees what it changed.

    python scripts/redact_dead_letters.py            # report only
    python scripts/redact_dead_letters.py --apply    # rewrite

What it does to each row where `redacted` is false:

  * replaces `raw_fragment` with `redact_fragment(...)` -- keys, types,
    lengths, never a value;
  * records `fragment_sha256` of the ORIGINAL first, so a later repair can
    be checked against the batch's raw object;
  * sets `redacted = true`.

The verbatim bytes are NOT destroyed by this: they remain in the batch's
raw object under the batch's own retention and access rules, which is
where third-party credentials belong if they are held at all. What this
removes is the second, unlabelled copy.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from noctornal_api.db import connect  # noqa: E402
from noctornal_api.ingest import redact_fragment, scrub_nuls  # noqa: E402

BATCH = 500


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="actually rewrite. Without it, report only.")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after N rows (0 = all)")
    args = parser.parse_args()

    conn = connect()
    total = conn.execute(
        "SELECT count(*) FROM ingest.dead_letter WHERE NOT redacted"
    ).fetchone()[0]
    print(f"{total} unredacted dead-letter row(s)")
    if total == 0:
        print("nothing to do")
        return 0
    if not args.apply:
        rows = conn.execute(
            """SELECT id, error_class, length(raw_fragment), occurred_at
                 FROM ingest.dead_letter WHERE NOT redacted
                ORDER BY occurred_at LIMIT 20""").fetchall()
        print("\nfirst 20, by age (lengths only -- this is a dry run and it "
              "is not going to print the content it exists to remove):")
        for row in rows:
            print(f"  {row[0]}  {row[3]:%Y-%m-%d}  {row[1]:<24} "
                  f"{row[2]:>7} chars")
        print("\nre-run with --apply to rewrite. This cannot be undone; the "
              "verbatim bytes remain in each batch's raw object.")
        return 0

    done = 0
    while True:
        rows = conn.execute(
            """SELECT id, raw_fragment FROM ingest.dead_letter
                WHERE NOT redacted ORDER BY occurred_at LIMIT %s""",
            (BATCH,)).fetchall()
        if not rows:
            break
        for row_id, fragment in rows:
            original = fragment or ""
            digest = hashlib.sha256(original.encode("utf-8", "replace")).digest()
            conn.execute(
                """UPDATE ingest.dead_letter
                      SET raw_fragment = %s, fragment_sha256 = %s,
                          redacted = true
                    WHERE id = %s""",
                (scrub_nuls(redact_fragment(original)), digest, row_id))
            done += 1
            if args.limit and done >= args.limit:
                break
        print(f"  {done}/{total}")
        if args.limit and done >= args.limit:
            break
    print(f"redacted {done} row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
