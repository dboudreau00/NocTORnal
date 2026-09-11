"""Re-seal every envelope-encrypted secret under the ACTIVE key.

Step 3 of the rotation runbook in `security/envelope.py`. Report mode
lists every (table, key id) group the database holds and how many of its
rows the ring opens; `--apply` moves every row the ring can open that is
not already under the active key, and leaves the rest exactly as found.

    python scripts/rewrap_secrets.py                    # report only
    python scripts/rewrap_secrets.py --apply            # re-seal
    python scripts/rewrap_secrets.py --apply --legacy-key-file /root/old.kek

`--legacy-key-file` is for the pre-ring world: before 2026-09-11 every
blob was recorded under `env:v1` whatever key sealed it, so a deployment
that ever changed its KEK holds rows under two keys and one id, which no
ring can express. Given the old key (base64, in a file -- never on the
command line, which is in `ps` and the shell history), rows the ring
cannot open are tried under it and, when it opens them, re-sealed under
the active key. Rows nothing opens are counted and left; the readiness
check `kek_ring_opens_stored_secrets` keeps naming them, and an account
in that state re-enrols.

Each row is a compare-and-set on its own ciphertext
(`security/sealed.rewrap_table`), so a row re-enrolled while this runs is
left alone rather than overwritten. One audit event records the pass.

Exit 0 when every row is under the active key (or would be), 1 when rows
remain that nothing opens, 2 when the environment itself is not usable.
"""
from __future__ import annotations

import argparse
import base64
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from _env import load_env_local  # noqa: E402

load_env_local()


def _legacy_key(path: str | None) -> bytes | None:
    if path is None:
        return None
    key = base64.b64decode(open(path, encoding="utf-8").read().strip())
    if len(key) != 32:
        raise SystemExit(f"{path} does not hold a base64 32-byte key")
    return key


def main() -> int:
    from psycopg.types.json import Json

    from noctornal_api.db import connect
    from noctornal_api.security import envelope
    from noctornal_api.security.sealed import inventory, rewrap_all

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="re-seal. Without it, report only.")
    parser.add_argument("--legacy-key-file", metavar="PATH",
                        help="a file holding the base64 key that sealed rows "
                             "recorded under an id the ring now maps to a "
                             "different key (the pre-ring world)")
    args = parser.parse_args()

    try:
        ids = envelope.key_ids()
    except (RuntimeError, ValueError) as exc:
        print(f"the key ring is not usable: {exc}", file=sys.stderr)
        return 2
    legacy = _legacy_key(args.legacy_key_file)
    active = ids[0]
    print(f"ring: active {active}"
          + (f", retired {', '.join(ids[1:])}" if ids[1:] else ", no retired keys"))

    conn = connect()
    groups = inventory(conn)
    if not groups:
        print("no sealed rows in any table; nothing to do")
        return 0
    for g in groups:
        print("  " + g.describe())
    unopenable = sum(g.unopenable for g in groups)
    pending = sum(g.rows for g in groups if g.key_id != active)
    if not args.apply:
        print(f"\n{pending} rows are recorded under a retired id and would be "
              f"re-sealed under {active}; run with --apply to do it")
        if unopenable:
            print(f"{unopenable} of the checked rows open under nothing in the "
                  f"ring: add the key that sealed them to NOCTORNAL_TOTP_KEK_RETIRED "
                  f"(a rotation), or hand it over with --legacy-key-file (the "
                  f"pre-ring world, same id), or accept that those accounts "
                  f"re-enrol", file=sys.stderr)
        return 1 if unopenable else 0

    reports = rewrap_all(conn, legacy=legacy)
    for r in reports:
        print(f"  {r.table:32} re-sealed {r.rewrapped}, recovered {r.recovered}, "
              f"skipped {r.skipped}, unopenable {r.unopenable}")
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (NULL, 'SYSTEM', 'KEK_REWRAP', 'kek', NULL, NULL, %s)""",
        (Json({"active_key_id": active, "legacy_key_used": legacy is not None,
               "tables": [r.__dict__ for r in reports]}),))
    left = sum(r.unopenable for r in reports)
    if left:
        print(f"\n{left} rows open under nothing and were left as found; the "
              f"readiness register will keep naming them", file=sys.stderr)
        return 1
    print(f"\nevery sealed row is under {active}; the retired entries can be dropped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
