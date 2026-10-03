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
ring can express. Given the old key (base64, in a file and never on
the command line, which is in `ps` and the shell history), rows the ring
cannot open are tried under it and, when it opens them, re-sealed under
the active key. Rows nothing opens are counted and left; the readiness
check `kek_ring_opens_stored_secrets` keeps naming them, and an account
in that state re-enrols.

Each row is a compare-and-set on its own ciphertext
(`security/sealed.rewrap_table`), so a row re-enrolled while this runs is
left alone rather than overwritten. One audit event records the pass.

Exit 0 when every row is under the active key (or would be), 1 when rows
remain that nothing opens, 2 when the environment itself is not usable.

## Persona credentials, `--persona` (A collector process, 2026-10-02)

A persona credential seals under its own ring, NOCTORNAL_PERSONA_KEK, which
in production only the collector holds; the TOTP pass above no longer
touches `collect.collection_account`. `--persona` reports every persona
credential by key id, and with `--apply` moves each one sealed before the
split (under a TOTP ring id) onto the persona ring and re-seals each one
under a retired persona key under the active one. It needs BOTH rings, so
it runs in the collector:

    docker compose -f infra/production/compose.yml run --rm collector \\
        python scripts/rewrap_secrets.py --persona --apply

The upgrade note: until it has run, the vault refuses every persona
credential sealed before the split by name, polls of those personas are
BLOCKED with that sentence, and the readiness row `collector_split` counts
them.
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

    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.security import envelope
    from noctornal_api.security.sealed import inventory, rewrap_all

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true",
                        help="re-seal. Without it, report only.")
    parser.add_argument("--legacy-key-file", metavar="PATH",
                        help="a file holding the base64 key that sealed rows "
                             "recorded under an id the ring now maps to a "
                             "different key (the pre-ring world)")
    parser.add_argument("--persona", action="store_true",
                        help="persona credentials: move them onto the persona "
                             "key ring (needs both rings: run it in the "
                             "collector)")
    args = parser.parse_args()
    if args.persona:
        return _persona(args)

    try:
        ids = envelope.key_ids()
    except (RuntimeError, ValueError) as exc:
        print(f"the key ring is not usable: {exc}", file=sys.stderr)
        return 2
    legacy = _legacy_key(args.legacy_key_file)
    active = ids[0]
    print(f"ring: active {active}"
          + (f", retired {', '.join(ids[1:])}" if ids[1:] else ", no retired keys"))

    conn = connect_system(SystemPurpose.SCRIPT)
    from noctornal_api.security.persona_sealed import sealed_before_split
    stranded = sealed_before_split(conn)
    if stranded:
        # A collector process (2026-10-02): this pass no longer moves
        # persona credentials, and a TOTP key dropped from the ring takes
        # the ones still sealed under it with it.
        from noctornal_api.wording import count_of
        print(f"{count_of(stranded, 'persona credential is', 'persona credentials are')} "
              f"still sealed under this ring, "
              f"from before the persona key existed: keep every key that sealed "
              f"them in the ring until --persona --apply has moved them",
              file=sys.stderr)
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


def _persona(args) -> int:
    """`--persona`: the persona ring's report, and with --apply the move."""
    from psycopg.types.json import Json

    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.security import envelope, persona_envelope
    from noctornal_api.security.persona_sealed import (
        inventory,
        move_and_rewrap,
        reseal_sessions,
        sealed_before_split,
    )
    from noctornal_api.wording import count_of

    if args.legacy_key_file:
        print("--legacy-key-file is for the TOTP ring's pre-ring rows; it does "
              "not apply to --persona", file=sys.stderr)
        return 2
    try:
        ids = persona_envelope.key_ids()
    except persona_envelope.PersonaKeyError as exc:
        print(f"the persona key ring is not usable here: {exc}", file=sys.stderr)
        return 2
    active = ids[0]
    print(f"persona ring: active {active}"
          + (f", retired {', '.join(ids[1:])}" if ids[1:] else ", no retired keys"))
    conn = connect_system(SystemPurpose.SCRIPT)
    # BEFORE the inventory opens anything (verify:g38, 2026-10-03): a row
    # still sealed under the TOTP ring is opened with that ring, so a
    # process without the TOTP key must be refused by name here, with exit
    # 2, and not crash in the inventory with a traceback and exit 1.
    stranded = sealed_before_split(conn)
    if stranded:
        try:
            envelope.key_ids()
        except (RuntimeError, ValueError) as exc:
            print(f"{count_of(stranded, 'persona credential is', 'persona credentials are')} "
                  f"still sealed under the TOTP key ring, and opening "
                  f"{'it' if stranded == 1 else 'them'} needs that ring, which "
                  f"is not usable here ({exc}): run this where both keys are "
                  f"held, the collector", file=sys.stderr)
            return 2
    groups = inventory(conn)
    if not groups:
        print("no persona credential is sealed; nothing to do")
        return 0
    for g in groups:
        print("  " + g.describe())
    unopenable = sum(g.unopenable for g in groups)
    pending = sum(g.rows for g in groups if g.key_id != active)
    if not args.apply:
        print(f"\n{count_of(pending, 'persona credential would be', 'persona credentials would be')} "
              f"sealed under {active}; run with --apply to do it")
        if unopenable:
            print(f"{unopenable} of the checked rows open under nothing held here: "
                  f"a credential sealed before the split needs the TOTP key that "
                  f"sealed it in NOCTORNAL_TOTP_KEK or _RETIRED, and one under a "
                  f"retired persona key needs it in NOCTORNAL_PERSONA_KEK_RETIRED; "
                  f"or re-enrol that persona", file=sys.stderr)
        return 1 if unopenable else 0
    report = move_and_rewrap(conn)
    print(f"  {report.table:32} moved {report.recovered}, re-sealed "
          f"{report.rewrapped}, skipped {report.skipped}, unopenable "
          f"{report.unopenable}")
    # A forum persona's session cookies seal under the same ring: re-sealed
    # with the credentials, or cleared when sealed before the ring existed.
    sessions, session_cleared = reseal_sessions(conn)
    print(f"  {sessions.table:32} re-sealed {sessions.rewrapped}, cleared "
          f"{session_cleared}, skipped {sessions.skipped}, unopenable "
          f"{sessions.unopenable}")
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (NULL, 'SYSTEM', 'PERSONA_KEK_REWRAP', 'kek', NULL, NULL, %s)""",
        (Json({"active_key_id": active, "moved": report.recovered,
               "rewrapped": report.rewrapped, "skipped": report.skipped,
               "unopenable": report.unopenable,
               "sessions": {"rewrapped": sessions.rewrapped,
                            "cleared": session_cleared,
                            "skipped": sessions.skipped,
                            "unopenable": sessions.unopenable}}),))
    if report.unopenable:
        print(f"\n{report.unopenable} persona credentials open under nothing held "
              f"here and were left as found; the readiness row collector_split "
              f"keeps counting the ones sealed before the split", file=sys.stderr)
        return 1
    print(f"\nevery persona credential is under {active}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
