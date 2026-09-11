"""List the Telegram ids recorded under the assumption that a bare positive
number is a user.

Until 2026-09-11 `telegram_id_norm` stamped a bare positive id `u:<id>` on
the reasoning that most bare positives are users. It now refuses one, and
nothing can recompute a type that was never observed: the rows written
under the assumption keep their `u:`, and this lists them so an analyst
can confirm each against its source -- an MTProto channel observation
recorded as a bare number is a channel wearing a user's row -- and
re-record it typed (`c:<id>`) where it was wrong. Report only; it changes
nothing.

    python scripts/telegram_bare_ids.py

Two tables carry them: `core.selector` (TELEGRAM_ID rows whose `raw_value`
is a bare positive) and `comms.channel_binding` (TELEGRAM bindings whose
`observed_value` is one and that got a durable value anyway).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from _env import load_env_local  # noqa: E402

load_env_local()

BARE = r"^\s*\+?\d[\d\s]*$"


def main() -> int:
    from noctornal_api.db import connect

    conn = connect()
    selectors = conn.execute(
        """SELECT s.case_id, c.code, s.raw_value, s.norm_value, s.node_id,
                  s.first_seen, s.observation_cnt
             FROM core.selector s JOIN core."case" c ON c.id = s.case_id
            WHERE s.selector_type = 'TELEGRAM_ID' AND s.raw_value ~ %s
            ORDER BY c.code, s.first_seen""", (BARE,)).fetchall()
    bindings = conn.execute(
        """SELECT b.case_id, c.code, b.observed_value, b.durable_value,
                  b.verification, b.identity_node_id
             FROM comms.channel_binding b JOIN core."case" c ON c.id = b.case_id
            WHERE b.platform_key = 'TELEGRAM' AND b.durable_value IS NOT NULL
              AND b.observed_value ~ %s
            ORDER BY c.code""", (BARE,)).fetchall()
    if not selectors and not bindings:
        print("no Telegram id was recorded from a bare positive number; nothing to review")
        return 0
    print(f"{len(selectors)} selector rows and {len(bindings)} channel bindings were "
          f"typed by assumption (u:) before 2026-09-11 and should be confirmed:\n")
    for _case_id, code, raw, norm, node, seen, n in selectors:
        when = seen.strftime("%Y-%m-%d") if seen else "-"
        print(f"  selector  {code:14} {raw!r:>16} -> {norm:16} node {node or '-'}  "
              f"seen {when} x{n}")
    for _case_id, code, observed, durable, verification, node in bindings:
        print(f"  binding   {code:14} {observed!r:>16} -> {durable:16} "
              f"{verification:10} identity {node or '-'}")
    print("\nConfirm each against its source. A channel wearing a user's row is "
          "re-recorded typed (c:<id>); the assumed row is retracted the way any "
          "wrong attribution is.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
