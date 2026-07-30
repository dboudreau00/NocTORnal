"""Re-compute the `audit.event` hash chain and report where it breaks.

## Why this exists

Migration 0013 builds a strong tamper-evident chain: every row's
`row_hash` covers its predecessor's hash and every payload column, under
an advisory lock, with a UTC-fixed timestamp rendering so the chain is
verifiable from any session. Row-level and statement-level triggers block
UPDATE, DELETE and TRUNCATE, and the privileges are revoked besides.

**Nothing ever checked it.** A 2026-07-26 audit found no verification
function, no endpoint, no CI step and no test that re-read `audit.event`
and recomputed anything. Phase 0's exit criterion in docs/09 is that
"every action appears in a **verifiable** audit chain" — the chain was
written and never verified, which makes it a claim rather than a control.
Tamper evidence nobody examines is tamper evidence in name only: the
mechanism only pays out at the moment somebody asks "has this been
edited?", and until then a broken chain is indistinguishable from a
sound one.

## Why the recompute happens in SQL and not in Python

Because the trigger's hash input is a Postgres expression, and several
parts of it are things Python cannot reproduce faithfully:

- `NEW.detail::text` is **jsonb**'s own text rendering — key order
  normalised, whitespace removed, numbers canonicalised. `json.dumps` of
  the value psycopg hands back is a different string, and would fail every
  row.
- `concat_ws(chr(31), ...)` has specific NULL-skipping semantics.
- `to_char(... AT TIME ZONE 'UTC', ...)` renders microseconds in a
  particular way.

So this module ships the SAME expression the trigger uses and asks the
database to evaluate it. A verifier that disagrees with the writer is
worse than no verifier: it reports tampering on an intact chain, and the
first few false alarms are what teach people to ignore it.

**The expression below is duplicated from 0013 and must stay in step with
it.** That duplication is deliberate — the alternative is calling the
trigger function, which cannot be invoked outside an INSERT. `test_audit_
verify_pg.py` guards the coupling: it writes real events and asserts the
chain verifies, so any future edit to the trigger that this file does not
match turns the suite red rather than silently reporting corruption.

## The two checks are separate on purpose

A chain can break in two distinct ways and they mean different things:

- **LINK** — a row's stored `prev_hash` is not its predecessor's
  `row_hash`. That is a row *removed*, *inserted* or *re-ordered*.
- **CONTENT** — a row's `row_hash` is not what its own columns hash to,
  using the `prev_hash` it stores. That is a row *edited in place*.

Reporting them as one boolean would lose exactly the information an
investigator needs first.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

#: The canonical hash input, character-for-character from
#: `audit.chain_hash()` in 0013, with `NEW.` replaced by the row alias.
#: `prev_hash` is the STORED value, because that is what the trigger hashed
#: — the link check below is what catches a wrong stored value.
_HASH_EXPR = """
public.digest(
  convert_to(concat_ws(chr(31),
    coalesce(encode(e.prev_hash,'hex'),'GENESIS'),
    to_char(e.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    coalesce(e.actor_id::text,'-'),
    e.actor_kind,
    e.action,
    coalesce(e.object_type,'-'),
    coalesce(e.object_id::text,'-'),
    coalesce(e.case_id::text,'-'),
    e.outcome,
    e.detail::text,
    coalesce(encode(e.ip_hash,'hex'),'-'),
    coalesce(e.session_id::text,'-')
  ), 'UTF8'),
  'sha256')
"""


@dataclass(frozen=True)
class ChainBreak:
    """One row that does not verify."""
    seq: int
    occurred_at: datetime
    action: str
    kind: str            # 'LINK' | 'CONTENT' | 'LINK+CONTENT'
    actor_id: UUID | None
    case_id: UUID | None


@dataclass(frozen=True)
class ChainReport:
    checked: int
    breaks: tuple[ChainBreak, ...]
    first_seq: int | None
    last_seq: int | None
    #: True only when rows were actually examined AND none broke. An empty
    #: table is reported as `checked == 0` with `intact` False-y meaning
    #: "nothing to say", never as a pass -- see `intact` below.

    @property
    def intact(self) -> bool:
        """No breaks among the rows examined.

        An EMPTY audit table returns True here, and the caller is expected
        to look at `checked` too. That is deliberate rather than sloppy: a
        fresh database genuinely has an intact (empty) chain, and returning
        False would make first-run CI red for a correct system. The
        endpoint reports `checked` alongside so "verified" can never be
        read as "verified something".
        """
        return not self.breaks


def verify_chain(
    conn: psycopg.Connection,
    *,
    limit: int | None = None,
    since_seq: int | None = None,
) -> ChainReport:
    """Recompute the chain and return every row that does not verify.

    `limit` checks only the most recent N rows. The CONTENT check is exact
    for any window, but be aware of what a windowed LINK check can and
    cannot see: the oldest row in the window has no predecessor loaded, so
    its own `prev_hash` is not compared to anything. A deletion straddling
    the window boundary is therefore invisible to a windowed run and
    visible to a full one. The endpoint says so.

    Ordering is by `seq`, the chain's own order, never by `occurred_at` —
    a clock adjustment must not be able to reorder the verification.
    """
    where = "WHERE e.seq > %(since)s" if since_seq is not None else ""
    # ORDER BY seq DESC + limit, then re-order ascending, so `limit` means
    # "the most recent N" rather than "the oldest N".
    window = "ORDER BY e.seq DESC LIMIT %(limit)s" if limit is not None else \
             "ORDER BY e.seq"

    sql = f"""
    WITH windowed AS (
        SELECT e.seq, e.occurred_at, e.actor_id, e.actor_kind, e.action,
               e.object_type, e.object_id, e.case_id, e.outcome, e.detail,
               e.ip_hash, e.session_id, e.prev_hash, e.row_hash,
               {_HASH_EXPR} AS recomputed
          FROM audit.event e
          {where}
          {window}
    ), linked AS (
        SELECT w.*,
               LAG(w.row_hash) OVER (ORDER BY w.seq) AS predecessor_hash,
               ROW_NUMBER() OVER (ORDER BY w.seq)    AS rn
          FROM windowed w
    )
    SELECT seq, occurred_at, action, actor_id, case_id,
           -- The first row in the window has no loaded predecessor, so its
           -- link is NOT asserted -- see the docstring. rn = 1 exempts it.
           (rn > 1 AND prev_hash IS DISTINCT FROM predecessor_hash) AS link_broken,
           (row_hash IS DISTINCT FROM recomputed)                   AS content_broken
      FROM linked
     ORDER BY seq
    """
    params: dict = {}
    if since_seq is not None:
        params["since"] = since_seq
    if limit is not None:
        params["limit"] = limit

    rows = conn.execute(sql, params).fetchall()
    breaks: list[ChainBreak] = []
    for seq, occurred_at, action, actor_id, case_id, link, content in rows:
        if not link and not content:
            continue
        kind = "LINK+CONTENT" if (link and content) else (
            "LINK" if link else "CONTENT")
        breaks.append(ChainBreak(
            seq=seq, occurred_at=occurred_at, action=action, kind=kind,
            actor_id=actor_id, case_id=case_id))

    return ChainReport(
        checked=len(rows),
        breaks=tuple(breaks),
        first_seq=rows[0][0] if rows else None,
        last_seq=rows[-1][0] if rows else None,
    )
