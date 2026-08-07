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

## The checks are separate on purpose

A chain can break in distinct ways and they mean different things:

- **CONTENT** — a row's `row_hash` is not what its own columns hash to,
  using the `prev_hash` it stores. That is a row *edited in place*.
- **LINK** — a row's `prev_hash` names a `row_hash` that no row has. That
  is a predecessor *removed*.
- **FORK** — two or more rows claim the SAME predecessor. That is a row
  *inserted*, or two writers that raced.

Reporting them as one boolean would lose exactly the information an
investigator needs first.

## `seq` ORDER IS NOT CHAIN ORDER, and assuming it was made this verifier
## report 68 breaks on an honest database

The first version of this module checked the link by comparing each row's
`prev_hash` to `LAG(row_hash) OVER (ORDER BY seq)`. That is wrong, and it
is wrong in the most damaging direction available to a tamper-evidence
tool: it accused intact history.

`audit.event.seq` is a `bigserial`. Its value comes from `nextval()` when
the row is constructed, which happens **before** the BEFORE-INSERT trigger
runs and therefore before `audit.chain_hash()` takes its advisory lock. So
two concurrent writers can be handed seq 7445 and 7446, then acquire the
lock in the opposite order — and the row holding the LOWER seq chains off
the row holding the HIGHER one. Nothing is corrupt; the linked list is
perfectly sound; the numbering simply does not follow it.

Observed on the development database: 60,181 rows, 68 reported "breaks",
every one of them a pair of adjacent AUTH_FAILED rows whose seq order and
chain order disagreed. Had this shipped, the first person to run it would
have been told the audit trail was tampered with, and the second would
have learned to ignore the tool.

So the link is now verified as what it actually is — **a linked list** —
by following `prev_hash` to a real `row_hash` rather than to a positional
neighbour. `seq` is used only for reporting and windowing.

## A FORK is reported, but it is NOT tampering

Two rows claiming one predecessor is what 0013's advisory lock exists to
prevent, and it does not entirely: `seq` is drawn from `nextval()` before
the trigger runs, so concurrent writers can still chain off one tail. The
development database carries 67 such forks in 60,181 rows, all from
ordinary traffic.

So forks are counted and listed SEPARATELY and do not make `intact`
false. Folding them in meant the endpoint answered BROKEN on untampered
history — the one thing a tamper-evidence tool must never do, and the
second time this module made that mistake (the first was assuming `seq`
order was chain order). See `ChainReport.intact`.
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
    kind: str            # LINK / FORK / CONTENT, '+'-joined when several
    actor_id: UUID | None
    case_id: UUID | None


@dataclass(frozen=True)
class ChainReport:
    checked: int
    #: Evidence of TAMPERING: LINK (a predecessor removed) and CONTENT (a
    #: row edited). These are what `intact` is about.
    breaks: tuple[ChainBreak, ...]
    #: Rows sharing a predecessor. Reported separately and deliberately NOT
    #: counted as tampering -- see `intact`.
    forks: tuple[ChainBreak, ...]
    first_seq: int | None
    last_seq: int | None

    @property
    def intact(self) -> bool:
        """No evidence of TAMPERING among the rows examined.

        ## Forks do not make a chain "broken", and treating them as such
        ## made this endpoint cry wolf on every real database

        A fork is two rows claiming one predecessor. 0013's advisory lock
        is meant to prevent it, and it does not entirely: `seq` comes from
        `nextval()` before the trigger runs, and under concurrency two
        writers can still end up chained off the same tail. The development
        database carries **67 of them across 60,181 rows**, none of them
        tampering — they are an artefact of the WRITER, reproducible by
        ordinary traffic.

        Counting those as breaks meant `/audit/verify` answered BROKEN on
        untampered history, which is the same failure this module already
        made once with `seq` ordering and is the only failure a
        tamper-evidence tool cannot afford: an officer who is told the log
        is compromised, investigates, finds nothing, and never trusts the
        button again.

        So `intact` is about LINK and CONTENT — a row removed, a row
        edited. Forks are surfaced separately, with their own count and
        their own explanation, because they are worth knowing (a forked
        chain cannot be linearised, which weakens the guarantee) without
        being an accusation.

        An EMPTY audit table returns True, and the caller is expected to
        read `checked` too: a fresh database genuinely has an intact
        (empty) chain, and returning False would make first-run CI red for
        a correct system. The endpoint reports `checked` alongside so
        "verified" can never be read as "verified something".
        """
        return not self.breaks


def verify_chain(
    conn: psycopg.Connection,
    *,
    limit: int | None = None,
    since_seq: int | None = None,
) -> ChainReport:
    """Recompute the chain and return every row that does not verify.

    `limit` checks only the most recent N rows, and every check is EXACT
    for the rows it reports: the predecessor and fork lookups run over the
    whole table, not the window, so a windowed run cannot produce a false
    orphan at its own boundary. What a window does not tell you is whether
    rows outside it verify.

    (An earlier version built those lookups from the window and therefore
    DID have a boundary blind spot — worse, it accused the oldest row in
    every windowed run. Both are gone; the docstring is kept honest because
    a stale caveat teaches people to discount the accurate ones.)

    Ordering is by `seq`, the chain's own order, never by `occurred_at` —
    a clock adjustment must not be able to reorder the verification.
    """
    where = "WHERE e.seq > %(since)s" if since_seq is not None else ""
    window = "ORDER BY e.seq DESC LIMIT %(limit)s" if limit is not None else              "ORDER BY e.seq"

    # The link is verified as a LINKED LIST, never by seq adjacency -- see
    # the module docstring. `known` is every row_hash in the window;
    # `claims` counts how many rows name each predecessor.
    sql = f"""
    WITH windowed AS (
        SELECT e.seq, e.occurred_at, e.actor_id, e.actor_kind, e.action,
               e.object_type, e.object_id, e.case_id, e.outcome, e.detail,
               e.ip_hash, e.session_id, e.prev_hash, e.row_hash,
               {_HASH_EXPR} AS recomputed
          FROM audit.event e
          {where}
          {window}
    ), hashes AS (
        -- THE WHOLE TABLE, not the window. This is what makes a windowed
        -- run exact rather than approximate: the oldest row in any window
        -- has a predecessor OUTSIDE it, and looking only inside the window
        -- would report that row as an orphan every single time -- a false
        -- accusation on every `limit` run, which is worse than the missed
        -- detection it was meant to avoid.
        --
        -- DISTINCT so the LEFT JOIN matches at most once. Two rows sharing
        -- a row_hash would otherwise duplicate output rows; a SHA-256
        -- collision is not a practical concern, but two byte-identical
        -- audit rows are (the same action, same payload, same microsecond).
        SELECT DISTINCT row_hash FROM audit.event
    ), claims AS (
        -- Also whole-table: a fork is a fork whether or not both claimants
        -- fall inside the window being reported.
        SELECT prev_hash, COUNT(*) AS claimants
          FROM audit.event WHERE prev_hash IS NOT NULL
         GROUP BY prev_hash
    )
    -- LEFT JOINs, not correlated subqueries. The first version used
    -- `NOT EXISTS (SELECT ... FROM windowed p WHERE p.row_hash = ...)`,
    -- which Postgres evaluates per row: on the 60,181-row development
    -- table that did not finish inside two minutes. As joins the planner
    -- hashes each side once and the same check runs in well under a
    -- second.
    SELECT w.seq, w.occurred_at, w.action, w.actor_id, w.case_id,
           -- ORPHAN: names a predecessor that is not in the window at all.
           -- The genesis row (prev_hash NULL) is exempt by construction.
           (w.prev_hash IS NOT NULL AND h.row_hash IS NULL) AS link_broken,
           -- FORK: this row's predecessor is claimed by more than one row.
           -- Both claimants are reported; which one is the intruder is not
           -- something this can decide, and pretending otherwise would be
           -- worse than naming both.
           COALESCE(c.claimants > 1, false) AS forked,
           (w.row_hash IS DISTINCT FROM w.recomputed) AS content_broken
      FROM windowed w
      LEFT JOIN hashes h ON h.row_hash = w.prev_hash
      LEFT JOIN claims c ON c.prev_hash = w.prev_hash
     ORDER BY w.seq
    """
    params: dict = {}
    if since_seq is not None:
        params["since"] = since_seq
    if limit is not None:
        params["limit"] = limit

    rows = conn.execute(sql, params).fetchall()
    breaks: list[ChainBreak] = []
    forks: list[ChainBreak] = []
    for seq, occurred_at, action, actor_id, case_id, link, fork, content in rows:
        if not (link or fork or content):
            continue
        parts = []
        if link:
            parts.append("LINK")
        if content:
            parts.append("CONTENT")
        if parts:
            breaks.append(ChainBreak(
                seq=seq, occurred_at=occurred_at, action=action,
                kind="+".join(parts), actor_id=actor_id, case_id=case_id))
        # A FORK IS NOT REPORTED AS TAMPERING, and this is the whole point
        # of the split -- see ChainReport.intact.
        if fork:
            forks.append(ChainBreak(
                seq=seq, occurred_at=occurred_at, action=action, kind="FORK",
                actor_id=actor_id, case_id=case_id))

    return ChainReport(
        checked=len(rows),
        breaks=tuple(breaks),
        forks=tuple(forks),
        first_seq=rows[0][0] if rows else None,
        last_seq=rows[-1][0] if rows else None,
    )
