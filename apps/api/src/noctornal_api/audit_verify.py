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

## `seq` order is chain order since 0153, and was not before

Until 0153 `audit.event.seq` was a `bigserial` drawn BEFORE the chaining
trigger took its advisory lock, so two concurrent writers could be handed
7445 and 7446 and take the lock in the opposite order: the row holding the
LOWER seq chained off the row holding the HIGHER one. The linked list stayed
sound and the numbering did not follow it. The first version of this module
compared each row's `prev_hash` to `LAG(row_hash) OVER (ORDER BY seq)` and
accused 68 honest rows on the development database, so the link is verified
as what it is, a linked list, by following `prev_hash` to a real `row_hash`.
`seq` is used for reporting and windowing, and is the chain's order for
every row written since 0153.

## A fork is a break from 0153 on

Two rows claiming one predecessor was the visible trace of that race. This
module counted it as not tampering, on the stated ground that ordinary
traffic could not fork the chain, and a 2026-08-10 erratum here said the
same. Both were wrong: with the sequence drawn before the lock, ordinary
concurrent traffic forks the chain (reproduced on 2026-10-03: four writers in
parallel forked it in 8 rounds of 10), and the dead-end row of a fork can be
deleted with the answer still `intact`.

0153 takes the lock first, draws the sequence inside it and reads the true
tail, and refuses a transaction that is not READ COMMITTED (the one level at
which that tail read is stale, and one a request may choose for itself,
verify:g37 tail-read-isolation, 2026-10-03), so nothing honest forks the
chain, and the verifier splits the forks by age:

- a fork whose claimant was written before the boundary row 0153 appended
  (`AUDIT_CHAIN_SERIALISED`, the latest of them) is history: reported,
  listed, and not counted, because the table is append-only and a deployment
  cannot clean it;
- a fork claimed by a row newer than the boundary is a FORK break and turns
  `intact` False.

A database born at 0153 has no boundary row and no older rows, and every
fork in it counts.

## What `intact` cannot see, and what to do about it

Every check here is relative: a row is accused because another row
disagrees with it. Two things leave nothing to disagree with:

- **Rows removed from the END.** Nothing names the newest row as its
  predecessor, so deleting the last k rows orphans nothing. One DELETE, no
  hashing, and the answer is `intact`.
- **A re-chain.** The hash is plain SHA-256 and its expression is in this
  repository, so whoever owns the database can edit row k and recompute
  every later hash. The result agrees with itself.

Both need rights on the table that the runtime role does not hold, but the
schema owner's password still reaches the runtime services (docs/17 F52).
The defence has to live where the owner cannot reach: record
`ChainReport.tail_seq` and `tail_row_hash` somewhere this database cannot
(a ticket, a signed message, an operator's notebook; `scripts/audit_anchor.py`
prints them) and pass them back as `anchor`. The check then fails with a
`ANCHOR` break if the row at that seq is gone or its hash changed, which a
truncation below it and a re-chain through it both do. Rows newer than the
anchor are covered by the next one: record a new anchor on a schedule.
Until somebody does, `intact` means only that the rows present agree with
each other, and `BLIND_SPOTS` is what every answer says so in words.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

#: A row hash as `encode(row_hash, 'hex')` renders it.
_HEX_HASH = re.compile(r"[0-9a-f]{64}")

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
    #: None only for NO_GENESIS, which is a finding about a row that is
    #: NOT THERE and therefore has no timestamp to report.
    occurred_at: datetime | None
    action: str
    #: LINK / FORK / CONTENT, '+'-joined when several. Plus the two
    #: whole-chain findings, which describe the chain rather than a row:
    #: GENESIS (more than one row claims to be first) and NO_GENESIS (a
    #: non-empty chain has no first row).
    kind: str
    actor_id: UUID | None
    case_id: UUID | None


#: The action of the row 0153 appends, on a database that already had audit
#: rows, when the chain started drawing its sequence inside the lock. The
#: latest such row is the fork boundary.
FORK_MARKER_ACTION = "AUDIT_CHAIN_SERIALISED"

#: What `intact` does not say. Part of every answer, the endpoint's and the
#: console's, so the green tick is never read as more than it is.
BLIND_SPOTS = (
    "Intact means the rows that are here agree with each other. It cannot "
    "see rows removed from the end of the log, and it cannot see a rewrite "
    "that recomputes every later hash: the hash is unkeyed, and whoever "
    "owns the database can recompute it. Record tail_seq and tail_row_hash "
    "somewhere this database cannot reach, and pass them back as anchor_seq "
    "and anchor_hash on a later check. The check then fails if the row at "
    "that seq is gone or has changed."
)


@dataclass(frozen=True)
class AnchorCheck:
    """A recorded anchor and whether the log still holds it."""
    seq: int
    row_hash: str
    held: bool


@dataclass(frozen=True)
class ChainReport:
    checked: int
    #: Evidence of TAMPERING: LINK (a predecessor removed), CONTENT (a row
    #: edited), a FORK claimed by a row newer than `fork_boundary_seq`, and
    #: an ANCHOR that no longer holds. These are what `intact` is about.
    breaks: tuple[ChainBreak, ...]
    #: Every row sharing a predecessor, old and new. The ones newer than
    #: the boundary are also in `breaks`; the older ones are history.
    forks: tuple[ChainBreak, ...]
    first_seq: int | None
    last_seq: int | None
    #: How many rows claim to be the chain's first. Surfaced even when it
    #: is 1 -- like `checked` -- so a caller can tell "anchored" from
    #: "nobody looked", which a bare `intact` cannot express.
    genesis_count: int = 0
    #: Whole table, whatever window was asked for: how many rows, and the
    #: newest one's seq and hash (hex). The value to record out of band
    #: (`BLIND_SPOTS`).
    rows: int = 0
    tail_seq: int | None = None
    tail_row_hash: str | None = None
    #: The seq of the row 0153 appended, or 0 on a database born after it.
    #: A fork claimed by a row newer than this is a break.
    fork_boundary_seq: int = 0
    #: The anchor the caller supplied and whether it held, else None.
    anchor: AnchorCheck | None = None

    @property
    def intact(self) -> bool:
        """The rows examined agree with each other and with every anchor
        supplied.

        NOT "nothing was removed". Rows deleted from the end of the log, and
        a rewrite that recomputes every later hash, leave a chain that
        agrees with itself (see `BLIND_SPOTS` and the module docstring);
        only an anchor recorded outside the database tells them apart.

        A fork is a break when a row written since 0153 claims a
        predecessor another row also claims, because the chain trigger
        reads the tail inside its lock, refuses a transaction that is not
        READ COMMITTED, and honest traffic cannot do that.
        A fork between rows written before 0153 is history, reported in
        `forks` and not counted: the table is append-only, and counting it
        would answer BROKEN on a chain nobody tampered with.

        An EMPTY audit table returns True, and the caller is expected to
        read `checked` too: a fresh database genuinely has an intact
        (empty) chain, and returning False would make first-run CI red for
        a correct system. The endpoint reports `checked` alongside so
        "verified" can never be read as "verified something".
        """
        return not self.breaks

    @property
    def forks_since_fix(self) -> int:
        """How many of `forks` are newer than the boundary (the ones that
        are breaks)."""
        return sum(1 for f in self.forks if f.seq > self.fork_boundary_seq)


def verify_chain(
    conn: psycopg.Connection,
    *,
    limit: int | None = None,
    since_seq: int | None = None,
    anchor: tuple[int, str] | None = None,
    fork_boundary_seq: int | None = None,
) -> ChainReport:
    """Recompute the chain and return every row that does not verify.

    `limit` checks only the most recent N rows, and every check is EXACT
    for the rows it reports: the predecessor and fork lookups run over the
    whole table, not the window, so a windowed run cannot produce a false
    orphan at its own boundary. What a window does not tell you is whether
    rows outside it verify. (An earlier version built those lookups from
    the window and had a boundary blind spot, and accused the oldest row of
    every windowed run; both are gone.)

    `anchor` is a (seq, hex row_hash) pair the caller recorded from an
    earlier run's `tail_seq` and `tail_row_hash`. When the log no longer
    holds that row, an ANCHOR break is added: a truncation below it and a
    re-chain through it both leave a log that disagrees with the record.

    `fork_boundary_seq` overrides the boundary the log carries (the
    `AUDIT_CHAIN_SERIALISED` row; 0 when there is none). Tests use it; the
    endpoint does not.

    Ordering is by `seq`, never by `occurred_at`: a clock adjustment must
    not be able to reorder the verification.
    """
    if anchor is not None:
        anchor_seq, anchor_hash = anchor
        if not _HEX_HASH.fullmatch(anchor_hash or ""):
            raise ValueError("an anchor hash is 64 lower-case hex characters")
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

    # The genesis anchor: where does the chain START? Every check above is
    # relative, and the LINK check exempts a NULL predecessor by
    # construction, so a row inserted with `prev_hash NULL` is an unlinked
    # island that passes every one of them (the CONTENT check even blesses
    # it, because its hash input is the literal 'GENESIS'). Two rows
    # claiming to be first is the shape of a truncation: delete the first k
    # rows, re-genesis row k+1, and the chain reads intact.
    #
    # Queried over the WHOLE table and reported at REPORT level, never per
    # row: the true genesis is almost never inside a `limit` window, so a
    # windowed check would answer "no genesis" on every windowed run, a
    # false accusation this module has already made twice.
    genesis = conn.execute(
        "SELECT seq, occurred_at, action, actor_id, case_id "
        "FROM audit.event WHERE prev_hash IS NULL ORDER BY seq").fetchall()
    total = conn.execute("SELECT count(*) FROM audit.event").fetchone()[0]
    # The newest row of the WHOLE log, scoped never: the value to record out
    # of band (BLIND_SPOTS).
    tail = conn.execute(
        "SELECT seq, encode(row_hash, 'hex') FROM audit.event "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    boundary = fork_boundary_seq
    if boundary is None:
        boundary = conn.execute(
            "SELECT coalesce(max(seq), 0) FROM audit.event "
            "WHERE action = %s AND object_type = 'audit'",
            (FORK_MARKER_ACTION,)).fetchone()[0]

    if total and not genesis:
        # The first row is gone. Nothing else can detect this: every
        # surviving row still links to a real predecessor.
        breaks.append(ChainBreak(
            seq=0, occurred_at=None, action="(chain has no first row)",
            kind="NO_GENESIS", actor_id=None, case_id=None))
    elif len(genesis) > 1:
        # Not reachable by honest traffic: the trigger writes a NULL
        # predecessor only into an empty table, under the advisory lock,
        # and no application code writes prev_hash at all. So it goes in
        # `breaks` and turns `intact` False.
        for g_seq, g_at, g_action, g_actor, g_case in genesis:
            breaks.append(ChainBreak(
                seq=g_seq, occurred_at=g_at, action=g_action,
                kind="GENESIS", actor_id=g_actor, case_id=g_case))

    for seq, occurred_at, action, actor_id, case_id, link, fork, content in rows:
        if not (link or fork or content):
            continue
        parts = []
        if link:
            parts.append("LINK")
        if content:
            parts.append("CONTENT")
        # A fork claimed by a row written since 0153 is a break: the chain
        # trigger reads the tail inside its lock and refuses any transaction
        # that is not READ COMMITTED (the stale-tail level a request could
        # choose), so nothing honest does this. A fork between older rows is
        # history (see `intact`).
        if fork and seq > boundary:
            parts.append("FORK")
        if parts:
            breaks.append(ChainBreak(
                seq=seq, occurred_at=occurred_at, action=action,
                kind="+".join(parts), actor_id=actor_id, case_id=case_id))
        if fork:
            forks.append(ChainBreak(
                seq=seq, occurred_at=occurred_at, action=action, kind="FORK",
                actor_id=actor_id, case_id=case_id))

    anchor_check = None
    if anchor is not None:
        held = conn.execute(
            "SELECT EXISTS (SELECT 1 FROM audit.event "
            "WHERE seq = %s AND row_hash = decode(%s, 'hex'))",
            (anchor_seq, anchor_hash)).fetchone()[0]
        anchor_check = AnchorCheck(anchor_seq, anchor_hash, bool(held))
        if not held:
            # Either the row is gone (a truncation below the anchor) or its
            # hash changed (a re-chain through it): the log no longer
            # matches what was recorded.
            breaks.append(ChainBreak(
                seq=anchor_seq, occurred_at=None,
                action="(the recorded anchor row is missing or has changed)",
                kind="ANCHOR", actor_id=None, case_id=None))

    return ChainReport(
        checked=len(rows),
        breaks=tuple(breaks),
        forks=tuple(forks),
        first_seq=rows[0][0] if rows else None,
        last_seq=rows[-1][0] if rows else None,
        genesis_count=len(genesis),
        rows=total,
        tail_seq=tail[0] if tail else None,
        tail_row_hash=tail[1] if tail else None,
        fork_boundary_seq=boundary,
        anchor=anchor_check,
    )
