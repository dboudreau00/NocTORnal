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

**The expression below is duplicated from 0013 (restated by 0149) and must
stay in step with it.** That duplication is deliberate: the alternative is
calling the trigger function, which cannot be invoked outside an INSERT.
`test_audit_verify_pg.py` guards the coupling: it writes real events and
asserts the chain verifies, so any future edit to the trigger that this
file does not match turns the suite red rather than silently reporting
corruption.

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

## `seq` ORDER WAS NOT CHAIN ORDER until 0149, and assuming it was made this
## verifier report 68 breaks on an honest database

The first version of this module checked the link by comparing each row's
`prev_hash` to `LAG(row_hash) OVER (ORDER BY seq)`. That is wrong for
history written before 0149, and it was wrong in the most damaging
direction available to a tamper-evidence tool: it accused intact history.

`audit.event.seq` is a `bigserial`. Until 0149 its value came from
`nextval()` when the row was constructed, which happens **before** the
BEFORE-INSERT trigger runs and therefore before `audit.chain_hash()` took
its advisory lock. So two concurrent writers could be handed seq 7445 and
7446, then acquire the lock in the opposite order, and the row holding the
LOWER seq chained off the row holding the HIGHER one. Nothing was corrupt;
the linked list was perfectly sound; the numbering simply did not follow it.

Observed on the development database: 60,181 rows, 68 reported "breaks",
every one of them a pair of adjacent AUTH_FAILED rows whose seq order and
chain order disagreed. Had this shipped, the first person to run it would
have been told the audit trail was tampered with, and the second would
have learned to ignore the tool.

So the link is verified as what it actually is, **a linked list**, by
following `prev_hash` to a real `row_hash` rather than to a positional
neighbour. `seq` is used for reporting, windowing and the fork boundary.

## A FORK before the boundary is legacy; a FORK after it is a break

Two rows claiming one predecessor is what the advisory lock exists to
prevent. Until 0149 it did not, because `seq` was drawn before the lock and
the next writer picks the HIGHEST seq as its predecessor: an inverted pair
left a dead-end row, and the pair of rows that claimed one predecessor was a
fork. They came from ordinary traffic. The review of 2026-10-03 found ten on
an ordinary test run, and an earlier correction of this module (2026-08-10)
that called a fork "not known to be reachable by ordinary traffic" was wrong
a second time: it measured the lock, not the choice of tail.

Since 0149 the trigger takes the lock and THEN draws the number and reads the
tail, so number order is chain order and a fork cannot come from honest
traffic. `audit.chain_ordered_after()` records the largest seq that existed
when 0149 ran. A fork whose claimants are all above it is reported as a
`FORK` break and makes `intact` false. A fork with a claimant at or below it
is legacy: an append-only table cannot be cleaned of it, so it stays a
separate count and does not make `intact` false. A deployment that has never
run 0149 has no boundary and every fork is legacy. Why that matters: a
dead-end row is one whose removal orphans nothing, so with the table owner's
rights it could be deleted and the verifier would still answer intact. After
the boundary a dead end cannot arise, so a fork is evidence.

## What this cannot see

Every check here is relative: a row is accused because another row disagrees
with it. Nothing names the newest row as a predecessor, so rows removed from
the END of the log orphan nothing, and a run of rows edited and then
re-chained with fresh hashes (plain SHA-256, the expression is in this file)
is self-consistent. Both need the table owner's rights, which the runtime
holds in a development stack and which F52 in docs/17 records for a
production one. The defence is an anchor recorded where this system cannot
write: `tail_seq` and `tail_row_hash` from one run, handed back as a
`ChainAnchor` on a later run. A row that was removed or rewritten since is
then reported as an `ANCHOR_*` break. A run without an anchor is no better
protected than before, and says so in its caveat.
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
    #: None only for NO_GENESIS, which is a finding about a row that is
    #: NOT THERE and therefore has no timestamp to report.
    occurred_at: datetime | None
    action: str
    #: LINK / CONTENT, '+'-joined when both. FORK for a fork whose claimants
    #: are all above the 0149 boundary (see `ChainReport.forks`). The
    #: whole-chain findings, which describe the chain rather than a row:
    #: GENESIS (more than one row claims to be first) and NO_GENESIS (a
    #: non-empty chain has no first row). And the anchor findings, which
    #: name the row an operator recorded: ANCHOR_MISSING (no row has that
    #: seq or that hash), ANCHOR_REWRITTEN (the row at that seq has another
    #: hash) and ANCHOR_MOVED (the hash is in the table at another seq).
    kind: str
    actor_id: UUID | None
    case_id: UUID | None


@dataclass(frozen=True)
class ChainAnchor:
    """The newest row's `seq` and hex `row_hash` from an earlier run, kept
    somewhere this system cannot write. Hand it back to `verify_chain` to
    learn whether that row, and so everything before it, is still here."""
    seq: int
    row_hash: str

    def __post_init__(self) -> None:
        if (len(self.row_hash) != 64
                or any(c not in "0123456789abcdef" for c in self.row_hash)):
            raise ValueError("an anchor hash is 64 lowercase hex characters")


@dataclass(frozen=True)
class AnchorResult:
    """What became of a recorded anchor."""
    anchor: ChainAnchor
    #: HELD (the row is here, at its seq), MISSING (no row has that hash and
    #: none has that seq: removed, or the tail was cut back past it),
    #: REWRITTEN (a row with that seq has another hash: edited and
    #: re-chained) or MOVED (that hash is here under another seq).
    status: str
    #: The seq the anchored hash was found at, or None.
    found_seq: int | None
    #: Rows written after the anchor, for HELD; None otherwise.
    rows_since: int | None


@dataclass(frozen=True)
class ChainReport:
    checked: int
    #: Evidence of TAMPERING: LINK (a predecessor removed), CONTENT (a row
    #: edited), FORK above the boundary, GENESIS, NO_GENESIS and a failed
    #: anchor. These are what `intact` is about.
    breaks: tuple[ChainBreak, ...]
    #: Every row that shares a predecessor with another, legacy and new.
    #: Those with a claimant at or below `fork_boundary` are left over from
    #: before 0149 and are NOT counted as tampering, see `intact`; a fork
    #: whose claimants are all above it is also in `breaks`.
    forks: tuple[ChainBreak, ...]
    first_seq: int | None
    last_seq: int | None
    #: How many rows claim to be the chain's first. Surfaced even when it
    #: is 1 -- like `checked` -- so a caller can tell "anchored" from
    #: "nobody looked", which a bare `intact` cannot express.
    genesis_count: int = 0
    #: The newest row in the WHOLE table, windowed run or not: the row the
    #: trigger would chain the next insert onto, and so the value to record
    #: out of band. None on an empty table.
    tail_seq: int | None = None
    tail_row_hash: str | None = None
    #: Rows in the whole table.
    total_rows: int = 0
    #: `audit.chain_ordered_after()`: the largest seq that existed when 0149
    #: ran, or None on a database that has not run it.
    fork_boundary: int | None = None
    #: What became of the anchor the caller supplied, or None when it
    #: supplied none.
    anchor: AnchorResult | None = None

    @property
    def intact(self) -> bool:
        """No evidence of TAMPERING among the rows examined.

        ## A fork is a break only after the 0149 boundary

        A fork is two rows claiming one predecessor. Until 0149 ordinary
        concurrent traffic made them (the sequence number was drawn before
        the chain lock, so an inverted pair left a dead-end row), and an
        append-only table cannot be cleaned of the ones it holds. Counting
        those as breaks made `/audit/verify` answer BROKEN on untampered
        history, the failure that taught this module twice already to
        separate what is evidence from what is noise.

        Since 0149 the trigger draws the number inside the lock, so a fork
        whose claimants are ALL above `fork_boundary` cannot come from honest
        traffic and is in `breaks` as a FORK: a dead-end row is exactly what
        an owner can delete without orphaning anything. A fork with a
        claimant at or below the boundary is legacy and is only listed in
        `forks`. On a database that has not run 0149 there is no boundary and
        every fork is legacy.

        `intact` is also about LINK and CONTENT (a row removed, a row
        edited), GENESIS and NO_GENESIS, and, when the caller supplied one, a
        failed anchor.

        NOT "nothing was removed from the end", and not "nothing was
        re-chained": every check but the anchor is relative. See "What this
        cannot see" in the module docstring, and `tail_row_hash`.

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
    anchor: ChainAnchor | None = None,
) -> ChainReport:
    """Recompute the chain and return every row that does not verify.

    `anchor` is a `(seq, row_hash)` the operator recorded from an earlier
    run. When given, the report says whether that row is still in the table
    at that seq with that hash (`AnchorResult.status`), and a row that is
    not turns `intact` false: that is the only check here that can see rows
    removed from the end, or edited and re-chained. Without one the report
    carries `tail_seq` and `tail_row_hash` for the operator to record and
    is no better protected than before.

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
        SELECT prev_hash, COUNT(*) AS claimants, MIN(seq) AS lowest
          FROM audit.event WHERE prev_hash IS NOT NULL
         GROUP BY prev_hash
    )
    -- LEFT JOINs, not correlated subqueries. The first version used
    -- `NOT EXISTS (SELECT ... FROM windowed p WHERE p.row_hash = ...)`,
    -- which Postgres evaluates per row: on the 60,181-row development
    -- table that did not finish inside two minutes. As joins the planner
    -- hashes each side once and the same check runs in well under a
    -- second.
    , judged AS MATERIALIZED (
    SELECT w.seq, w.occurred_at, w.action, w.actor_id, w.case_id,
           -- ORPHAN: names a predecessor that is not in the window at all.
           -- The genesis row (prev_hash NULL) is exempt by construction.
           (w.prev_hash IS NOT NULL AND h.row_hash IS NULL) AS link_broken,
           -- FORK: this row's predecessor is claimed by more than one row.
           -- Both claimants are reported; which one is the intruder is not
           -- something this can decide, and pretending otherwise would be
           -- worse than naming both.
           COALESCE(c.claimants > 1, false) AS forked,
           COALESCE(c.claimants > 1 AND c.lowest > %(boundary)s::bigint, false)
               AS fresh_fork,
           (w.row_hash IS DISTINCT FROM w.recomputed) AS content_broken
      FROM windowed w
      LEFT JOIN hashes h ON h.row_hash = w.prev_hash
      LEFT JOIN claims c ON c.prev_hash = w.prev_hash
    )
    -- Only the rows that do not verify leave the database, beside the
    -- count and the span of what was checked (2026-10-07): every row
    -- came back to Python, 380 MB and 35 seconds of the API process for a
    -- 1.5 million row log. One summary row always, even with nothing wrong.
    SELECT s.checked, s.first_seq, s.last_seq,
           f.seq, f.occurred_at, f.action, f.actor_id, f.case_id,
           f.link_broken, f.forked, f.fresh_fork, f.content_broken
      FROM (SELECT count(*) AS checked, min(seq) AS first_seq,
                   max(seq) AS last_seq FROM judged) s
      LEFT JOIN LATERAL (
           SELECT * FROM judged
            WHERE link_broken OR forked OR content_broken) f ON true
     ORDER BY f.seq
    """
    # `fresh_fork` in the query is a fork whose claimants are ALL above the
    # 0149 boundary: honest traffic cannot make one. No boundary, no such fork.
    boundary = _fork_boundary(conn)
    params: dict = {"boundary": boundary}
    if since_seq is not None:
        params["since"] = since_seq
    if limit is not None:
        params["limit"] = limit

    summary = conn.execute(sql, params).fetchall()
    checked, first_seq, last_seq = summary[0][:3]
    # The rows that did not verify; a run with none answers the summary row
    # alone, with no row columns.
    rows = [r[3:] for r in summary if r[3] is not None]
    breaks: list[ChainBreak] = []
    forks: list[ChainBreak] = []

    # ── the anchor ────────────────────────────────────────────────────
    #
    # Every check above is RELATIVE: it asks whether each row agrees with
    # its predecessor. None of them asks where the chain STARTS, and the
    # LINK check exempts a NULL predecessor by construction -- so a row
    # inserted with `prev_hash NULL` is an unlinked island that passes
    # every test, and the CONTENT check actively blesses it, because the
    # hash input for such a row is the literal string 'GENESIS' (see
    # `_HASH_EXPR`). The fork check cannot see it either: it filters
    # `prev_hash IS NOT NULL`, and SQL NULL never equals NULL in the join.
    #
    # Two rows claiming to be first is therefore invisible today, and that
    # is the shape of a truncation: delete the first k rows, re-genesis row
    # k+1, and the chain reports INTACT with history simply starting later.
    #
    # This is queried over the WHOLE table and reported at REPORT level,
    # never per-row, for the same reason `hashes` and `claims` are
    # whole-table: the true genesis is almost never inside a `limit`
    # window, so a windowed check would answer "no genesis" on every
    # windowed run -- the false accusation this module has already made
    # twice and cannot afford a third time.
    genesis = conn.execute(
        "SELECT seq, occurred_at, action, actor_id, case_id "
        "FROM audit.event WHERE prev_hash IS NULL ORDER BY seq").fetchall()
    total = conn.execute("SELECT count(*) FROM audit.event").fetchone()[0]

    if total and not genesis:
        # The first row is gone. Nothing else can detect this: every
        # surviving row still links to a real predecessor.
        breaks.append(ChainBreak(
            seq=0, occurred_at=None, action="(chain has no first row)",
            kind="NO_GENESIS", actor_id=None, case_id=None))
    elif len(genesis) > 1:
        # Unlike a fork, this is NOT reachable by honest traffic: 0013
        # writes a NULL predecessor only into an empty table, under the
        # advisory lock, and no application code writes prev_hash at all.
        # So it goes in `breaks` and turns `intact` False.
        for g_seq, g_at, g_action, g_actor, g_case in genesis:
            breaks.append(ChainBreak(
                seq=g_seq, occurred_at=g_at, action=g_action,
                kind="GENESIS", actor_id=g_actor, case_id=g_case))

    for seq, occurred_at, action, actor_id, case_id, link, fork, fresh, content in rows:
        parts = []
        if link:
            parts.append("LINK")
        if content:
            parts.append("CONTENT")
        if parts:
            breaks.append(ChainBreak(
                seq=seq, occurred_at=occurred_at, action=action,
                kind="+".join(parts), actor_id=actor_id, case_id=case_id))
        if fork:
            row = ChainBreak(
                seq=seq, occurred_at=occurred_at, action=action, kind="FORK",
                actor_id=actor_id, case_id=case_id)
            forks.append(row)
            # A fork written since 0149 is a break (see ChainReport.intact);
            # one with a claimant at or below the boundary is legacy and
            # stays a separate, quieter finding.
            if fresh:
                breaks.append(row)

    # The tail of the WHOLE table, `ORDER BY seq DESC LIMIT 1` being how the
    # trigger picks the next predecessor. Reported on every run, windowed or
    # not, so the operator always has something to record.
    tail = conn.execute(
        "SELECT seq, encode(row_hash, 'hex') FROM audit.event "
        "ORDER BY seq DESC LIMIT 1").fetchone()

    result = None
    if anchor is not None:
        result = _check_anchor(conn, anchor)
        if result.status != "HELD":
            breaks.append(ChainBreak(
                seq=anchor.seq, occurred_at=None, action="(anchored row)",
                kind="ANCHOR_" + result.status, actor_id=None, case_id=None))

    return ChainReport(
        checked=checked,
        breaks=tuple(breaks),
        forks=tuple(forks),
        first_seq=first_seq,
        last_seq=last_seq,
        genesis_count=len(genesis),
        tail_seq=tail[0] if tail else None,
        tail_row_hash=tail[1] if tail else None,
        total_rows=total,
        fork_boundary=boundary,
        anchor=result,
    )


def _fork_boundary(conn: psycopg.Connection) -> int | None:
    """`audit.chain_ordered_after()`, or None on a database that has not run
    0149. Asked in two steps because a call to a function that does not exist
    fails when the statement is parsed, branch taken or not."""
    present = conn.execute(
        "SELECT to_regprocedure('audit.chain_ordered_after()') IS NOT NULL"
    ).fetchone()[0]
    if not present:
        return None
    return conn.execute("SELECT audit.chain_ordered_after()").fetchone()[0]


def _check_anchor(conn: psycopg.Connection, anchor: ChainAnchor) -> AnchorResult:
    """Is the recorded row still here, where it was?

    Rows before it cannot have changed without changing its hash (each hash
    covers its predecessor's), so a HELD anchor vouches for everything up to
    it. It says nothing about rows after it: record a newer one."""
    seqs = [r[0] for r in conn.execute(
        "SELECT seq FROM audit.event WHERE row_hash = decode(%s, 'hex') "
        "ORDER BY seq", (anchor.row_hash,)).fetchall()]
    if anchor.seq in seqs:
        since = conn.execute(
            "SELECT count(*) FROM audit.event WHERE seq > %s",
            (anchor.seq,)).fetchone()[0]
        return AnchorResult(anchor, "HELD", anchor.seq, since)
    if seqs:
        return AnchorResult(anchor, "MOVED", seqs[0], None)
    there = conn.execute(
        "SELECT 1 FROM audit.event WHERE seq = %s", (anchor.seq,)).fetchone()
    return AnchorResult(anchor, "REWRITTEN" if there else "MISSING", None, None)
