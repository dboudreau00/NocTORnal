"""Re-compute the `audit.event` hash chain and report where it breaks.

Migration 0013 chains every row: `row_hash` covers the predecessor's hash and every payload column,
under an advisory lock. Tamper evidence nobody examines is a claim rather than a control (docs/09),
so this module checks it.

The recompute runs in SQL because the trigger's hash input is a Postgres expression Python cannot
reproduce faithfully (jsonb's own text rendering, `concat_ws` NULL-skipping, `to_char`
microseconds). The expression below is duplicated from 0013 (restated by 0149) and must stay in step
with it, because the trigger function cannot be called outside an INSERT; `test_audit_verify_pg.py`
guards the coupling. A verifier that disagrees with the writer is worse than none: false alarms
teach people to ignore it.

The checks are separate because they mean different things: CONTENT (a row's hash does not match its
own columns: edited in place), LINK (a `prev_hash` names no row: a predecessor removed) and FORK
(two rows claim one predecessor: a row inserted, or writers that raced). The link is verified by
following `prev_hash` to a real `row_hash`, never by `seq` adjacency, because before 0149 `seq`
order was not chain order and a positional check accused intact history.

A fork whose claimants are all above the 0149 boundary (`audit.chain_ordered_after()`, the largest
seq that existed when 0149 ran) is a `FORK` break: since 0149 the trigger draws the number inside
the lock, so honest traffic cannot fork, and a dead-end row is exactly what an owner could delete
without orphaning anything. An older fork is legacy: an append-only table cannot be cleaned of it,
so it is counted apart and does not make `intact` false. Without a boundary every fork is legacy.

What this cannot see: every check is relative, so rows removed from the end of the log orphan
nothing, and rows edited and re-chained with fresh hashes (plain SHA-256) are self-consistent. Both
need the table owner's rights, which the runtime holds in a development stack (docs/17 records the
production one). The defence is an anchor recorded where this system cannot write: `tail_seq` and
`tail_row_hash` from one run, handed back as a `ChainAnchor` on a later run, so a row removed or
rewritten since is an `ANCHOR_*` break. A run without an anchor is no better protected and says so
in its caveat.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

#: The canonical hash input, character-for-character from `audit.chain_hash()` in 0013, with the row
#: alias in place of `NEW.`. `prev_hash` is the stored value, because that is what the trigger
#: hashed: the link check below catches a wrong stored value.
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
    #: None only for NO_GENESIS, which reports a row that is not there and so has no timestamp.
    occurred_at: datetime | None
    action: str
    #: LINK or CONTENT ('+'-joined when both); FORK for a fork whose claimants are all above the
    #: 0149 boundary (see `ChainReport.forks`). Whole-chain kinds describe the chain rather than a
    #: row: GENESIS (more than one row claims to be first) and NO_GENESIS (a non-empty chain has no
    #: first row). Anchor kinds name the row an operator recorded: ANCHOR_MISSING (no row has that
    #: seq or that hash), ANCHOR_REWRITTEN (the row at that seq has another hash) and ANCHOR_MOVED
    #: (the hash is in the table at another seq).
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
        """No evidence of tampering among the rows examined.

        A fork counts as a break only after the 0149 boundary: one whose claimants are all above
        `fork_boundary` cannot come from honest traffic and is in `breaks` as a FORK, while one with
        a claimant at or below it is legacy and only listed in `forks`. Counting legacy forks as
        breaks would make `/audit/verify` answer BROKEN on untampered history. Without a boundary
        (0149 never ran) every fork is legacy. `intact` is also about LINK and CONTENT, GENESIS and
        NO_GENESIS and, when the caller supplied one, a failed anchor.

        It does not mean "nothing was removed from the end" or "nothing was re-chained": every check
        but the anchor is relative. See "What this cannot see" in the module docstring, and
        `tail_row_hash`.

        An empty audit table returns True and the caller is expected to read `checked` too: a fresh
        database genuinely has an intact (empty) chain, and returning False would make first-run CI
        red for a correct system. The endpoint reports `checked` alongside so "verified" is never
        read as "verified something".
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

    `anchor` is a `(seq, row_hash)` the operator recorded from an earlier run. When given, the
    report says whether that row is still in the table at that seq with that hash
    (`AnchorResult.status`), and a row that is not turns `intact` false: that is the only check here
    that can see rows removed from the end, or edited and re-chained. Without one the report carries
    `tail_seq` and `tail_row_hash` for the operator to record and is no better protected.

    `limit` checks only the most recent N rows, and every check is exact for the rows it reports:
    the predecessor and fork lookups run over the whole table, not the window, so a windowed run
    cannot produce a false orphan at its own boundary. What a window does not tell you is whether
    rows outside it verify.

    Ordering is by `seq`, the chain's own order, never by `occurred_at`: a clock adjustment must not
    be able to reorder the verification.
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

    # Where the chain starts. Every check above is relative: it asks whether each row agrees with
    # its predecessor, and none asks where the chain begins. The LINK check exempts a NULL
    # predecessor by construction, so a row inserted with `prev_hash NULL` is an unlinked island
    # that passes every test, and the CONTENT check blesses it because its hash input is the literal
    # string 'GENESIS' (see `_HASH_EXPR`). The fork check cannot see it either: it filters
    # `prev_hash IS NOT NULL`, and SQL NULL never equals NULL in the join.
    #
    # Two rows claiming to be first is the shape of a truncation: delete the first k rows,
    # re-genesis row k+1, and the chain reports INTACT with history simply starting later.
    #
    # Queried over the whole table and reported at report level, never per row, like `hashes` and
    # `claims`: the true genesis is almost never inside a `limit` window, so a windowed check would
    # answer "no genesis" on every windowed run.
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
            # A fork written since 0149 is a break (see ChainReport.intact); one with a claimant at
            # or below the boundary is legacy and stays a separate, quieter result.
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
    """Is the recorded row still here, at the seq recorded?

    Rows before it cannot have changed without changing its hash (each hash covers its
    predecessor's), so a held anchor vouches for everything up to it. It says nothing about rows
    after it: record a newer one."""
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
