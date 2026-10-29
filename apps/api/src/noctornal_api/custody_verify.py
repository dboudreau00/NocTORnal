"""Re-compute the `core.evidence_custody` hash chain and report where it breaks.

Migration 0024 hash-chains the custody ledger: each row's `row_hash` covers its predecessor's hash
and every payload column, under an advisory lock, so a record like this can be admitted on the
strength of its own integrity mechanism (US FRE 902(13)-(14), Canada Evidence Act ss. 31.1-31.8).
This is the verifier, ported from `audit_verify.py`.

The chain is GLOBAL: `core.custody_chain_hash()` picks its predecessor with `ORDER BY id DESC LIMIT
1` over the whole table, so a row's predecessor is almost always another exhibit's. `evidence_id`
therefore narrows the REPORT, never the lookups (the predecessor set, the fork census and the
genesis count are whole-table), or every row of one exhibit would be reported as an orphan. A scoped
`intact` speaks only for the rows reported, and the endpoint says so in its caveat.

The recompute is in SQL, not Python, so it agrees with the writer on jsonb's canonical text,
`concat_ws` NULL semantics, microsecond rendering and `true`/`false`: a verifier that disagrees
reports tampering on an intact chain. `_HASH_EXPR` is duplicated from 0024 and must stay in step
with it; `test_custody_verify_pg.py` writes real rows through the trigger and asserts the chain
verifies.

`id` order is chain order only from 0149. Before it, `nextval()` ran before the trigger took the
lock, so the row with the LOWER id could chain off the HIGHER one. The link is therefore verified as
a linked list (`prev_hash` to a real `row_hash`), and `id` is used for reporting, ordering and the
fork boundary. `core.custody_chain_ordered_after()` is the largest id that existed when 0149 ran: a
fork whose claimants are all above it cannot come from honest traffic and is a `FORK` break; one
with a claimant at or below it is legacy, listed and not counted as tampering (see
`audit_verify.ChainReport.intact`). After the boundary a dead-end row, whose deletion would orphan
nothing, cannot arise.

Checks: CONTENT (`row_hash` is not what the row's columns hash to: edited in place); LINK
(`prev_hash` names no row: a predecessor removed); FORK; GENESIS / NO_GENESIS (exactly one row
claims to be first; more is what a truncation leaves, none means the first row is gone, and no
application code writes `prev_hash`).

Of the three positions a row can be deleted from, the MIDDLE is caught (LINK, raised on its orphaned
successor), the FIRST is caught (NO_GENESIS), and the LAST is not caught at all. An edit in place is
caught (CONTENT), and a removed or duplicated anchor is caught (NO_GENESIS / GENESIS).

What it cannot see: every check is RELATIVE, so a TAIL DELETION orphans nothing and reads
`intact=True` with only `checked` moving. It costs one DELETE and no hashing, and the tail is what
an export or a destruction writes last. A pure renumbering is invisible too (`id` is not
hashed), and so is a re-chaining attack (edit row k, recompute every hash to the tail). All three want an
EXTERNAL ANCHOR: `CustodyReport.tail_id` and `tail_row_hash` are the values to record out of band
and hand back as a `CustodyAnchor`, which turns a removed or rewritten anchored row into an
`ANCHOR_*` break. This module does not persist them, and until somebody does a tail deletion goes
undetected and every report says so. 0024's own docstring claims a deleted or reordered row is
detectable on replay; that does not hold for a tail deletion or a reordering, and this module does
not inherit the claim.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

#: The canonical hash input, character-for-character from `core.custody_chain_hash()` in 0024, with
#: `NEW.` replaced by the row alias `c` and the trigger's `prev` variable by the STORED `prev_hash`,
#: because that is what the trigger hashed. The link check is what catches a wrong stored value.
_HASH_EXPR = """
public.digest(
  convert_to(concat_ws(chr(31),
    coalesce(encode(c.prev_hash,'hex'),'GENESIS'),
    c.evidence_id::text,
    c.action,
    coalesce(c.actor_id::text,'-'),
    to_char(c.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    c.detail::text,
    coalesce(c.hash_verified::text,'-')
  ), 'UTF8'),
  'sha256')
"""


@dataclass(frozen=True)
class CustodyBreak:
    """One custody row that does not verify."""
    id: int
    #: None only for NO_GENESIS, which is a finding about a row that is NOT THERE and so has no
    #: exhibit to name.
    evidence_id: UUID | None
    occurred_at: datetime | None
    action: str
    #: LINK / CONTENT, '+'-joined when both; FORK for a fork whose claimants
    #: are all above the 0149 boundary (all forks are listed in `forks`);
    #: GENESIS and NO_GENESIS for the whole-chain findings; and the anchor
    #: findings ANCHOR_MISSING, ANCHOR_REWRITTEN and ANCHOR_MOVED.
    kind: str
    actor_id: UUID | None


@dataclass(frozen=True)
class CustodyAnchor:
    """The newest custody row's `id` and hex `row_hash` from an earlier run,
    kept somewhere this system cannot write."""
    id: int
    row_hash: str

    def __post_init__(self) -> None:
        if (len(self.row_hash) != 64
                or any(c not in "0123456789abcdef" for c in self.row_hash)):
            raise ValueError("an anchor hash is 64 lowercase hex characters")


@dataclass(frozen=True)
class CustodyAnchorResult:
    """What became of a recorded anchor: HELD, MISSING (no row has that hash
    or that id), REWRITTEN (a row with that id has another hash) or MOVED
    (that hash is here under another id)."""
    anchor: CustodyAnchor
    status: str
    found_id: int | None
    rows_since: int | None


@dataclass(frozen=True)
class CustodyReport:
    checked: int
    #: Evidence of TAMPERING: LINK, CONTENT, FORK above the boundary,
    #: GENESIS, NO_GENESIS and a failed anchor.
    breaks: tuple[CustodyBreak, ...]
    #: Every row sharing a predecessor, legacy and new. Those with a claimant
    #: at or below `fork_boundary` are not counted as tampering (see
    #: `intact`); one whose claimants are all above it is also in `breaks`.
    forks: tuple[CustodyBreak, ...]
    first_id: int | None
    last_id: int | None
    #: How many rows claim to be the chain's first, ALWAYS whole-table.
    #: Surfaced even when it is 1 so a caller can tell "anchored" from
    #: "nobody looked", which a bare `intact` cannot express.
    genesis_count: int = 0
    #: The exhibit the report was narrowed to, or None for the whole chain.
    #: Echoed so a caller cannot mistake a scoped answer for a global one.
    evidence_id: UUID | None = None
    #: Hex `row_hash` of the newest row in the WHOLE ledger (`ORDER BY id DESC LIMIT 1`, the row the
    #: 0024 trigger would chain the next insert onto), or None on an empty ledger. Whole-ledger even
    #: on a scoped run, like `genesis_count`: the chain has one tail, and an exhibit's newest row is
    #: almost never it.
    #:
    #: Tail-to-tail equality is not the defence it looks like: this hash changes on every honest
    #: append, so run-to-run equality mismatches on any live ledger. Two checks work against a tail
    #: deletion: `last_id` and `checked` are monotone on an append-only ledger, so either DECREASING
    #: against a recorded value is a truncation signal that cannot fire honestly; and a recorded
    #: hash should be checked for continued EXISTENCE in the ledger rather than for equality with
    #: the tail. Both work only if somebody records the value OUT OF BAND and compares it on the
    #: next run; nothing in this tree persists it yet. The anchor check below is what makes a
    #: recorded value useful.
    tail_row_hash: str | None = None
    #: The id of that newest row, and the rows in the whole ledger, so a
    #: caller can record the pair and watch the count only ever grow.
    tail_id: int | None = None
    total_rows: int = 0
    #: `core.custody_chain_ordered_after()`, or None on a database that has
    #: not run 0149.
    fork_boundary: int | None = None
    #: What became of the anchor the caller supplied, or None.
    anchor: CustodyAnchorResult | None = None

    @property
    def intact(self) -> bool:
        """No row examined disagrees with its predecessor.

        NOT "nothing was removed". Every relative check is blind to a deletion at the END of the
        ledger (see "What it cannot see" in the module docstring), so `intact` is a statement about
        the rows that ARE here and never about rows that are not. Compare `tail_row_hash` against a
        value recorded out of band for that.

        A fork is a break only above the 0149 boundary, for the reasons
        `audit_verify.ChainReport.intact` records; older ones are surfaced with their own count.

        An EMPTY result USUALLY returns True, and the caller is expected to read `checked` too: an
        exhibit with no custody rows, or a fresh database, has an intact (empty) chain and is
        evidence of nothing. "Usually", because GENESIS and NO_GENESIS are WHOLE-LEDGER findings
        injected into every report, scoped or not. So a scoped run, an empty one included, can come
        back not-intact on the strength of rows OUTSIDE its scope: a second genesis forged on
        another exhibit gives a clean exhibit two GENESIS breaks. That is intended, since an officer
        producing one exhibit still needs to be told the ledger it sits in was re-anchored, but a
        caller must read `breaks[].evidence_id` rather than assume a scoped finding is about the
        scope.

        When `evidence_id` is set, the LINK/CONTENT half is a statement about the rows REPORTED: a
        deletion inside this exhibit's history is revealed by whichever row followed it in the
        GLOBAL chain, which is usually another exhibit's, so an unscoped run sees more. It does not
        see everything: if the removed rows were the LEDGER's newest, the unscoped run is blind to
        them too.
        """
        return not self.breaks


def verify_custody_chain(
    conn: psycopg.Connection,
    *,
    evidence_id: UUID | None = None,
    anchor: CustodyAnchor | None = None,
) -> CustodyReport:
    """Recompute the custody chain and return every row that does not verify.

    `evidence_id` narrows which rows are REPORTED (a per-exhibit view for an officer producing one
    exhibit's custody). The predecessor set, the fork census and the genesis count are computed over
    the whole table, so a scoped run can never produce a false orphan (the module docstring says why
    a scoped `intact` is still not a statement about the exhibit's history being complete).

    Ordering is by `id`, never by `occurred_at`: `occurred_at` is server-pinned by the trigger, but
    a verifier must not let a clock adjustment reorder what it reports.

    NO result from this function is a completeness proof, scoped or not: the checks are relative,
    and rows deleted from the END of the ledger leave nothing behind to disagree with.
    `tail_row_hash` is returned so the one defence that works is possible, recording the tail out of
    band and comparing it next time: hand the recorded `(id, row_hash)` back as `anchor` and a row
    removed or rewritten since is an `ANCHOR_*` break. This function does not persist it.
    """
    where = "WHERE c.evidence_id = %(evidence_id)s" if evidence_id is not None else ""

    # The link is verified as a LINKED LIST, never by id adjacency (see the module docstring).
    # `hashes` is every row_hash IN THE TABLE; `claims` counts how many rows name each predecessor,
    # table-wide. LEFT JOINs rather than correlated subqueries, as in audit_verify: a per-row NOT
    # EXISTS did not finish on the development audit table.
    sql = f"""
    WITH scoped AS (
        SELECT c.id, c.evidence_id, c.action, c.actor_id, c.occurred_at,
               c.prev_hash, c.row_hash,
               {_HASH_EXPR} AS recomputed
          FROM core.evidence_custody c
          {where}
    ), hashes AS (
        -- THE WHOLE TABLE. This is what makes a scoped run exact: an
        -- exhibit's rows chain off OTHER exhibits' rows, and looking only
        -- inside the scope would orphan every one of them.
        --
        -- DISTINCT so the LEFT JOIN matches at most once; two byte-identical
        -- custody rows in the same microsecond are not impossible.
        SELECT DISTINCT row_hash FROM core.evidence_custody
    ), claims AS (
        -- Also whole-table: a fork is a fork whether or not both claimants
        -- belong to the exhibit being reported.
        SELECT prev_hash, COUNT(*) AS claimants, MIN(id) AS lowest
          FROM core.evidence_custody WHERE prev_hash IS NOT NULL
         GROUP BY prev_hash
    ), judged AS MATERIALIZED (
    SELECT s.id, s.evidence_id, s.action, s.actor_id, s.occurred_at,
           -- ORPHAN: names a predecessor no row has. The genesis row
           -- (prev_hash NULL) is exempt by construction; the anchor check
           -- below is what covers it.
           (s.prev_hash IS NOT NULL AND h.row_hash IS NULL) AS link_broken,
           -- FORK: this row's predecessor is claimed by more than one row.
           -- Both claimants are reported; which is the intruder is not
           -- something this can decide.
           COALESCE(cl.claimants > 1, false) AS forked,
           COALESCE(cl.claimants > 1 AND cl.lowest > %(boundary)s::bigint, false)
               AS fresh_fork,
           (s.row_hash IS DISTINCT FROM s.recomputed) AS content_broken
      FROM scoped s
      LEFT JOIN hashes h ON h.row_hash = s.prev_hash
      LEFT JOIN claims cl ON cl.prev_hash = s.prev_hash
    )
    -- Only the rows that do not verify leave the database, beside the
    -- count and the span of what was checked, as `audit_verify` does it
    -- (2026-10-07). One summary row always, even with nothing wrong.
    SELECT j.checked, j.first_id, j.last_id,
           f.id, f.evidence_id, f.action, f.actor_id, f.occurred_at,
           f.link_broken, f.forked, f.fresh_fork, f.content_broken
      FROM (SELECT count(*) AS checked, min(id) AS first_id,
                   max(id) AS last_id FROM judged) j
      LEFT JOIN LATERAL (
           SELECT * FROM judged
            WHERE link_broken OR forked OR content_broken) f ON true
     ORDER BY f.id
    """
    # `fresh_fork` in the query is a fork whose claimants are ALL above the
    # 0149 boundary: honest traffic cannot make one. No boundary, no such fork.
    boundary = _fork_boundary(conn)
    params: dict = {"boundary": boundary}
    if evidence_id is not None:
        params["evidence_id"] = evidence_id

    summary = conn.execute(sql, params).fetchall()
    checked, first_id, last_id = summary[0][:3]
    # The rows that did not verify; a run with none answers the summary row
    # alone, with no row columns.
    rows = [r[3:] for r in summary if r[3] is not None]
    breaks: list[CustodyBreak] = []
    forks: list[CustodyBreak] = []

    # The anchor. Every check above is RELATIVE. A row inserted with `prev_hash NULL` is an unlinked
    # island that passes all of them: LINK exempts it, FORK filters it out, and CONTENT blesses it
    # because its hash input is the literal 'GENESIS'. Two rows claiming to be first is the shape of
    # a truncation; zero, on a table that has rows, means the first row is gone and every survivor
    # still agrees with its predecessor. Queried over the WHOLE table, never the scope, and reported
    # at REPORT level: the true genesis is almost never one of the exhibit's own rows, so a scoped
    # check would answer "no genesis" on every scoped run.
    genesis = conn.execute(
        "SELECT id, evidence_id, action, actor_id, occurred_at "
        "FROM core.evidence_custody WHERE prev_hash IS NULL ORDER BY id").fetchall()
    total = conn.execute("SELECT count(*) FROM core.evidence_custody").fetchone()[0]

    # The tail, which is the anchor this module CANNOT check itself. `ORDER BY id DESC LIMIT 1` is
    # how `core.custody_chain_hash()` picks a predecessor, so this is the chain's tail as the WRITER
    # sees it. Whole-ledger, never scoped, like `genesis_count`: there is one chain and one tail.
    # Returned so an operator can record it out of band and compare it on the next run, the only
    # thing that reveals a tail deletion, which every check above is blind to.
    tail = conn.execute(
        "SELECT encode(row_hash, 'hex'), id FROM core.evidence_custody "
        "ORDER BY id DESC LIMIT 1").fetchone()

    if total and not genesis:
        breaks.append(CustodyBreak(
            id=0, evidence_id=None, occurred_at=None,
            action="(chain has no first row)", kind="NO_GENESIS", actor_id=None))
    elif len(genesis) > 1:
        # Not reachable by honest traffic -- 0024 writes a NULL predecessor
        # only into an empty table, under the advisory lock, and no
        # application code writes prev_hash. So it turns `intact` False.
        for g_id, g_ev, g_action, g_actor, g_at in genesis:
            breaks.append(CustodyBreak(
                id=g_id, evidence_id=g_ev, occurred_at=g_at, action=g_action,
                kind="GENESIS", actor_id=g_actor))

    for row_id, ev, action, actor_id, occurred_at, link, fork, fresh, content in rows:
        parts = []
        if link:
            parts.append("LINK")
        if content:
            parts.append("CONTENT")
        if parts:
            breaks.append(CustodyBreak(
                id=row_id, evidence_id=ev, occurred_at=occurred_at,
                action=action, kind="+".join(parts), actor_id=actor_id))
        if fork:
            row = CustodyBreak(
                id=row_id, evidence_id=ev, occurred_at=occurred_at,
                action=action, kind="FORK", actor_id=actor_id)
            forks.append(row)
            # A fork written since 0149 is a break (see CustodyReport.intact);
            # one with a claimant at or below the boundary is legacy.
            if fresh:
                breaks.append(row)

    result = None
    if anchor is not None:
        result = _check_anchor(conn, anchor)
        if result.status != "HELD":
            breaks.append(CustodyBreak(
                id=anchor.id, evidence_id=None, occurred_at=None,
                action="(anchored row)", kind="ANCHOR_" + result.status,
                actor_id=None))

    return CustodyReport(
        checked=checked,
        breaks=tuple(breaks),
        forks=tuple(forks),
        first_id=first_id,
        last_id=last_id,
        genesis_count=len(genesis),
        evidence_id=evidence_id,
        tail_row_hash=tail[0] if tail else None,
        tail_id=tail[1] if tail else None,
        total_rows=total,
        fork_boundary=boundary,
        anchor=result,
    )


def _fork_boundary(conn: psycopg.Connection) -> int | None:
    """`core.custody_chain_ordered_after()`, or None on a database that has
    not run 0149. Asked in two steps because a call to a function that does
    not exist fails when the statement is parsed, branch taken or not."""
    present = conn.execute(
        "SELECT to_regprocedure('core.custody_chain_ordered_after()') IS NOT NULL"
    ).fetchone()[0]
    if not present:
        return None
    return conn.execute("SELECT core.custody_chain_ordered_after()").fetchone()[0]


def _check_anchor(conn: psycopg.Connection,
                  anchor: CustodyAnchor) -> CustodyAnchorResult:
    """Is the recorded row still here, where it was? Each hash covers its
    predecessor's, so a HELD anchor vouches for every row before it and says
    nothing about the rows after it: record a newer one."""
    ids = [r[0] for r in conn.execute(
        "SELECT id FROM core.evidence_custody WHERE row_hash = decode(%s, 'hex') "
        "ORDER BY id", (anchor.row_hash,)).fetchall()]
    if anchor.id in ids:
        since = conn.execute(
            "SELECT count(*) FROM core.evidence_custody WHERE id > %s",
            (anchor.id,)).fetchone()[0]
        return CustodyAnchorResult(anchor, "HELD", anchor.id, since)
    if ids:
        return CustodyAnchorResult(anchor, "MOVED", ids[0], None)
    there = conn.execute(
        "SELECT 1 FROM core.evidence_custody WHERE id = %s",
        (anchor.id,)).fetchone()
    return CustodyAnchorResult(
        anchor, "REWRITTEN" if there else "MISSING", None, None)
