"""Re-compute the `core.evidence_custody` hash chain and report where it breaks.

## Why this exists

Migration 0024 hash-chains the custody ledger: every row's `row_hash`
covers its predecessor's hash and every payload column, under an advisory
lock, with a UTC-fixed timestamp rendering. Its docstring invokes
US FRE 902(13)-(14) and the Canada Evidence Act ss. 31.1-31.8 — the
provisions under which a record like this is admitted on the strength of
its own integrity mechanism.

**Nothing ever checked it.** As of 2026-09-02 the tree had no function, no
endpoint, no CI step and only one test that touched the hashes at all —
`test_custody_is_hash_chained`, which asserts that the WRITER links two
adjacent rows. That is a test of the trigger, not of the ledger: a row
edited in place with the trigger stood down, a row deleted from the
middle, a deleted first row, or a forged second genesis all pass it. The
audit chain went through exactly this in July 2026 (see `audit_verify.py`)
and got a verifier; the custody chain, whose whole purpose is to be
produced to a court, did not. This module is that verifier, ported from
`audit_verify.py` with the differences below.

## THE CHAIN IS GLOBAL — one linked list across every exhibit

`core.custody_chain_hash()` picks its predecessor with
`ORDER BY id DESC LIMIT 1` over the WHOLE table. There is no per-exhibit
chain: the rows of one exhibit are interleaved with every other exhibit's,
and a given row's predecessor is almost always some other exhibit's row.
Three consequences drive the design of `verify_custody_chain`:

- **`evidence_id` narrows the REPORT, never the lookups.** The predecessor
  set (`hashes`), the fork census (`claims`) and the genesis count are
  always computed over the whole table. A LINK lookup restricted to one
  exhibit would report every one of its rows as an orphan — a false
  accusation on every scoped run, which is the one thing a tamper-evidence
  tool cannot afford.
- **A scoped `intact` is a statement about the rows REPORTED, not about
  the exhibit's history being complete.** Delete a row from exhibit X and
  the orphan that reveals it is whichever row came next in the global
  chain — usually some other exhibit's. So the scoped view of X can stay
  intact while the global run reports the deletion. The endpoint labels a
  scoped answer as scoped and says this in its caveat.
- **The anchor is a property of the chain, not of an exhibit.** There is
  exactly one genesis for the whole ledger, and it is reported at report
  level on every run, scoped or not.

## Why the recompute happens in SQL and not in Python

For the same reasons as the audit verifier: `detail::text` is jsonb's own
canonical rendering (key order, whitespace, numbers), `concat_ws(chr(31),
...)` has specific NULL semantics, `to_char(... 'US')` renders
microseconds a particular way, and `hash_verified::text` is Postgres's
`true`/`false`, not Python's. A verifier that disagrees with the writer
reports tampering on an intact chain, and the first few false alarms are
what teach people to ignore it.

**`_HASH_EXPR` is duplicated from 0024 and must stay in step with it.**
`test_custody_verify_pg.py` guards the coupling: it writes real custody
rows through the trigger and asserts the chain verifies, so an edit to the
trigger that this file does not match turns the suite red rather than
silently reporting corruption.

## `id` ORDER IS NOT CHAIN ORDER

`core.evidence_custody.id` is a `bigserial`, drawn from `nextval()` when
the row is constructed — BEFORE the BEFORE-INSERT trigger takes the
advisory lock. Two concurrent writers can therefore be handed ids 10 and
11 and acquire the lock in the opposite order, and the row holding the
LOWER id then chains off the row holding the HIGHER one. The linked list
is sound; the numbering does not follow it. `audit_verify.py` shipped an
adjacency check on `seq` once and accused 68 honest rows on the
development database. So the link is verified here as what it is — a
linked list, by following `prev_hash` to a real `row_hash` — and `id` is
used only for reporting and ordering the output.

## The checks are separate on purpose

- **CONTENT** — `row_hash` is not what the row's own columns hash to,
  using the `prev_hash` it stores. A row *edited in place*.
- **LINK** — `prev_hash` names a `row_hash` no row has. A predecessor
  *removed*.
- **FORK** — two or more rows claim the same predecessor. Reported
  separately and NOT counted as tampering, for the reasons
  `audit_verify.ChainReport.intact` gives at length: it is not proof of
  editing, an append-only table cannot be cleaned of legacy ones, and
  folding it into `intact` recreates the cry-wolf failure. On a chain
  written by 0024 a fork should not occur, so one deserves investigation.
- **GENESIS / NO_GENESIS** — how many rows claim to be first. Exactly one
  is an anchored chain; more than one is the shape a truncation leaves
  (delete the first k rows, re-anchor row k+1, and every relative check
  still passes); none, on a non-empty table, means the first row is gone.
  Both are tampering: 0024 writes a NULL predecessor only into an empty
  table, under the lock, and no application code writes `prev_hash`.

## What this cannot see

A re-chaining attack — edit row k, then recompute every `row_hash` from k
to the tail — is self-consistent and invisible to any verifier that reads
only the table. That is what an external anchor (a published tail hash,
a signed snapshot) is for, and this module does not provide one; it
detects the cheap tampering that leaves the ledger disagreeing with
itself, which is every case the docstring on 0024 was previously claiming
to catch without anything checking.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg

#: The canonical hash input, character-for-character from
#: `core.custody_chain_hash()` in 0024, with `NEW.` replaced by the row
#: alias `c` and the trigger's `prev` variable by the STORED `prev_hash` --
#: because that is what the trigger hashed. The link check is what catches
#: a wrong stored value.
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
    #: None only for NO_GENESIS, which is a finding about a row that is
    #: NOT THERE and therefore has no exhibit to name.
    evidence_id: UUID | None
    occurred_at: datetime | None
    action: str
    #: LINK / CONTENT, '+'-joined when both; FORK in `forks`; GENESIS and
    #: NO_GENESIS for the whole-chain findings.
    kind: str
    actor_id: UUID | None


@dataclass(frozen=True)
class CustodyReport:
    checked: int
    #: Evidence of TAMPERING: LINK, CONTENT, GENESIS, NO_GENESIS.
    breaks: tuple[CustodyBreak, ...]
    #: Rows sharing a predecessor. Reported, not counted -- see `intact`.
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

    @property
    def intact(self) -> bool:
        """No evidence of TAMPERING among the rows examined.

        Forks are excluded for the reasons `audit_verify.ChainReport.intact`
        records; they are surfaced with their own count.

        An EMPTY result returns True, and the caller is expected to read
        `checked` too: an exhibit with no custody rows, or a fresh
        database, has an intact (empty) chain and is evidence of nothing.
        When `evidence_id` is set this is a statement about the rows
        REPORTED; a deletion inside this exhibit's history is revealed by
        whichever row followed it in the GLOBAL chain, which is usually
        another exhibit's -- run without `evidence_id` for that.
        """
        return not self.breaks


def verify_custody_chain(
    conn: psycopg.Connection,
    *,
    evidence_id: UUID | None = None,
) -> CustodyReport:
    """Recompute the custody chain and return every row that does not verify.

    `evidence_id` narrows which rows are REPORTED (a per-exhibit view for
    an officer producing one exhibit's custody). Every check stays exact
    for the rows it reports: the predecessor set, the fork census and the
    genesis count are computed over the whole table, so a scoped run can
    never produce a false orphan -- see the module docstring for why a
    scoped run's `intact` is nonetheless not a statement about the
    exhibit's history being complete.

    Ordering is by `id`, never by `occurred_at`: `occurred_at` is
    server-pinned by the trigger, but a verifier must not let a clock
    adjustment reorder what it reports.
    """
    where = "WHERE c.evidence_id = %(evidence_id)s" if evidence_id is not None else ""

    # The link is verified as a LINKED LIST, never by id adjacency -- see
    # the module docstring. `hashes` is every row_hash IN THE TABLE;
    # `claims` counts how many rows name each predecessor, table-wide.
    # LEFT JOINs rather than correlated subqueries, for the same reason
    # audit_verify gives: a per-row NOT EXISTS did not finish on the
    # development audit table.
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
        SELECT prev_hash, COUNT(*) AS claimants
          FROM core.evidence_custody WHERE prev_hash IS NOT NULL
         GROUP BY prev_hash
    )
    SELECT s.id, s.evidence_id, s.action, s.actor_id, s.occurred_at,
           -- ORPHAN: names a predecessor no row has. The genesis row
           -- (prev_hash NULL) is exempt by construction; the anchor check
           -- below is what covers it.
           (s.prev_hash IS NOT NULL AND h.row_hash IS NULL) AS link_broken,
           -- FORK: this row's predecessor is claimed by more than one row.
           -- Both claimants are reported; which is the intruder is not
           -- something this can decide.
           COALESCE(cl.claimants > 1, false) AS forked,
           (s.row_hash IS DISTINCT FROM s.recomputed) AS content_broken
      FROM scoped s
      LEFT JOIN hashes h ON h.row_hash = s.prev_hash
      LEFT JOIN claims cl ON cl.prev_hash = s.prev_hash
     ORDER BY s.id
    """
    params: dict = {}
    if evidence_id is not None:
        params["evidence_id"] = evidence_id

    rows = conn.execute(sql, params).fetchall()
    breaks: list[CustodyBreak] = []
    forks: list[CustodyBreak] = []

    # ── the anchor ────────────────────────────────────────────────────
    #
    # Every check above is RELATIVE. A row inserted with `prev_hash NULL`
    # is an unlinked island that passes all of them -- LINK exempts it,
    # FORK filters it out, and CONTENT actively blesses it because its hash
    # input is the literal 'GENESIS'. Two rows claiming to be first is the
    # shape of a truncation; zero rows claiming to be first, on a table
    # that has rows, means the first row is gone and every survivor still
    # agrees with its predecessor.
    #
    # Queried over the WHOLE table, never the scope, and reported at
    # REPORT level: the true genesis is almost never one of the exhibit's
    # own rows, so a scoped anchor check would answer "no genesis" on
    # every scoped run.
    genesis = conn.execute(
        "SELECT id, evidence_id, action, actor_id, occurred_at "
        "FROM core.evidence_custody WHERE prev_hash IS NULL ORDER BY id").fetchall()
    total = conn.execute("SELECT count(*) FROM core.evidence_custody").fetchone()[0]

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

    for row_id, ev, action, actor_id, occurred_at, link, fork, content in rows:
        if not (link or fork or content):
            continue
        parts = []
        if link:
            parts.append("LINK")
        if content:
            parts.append("CONTENT")
        if parts:
            breaks.append(CustodyBreak(
                id=row_id, evidence_id=ev, occurred_at=occurred_at,
                action=action, kind="+".join(parts), actor_id=actor_id))
        # A FORK IS NOT REPORTED AS TAMPERING -- see CustodyReport.intact.
        if fork:
            forks.append(CustodyBreak(
                id=row_id, evidence_id=ev, occurred_at=occurred_at,
                action=action, kind="FORK", actor_id=actor_id))

    return CustodyReport(
        checked=len(rows),
        breaks=tuple(breaks),
        forks=tuple(forks),
        first_id=rows[0][0] if rows else None,
        last_id=rows[-1][0] if rows else None,
        genesis_count=len(genesis),
        evidence_id=evidence_id,
    )
