"""The audit trail over HTTP: read it, and verify it has not been edited.

Global rather than per-case: the trail oversees the people who hold cases, and a view limited to
the cases one already holds is not oversight. The compensating control is that only
SECURITY_OFFICER holds `audit.read` (0021), so no analyst's view of case content widens.
`audit.event.detail` is free-form and can name case material, so neither the listing nor `/verify`
returns it, only the structural columns.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query

from noctornal_api.audit_verify import ChainAnchor, verify_chain
from noctornal_api.custody_verify import CustodyAnchor, verify_custody_chain
from noctornal_api.db import SystemPurpose
from noctornal_api.http.deps import CurrentUser, get_conn, require_global, system_conn
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/audit", tags=["audit"])

#: The caveat beside every green tick on the audit log, windowed or not: each check compares a row
#: with its neighbours, so rows removed from the end, or rewritten and re-chained, leave nothing
#: behind to disagree.
_AUDIT_CAVEAT = (
    "What NO run can tell you is whether rows were removed from the END of the "
    "log, or edited and re-chained with fresh hashes. Every check compares a "
    "row with the rows around it, and the hash is plain SHA-256, so either "
    "is within reach of a person with the database owner's credentials and "
    "leaves `intact` true. The defence is an anchor recorded somewhere this "
    "system cannot write: keep `tail_seq` and `tail_row_hash`, and pass them "
    "back as `anchor_seq` and `anchor_hash` on a later run. This service does "
    "not persist them."
)

_WINDOWED_CAVEAT = (
    "Windowed: LINK, FORK and CONTENT are each exact for the rows "
    "reported, because the predecessor lookup covers the whole "
    "table. What a window cannot tell you is whether rows OUTSIDE "
    "it verify. Run without `limit` for that. "
)

#: What a fork is, said once for both ledgers. A legacy fork is one with a
#: claimant at or below the boundary 0149 recorded, an artefact of the old
#: sequence order that an append only table cannot be cleaned of; a fresh one
#: is a break, because since 0149 honest traffic cannot make one.
_LEGACY_FORKS = (
    "Rows that share a predecessor from before migration 0149, when the "
    "sequence number was drawn before the chain lock and two concurrent "
    "writers could chain off one tail. Not evidence of editing, and an "
    "append only table cannot be cleaned of them. They are also why a "
    "dead end row from that period could have been removed unseen."
)
_FRESH_FORKS = (
    "Rows written after migration 0149 share a predecessor. Since then the "
    "chaining trigger draws the sequence number inside its lock, so honest "
    "traffic cannot make this: it is counted as a break, and the usual cause "
    "is a row inserted with the trigger stood down."
)

_ANCHOR_NOTES = {
    "HELD": (
        "The row you recorded is still here with the same hash, so every row "
        "up to it is unchanged. Rows written after it are not covered: record "
        "a newer anchor."),
    "MISSING": (
        "No row has the {unit} or the hash you recorded. Rows were removed "
        "from the end of the {what}, or the {what} was cut back past that "
        "row."),
    "REWRITTEN": (
        "A row has the {unit} you recorded but not the hash. That row, or one "
        "before it, was edited and the chain recomputed after it."),
    "MOVED": (
        "The hash you recorded is in the {what} under a different {unit}: "
        "the rows were renumbered."),
}


def _anchor_note(status: str, *, unit: str, what: str) -> str:
    return _ANCHOR_NOTES[status].format(unit=unit, what=what)


def _hex_pair(number: int | None, digest: str | None, names: tuple[str, str]):
    """`(number, digest)` when both were given, None when neither, a 422 when
    one was: half an anchor names no row."""
    if number is None and digest is None:
        return None
    if number is None or digest is None:
        raise Problem(422, "Invalid field",
                      f"{names[0]} and {names[1]} go together: an anchor is "
                      "a position and the hash recorded there")
    return number, digest


@router.get("/verify", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.suite"))])
def verify(
    limit: int | None = Query(
        None, ge=1, le=200_000,
        description="check only the most recent N events; omit for the "
                    "whole chain"),
    anchor_seq: int | None = Query(
        None, ge=1,
        description="the tail_seq of an earlier run you recorded somewhere "
                    "this system cannot write; goes with anchor_hash"),
    anchor_hash: str | None = Query(
        None, pattern="^[0-9a-f]{64}$",
        description="the tail_row_hash recorded with anchor_seq"),
    user: CurrentUser = Depends(require_global("audit.read")),
    conn: psycopg.Connection = Depends(get_conn),
    # A check that sees only part of the chain reports breaks that are not there, so it walks every
    # row on a system connection.
    chain: psycopg.Connection = Depends(system_conn(SystemPurpose.AUDIT_VERIFY)),
) -> dict:
    """Recompute the hash chain and report every row that does not verify.

    Metered under `analytics.suite`, as a full run hashes every audit row. LINK (a predecessor
    removed) and CONTENT (a row edited in place) are reported apart. A FORK is a break when every
    row sharing the predecessor postdates migration 0149, which numbers rows inside the chain lock;
    older forks are counted apart. The checks are relative: pass a recorded `tail_seq` and
    `tail_row_hash` back as `anchor_seq` and `anchor_hash` to make a removed or rewritten anchored
    row a break.
    """
    pair = _hex_pair(anchor_seq, anchor_hash, ("anchor_seq", "anchor_hash"))
    report = verify_chain(
        chain, limit=limit,
        anchor=ChainAnchor(*pair) if pair else None)
    fresh = [b for b in report.breaks if b.kind == "FORK"]
    return {
        "intact": report.intact,
        "checked": report.checked,
        "first_seq": report.first_seq,
        "last_seq": report.last_seq,
        # Stated explicitly so "intact: true, checked: 0" can never be read
        # as a pass. An empty audit table is a legitimately intact chain
        # and also evidence of nothing.
        "windowed": limit is not None,
        # The newest row of the WHOLE log, windowed or not, and how many rows
        # there are: the values to record, and a count that can only grow.
        "tail_seq": report.tail_seq,
        "tail_row_hash": report.tail_row_hash,
        "rows_in_log": report.total_rows,
        # A caveat on every run; the windowed sentence is added when it applies and names a
        # window's own blind spot, the rows outside it.
        "caveat": (_WINDOWED_CAVEAT if limit is not None else "") + _AUDIT_CAVEAT,
        "anchor": None if report.anchor is None else {
            "status": report.anchor.status,
            "held": report.anchor.status == "HELD",
            "seq": report.anchor.anchor.seq,
            "found_seq": report.anchor.found_seq,
            "rows_since": report.anchor.rows_since,
            "note": _anchor_note(report.anchor.status, unit="seq", what="log"),
        },
        # Every fork, legacy and new. The ones above the boundary are also in
        # `breaks` and make `intact` false; `fork_boundary_seq` is where the
        # line sits, and None on a database that has not run 0149.
        "forks": len(report.forks),
        "fork_boundary_seq": report.fork_boundary,
        "fork_note": (
            _FRESH_FORKS if fresh else _LEGACY_FORKS) if report.forks else None,
        # How many rows claim to be the chain's first. Always reported, like
        # `checked`: 1 is the answer that says the chain is anchored, and
        # only an explicit number distinguishes that from "not looked at".
        "genesis_count": report.genesis_count,
        "genesis_note": (
            "More than one row claims to be the first. The chaining trigger "
            "writes a NULL predecessor only into an EMPTY table, under a "
            "lock, and no application code writes prev_hash at all, so a "
            "second one means the trigger was bypassed. Unlike a legacy "
            "fork, this IS evidence of tampering, and it is the shape a "
            "truncation leaves: delete the first rows, re-anchor the next "
            "one, and every other check still passes."
            if report.genesis_count > 1 else
            "The chain has no first row, though it has rows. The original "
            "genesis was removed; every surviving row still links to a real "
            "predecessor, so no other check can see this."
        ) if report.genesis_count != 1 and report.checked else None,
        "breaks": [
            {
                "seq": b.seq,
                # NO_GENESIS describes a row that is NOT THERE, so it has no
                # timestamp. Calling .isoformat() on it unconditionally
                # would 500 the one endpoint an officer reaches for during
                # an incident -- the same failure break-glass already had.
                "occurred_at": (b.occurred_at.isoformat()
                                if b.occurred_at else None),
                "action": b.action,
                "kind": b.kind,
                "actor_id": str(b.actor_id) if b.actor_id else None,
                "case_id": str(b.case_id) if b.case_id else None,
            }
            for b in report.breaks
        ],
    }


@router.get("/custody/verify", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.suite"))])
def verify_custody(
    evidence_id: UUID | None = Query(
        None,
        description="report only this exhibit's custody rows; the chain "
                    "checks still run against the whole ledger"),
    anchor_id: int | None = Query(
        None, ge=1,
        description="the tail_id of an earlier run you recorded somewhere "
                    "this system cannot write; goes with anchor_hash"),
    anchor_hash: str | None = Query(
        None, pattern="^[0-9a-f]{64}$",
        description="the tail_row_hash recorded with anchor_id"),
    user: CurrentUser = Depends(require_global("audit.read")),
    conn: psycopg.Connection = Depends(get_conn),
    # A check that sees only part of the chain reports breaks that are not there, so it walks every
    # row on a system connection.
    chain: psycopg.Connection = Depends(system_conn(SystemPurpose.AUDIT_VERIFY)),
) -> dict:
    """Recompute the custody hash chain and report every row that does not verify.

    Same gate, metering and shape as `/verify`. The ledger is one chain across every exhibit, so
    `evidence_id` narrows what is reported, not what is checked: a link check confined to one
    exhibit would call each of its rows an orphan. Called by the console's `btn-custody-verify`
    (`wireCustodyVerify()` and `custodyVerdict()` in `static/app.js`).
    """
    pair = _hex_pair(anchor_id, anchor_hash, ("anchor_id", "anchor_hash"))
    report = verify_custody_chain(
        chain, evidence_id=evidence_id,
        anchor=CustodyAnchor(*pair) if pair else None)
    fresh = [b for b in report.breaks if b.kind == "FORK"]
    return {
        "intact": report.intact,
        "checked": report.checked,
        "first_id": report.first_id,
        "last_id": report.last_id,
        # Stated explicitly so "intact: true, checked: 0" -- an exhibit with
        # no custody rows -- can never be read as a pass.
        "scoped": evidence_id is not None,
        "evidence_id": str(evidence_id) if evidence_id else None,
        # The newest row in the whole ledger, scoped run or not: recorded out of band and passed
        # back as `anchor_id` and `anchor_hash`, they make a removed or rewritten anchored row a
        # break. Nothing here or in CI persists them; an operator has to.
        "tail_row_hash": report.tail_row_hash,
        "tail_id": report.tail_id,
        "rows_in_ledger": report.total_rows,
        "anchor": None if report.anchor is None else {
            "status": report.anchor.status,
            "held": report.anchor.status == "HELD",
            "id": report.anchor.anchor.id,
            "found_id": report.anchor.found_id,
            "rows_since": report.anchor.rows_since,
            "note": _anchor_note(report.anchor.status, unit="id", what="ledger"),
        },
        # A caveat on every run, scoped or not: the checks are relative, so removing the newest
        # custody rows leaves `intact: true` and no trace, and a null caveat would read as an
        # unqualified pass.
        "caveat": (
            ("Scoped to one exhibit: LINK, FORK and CONTENT are each exact "
             "for the rows reported, because the predecessor lookup covers "
             "the whole ledger. GENESIS and NO_GENESIS are whole-ledger "
             "findings and are reported here too, so a scoped run can come "
             "back not-intact naming rows of OTHER exhibits. Read "
             "`breaks[].evidence_id` before attributing one. An unscoped "
             "run sees more of this exhibit's history, because a row "
             "deleted from it is revealed by whichever row came next in the "
             "global chain, which is usually another exhibit's. "
             if evidence_id is not None else
             "Whole ledger, every exhibit. ")
            + "What NO run can tell you is whether rows were removed from "
              "the END. Nothing names the newest row as its predecessor, so "
              "deleting the last entries (the export, the destruction) "
              "orphans nothing, costs one DELETE and no rehashing, and "
              "leaves `intact` true. The defence is `tail_row_hash`: record "
              "it, with `tail_id`, somewhere this system cannot reach and "
              "pass them back as `anchor_hash` and `anchor_id` on a later "
              "run. This service does not persist them."
        ),
        "forks": len(report.forks),
        "fork_boundary_id": report.fork_boundary,
        # The ids, not just the count: `fork_note` says a fork is worth investigating, and these
        # are what to investigate with.
        "fork_ids": [b.id for b in report.forks],
        "fork_note": (
            _FRESH_FORKS if fresh else _LEGACY_FORKS) if report.forks else None,
        # Always whole-ledger, always reported: 1 says the chain is anchored,
        # and only an explicit number distinguishes that from "not looked at".
        "genesis_count": report.genesis_count,
        "genesis_note": (
            "More than one row claims to be the first. The chaining trigger "
            "writes a NULL predecessor only into an EMPTY table, under a "
            "lock, and no application code writes prev_hash at all, so a "
            "second one means the trigger was bypassed. This IS evidence of "
            "tampering, and it is the shape a truncation leaves: delete the "
            "first rows, re-anchor the next one, and every other check still "
            "passes."
            if report.genesis_count > 1 else
            "The ledger has no first row, though it has rows. The original "
            "genesis was removed; every surviving row still links to a real "
            "predecessor, so no other check can see this."
        ) if report.genesis_count != 1 and (report.checked or report.breaks) else None,
        "breaks": [
            {
                "id": b.id,
                "evidence_id": str(b.evidence_id) if b.evidence_id else None,
                # NO_GENESIS describes a row that is not there, so it has no timestamp; an
                # unconditional .isoformat() would 500 on exactly the break it exists to report.
                "occurred_at": (b.occurred_at.isoformat()
                                if b.occurred_at else None),
                "action": b.action,
                "kind": b.kind,
                "actor_id": str(b.actor_id) if b.actor_id else None,
            }
            for b in report.breaks
        ],
    }


@router.get("/events", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def events(
    case_id: UUID | None = Query(None),
    action: str | None = Query(None),
    actor_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    before_seq: int | None = Query(
        None, description="keyset pagination: return events before this seq"),
    user: CurrentUser = Depends(require_global("audit.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The audit trail, newest first.

    `detail` is deliberately omitted — see the module docstring. Keyset
    pagination on `seq` rather than OFFSET: the table only grows at the
    head, so OFFSET would drift under concurrent writes and silently skip
    rows in a log somebody is reading to establish what happened.
    """
    clauses = ["true"]
    params: list = []
    if case_id is not None:
        clauses.append("case_id = %s")
        params.append(case_id)
    if action is not None:
        clauses.append("action = %s")
        params.append(action)
    if actor_id is not None:
        clauses.append("actor_id = %s")
        params.append(actor_id)
    if before_seq is not None:
        clauses.append("seq < %s")
        params.append(before_seq)
    params.append(limit)

    rows = conn.execute(
        f"""SELECT seq, occurred_at, actor_id, actor_kind, action,
                   object_type, object_id, case_id, outcome
              FROM audit.event
             WHERE {' AND '.join(clauses)}
             ORDER BY seq DESC
             LIMIT %s""",
        params,
    ).fetchall()

    return {
        "events": [
            {
                "seq": r[0],
                "occurred_at": r[1].isoformat(),
                "actor_id": str(r[2]) if r[2] else None,
                "actor_kind": r[3],
                "action": r[4],
                "object_type": r[5],
                "object_id": str(r[6]) if r[6] else None,
                "case_id": str(r[7]) if r[7] else None,
                "outcome": r[8],
            }
            for r in rows
        ],
        "next_before_seq": rows[-1][0] if len(rows) == limit else None,
    }
