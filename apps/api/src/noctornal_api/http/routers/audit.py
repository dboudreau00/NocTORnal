"""The audit trail over HTTP: read it, and verify it has not been edited.

`audit.read` was seeded in 0017 and granted to SECURITY_OFFICER in 0021,
and until 2026-07-26 it had **zero call sites**. Nothing in the product
read `audit.event` — `scripts/bootstrap.py` told the operator to run raw
SQL — and nothing ever recomputed the hash chain, so docs/09's Phase 0
exit criterion ("every action appears in a *verifiable* audit chain") was
unmet by the only word in it that carries weight.

## Global, not per-case, and why that is the safe direction here

Every other read router in this tree is `/cases/{case_id}/...` and gated
by case assignment. This one is not, because the audit trail's purpose is
oversight of the people who hold cases, and an oversight surface that only
shows you what you already have access to is not oversight.

The compensating control is that `audit.read` is granted to
SECURITY_OFFICER **and to nobody else** (0021: "the admin configures, the
officer audits, and neither reads case data by default"). SYS_ADMIN does
not hold it. So this endpoint widens no analyst's view of case content.

**What it can still leak, and what is done about it.** `audit.event.detail`
is free-form jsonb written by every service in the tree, and some of it
names case material. So `detail` is NOT returned by the listing endpoint —
only the structural columns are. An officer establishing *that* an action
happened does not need its payload, and returning it would hand the one
role with global reach a keyhole onto every case. `/verify` returns no
`detail` either.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query

from noctornal_api.audit_verify import verify_chain
from noctornal_api.custody_verify import verify_custody_chain
from noctornal_api.http.deps import CurrentUser, get_conn, require_global
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/verify", response_model=dict,
            dependencies=[Depends(rate_limit("analytics.suite"))])
def verify(
    limit: int | None = Query(
        None, ge=1, le=200_000,
        description="check only the most recent N events; omit for the "
                    "whole chain"),
    user: CurrentUser = Depends(require_global("audit.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Recompute the hash chain and report every row that does not verify.

    Metered under `analytics.suite` rather than a read limit: a full-chain
    verification is an O(n) SHA-256 over every audit row ever written, and
    it is not something anyone needs to run in a loop.

    The response distinguishes LINK (a predecessor removed) from CONTENT
    (a row edited in place), because they point an investigator in
    different directions — and reports FORKS separately from both, because
    they are an artefact of concurrent writers rather than evidence of
    tampering, and counting them as breaks made this answer BROKEN on
    untampered history.
    """
    report = verify_chain(conn, limit=limit)
    return {
        "intact": report.intact,
        "checked": report.checked,
        "first_seq": report.first_seq,
        "last_seq": report.last_seq,
        # Stated explicitly so "intact: true, checked: 0" can never be read
        # as a pass. An empty audit table is a legitimately intact chain
        # and also evidence of nothing.
        "windowed": limit is not None,
        # The caveat DESCRIBES THE ACTUAL BLIND SPOT, which is not the one
        # it originally claimed. It said a windowed run "cannot see a
        # deletion that straddles the window boundary" -- that was true of
        # the first implementation, and stopped being true when `hashes`
        # and `claims` were widened to the whole table. Leaving it would
        # have had an officer distrust a result that is in fact exact, and
        # a caveat nobody can reproduce is how the honest ones stop being
        # read.
        "caveat": (
            "Windowed: LINK, FORK and CONTENT are each exact for the rows "
            "reported, because the predecessor lookup covers the whole "
            "table. What a window cannot tell you is whether rows OUTSIDE "
            "it verify — run without `limit` for that."
        ) if limit is not None else None,
        # Forks are NOT tampering -- see ChainReport.intact. Reported so an
        # officer knows the chain is not linearisable, which weakens the
        # guarantee, without being told the log was edited.
        "forks": len(report.forks),
        "fork_note": (
            "Rows sharing a predecessor. Still not evidence of editing, and "
            "still not counted as tampering — but no longer explained away "
            "as normal concurrency. Measured on this code, the chaining "
            "trigger's advisory lock DOES serialise concurrent writers and a "
            "multi-row insert chains correctly, so a fork is not known to be "
            "reachable by ordinary traffic. Treat one as worth "
            "investigating: what it means for certain is that the chain "
            "cannot be fully linearised."
        ) if report.forks else None,
        # How many rows claim to be the chain's first. Always reported, like
        # `checked`: 1 is the answer that says the chain is anchored, and
        # only an explicit number distinguishes that from "not looked at".
        "genesis_count": report.genesis_count,
        "genesis_note": (
            "More than one row claims to be the first. The chaining trigger "
            "writes a NULL predecessor only into an EMPTY table, under a "
            "lock, and no application code writes prev_hash at all — so a "
            "second one means the trigger was bypassed. Unlike a fork, this "
            "IS evidence of tampering, and it is the shape a truncation "
            "leaves: delete the first rows, re-anchor the next one, and "
            "every other check still passes."
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
    user: CurrentUser = Depends(require_global("audit.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Recompute the custody hash chain and report every row that does not
    verify.

    Same gate, metering and shape as `/verify`, for the other tamper-evident
    ledger in the system: `core.evidence_custody` was hash-chained in 0024
    with a docstring invoking FRE 902(13)-(14), and until 2026-09-02 nothing
    recomputed it — the same "written and never verified" gap `/verify`
    closed for `audit.event`, on the record that is actually produced to a
    court.

    The custody ledger is ONE chain across every exhibit (the trigger's
    predecessor is the newest row in the whole table), so `evidence_id`
    narrows what is REPORTED, not what is checked: an exhibit's rows chain
    off other exhibits' rows, and a link check confined to one exhibit
    would call every one of its rows an orphan. The scoped answer says it
    is scoped, and its caveat says what it cannot tell you.
    """
    report = verify_custody_chain(conn, evidence_id=evidence_id)
    return {
        "intact": report.intact,
        "checked": report.checked,
        "first_id": report.first_id,
        "last_id": report.last_id,
        # Stated explicitly so "intact: true, checked: 0" -- an exhibit with
        # no custody rows -- can never be read as a pass.
        "scoped": evidence_id is not None,
        "evidence_id": str(evidence_id) if evidence_id else None,
        "caveat": (
            "Scoped to one exhibit: LINK, FORK and CONTENT are each exact "
            "for the rows reported, because the predecessor lookup covers "
            "the whole ledger. What a scoped run cannot tell you is whether "
            "this exhibit's history is COMPLETE — a row deleted from it is "
            "revealed by whichever row came next in the global chain, which "
            "is usually another exhibit's. Run without `evidence_id` for "
            "that."
        ) if evidence_id is not None else None,
        "forks": len(report.forks),
        "fork_note": (
            "Rows sharing a predecessor. Not counted as tampering, for the "
            "reasons /audit/verify gives — but on a ledger written by 0024, "
            "whose advisory lock serialises writers, a fork is not known to "
            "be reachable by ordinary traffic and is worth investigating. "
            "What it means for certain is that the chain cannot be fully "
            "linearised."
        ) if report.forks else None,
        # Always whole-ledger, always reported: 1 says the chain is anchored,
        # and only an explicit number distinguishes that from "not looked at".
        "genesis_count": report.genesis_count,
        "genesis_note": (
            "More than one row claims to be the first. The chaining trigger "
            "writes a NULL predecessor only into an EMPTY table, under a "
            "lock, and no application code writes prev_hash at all — so a "
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
                # NO_GENESIS describes a row that is NOT THERE, so it has no
                # timestamp; an unconditional .isoformat() would 500 the
                # endpoint on exactly the finding it exists to report.
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
