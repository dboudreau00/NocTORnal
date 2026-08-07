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
        "caveat": (
            "A windowed run cannot see a deletion that straddles the "
            "window boundary: the oldest row checked has no loaded "
            "predecessor, so its link is not asserted. Run without `limit` "
            "for a complete answer."
        ) if limit is not None else None,
        # Forks are NOT tampering -- see ChainReport.intact. Reported so an
        # officer knows the chain is not linearisable, which weakens the
        # guarantee, without being told the log was edited.
        "forks": len(report.forks),
        "fork_note": (
            "Rows sharing a predecessor. Produced by concurrent writers, not "
            "by editing: `seq` is drawn before the chaining trigger takes its "
            "lock, so two writers can chain off one tail. Worth knowing (the "
            "chain cannot be fully linearised) but it is not evidence of "
            "tampering."
        ) if report.forks else None,
        "breaks": [
            {
                "seq": b.seq,
                "occurred_at": b.occurred_at.isoformat(),
                "action": b.action,
                "kind": b.kind,
                "actor_id": str(b.actor_id) if b.actor_id else None,
                "case_id": str(b.case_id) if b.case_id else None,
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
