"""Where notifications actually get raised: one function per event, so the
wording, the priority and the classification of each are decided once.

Kept out of `notifications.py` (which is the mechanism) and out of the
routers (which would each invent their own wording) for the reason docs/07
gives: the *content rules* are the security-relevant part, and they are only
checkable if there is one place to check them.

## The three-field discipline, applied

Every function here obeys the contract migration 0029 states:

- `subject` — no intelligence. The case CODE and what happened. This string
  renders on a phone lock screen.
- `summary` — no entity names, no handles, no selectors. This string can go
  in an email body.
- `body` — may name entities. In-app only; the reader has already passed the
  five-part gate.

A merge notification is the sharp case. "shadowbroker merged into A. Petrov"
is exactly the sentence that must not leave the building, and exactly the
sentence the case owner needs to see. So it lives in `body`, and the summary
says only that a merge happened and how many edges moved.
"""
from __future__ import annotations

from uuid import UUID

import psycopg

from noctornal_api.notifications import NotificationService


def _case(conn: psycopg.Connection, case_id: UUID) -> tuple[str, str, frozenset[str]]:
    """(code, classification, compartments). A notification about a case is
    at least as classified as the case."""
    row = conn.execute(
        'SELECT code, classification, compartments FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    if row is None:
        return "?", "AMBER", frozenset()
    return row[0], row[1], frozenset(row[2] or [])


def merge_performed(conn: psycopg.Connection, *, case_id: UUID, merge_id: UUID,
                    source_label: str, target_label: str, edges_repointed: int,
                    reason: str, actor_id: UUID,
                    element_classification: str | None = None,
                    element_compartments: frozenset[str] = frozenset()) -> None:
    """docs/01 asks for this one by name: "Merges require `graph.merge` with
    step-up auth, and generate an audit event and a case-owner
    notification." The audit event has existed since decision 41; this is
    the other half.

    The owner, not the deputy. Two people told about every merge is two
    people who mute it, and the owner is who docs/01 names.
    """
    code, classification, compartments = _case(conn, case_id)
    NotificationService(conn).notify_case_owner(
        case_id,
        kind="MERGE_PERFORMED",
        subject=f"{code}: two entities were merged",
        # No labels here: this line may be emailed.
        summary=(f"A merge in {code} re-pointed {edges_repointed} "
                 f"relationship(s). Sign in to review it."),
        # Labels here: in-app only, behind the gate.
        body=(f"{source_label!r} was merged into {target_label!r}, moving "
              f"{edges_repointed} relationship(s).\n\nReason given: {reason}\n\n"
              f"Merging is the operation most likely to quietly corrupt a "
              f"case (docs/01). If this is wrong, it is reversible from the "
              f"entity-resolution panel and the reversal restores every "
              f"original endpoint exactly."),
        classification=classification, compartments=compartments,
        element_classification=element_classification,
        element_compartments=element_compartments,
        object_type="node_merge", object_id=merge_id, actor_id=actor_id)


def merge_reversed(conn: psycopg.Connection, *, case_id: UUID, merge_id: UUID,
                   edges_restored: int, reason: str, actor_id: UUID,
                   element_classification: str | None = None,
                   element_compartments: frozenset[str] = frozenset()) -> None:
    code, classification, compartments = _case(conn, case_id)
    NotificationService(conn).notify_case_owner(
        case_id,
        kind="MERGE_REVERSED",
        subject=f"{code}: a merge was reversed",
        summary=(f"A merge in {code} was reversed, restoring "
                 f"{edges_restored} relationship(s)."),
        body=(f"A merge was reversed. {edges_restored} relationship(s) were "
              f"restored to their original endpoints.\n\nReason given: {reason}"),
        classification=classification, compartments=compartments,
        element_classification=element_classification,
        element_compartments=element_compartments,
        object_type="node_merge", object_id=merge_id, actor_id=actor_id)


def approval_requested(conn: psycopg.Connection, *, case_id: UUID,
                       request_id: UUID, operation: str, permission: str,
                       justification: str, actor_id: UUID) -> int:
    """Tell everyone on the case who could actually approve it.

    Not the case owner, and not everyone assigned: the people who hold the
    OPERATION's permission on this case, which is the same set the decide
    endpoint will accept. Notifying anyone else produces a queue item they
    cannot action, and a queue full of those is a queue nobody reads.

    An approval nobody is told about is an approval nobody gives, and then
    dual control is just a merge button that does not work.

    The `expires_at` predicate is not decoration. Without it this notified
    every user who was EVER assigned to the case, which is a fresh WRITE of
    case material — the justification quotes case facts — to somebody the
    access gate would answer 404. It is also the same set the decide
    endpoint accepts, and that endpoint has always checked expiry, so the
    queue item was one the recipient could not have actioned anyway.
    """
    code, classification, compartments = _case(conn, case_id)
    rows = conn.execute(
        """SELECT DISTINCT ca.user_id
             FROM iam.case_assignment ca
             JOIN iam.role_permission rp ON rp.role_key = ca.role_key
             JOIN iam.app_user u ON u.id = ca.user_id
            WHERE ca.case_id = %s AND rp.permission_key = %s
              AND u.is_active AND ca.user_id <> %s
              AND (ca.expires_at IS NULL OR ca.expires_at > now())""",
        (case_id, permission, actor_id)).fetchall()
    svc = NotificationService(conn)
    sent = 0
    for (user_id,) in rows:
        raised = svc.notify(
            recipient_id=user_id, case_id=case_id,
            kind="APPROVAL_REQUESTED",
            subject=f"{code}: a second signature is needed",
            summary=(f"Someone on {code} is asking for a second signature on "
                     f"a {operation} operation. Sign in to review it."),
            body=(f"A colleague has asked for your approval of a "
                  f"{operation} operation.\n\nTheir justification:\n\n"
                  f"    {justification}\n\n"
                  f"You are being asked because you independently hold "
                  f"{permission} on this case. Approving means you have "
                  f"checked the specific parameters, not that you trust the "
                  f"person asking."),
            classification=classification, compartments=compartments,
            object_type="approval_request", object_id=request_id,
            actor_id=actor_id)
        if raised is not None:
            sent += 1
    return sent


def approval_decided(conn: psycopg.Connection, *, case_id: UUID,
                     request_id: UUID, operation: str, requested_by: UUID,
                     approved: bool, note: str | None, actor_id: UUID) -> None:
    code, classification, compartments = _case(conn, case_id)
    verdict = "approved" if approved else "declined"
    NotificationService(conn).notify(
        recipient_id=requested_by, case_id=case_id,
        kind="APPROVAL_DECIDED",
        subject=f"{code}: your request was {verdict}",
        summary=f"Your {operation} request on {code} was {verdict}.",
        body=(f"Your request for a second signature on a {operation} "
              f"operation was {verdict}."
              + (f"\n\nThey said:\n\n    {note}" if note else "")
              + ("\n\nThe approval is single use and expires; consume it from "
                 "the operation it was raised for." if approved else
                 "\n\nA declined request cannot be re-decided. If the facts "
                 "have changed, raise a new one -- the history will show "
                 "both, which is the point.")),
        classification=classification, compartments=compartments,
        object_type="approval_request", object_id=request_id, actor_id=actor_id)


def proposals_queued(conn: psycopg.Connection, *, case_id: UUID, count: int,
                     actor_id: UUID) -> None:
    """Triage had no notification at all: an analyst found out there was work
    by looking. Low priority and digest-friendly by default, because a
    capture that raises forty proposals must not raise forty emails."""
    if count <= 0:
        return
    code, classification, compartments = _case(conn, case_id)
    NotificationService(conn).notify_case_owner(
        case_id,
        kind="PROPOSAL_QUEUED",
        subject=f"{code}: {count} proposal(s) waiting in triage",
        summary=f"{count} new proposal(s) are waiting for review on {code}.",
        body=(f"{count} new proposal(s) were raised from captured material "
              f"and are waiting in the triage queue.\n\nNothing has been "
              f"written to the graph: extractors propose, analysts dispose "
              f"(invariant 3)."),
        classification=classification, compartments=compartments,
        actor_id=actor_id)
