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

import logging
from datetime import date, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg

from noctornal_api.notifications import Notification, NotificationService

log = logging.getLogger(__name__)


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
                    #: Ties BETWEEN the two entities, destroyed rather than
                    #: moved. Folded into `edges_repointed` they read as
                    #: relationships that survived the merge somewhere else,
                    #: which is a destruction described as a move.
                    self_loops_deleted: int = 0,
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
              f"{edges_repointed} relationship(s)."
              + (f" A further {self_loops_deleted} relationship(s) BETWEEN "
                 f"the two were destroyed rather than moved: a tie from an "
                 f"entity to itself means nothing, so the merge retired it. "
                 f"Reversing the merge brings it back."
                 if self_loops_deleted else "")
              + f"\n\nReason given: {reason}\n\n"
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
                     approved: bool, note: str | None,
                     actor_id: UUID) -> Notification | None:
    """Tell the requester their request was decided. Returns the row, or
    None when the requester could not be told -- suppressed because they
    may no longer read the case, or because they decided it themselves.

    N1 (2026-09-02). This returned nothing, and `ApprovalService.decide`
    reported `requester_notified` as `... is not None` -- two halves each
    consistent with itself and wrong together: every decision, including
    one whose notification was written and delivered, was reported to the
    approver as "the requester was not notified". The return value IS the
    contract now; the router's warning depends on it.
    """
    code, classification, compartments = _case(conn, case_id)
    verdict = "approved" if approved else "declined"
    return NotificationService(conn).notify(
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
                     actor_id: UUID) -> bool:
    """Triage had no notification at all: an analyst found out there was work
    by looking. Low priority and digest-friendly by default, because a
    capture that raises forty proposals must not raise forty emails.

    Returns whether the owner was actually told. False when there was
    nothing to say (no proposals), when the owner is the person who pasted
    the material (suppression 1), or when the owner may not read the case
    (suppression 2). The router publishes it as `owner_notified` so the
    analyst can see that nobody is coming to triage this.

    Until N2 (2026-09-02) this function existed, was correct, and was called
    by NOTHING -- the same shape `effective_labels_for_notification` had
    before F19. PROPOSAL_QUEUED sat in the preferences panel as a kind the
    user could tune for an event that could not happen.
    """
    if count <= 0:
        return False
    code, classification, compartments = _case(conn, case_id)
    raised = NotificationService(conn).notify_case_owner(
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
    return raised is not None


def evidence_integrity_alarm(conn: psycopg.Connection, *, case_id: UUID,
                             evidence_id: UUID, actor_id: UUID,
                             on_read: bool) -> Notification | None:
    """The tamper alarm. `KINDS` has registered EVIDENCE_INTEGRITY_ALARM at
    URGENT -- one of two priority-1 kinds in the system, "it wakes people
    up" -- since Phase 5, and until N2 (2026-09-02) nothing raised it. The
    string existed in `evidence.py` only as an AUDIT action on the
    incidental read path; the explicit verify wrote HASH_VERIFIED and
    stopped. A kind that cannot fire is a promise in the preferences panel.

    `on_read` says how the mismatch was found, because the two are
    different events for the owner: an explicit verify is somebody
    checking; a mismatch on read is an analyst who tried to open the
    exhibit and was refused it, which means the case is working from
    evidence that cannot currently be served.

    Labelled with the exhibit's own labels composed over the case's, the
    same way a merge notification carries its nodes' labels: an exhibit may
    be classified above its case, and the label is what decides whether the
    summary may go out by email.

    Suppression 1 applies: an owner who ran the verify themselves is not
    told what they just did -- they hold the `ok=False`, and the custody and
    audit rows are written regardless. The notification is for the owner
    finding out from somebody ELSE's discovery, and its URGENT priority is
    what puts it in front of `escalate_unacknowledged` if they then sit on
    it.
    """
    code, classification, compartments = _case(conn, case_id)
    labels = conn.execute(
        "SELECT classification, compartments FROM core.evidence WHERE id = %s",
        (evidence_id,)).fetchone()
    how = ("found on read: an analyst opened the exhibit and the bytes served "
           "did not match the hash recorded at acquisition, so the exhibit was "
           "refused rather than served"
           if on_read else
           "found by an explicit verify of the stored bytes against the hash "
           "recorded at acquisition")
    return NotificationService(conn).notify_case_owner(
        case_id,
        kind="EVIDENCE_INTEGRITY_ALARM",
        subject=f"{code}: an exhibit failed its integrity check",
        # No exhibit title here: this line may be emailed, and titles are
        # written by analysts about case material.
        summary=(f"An exhibit on {code} no longer matches the hash recorded "
                 f"when it was acquired. Treat the case's evidence as suspect "
                 f"until this is explained."),
        body=(f"Exhibit {evidence_id} failed its integrity check. The "
              f"mismatch was {how}.\n\n"
              f"Either the stored object or the recorded hash has changed "
              f"since acquisition. The object store is WORM-locked and the "
              f"hash columns are only ever written at ingest, so neither "
              f"should be possible -- which is exactly why this is priority "
              f"1. The custody log for the exhibit carries the failed "
              f"HASH_VERIFIED entry and the audit trail carries "
              f"EVIDENCE_INTEGRITY_ALARM."),
        classification=classification, compartments=compartments,
        element_classification=labels[0] if labels else None,
        element_compartments=frozenset(labels[1] or []) if labels else frozenset(),
        object_type="evidence", object_id=evidence_id, actor_id=actor_id)


def case_reviews_due(conn: psycopg.Connection, *, as_of: date | None = None,
                     horizon_days: int = 14) -> int:
    """Tell each owner of an ACTIVE case whose review falls within the
    horizon, once per (case, review_due). Returns how many notifications
    were WRITTEN -- not how many cases were seen -- so a sweep whose every
    owner was suppressed reports 0 and does not claim to have told anyone.

    Idempotent by construction rather than by a "last swept" column: the
    `object_id` is a uuid5 over the case id and the due date, so the row
    the sweep writes is the row the next sweep looks for, and a review that
    is moved to a new date is a new deadline and is announced again. The
    table has no slot for the date itself and a migration is out of scope
    for this change; a deterministic id is the honest substitute and is
    stated here so nobody later reads the object_id as a reference.

    Overdue reviews are included (`review_due <= as_of + horizon`, not a
    band). A sweep that only looked forward would never announce a review
    whose date passed while nothing was running the drain -- which is the
    exact week a review most needs announcing.

    `as_of` defaults to the DATABASE's current date, for the same reason
    `_queue_deliveries` uses the database clock: one clock, and it has to
    be the one the rows are compared against.

    Called from `transports.dispatch_due` (N3), so one drain does the
    outbox, this sweep and the escalations. Until N2 (2026-09-02)
    CASE_REVIEW_DUE was a description in `KINDS` and nothing else.
    """
    if as_of is None:
        as_of = conn.execute("SELECT current_date").fetchone()[0]
    rows = conn.execute(
        """SELECT id, code, review_due, classification, compartments
             FROM core."case"
            WHERE status = 'ACTIVE' AND review_due <= %s
            ORDER BY review_due ASC""",
        (as_of + timedelta(days=horizon_days),)).fetchall()
    if not rows:
        return 0
    wanted = {_review_object_id(r[0], r[2]): r for r in rows}
    already = {r[0] for r in conn.execute(
        """SELECT object_id FROM notify.notification
            WHERE kind = 'CASE_REVIEW_DUE' AND object_type = 'case_review'
              AND object_id = ANY(%s)""", (list(wanted),)).fetchall()}
    svc = NotificationService(conn)
    written = 0
    for object_id, (case_id, code, review_due, classification, compartments) \
            in wanted.items():
        if object_id in already:
            continue
        overdue = review_due < as_of
        try:
            raised = svc.notify_case_owner(
                case_id,
                kind="CASE_REVIEW_DUE",
                subject=(f"{code}: review overdue" if overdue
                         else f"{code}: review due {review_due.isoformat()}"),
                summary=(f"The review of {code} was due on "
                         f"{review_due.isoformat()} and has not been recorded."
                         if overdue else
                         f"The review of {code} is due on "
                         f"{review_due.isoformat()}."),
                body=("A case review confirms that the legal basis still "
                      "holds, that the retention date is still right, and "
                      "that the people assigned still need to be. Record it "
                      "by updating the case's review date; this reminder is "
                      "raised once per due date and will not repeat unless "
                      "the date moves."),
                classification=classification,
                compartments=frozenset(compartments or []),
                object_type="case_review", object_id=object_id)
        except Exception:  # noqa: BLE001 - one bad case must not end the sweep
            # `notify()` fails loudly on an unparseable label, and it is
            # right to. But this runs inside the drain, over every active
            # case, and one case with a broken label must not stop every
            # other owner being told. Logged, skipped, retried next sweep.
            log.exception("could not raise CASE_REVIEW_DUE for case %s", case_id)
            continue
        if raised is not None:
            written += 1
    return written


def _review_object_id(case_id: UUID, review_due: date) -> UUID:
    return uuid5(NAMESPACE_URL, f"noctornal:case-review:{case_id}:{review_due.isoformat()}")


def escalation_to_owner(conn: psycopg.Connection, *, original: Notification,
                        owner_id: UUID, age: timedelta) -> Notification | None:
    """An unacknowledged priority-1, escalated to the owner of the case it
    is about. Carries the original's subject -- which by the three-field
    discipline holds the case code and what happened, nothing more -- and
    is labelled with the case's labels because it names the case.

    `object_type="notification"` / `object_id=original.id` is the idempotence
    key `notifications.escalate_unacknowledged` looks for. Raised with no
    actor: nobody DID this, somebody failed to.
    """
    code, classification, compartments = _case(conn, original.case_id)
    minutes = int(age.total_seconds() // 60)
    return NotificationService(conn).notify(
        recipient_id=owner_id, case_id=original.case_id,
        kind="ESCALATION",
        subject=f"{code}: an urgent notification is unacknowledged",
        summary=(f"A priority-1 {original.kind} notification on {code} has not "
                 f"been acknowledged after {minutes} minutes."),
        body=(f"{original.subject!r}, raised at "
              f"{original.created_at.isoformat(timespec='minutes')} for user "
              f"{original.recipient_id}, has not been acknowledged.\n\n"
              f"It is escalated to you as the case owner. Acknowledge it, or "
              f"have its recipient acknowledge it: an urgent notification "
              f"nobody has acknowledged is the one alert that mattered, "
              f"muted by absence rather than by choice (docs/07). This "
              f"escalation is raised once; it will not repeat."),
        classification=classification, compartments=compartments,
        object_type="notification", object_id=original.id)


def escalation_to_officer(conn: psycopg.Connection, *, original: Notification,
                          officer_id: UUID, age: timedelta) -> Notification | None:
    """The same escalation, to a SECURITY_OFFICER, when the case owner IS the
    unresponsive recipient (or there is no case owner to go to).

    Carries NO case material, for the reason `break_glass._alert` gives at
    length: the officer holds `audit.read` and no case-content permission,
    so this is GREEN, case-less, and says that a notification of a given
    kind went unanswered by a given user id. The kind name and the user id
    are facts about the system, not about the case.
    """
    minutes = int(age.total_seconds() // 60)
    return NotificationService(conn).notify(
        recipient_id=officer_id, case_id=None,
        kind="ESCALATION",
        subject="An urgent notification went unacknowledged",
        summary=(f"A priority-1 {original.kind} notification raised {minutes} "
                 f"minutes ago has not been acknowledged by its recipient. It "
                 f"needs a human."),
        body=(f"Notification {original.id} ({original.kind}), raised at "
              f"{original.created_at.isoformat(timespec='minutes')} for user "
              f"{original.recipient_id}, is unacknowledged after {minutes} "
              f"minutes.\n\n"
              f"It is escalated to you because that recipient is the owner of "
              f"the case it concerns, or because it concerns no case, so "
              f"there is nobody above them to go to. Nothing about the case "
              f"is reproduced here: you hold no case-content permission, and "
              f"an escalation is about a silence, not about a case. The "
              f"audit trail, which you may read, has the rest."),
        classification="GREEN", compartments=frozenset(),
        object_type="notification", object_id=original.id)
