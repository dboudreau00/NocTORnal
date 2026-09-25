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
import os
from dataclasses import dataclass
from datetime import date, timedelta
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

import psycopg

from noctornal_api.notifications import Notification, NotificationService
from noctornal_api.wording import agree, count_of

log = logging.getLogger(__name__)


def _case(conn: psycopg.Connection, case_id: UUID) -> tuple[str, str, frozenset[str]]:
    """(code, classification, compartments). A notification about a case is
    at least as classified as the case."""
    # The labels are lock facts (`iam.case_facts`) and the code comes
    # through `iam.case_code` (S1, 2026-09-25), so a notification is never
    # labelled below its case because row-level security hid the case row
    # from whoever triggered it. A case that does not exist is refused
    # rather than guessed at: the old fallback labelled it AMBER.
    row = conn.execute(
        "SELECT iam.case_code(%s), classification, compartments "
        "  FROM iam.case_facts(%s)", (case_id, case_id)).fetchone()
    if row is None:
        raise ValueError(f"notification about a case that does not exist: {case_id}")
    return row[0] or "?", row[1], frozenset(row[2] or [])


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
        # Counts agreed, never a bracketed plural (F7, 2026-09-24): the
        # summary reaches Jira as well as email now.
        summary=(f"A merge in {code} re-pointed "
                 f"{count_of(edges_repointed, 'relationship', 'relationships')}. "
                 f"Sign in to review it."),
        # Labels here: in-app only, behind the gate.
        body=(f"{source_label!r} was merged into {target_label!r}, moving "
              f"{count_of(edges_repointed, 'relationship', 'relationships')}."
              + (f" A further "
                 f"{count_of(self_loops_deleted, 'relationship', 'relationships')} "
                 f"BETWEEN the two {agree(self_loops_deleted, 'was', 'were')} "
                 f"destroyed rather than moved: a tie from an entity to itself "
                 f"means nothing, so the merge retired "
                 f"{agree(self_loops_deleted, 'it', 'them')}. Reversing the "
                 f"merge brings {agree(self_loops_deleted, 'it', 'them')} back."
                 if self_loops_deleted else "")
              + f"\n\nReason given: {reason}\n\n"
              f"Merging is the operation most likely to quietly corrupt a "
              f"case. If this is wrong, it is reversible from the "
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
                 f"{count_of(edges_restored, 'relationship', 'relationships')}."),
        body=(f"A merge was reversed. "
              f"{count_of(edges_restored, 'relationship', 'relationships')} "
              f"{agree(edges_restored, 'was', 'were')} restored to "
              f"{agree(edges_restored, 'its', 'their')} original endpoints."
              f"\n\nReason given: {reason}"),
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
    # One request is one event however many signers are told (F8,
    # 2026-09-24): Jira posts it once, not once per recipient.
    event = uuid4()
    for (user_id,) in rows:
        raised = svc.notify(
            recipient_id=user_id, case_id=case_id, event_id=event,
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
                 "have changed, raise a new one. The history will show "
                 "both, which is the point.")),
        classification=classification, compartments=compartments,
        object_type="approval_request", object_id=request_id, actor_id=actor_id)


def proposals_queued(conn: psycopg.Connection, *, case_id: UUID, count: int,
                     actor_id: UUID, classification: str | None = None) -> bool:
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

    `classification` is the capture's own label (final review u12,
    2026-09-24), composed over the case's as an element's is. The notice
    was labelled at the case alone, so a RED paste into an AMBER case told
    an AMBER owner, by an email-safe summary, how many proposals RED
    material had raised, and its Open led to a queue that showed them
    nothing, since the queue filters each proposal by what it came from.
    Now suppression 2 keeps it from anyone who could not read them.
    """
    if count <= 0:
        return False
    code, case_classification, compartments = _case(conn, case_id)
    # Agreed in number, because the text is stored and read verbatim: the
    # inbox printed "3 proposal(s) were raised" (README screenshot set
    # review, 2026-09-23).
    one = count == 1
    noun = "proposal" if one else "proposals"
    raised = NotificationService(conn).notify_case_owner(
        case_id,
        kind="PROPOSAL_QUEUED",
        subject=f"{code}: {count} {noun} waiting in triage",
        summary=(f"{count} new {noun} {'is' if one else 'are'} waiting for "
                 f"review on {code}."),
        body=(f"{count} new {noun} {'was' if one else 'were'} raised from "
              f"captured material and {'is' if one else 'are'} waiting in "
              f"the triage queue.\n\nNothing has been "
              f"written to the graph: extractors propose, analysts "
              f"dispose."),
        classification=case_classification, compartments=compartments,
        element_classification=classification,
        # What the card's Open goes to: this case's triage queue. It named
        # nothing, so the notice about waiting work had no route to the
        # work (ux08-triage:notifications-no-path-to-object, 2026-09-23).
        object_type="triage", object_id=case_id,
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

    ## One alarm per exhibit while it is unanswered (2026-09-02)

    Returns None -- writing nothing -- when an unacknowledged alarm for
    this exhibit already exists. Until this fix the alarm fired on EVERY
    detection, which made the evidence read path an outbound-email
    amplifier: `GET /cases/{id}/evidence/{id}/content` and
    `POST /{id}/verify` carry no `rate_limit` dependency, so any caller
    holding `evidence.read` on a case with one corrupt exhibit minted one
    priority-1 notification plus one PENDING SMTP delivery to the case
    owner per HTTP request, on a path that previously wrote only a cheap
    internal audit row. Suppression 1 was no defence, because the owner is
    the RECIPIENT and the looper is anyone else. Worse, because the owner
    is the recipient, `notifications.escalate_unacknowledged` skips the
    owner and fans every one of those out to EVERY active
    SECURITY_OFFICER, once per drain until each is acknowledged
    individually -- so the party with the motive to bury the tamper alarm
    could drown it, and the system's only tamper alarm is the last thing
    that may be drowned.

    Keyed on `acknowledged_at IS NULL` rather than on existence, so a
    genuinely NEW failure after the owner has answered the last one is
    still raised. Deliberately the same shape as this module's other two
    producers -- `case_reviews_due`'s deterministic `object_id` and
    `escalate_unacknowledged`'s NOT EXISTS -- which were made idempotent
    on the same day precisely to stop fan-out; the one producer a hostile
    caller can drive got neither, which is the inconsistency this closes.
    Like theirs, the guard is a read-then-write with no unique index
    behind it, so it bounds a loop rather than winning a race: two
    simultaneous reads of the same tampered exhibit can still write two.
    That is a cap of one per concurrent request rather than one per
    request, which is the difference the amplifier turned on.

    The custody and audit rows are written by `evidence.py` regardless and
    are the durable record; this only decides whether the OWNER'S PHONE
    rings again about something they have already been told.
    """
    outstanding = conn.execute(
        """SELECT 1 FROM notify.notification
            WHERE kind = 'EVIDENCE_INTEGRITY_ALARM'
              AND object_type = 'evidence' AND object_id = %s
              AND acknowledged_at IS NULL
            LIMIT 1""", (evidence_id,)).fetchone()
    if outstanding is not None:
        log.info("exhibit %s already has an unacknowledged integrity alarm; "
                 "not raising another", evidence_id)
        return None
    code, classification, compartments = _case(conn, case_id)
    labels = conn.execute(
        "SELECT classification, compartments, title FROM core.evidence "
        "WHERE id = %s", (evidence_id,)).fetchone()
    # The exhibit by its TITLE in the body, which renders in-app only and
    # may name case material; the id stays beside it as the durable
    # reference. The body named a 36-character id and nothing else, so the
    # most urgent notification in the product sent the analyst hunting
    # for an exhibit by UUID (ux08-triage:notifications-no-path-to-object,
    # 2026-09-23).
    named = (f"Exhibit {labels[2]!r} ({evidence_id})"
             if labels and labels[2] else f"Exhibit {evidence_id}")
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
        body=(f"{named} failed its integrity check. The "
              f"mismatch was {how}.\n\n"
              f"Either the stored object or the recorded hash has changed "
              f"since acquisition. The object store is WORM-locked and the "
              f"hash columns are only ever written at ingest, so neither "
              f"should be possible, which is exactly why this is priority "
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

    Idempotent ACROSS sweeps rather than by a "last swept" column: the
    `object_id` is a uuid5 over the case id and the due date, so the row
    the sweep writes is the row the next sweep looks for, and a review that
    is moved to a new date is a new deadline and is announced again. The
    table has no slot for the date itself and a migration is out of scope
    for this change; a deterministic id is the honest substitute and is
    stated here so nobody later reads the object_id as a reference.

    That dedupe is a SELECT into `already` followed by INSERTs, with no
    lock and no unique index behind it (`notification_object_idx` is a
    plain partial btree on `object_id`), so it holds only while ONE sweep
    runs at a time. `transports.dispatch_due` is what guarantees that: it
    takes a session advisory lock across the whole drain. Corrected
    2026-09-02, when this docstring still said "idempotent by
    construction" without qualification and nothing serialised the callers.

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
              f"muted by absence rather than by choice. This "
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


# Deployment-wide approvals (F9, 2026-09-24).

def global_approval_requested(conn: psycopg.Connection, *, request_id: UUID,
                              operation: str, description: str,
                              permission: str, requester_permission: str,
                              actor_id: UUID) -> int:
    """Tell everyone who could sign a deployment-wide request.

    The recipients are the people the global decide route will accept: an
    active account whose GLOBAL role carries `permission` (the signer's),
    and, where the requester's permission is a different one, whose roles
    do not carry that too (`approvals.eligible_signers_sql`), minus the
    requester. No case, GREEN, and the justification is NOT quoted: a
    Security officer holds no case access, and free text written by an
    administrator can quote a case (the break-glass rule, F19). The subject
    and summary name only the operation's description; the justification
    is read in the console, under the officer's own gate.

    Returns how many were raised. One notification per recipient, each its
    own event in the delivery ledger: no shared event id is passed.
    """
    from noctornal_api.approvals import eligible_signers_sql

    rows = conn.execute(
        """SELECT u.id FROM iam.app_user u
            WHERE u.id <> %(actor)s AND """ + eligible_signers_sql("u"),
        {"actor": actor_id, "signer": permission,
         "requester": requester_permission}).fetchall()
    svc = NotificationService(conn)
    sent = 0
    for (user_id,) in rows:
        raised = svc.notify(
            recipient_id=user_id, case_id=None,
            kind="APPROVAL_REQUESTED",
            subject=f"A second signature is needed: {description}",
            summary=("A deployment-wide change is waiting for a second "
                     "signature. Sign in to review it."),
            body=(f"An administrator asked for your countersignature on: "
                  f"{description}.\n\nOpen Oversight, Two-person changes, or "
                  f"Administration, Two-person controls, to read it and "
                  f"countersign or refuse. The justification is shown there, "
                  f"not here."),
            classification="GREEN", compartments=frozenset(),
            object_type="approval_request", object_id=request_id,
            actor_id=actor_id)
        if raised is not None:
            sent += 1
    return sent


def global_approval_decided(conn: psycopg.Connection, *, request_id: UUID,
                            description: str, requested_by: UUID,
                            approved: bool,
                            actor_id: UUID) -> Notification | None:
    """Tell the requester their deployment-wide request was decided. No
    case, GREEN, and the countersigner's note is not quoted, for the same
    reason the request's justification is not."""
    verdict = "countersigned" if approved else "refused"
    return NotificationService(conn).notify(
        recipient_id=requested_by, case_id=None,
        kind="APPROVAL_DECIDED",
        subject=f"Your request was {verdict}: {description}",
        summary=f"Your deployment-wide request was {verdict}.",
        body=(f"{description}: your request for a second signature was "
              f"{verdict}.\n\n"
              + ("It is not in force yet. Apply it under Administration, "
                 "Two-person controls, before it expires; it applies once."
                 if approved else
                 "A refused request cannot be decided again. If the facts "
                 "have changed, propose it again; the history shows both.")),
        classification="GREEN", compartments=frozenset(),
        object_type="approval_request", object_id=request_id,
        actor_id=actor_id)


# The collection foundation (docs/00 decision 69, 2026-09-24).

def _global_holders(conn: psycopg.Connection, permission: str) -> list[UUID]:
    """Every active account whose GLOBAL role carries `permission`."""
    return [r[0] for r in conn.execute(
        """SELECT DISTINCT u.id FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
            WHERE u.is_active AND rp.permission_key = %s""",
        (permission,)).fetchall()]


def persona_suspended(conn: psycopg.Connection, *, persona_id: UUID,
                      reason: str) -> int:
    """A platform refused a persona's credential: tell the collection
    managers who may see the persona.

    Labelled with the highest classification among EVERY source the persona
    is registered on or bound to, active or not (the set set_status's
    visibility predicate reads), AMBER when there is none, so a manager that
    predicate hides from the persona is never told about it: the
    notification service refuses a recipient below the label (suppression
    2). When collect.source gains compartments through the compartment
    contract, the union of those sources' compartments goes on it too. One
    unacknowledged notification per persona at a time, the integrity
    alarm's guard: a platform refusing a credential on every poll must not
    ring a phone on every poll. Returns how many were raised."""
    outstanding = conn.execute(
        """SELECT 1 FROM notify.notification
            WHERE kind = 'PERSONA_SUSPENDED'
              AND object_type = 'collection_account' AND object_id = %s
              AND acknowledged_at IS NULL LIMIT 1""", (persona_id,)).fetchone()
    if outstanding is not None:
        return 0
    row = conn.execute(
        """SELECT a.handle, a.platform_uid,
                  (SELECT max(s.classification)::text FROM collect.source s
                    WHERE s.id = a.source_id OR s.collection_account_id = a.id)
             FROM collect.collection_account a WHERE a.id = %s""",
        (persona_id,)).fetchone()
    if row is None:
        return 0
    handle, uid, label = row
    svc = NotificationService(conn)
    raised = 0
    for user_id in _global_holders(conn, "collection_account.manage"):
        if svc.notify(
                recipient_id=user_id, case_id=None,
                kind="PERSONA_SUSPENDED",
                subject="A collection persona was suspended",
                summary=("A platform refused a persona's credential. "
                         "Collection through it is paused."),
                body=(f"Persona {handle} ({uid or 'no account id recorded'}) "
                      f"was locked: {reason}\n\nOpen Feeds, Sources, "
                      f"Personas."),
                classification=label or "AMBER", compartments=frozenset(),
                object_type="collection_account",
                object_id=persona_id) is not None:
            raised += 1
    return raised


def persona_credential_alert(conn: psycopg.Connection, *,
                             persona_id: UUID) -> int:
    """The platform reported one persona credential in use from two places
    at once, which is how a copied credential shows itself. URGENT, to every
    active security officer, GREEN and case-less, naming no handle: the
    officer reads no case content, and the audit trail has the rest."""
    officers = [r[0] for r in conn.execute(
        """SELECT DISTINCT u.id FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
            WHERE u.is_active AND ur.role_key = 'SECURITY_OFFICER'""").fetchall()]
    svc = NotificationService(conn)
    raised = 0
    for user_id in officers:
        if svc.notify(
                recipient_id=user_id, case_id=None,
                kind="PERSONA_CREDENTIAL_ALERT",
                subject="A persona's credential may have been copied",
                summary=("A platform reported one persona credential in use "
                         "from two places at once. That is how a copied "
                         "credential shows itself. Collection through it is "
                         "stopped."),
                body=(f"Persona {persona_id}. The audit trail, which you may "
                      f"read, has the rest."),
                classification="GREEN", compartments=frozenset(),
                object_type="collection_account",
                object_id=persona_id) is not None:
            raised += 1
    return raised


def collection_authority_pending(conn: psycopg.Connection, *,
                                 authority_id: UUID, actor_id: UUID) -> int:
    """An authority was recorded or extended: tell everyone who could
    confirm it, except the person who acted (who is never the second
    person). GREEN, case-less, naming no persona and no source, and at most
    one unacknowledged per authority and recipient, so adding sources one at
    a time does not stack notifications."""
    svc = NotificationService(conn)
    raised = 0
    for user_id in _global_holders(conn, "collection.authority.confirm"):
        if user_id == actor_id:
            continue
        waiting = conn.execute(
            """SELECT 1 FROM notify.notification
                WHERE kind = 'COLLECTION_AUTHORITY_PENDING'
                  AND object_type = 'collection_authority' AND object_id = %s
                  AND recipient_id = %s AND acknowledged_at IS NULL
                LIMIT 1""", (authority_id, user_id)).fetchone()
        if waiting is not None:
            continue
        if svc.notify(
                recipient_id=user_id, case_id=None,
                kind="COLLECTION_AUTHORITY_PENDING",
                subject="A collection authority needs a second person",
                summary=("An authority to collect from forum or Telegram "
                         "sources was recorded or extended. Nothing is read "
                         "under it until a second person confirms it."),
                body=(f"Open Oversight, Collection authorities. Authority "
                      f"{authority_id}."),
                classification="GREEN", compartments=frozenset(),
                object_type="collection_authority", object_id=authority_id,
                actor_id=actor_id) is not None:
            raised += 1
    return raised


# F15.2 and F15.3 (2026-09-24). Lowering a lookup
# provider's exposure takes a second administrator, and a lookup that sends
# case material to a vendor or the public takes a named second person's
# sign-off (docs/00 decision 75). Neither is ever routed to Jira
# (jira.JIRA_NEVER_KINDS). No selector value appears in any of these: the
# authoriser reads it in the product, behind the case gate.

def provider_change_requested(conn: psycopg.Connection, *, change_id: UUID,
                              provider_name: str, from_level: str, to_level: str,
                              actor_id: UUID) -> int:
    """Every OTHER active holder of integration.manage: the people who may
    decide it. No case, CLEAR, no case content."""
    rows = conn.execute(
        """SELECT DISTINCT ur.user_id FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE rp.permission_key = 'integration.manage' AND u.is_active
              AND ur.user_id <> %s""", (actor_id,)).fetchall()
    svc = NotificationService(conn)
    event = uuid4()
    sent = 0
    for (user_id,) in rows:
        raised = svc.notify(
            recipient_id=user_id, case_id=None, event_id=event,
            kind="PROVIDER_CHANGE_REQUESTED",
            subject=f"A second administrator is needed: {provider_name}",
            summary=(f"An administrator asks to lower a lookup provider's exposure "
                     f"from {from_level} to {to_level}. Sign in to decide it."),
            body=(f"An administrator asks to lower the exposure of {provider_name} "
                  f"from {from_level} to {to_level}. Read the basis they recorded "
                  f"under Administration, Providers, and approve or decline it. The "
                  f"request lapses after 72 hours."),
            classification="CLEAR", compartments=frozenset(),
            object_type="provider_exposure_change", object_id=change_id,
            actor_id=actor_id)
        if raised is not None:
            sent += 1
    return sent


def lookup_signoff_requested(conn: psycopg.Connection, *, case_id: UUID,
                             lookup_id: UUID, authoriser_id: UUID,
                             provider_name: str, expires_at, classification: str,
                             actor_id: UUID):
    code, _case_cls, compartments = _case(conn, case_id)
    return NotificationService(conn).notify(
        recipient_id=authoriser_id, case_id=case_id,
        kind="LOOKUP_SIGNOFF_REQUESTED",
        subject=(f"{code}: a lookup on {provider_name} needs your sign-off by "
                 f"{expires_at:%Y-%m-%d %H:%M} UTC"),
        summary=(f"A colleague on {code} asks you to sign off a lookup that sends a "
                 f"case selector to {provider_name}. Sign in to review it."),
        body=(f"A colleague asks you to sign off a lookup on {provider_name}. "
              f"Nothing has been sent. Open the case's Records, Lookups, read what "
              f"would leave and why, and sign it off or decline it before "
              f"{expires_at:%Y-%m-%d %H:%M} UTC, when it lapses."),
        classification=classification, compartments=compartments,
        object_type="lookup", object_id=lookup_id, actor_id=actor_id)


def lookup_signoff_decided(conn: psycopg.Connection, *, case_id: UUID,
                           lookup_id: UUID, requester_id: UUID, outcome: str,
                           classification: str, actor_id: UUID | None):
    """The outcome word only (signed off, declined, refused, lapsed), never a
    refusal reason: a requester no longer cleared for a raised subject must
    learn nothing of its new label."""
    code, _case_cls, compartments = _case(conn, case_id)
    return NotificationService(conn).notify(
        recipient_id=requester_id, case_id=case_id,
        kind="LOOKUP_SIGNOFF_DECIDED",
        subject=f"{code}: your lookup was {outcome}",
        summary=f"Your lookup on {code} was {outcome}.",
        body=(f"Your lookup was {outcome}. Open the case's Records, Lookups for "
              f"what happened."),
        classification=classification, compartments=compartments,
        object_type="lookup", object_id=lookup_id, actor_id=actor_id)


# Prohibited-content screening (F13) and the sandbox (F14), 2026-09-24.

@dataclass(frozen=True)
class Reach:
    """Who a screening alert reached. `notified` rows were written now;
    `coalesced` recipients already held an open alert from the last hour."""

    notified: int
    coalesced: int
    recipients: int
    designated_person_told: bool


def _screening_recipients(conn: psycopg.Connection) -> list[UUID]:
    """Every active Security Officer, and the active account whose email is
    the designated person's, once each."""
    from noctornal_api.iam_admin import active_role_holders
    people = active_role_holders(conn, "SECURITY_OFFICER")
    person = os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip()
    if person:
        row = conn.execute(
            "SELECT id FROM iam.app_user WHERE lower(email) = lower(%s) "
            "AND is_active", (person,)).fetchone()
        if row and row[0] not in people:
            people.append(row[0])
    return people


def _open_alert(conn: psycopg.Connection, recipient: UUID, kind: str, *,
                window: timedelta, case_id: UUID | None = None,
                unread: bool = False) -> bool:
    """Whether the recipient already holds an open notice of this kind from
    within the window (unacknowledged, or unread with `unread`)."""
    state = "read_at" if unread else "acknowledged_at"
    return conn.execute(
        f"""SELECT 1 FROM notify.notification
             WHERE recipient_id = %s AND kind = %s
               AND created_at > now() - %s
               AND {state} IS NULL
               AND (%s::uuid IS NULL OR case_id = %s::uuid)
             LIMIT 1""",
        (recipient, kind, window, case_id, case_id)).fetchone() is not None


_TRIGGER_WORDS = {"SUBMISSION": "when it was submitted",
                  "LIST_IMPORT": "when a list was imported",
                  "RESCAN": "in a screening pass"}
_DISPOSITION_WORDS = {
    "PRESERVE": "Its bytes are being moved into the preservation store under "
                "a legal hold.",
    "NOT_STORED": "It was never stored: this deployment destroys rejected "
                  "material.",
    "STORE_FAILED": "It could not be stored, so nothing is held.",
    "ALREADY_PRESERVED": "Its bytes were already in the preservation store.",
    "NO_BYTES": "Its bytes had already been destroyed.",
    "ALREADY_ISOLATED": "It had already matched and been isolated; this was "
                        "another attempt to bring it in.",
}


def screening_match(conn: psycopg.Connection, *, result_id: UUID,
                    list_ids, trigger: str, disposition: str,
                    detonations_sent: int = 0) -> Reach:
    """The officers' and the designated person's alert (F13). URGENT, GREEN
    and caseless, like the break-glass alert: it names the lists, what set
    it off and what happened to the bytes, and never a case code, a
    filename or a hash, because the Security Officer reads no case content
    and this goes out by email. Coalesced: a recipient already holding an
    unacknowledged alert of this kind from the last hour is not alerted
    again, so a bulk import of fifty matches raises one alert each."""
    from noctornal_api.notifications import URGENT
    from noctornal_api.screening import ALERT_WINDOW
    from noctornal_api.wording import count_of

    names = [r[0] for r in conn.execute(
        "SELECT name FROM lab.screening_list WHERE id = ANY(%s::uuid[]) "
        "ORDER BY seq", ([str(x) for x in list_ids],)).fetchall()]
    person = (os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip()
              or "the designated person")
    reference = (os.environ.get("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "").strip()
                 or "the prohibited-content policy")
    recipients = _screening_recipients(conn)
    designated = conn.execute(
        "SELECT id FROM iam.app_user WHERE lower(email) = lower(%s) AND is_active",
        (person,)).fetchone()
    svc = NotificationService(conn)
    notified = coalesced = 0
    told_person = False
    sent_line = ""
    if detonations_sent:
        sent_line = (
            "\n\n" + count_of(detonations_sent, "detonation of it was",
                              "detonations of it were")
            + " already sent to a sandbox, which nothing here can recall. "
              "The record names where.")
    for recipient in recipients:
        if _open_alert(conn, recipient, "SAMPLE_SCREENING_MATCH",
                       window=ALERT_WINDOW):
            coalesced += 1
            continue
        raised = svc.notify(
            recipient_id=recipient, case_id=None,
            kind="SAMPLE_SCREENING_MATCH", priority=URGENT,
            subject="A sample matched a prohibited-content list",
            summary=("A sample matched a prohibited-content hash list and was "
                     "isolated. It needs your review. Sign in to see it."),
            body=(f"A sample matched {count_of(len(names), 'list', 'lists')} "
                  f"({', '.join(names)}) {_TRIGGER_WORDS.get(trigger, '')}. "
                  f"It is isolated: nobody can open, download or send it. "
                  f"{_DISPOSITION_WORDS.get(disposition, '')}{sent_line}\n\n"
                  f"The designated person is {person}; follow {reference}. "
                  f"Screening compares exact hashes and does not establish "
                  f"what the material is.\n\n"
                  f"The record is under Oversight, Prohibited-content "
                  f"screening. Further matches within the hour are recorded "
                  f"there without another alert."),
            classification="GREEN", compartments=frozenset(),
            object_type="sample_screening", object_id=result_id)
        if raised is not None:
            notified += 1
            if designated and recipient == designated[0]:
                told_person = True
    return Reach(notified, coalesced, len(recipients), told_person)


def sample_withdrawn(conn: psycopg.Connection, *, sample_id: UUID,
                     case_id: UUID, result_id: UUID) -> bool | str:
    """The case owner is told a sample was withdrawn, at the SAMPLE's labels
    composed with the case's, so an owner not read into the sample's own
    compartments gets nothing (the notice would be an existence oracle for
    a more restricted sample). Coalesced per case owner per hour: a list
    matching five hundred samples of one case is one notice. Returns True
    when written, "coalesced", or False when suppressed."""
    from noctornal_api.screening import ALERT_WINDOW
    code, classification, compartments = _case(conn, case_id)
    own = conn.execute(
        "SELECT classification, compartments FROM lab.sample WHERE id = %s",
        (sample_id,)).fetchone()
    # The owner as a lock fact (S1, 2026-09-25), whoever is asking.
    owner = conn.execute('SELECT owner_user_id FROM iam.case_facts(%s)',
                         (case_id,)).fetchone()
    if own is None or owner is None:
        return False
    if _open_alert(conn, owner[0], "SAMPLE_WITHDRAWN", window=ALERT_WINDOW,
                   case_id=case_id, unread=True):
        return "coalesced"
    raised = NotificationService(conn).notify_case_owner(
        case_id, kind="SAMPLE_WITHDRAWN",
        subject=f"{code}: a sample was withdrawn",
        summary=(f"A sample attached to {code} was withdrawn by "
                 f"prohibited-content screening. The Security Officer holds "
                 f"the record."),
        body=(f"A sample attached to {code} matched a prohibited-content hash "
              f"list and was withdrawn from the Lab for everyone. The Security "
              f"Officer holds the record. Further samples of this case "
              f"withdrawn within the hour are not notified again."),
        classification=classification, compartments=compartments,
        element_classification=own[0],
        element_compartments=frozenset(own[1] or []),
        object_type="sample_screening", object_id=result_id)
    return raised is not None


def _sample_labels(conn: psycopg.Connection, sample_id: UUID):
    """(case id, case code, case classification, case compartments, the
    sample's own classification and compartments).

    The case through `iam.case_facts` (S1, 2026-09-25): the Lab analyst
    who asks for a detonation is on no case, and under row-level security
    a LEFT JOIN to `core."case"` read their sample's case as absent, so
    the notice lost the case's labels (a case notice was raised at no
    classification at all and the request failed)."""
    return conn.execute(
        """SELECT s.case_id, c.code, c.classification, c.compartments,
                  s.classification, s.compartments
             FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
            WHERE s.id = %s""", (sample_id,)).fetchone()


def _detonation_notice(conn: psycopg.Connection, *, recipient: UUID,
                       sample_id: UUID, kind: str, subject: str,
                       summary: str, body: str, detonation_id: UUID,
                       actor_id: UUID | None, caseless: bool = False
                       ) -> Notification | None:
    row = _sample_labels(conn, sample_id)
    if row is None:
        return None
    case_id, _code, case_cls, case_comps, own_cls, own_comps = row
    if case_id is None or caseless:
        # Labelled at the sample's composed labels, with no case: a malware
        # analyst holds no case assignment, and the notice must not need one.
        from noctornal_api.security.access import tlp_from_name
        level = own_cls
        if case_cls is not None:
            level = max(tlp_from_name(own_cls), tlp_from_name(case_cls)).name
        return NotificationService(conn).notify(
            recipient_id=recipient, case_id=None, kind=kind, subject=subject,
            summary=summary, body=body, classification=level,
            compartments=frozenset(own_comps or []) | frozenset(case_comps or []),
            object_type="detonation", object_id=detonation_id,
            actor_id=actor_id)
    return NotificationService(conn).notify(
        recipient_id=recipient, case_id=case_id, kind=kind, subject=subject,
        summary=summary, body=body, classification=case_cls,
        compartments=frozenset(case_comps or []),
        element_classification=own_cls,
        element_compartments=frozenset(own_comps or []),
        object_type="detonation", object_id=detonation_id, actor_id=actor_id)


def detonation_signoff_requested(conn: psycopg.Connection, *,
                                 detonation_id: UUID, sample_id: UUID,
                                 authoriser_id: UUID, requester_id: UUID,
                                 target: str) -> Notification | None:
    """The named authoriser is asked for their sign-off (F14). At the case's
    labels with the sample's own composed in, so an authoriser who cannot
    read the sample is told nothing."""
    row = _sample_labels(conn, sample_id)
    code = row[1] if row else None
    head = (f"{code}: a detonation needs your sign-off" if code
            else "A detonation needs your sign-off")
    return _detonation_notice(
        conn, recipient=authoriser_id, sample_id=sample_id,
        kind="DETONATION_SIGNOFF_REQUESTED", subject=head,
        summary=("A colleague asked to send a sample to a sandbox, and you are "
                 "named to sign it off. Sign in to approve or decline it."),
        body=(f"A request to send a sample to {target} names you as the "
              f"person who signs it off. Nothing is sent until you approve "
              f"it, and it lapses in 72 hours. Open the Lab: the request is "
              f"listed under Detonations awaiting your sign-off."),
        detonation_id=detonation_id, actor_id=requester_id)


def detonation_signoff_decided(conn: psycopg.Connection, *,
                               detonation_id: UUID, sample_id: UUID,
                               requester_id: UUID, approved: bool,
                               actor_id: UUID) -> Notification | None:
    """The requester is told the sign-off was given or declined (F14).
    Caseless and labelled at the sample's composed labels, like the result:
    the requester is a malware analyst who holds no case assignment, and a
    notice filed under the case would be suppressed for them. For the same
    reason the subject does not name the case."""
    verdict = "approved" if approved else "declined"
    return _detonation_notice(
        conn, recipient=requester_id, sample_id=sample_id,
        kind="DETONATION_SIGNOFF_DECIDED",
        subject=f"Your detonation was {verdict}",
        summary=f"The sign-off on your detonation request was {verdict}.",
        body=(f"Your request to send a sample to a sandbox was {verdict}."
              + (" The sandbox worker sends it on its next pass." if approved
                 else " Nothing was sent.")),
        detonation_id=detonation_id, actor_id=actor_id, caseless=True)


def sandbox_result(conn: psycopg.Connection, *, detonation_id: UUID,
                   sample_id: UUID, requester_id: UUID,
                   outcome: str) -> Notification | None:
    """The requester is told a sandbox run ended (F14): `outcome` says it
    finished, failed, was refused or ended without a result. Caseless and
    labelled at the sample's composed labels: a malware analyst holds no
    case assignment."""
    return _detonation_notice(
        conn, recipient=requester_id, sample_id=sample_id,
        kind="SANDBOX_RESULT", subject="A sandbox run ended",
        summary=(f"The detonation you requested {outcome}. Sign in to read "
                 f"it."),
        body=(f"The detonation you requested {outcome}. The Lab card of the "
              f"sample has the details."),
        detonation_id=detonation_id, actor_id=None, caseless=True)
