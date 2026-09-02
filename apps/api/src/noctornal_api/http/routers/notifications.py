"""The notification centre over HTTP, plus the outbox drain.

Not case-scoped: an inbox spans every case its owner is on, so the gate
here is "are you you", not "may you read this case". The content filter is
inside `NotificationService.inbox`, which re-checks the CURRENT clearance
in SQL -- a revoked clearance has to hide old notifications too, or the
centre quietly becomes a retention loophole for everything the analyst used
to be able to see.

Reading and acknowledging are scoped to the recipient by the WHERE clause,
not by a check the handler could forget: `mark_read(id, recipient_id)`
cannot touch somebody else's row even if the id is guessed.
"""
from __future__ import annotations

from datetime import datetime, time
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noctornal_api.http.deps import CurrentUser, current_user, get_conn, require_global
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.notifications import (
    KINDS,
    Notification,
    NotificationError,
    NotificationService,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])


class NotificationOut(BaseModel):
    id: str
    case_id: str | None
    kind: str
    priority: int
    subject: str
    summary: str
    body: str
    classification: str
    object_type: str | None
    object_id: str | None
    created_at: datetime
    read_at: datetime | None
    acknowledged_at: datetime | None


def _out(n: Notification) -> NotificationOut:
    return NotificationOut(
        id=str(n.id), case_id=str(n.case_id) if n.case_id else None,
        kind=n.kind, priority=n.priority, subject=n.subject, summary=n.summary,
        body=n.body, classification=n.classification,
        object_type=n.object_type,
        object_id=str(n.object_id) if n.object_id else None,
        created_at=n.created_at, read_at=n.read_at,
        acknowledged_at=n.acknowledged_at,
    )


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def inbox(
    unread_only: bool = Query(False),
    case_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    svc = NotificationService(conn)
    rows = svc.inbox(user.user_id, unread_only=unread_only, limit=limit,
                     case_id=case_id)
    return {"notifications": [_out(n).model_dump(mode="json") for n in rows],
            "unread": svc.unread_count(user.user_id)}


@router.get("/unread-count", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def unread(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The badge. Polled, so it is deliberately one indexed COUNT and
    nothing else."""
    return {"unread": NotificationService(conn).unread_count(user.user_id)}


@router.post("/{notification_id}/read", status_code=204)
def mark_read(
    notification_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> None:
    if not NotificationService(conn).mark_read(notification_id, user.user_id):
        raise Problem(404, "Not found", "no such notification")


@router.post("/read-all", response_model=dict)
def mark_all_read(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    return {"marked": NotificationService(conn).mark_all_read(user.user_id)}


@router.post("/{notification_id}/acknowledge", status_code=204)
def acknowledge(
    notification_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> None:
    """Distinct from reading (docs/07): acknowledgement is the signal that
    stops a thing nagging, and glancing at a list is not that."""
    if not NotificationService(conn).acknowledge(notification_id, user.user_id):
        raise Problem(404, "Not found", "no such notification")


class PreferenceIn(BaseModel):
    enabled: bool | None = None
    min_priority: int | None = Field(default=None, ge=1, le=3)
    digest: bool | None = None
    quiet_from: time | None = None
    quiet_to: time | None = None
    timezone: str | None = None
    address: str | None = None


class PreferenceOut(BaseModel):
    channel: str
    enabled: bool
    min_priority: int
    digest: bool
    quiet_from: time | None
    quiet_to: time | None
    timezone: str
    address: str | None


@router.get("/preferences", response_model=dict)
def get_preferences(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    prefs = NotificationService(conn).preferences(user.user_id)
    return {
        "preferences": [PreferenceOut(**vars(p)).model_dump(mode="json")
                        for p in prefs.values()],
        "kinds": {k: {"priority": v.default_priority,
                      "description": v.description} for k, v in KINDS.items()},
    }


@router.put("/preferences/{channel}", response_model=PreferenceOut)
def set_preference(
    channel: str, body: PreferenceIn,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> PreferenceOut:
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    # An explicit null on either half of the quiet window means "clear it",
    # which model_dump's None-stripping would otherwise swallow.
    if "quiet_from" in body.model_fields_set:
        fields["quiet_from"] = body.quiet_from
    if "quiet_to" in body.model_fields_set:
        fields["quiet_to"] = body.quiet_to
    if "address" in body.model_fields_set:
        fields["address"] = body.address
    try:
        return PreferenceOut(**vars(
            NotificationService(conn).set_preference(user.user_id, channel, **fields)))
    except NotificationError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


class DrainOut(BaseModel):
    sent: int
    redacted: int
    refused: int
    failed: int
    #: Rows made undeliverable by a clearance or assignment revoked AFTER
    #: they were queued (transports.revoke_undeliverable). The drain has
    #: always computed this; the model did not declare it, and pydantic
    #: drops an undeclared key without a sound -- so the one counter that
    #: says "these people were NOT told, on purpose" never reached the
    #: operator who pressed the button. test_ui_invariants holds the model
    #: to every key the drain returns.
    revoked: int
    #: N3 (2026-09-02): one drain does three things. How many case owners
    #: were told a review is due (notify_events.case_reviews_due) and how
    #: many unacknowledged priority-1 notifications were escalated
    #: (notifications.escalate_unacknowledged) in this pass.
    reviews_due: int
    escalated: int


@router.post("/dispatch", response_model=DrainOut)
def dispatch(
    _: CurrentUser = Depends(require_global("integration.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> DrainOut:
    """Drain the outbox once.

    A function you call, not a loop that runs. There is no worker process in
    this build -- decision 30 set that precedent for analytics and the same
    reasoning applies: a queue adds a process, a runtime and a failure mode.
    So the drain is driven by an operator, a cron entry or a test, and that
    limitation is written down here rather than hidden behind a thread that
    silently dies at 3am.

    Gated on `integration.manage`, which is step-up, because draining sends
    real email to real people. A cron entry cannot satisfy step-up;
    `scripts/notify_drain.py` is the drain for one (N3, 2026-09-02).
    """
    from noctornal_api.transports import dispatch_due
    return DrainOut(**dispatch_due(conn))


class DeliveryOut(BaseModel):
    """One row of the delivery ledger. Names the KIND and never the content:
    the reader holds `integration.manage`, which is not a case-content
    permission, and this table is not case-scoped."""

    id: str
    notification_id: str
    kind: str
    channel: str
    recipient_id: str
    #: The account email, which an administrator controls. Not the
    #: preference override -- that is `address`, and the two differing is
    #: the case an operator most needs to be able to see.
    recipient: str
    #: Where it actually went (`delivery.sent_to`, migration 0044). None if
    #: nothing has left yet, or nothing ever will.
    address: str | None
    #: The delivery state: PENDING, SENT, FAILED, REFUSED or SUPPRESSED.
    outcome: str
    #: The egress gate's reason code on a REFUSED row, the transport error
    #: on a FAILED or backed-off one, the suppression reason otherwise.
    reason: str | None
    redacted: bool
    attempts: int
    #: The last time a transport was tried. None for a row that has never
    #: been attempted -- queued, deferred, or suppressed at write time.
    attempted_at: datetime | None
    #: When the notification behind it was raised.
    raised_at: datetime


#: Outcomes that mean the recipient did NOT get the full summary on this
#: channel and somebody other than the recipient decided so. PENDING is
#: excluded: nothing has been decided yet. SUPPRESSED is NOT in this
#: tuple because it has two writers that mean opposite things, and the SQL
#: below tells them apart: `NotificationService._queue_deliveries` writes it
#: at raise time for a channel the recipient turned off or a priority below
#: their threshold (two such rows per notification, with no attempt
#: timestamp -- the recipient's own choice, not an absence to explain), and
#: `transports.revoke_undeliverable` writes it AFTER queueing, stamping
#: `last_attempt_at`, when a clearance or assignment was revoked -- the one
#: row that says "deliberately not told", which the filter exists to show.
#: The first version of this filter took every SUPPRESSED row and buried
#: each real refusal under the preference rows of every notification.
_NOT_DELIVERED = ("REFUSED", "FAILED")


@router.get("/deliveries", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def deliveries(
    kind: str | None = Query(None),
    refused_only: bool = Query(False),
    since: datetime | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _: CurrentUser = Depends(require_global("integration.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Read the delivery ledger back, newest first.

    N4 (2026-09-02). `notify.delivery` has recorded every refusal with a
    reason since migration 0029 and every destination since 0044, and
    nothing rendered it: the one table that answers "did the summary leave
    the building, and where did it go" was write-only. This is the read.

    `refused_only` narrows to REFUSED, FAILED, and the SUPPRESSED rows the
    system closed after queueing (a revoked clearance or assignment) -- the
    rows that explain an absence the recipient did not choose. A channel
    the recipient turned off is not one. `since` and the ordering both use the
    attempt time when there is one and the notification's own time when
    there is not, so a suppressed row sorts where it was decided.

    `kind` is not validated against `KINDS`: a kind that has since been
    unregistered still has rows, and an operator asking about them should
    get them, not a 400.

    Under `integration.manage` because the ledger spans every case and
    every recipient. It carries kinds, channels, addresses and reasons --
    never subjects or summaries.
    """
    rows = conn.execute(
        """SELECT d.id, d.notification_id, n.kind, d.channel, n.recipient_id,
                  u.email, d.sent_to, d.state, d.detail, d.redacted, d.attempts,
                  coalesce(d.last_attempt_at, d.sent_at), n.created_at
             FROM notify.delivery d
             JOIN notify.notification n ON n.id = d.notification_id
             JOIN iam.app_user u ON u.id = n.recipient_id
            WHERE (%(kind)s::text IS NULL OR n.kind = %(kind)s)
              AND (NOT %(refused_only)s
                   OR d.state = ANY(%(not_delivered)s)
                   OR (d.state = 'SUPPRESSED' AND d.last_attempt_at IS NOT NULL))
              AND (%(since)s::timestamptz IS NULL
                   OR coalesce(d.last_attempt_at, d.sent_at, n.created_at) >= %(since)s)
            ORDER BY coalesce(d.last_attempt_at, d.sent_at, n.created_at) DESC,
                     d.id DESC
            LIMIT %(limit)s""",
        {"kind": kind, "refused_only": refused_only,
         "not_delivered": list(_NOT_DELIVERED), "since": since,
         "limit": limit}).fetchall()
    return {"deliveries": [DeliveryOut(
        id=str(r[0]), notification_id=str(r[1]), kind=r[2], channel=r[3],
        recipient_id=str(r[4]), recipient=r[5], address=r[6], outcome=r[7],
        reason=r[8], redacted=r[9], attempts=r[10], attempted_at=r[11],
        raised_at=r[12]).model_dump(mode="json") for r in rows]}
