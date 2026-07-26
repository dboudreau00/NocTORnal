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
from noctornal_api.http.errors import Problem
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
        raise Problem(400, "Invalid request", str(exc)) from exc


class DrainOut(BaseModel):
    sent: int
    redacted: int
    refused: int
    failed: int


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
    real email to real people.
    """
    from noctornal_api.transports import dispatch_due
    return DrainOut(**dispatch_due(conn))
