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

import base64
import binascii
from datetime import datetime, time, timedelta, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.http.deps import CurrentUser, current_user, get_conn, require_global
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.notifications import (
    KINDS,
    Notification,
    NotificationError,
    NotificationService,
    escalates_at,
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
    #: When the drain escalates this unless it is acknowledged first, for
    #: an unacknowledged priority-1 row; None otherwise
    #: (ux08-triage:urgent-read-vs-ack-invisible, 2026-09-23).
    escalates_at: datetime | None = None
    #: The case CODE, so a card about another case can say which one it
    #: opens (ux08-triage:open-approvals-wrong-case, 2026-09-23). The
    #: subject already carries it; this is the same fact as a field.
    case_code: str | None = None


def _out(n: Notification, codes: dict | None = None) -> NotificationOut:
    return NotificationOut(
        id=str(n.id), case_id=str(n.case_id) if n.case_id else None,
        kind=n.kind, priority=n.priority, subject=n.subject, summary=n.summary,
        body=n.body, classification=n.classification,
        object_type=n.object_type,
        object_id=str(n.object_id) if n.object_id else None,
        created_at=n.created_at, read_at=n.read_at,
        acknowledged_at=n.acknowledged_at,
        escalates_at=escalates_at(n),
        case_code=(codes or {}).get(n.case_id),
    )


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def inbox(
    unread_only: bool = Query(False),
    needs_action: bool = Query(False),
    case_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """`needs_action` is the console's default filter: unread, or urgent
    and not yet acknowledged, which is what still escalates."""
    svc = NotificationService(conn)
    rows = svc.inbox(user.user_id, unread_only=unread_only, limit=limit,
                     case_id=case_id, needs_action=needs_action)
    case_ids = list({n.case_id for n in rows if n.case_id})
    codes = {r[0]: r[1] for r in conn.execute(
        'SELECT id, code FROM core."case" WHERE id = ANY(%s)',
        (case_ids,)).fetchall()} if case_ids else {}
    return {"notifications": [_out(n, codes).model_dump(mode="json")
                              for n in rows],
            "unread": svc.unread_count(user.user_id),
            "urgent_unacknowledged": svc.urgent_unacknowledged(user.user_id)}


@router.get("/unread-count", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def unread(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The badge. Polled, so it is deliberately two indexed COUNTs and
    nothing else: unread, and urgent-but-unacknowledged, which the badge
    marks apart because reading an alarm does not stop it escalating
    (ux08-triage:urgent-read-vs-ack-invisible, 2026-09-23)."""
    svc = NotificationService(conn)
    return {"unread": svc.unread_count(user.user_id),
            "urgent_unacknowledged": svc.urgent_unacknowledged(user.user_id)}


@router.get("/waiting", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def waiting(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What is waiting for this person, per case: proposals in the triage
    queue, and approval requests they could sign.

    ux08-triage:no-work-waiting-at-sign-in (2026-09-23). The case list
    showed code, title, status and classification, and the first question
    after sign-in ("what needs me now") was answered by opening each case
    to read its badges; a request whose notification had been read left
    no trace on any badge. Here, not under a case, because the case list
    is where it is read. Counts only, and only over cases the person may
    read (see `ProposalStore.waiting_by_case` and
    `ApprovalService.awaiting_signature`)."""
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.http.deps import user_ceiling
    from noctornal_api.proposals import ProposalStore

    clearance, held = user_ceiling(conn, user.user_id)
    triage = ProposalStore(conn).waiting_by_case(
        user.user_id, clearance=clearance.name, compartments=held)
    sign = ApprovalService(conn).awaiting_signature(
        user.user_id, clearance=clearance.name, compartments=held)
    cases = {}
    for cid in set(triage) | set(sign):
        cases[cid] = {"triage": triage.get(cid, 0),
                      "signatures": sign.get(cid, 0)}
    return {"cases": cases}


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
        # F8 and F7 (2026-09-24): whether each outbound channel can
        # deliver at all, and why not, so a preference is never switched on
        # into a channel that holds everything.
        "channels": _channels(conn),
    }


def _channels(conn) -> dict:
    from noctornal_api import jira, transports

    out = {}
    for channel in (transports.SMTP, transports.WEBHOOK):
        state = transports.route_state(channel, conn)
        out[channel] = {"available": state.ok, "why": state.why}
    routing = jira.routing(conn)
    dest = jira.live_destination(conn) if routing else None
    out["JIRA"] = {
        "available": routing is not None,
        "why": None if routing else ("No Jira destination is active. An administrator "
                                     "sets one up in Administration, Integrations."),
        "project_key": dest.project_key if dest else None,
        "host": dest.host if dest else None,
        "kinds": [KINDS[k].description for k in sorted(routing.kinds) if k in KINDS]
        if routing else [],
        "case_blocks_apply": True,
    }
    return out


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
    #: F8 and F7 (2026-09-24): due rows of a channel whose route is
    #: missing or refusing, left PENDING with their attempts untouched;
    #: Jira rows left for a later pass (circuit open, budget spent, an
    #: unsettled create); Jira rows withdrawn because nothing may route them
    #: any more.
    held: int = 0
    deferred: int = 0
    withdrawn: int = 0
    #: N3 (2026-09-02): one drain does three things. How many case owners
    #: were told a review is due (notify_events.case_reviews_due) and how
    #: many unacknowledged priority-1 notifications were escalated
    #: (notifications.escalate_unacknowledged) in this pass.
    reviews_due: int
    escalated: int


@router.post("/dispatch", response_model=DrainOut,
             dependencies=[Depends(rate_limit("integration.write"))])
def dispatch(
    user: CurrentUser = Depends(require_global("integration.manage")),
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

    Metered and audited (F8, 2026-09-24): a manual drain sends real
    mail and real Jira issues, so it writes NOTIFY_DRAIN_RUN with the
    caller and the counters. The cron drain writes nothing, as before.
    """
    from noctornal_api.transports import dispatch_due
    counters = dispatch_due(conn)
    _audit(conn, user.user_id, "NOTIFY_DRAIN_RUN", "notify_outbox", None, counters)
    return DrainOut(**counters)


def _audit(conn, actor_id, action: str, object_type: str, object_id, detail: dict) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, outcome, detail)
           VALUES (%s, 'USER', %s, %s, %s, 'SUCCESS', %s)""",
        (actor_id, action, object_type, object_id, Json(detail)))


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
    #: Whether that account is still active (F8): a delivery to an
    #: account since deactivated is read differently.
    recipient_active: bool = True
    #: Where it actually went (`delivery.sent_to`, migration 0044): an
    #: address, a webhook endpoint with its path WITHHELD (0096; the path is
    #: a bearer secret), or a Jira browse URL. None if nothing has left yet.
    address: str | None
    #: The delivery state: PENDING, SENT, FAILED, REFUSED or SUPPRESSED.
    outcome: str
    #: The human sentence stored with the row (the egress gate's reason
    #: code on a refusal, the transport error on a failure).
    reason: str | None
    redacted: bool
    attempts: int
    #: The last time a transport was tried. None for a row that has never
    #: been attempted -- queued, deferred, or suppressed at write time.
    attempted_at: datetime | None
    #: When the notification behind it was raised.
    raised_at: datetime
    #: F8 (2026-09-24): why, as a stable code and a sentence.
    cause: str | None = None
    cause_text: str | None = None
    #: What left: SUMMARY, SUBJECT, STUB or NOTHING; None while PENDING.
    left: str | None = None
    queued_at: datetime | None = None
    #: When the next attempt is due, while PENDING.
    next_attempt_at: datetime | None = None
    #: The Jira issue key, for a Jira row that reached an issue.
    jira_issue: str | None = None


#: The rows that explain an absence the recipient did not choose (F8):
#: refused, failed, revoked, withdrawn after queueing, and history from
#: before causes. Routine standing choices (a channel turned off, a
#: priority threshold, the Jira routing decisions) stay out and are
#: reachable through the cause filter.
_NOT_DELIVERED = ("REFUSED", "FAILED")
_UNCHOSEN_CAUSES = ("REVOKED", "WITHDRAWN", "LEGACY")

OUTCOMES = ("PENDING", "SENT", "FAILED", "REFUSED", "SUPPRESSED")
CHANNELS = ("IN_APP", "SMTP", "WEBHOOK", "JIRA")


def _left(state: str, channel: str, cause: str | None, exposure: str | None) -> str | None:
    if state == "PENDING":
        return None
    if channel == "IN_APP":
        return None
    if exposure in ("SUMMARY", "SUBJECT", "STUB"):
        return exposure
    return "NOTHING"


def _encode_cursor(at: datetime, row_id) -> str:
    raw = f"{at.isoformat()}|{row_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(text: str) -> tuple[datetime, UUID]:
    try:
        padded = text + "=" * (-len(text) % 4)
        at, sep, row_id = base64.urlsafe_b64decode(padded.encode("ascii")).decode(
            "utf-8").partition("|")
        if not sep:
            raise ValueError("no separator")
        moment = datetime.fromisoformat(at)
        if moment.tzinfo is None:
            raise ValueError("naive time")
        return moment, UUID(row_id)
    except (ValueError, UnicodeError, binascii.Error):
        raise Problem(400, "Invalid request",
                      "That page cursor is not one this server issued.") from None


_LEDGER_ORDER = "coalesce(d.last_attempt_at, d.sent_at, d.queued_at)"


@router.get("/deliveries", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def deliveries(
    kind: str | None = Query(None),
    refused_only: bool = Query(False),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    channel: str | None = Query(None),
    outbound: bool = Query(False),
    outcome: list[str] | None = Query(None),
    cause: list[str] | None = Query(None),
    recipient_id: UUID | None = Query(None),
    before: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _: CurrentUser = Depends(require_global("integration.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Read the delivery ledger back, newest first, a page at a time.

    N4 (2026-09-02). `notify.delivery` has recorded every refusal with a
    reason since migration 0029 and every destination since 0044, and
    nothing rendered it. This is the read.

    F8 (2026-09-24): every row carries a stable cause, so
    `refused_only` no longer infers anything from free text and an
    attempt time: it is REFUSED or FAILED, or a cause the recipient did not
    choose (REVOKED, WITHDRAWN, LEGACY). `outbound` leaves the in-app rows
    out (the console sends it by default). Order and cursor are
    coalesce(last attempt, sent, queued) then id, served by
    delivery_ledger_idx; `next` is null on the last page.

    `kind` is not validated against `KINDS`: a kind that has since been
    unregistered still has rows, and an operator asking about them should
    get them, not a 400.

    Under `integration.manage` because the ledger spans every case and
    every recipient. It carries kinds, channels, addresses and reasons --
    never subjects or summaries.
    """
    from noctornal_api.transports import CAUSES, cause_text

    if channel is not None and channel not in CHANNELS:
        raise Problem(400, "Invalid request", f"channel is one of {', '.join(CHANNELS)}")
    outcomes = outcome or []
    causes = cause or []
    if any(o not in OUTCOMES for o in outcomes):
        raise Problem(400, "Invalid request", f"outcome is one of {', '.join(OUTCOMES)}")
    if any(c not in CAUSES for c in causes):
        raise Problem(400, "Invalid request", "cause is one of the ledger's causes")
    clauses = ["true"]
    params: dict = {}
    if kind:
        clauses.append("n.kind = %(kind)s")
        params["kind"] = kind
    if channel:
        clauses.append("d.channel = %(channel)s")
        params["channel"] = channel
    if outbound:
        clauses.append("d.channel <> 'IN_APP'")
    if outcomes:
        clauses.append("d.state = ANY(%(outcomes)s)")
        params["outcomes"] = outcomes
    if causes:
        clauses.append("d.cause = ANY(%(causes)s)")
        params["causes"] = causes
    if refused_only:
        clauses.append("(d.state = ANY(%(not_delivered)s) OR d.cause = ANY(%(unchosen)s))")
        params.update(not_delivered=list(_NOT_DELIVERED), unchosen=list(_UNCHOSEN_CAUSES))
    if recipient_id:
        clauses.append("n.recipient_id = %(recipient)s")
        params["recipient"] = recipient_id
    if since:
        clauses.append(f"{_LEDGER_ORDER} >= %(since)s")
        params["since"] = since
    if until:
        clauses.append(f"{_LEDGER_ORDER} < %(until)s")
        params["until"] = until
    if before:
        at, row_id = _decode_cursor(before)
        clauses.append(f"({_LEDGER_ORDER}, d.id) < (%(at)s, %(row)s)")
        params.update(at=at, row=row_id)
    params["limit"] = limit + 1
    rows = conn.execute(
        f"""SELECT d.id, d.notification_id, n.kind, d.channel, n.recipient_id,
                  u.email, d.sent_to, d.state, d.detail, d.redacted, d.attempts,
                  coalesce(d.last_attempt_at, d.sent_at), n.created_at, d.cause,
                  d.exposure, d.queued_at, d.deliver_after, u.is_active, l.issue_key,
                  {_LEDGER_ORDER}
             FROM notify.delivery d
             JOIN notify.notification n ON n.id = d.notification_id
             JOIN iam.app_user u ON u.id = n.recipient_id
             LEFT JOIN notify.jira_link l ON l.id = d.jira_link_id
            WHERE {' AND '.join(clauses)}
            ORDER BY {_LEDGER_ORDER} DESC, d.id DESC
            LIMIT %(limit)s""", params).fetchall()
    more = len(rows) > limit
    rows = rows[:limit]
    out = []
    for r in rows:
        out.append(DeliveryOut(
            id=str(r[0]), notification_id=str(r[1]), kind=r[2], channel=r[3],
            recipient_id=str(r[4]), recipient=r[5], address=r[6], outcome=r[7],
            reason=r[8], redacted=r[9], attempts=r[10], attempted_at=r[11],
            raised_at=r[12], cause=r[13],
            cause_text=cause_text(r[13], channel=r[3], detail=r[8], exposure=r[14]),
            left=_left(r[7], r[3], r[13], r[14]), queued_at=r[15],
            next_attempt_at=r[16] if r[7] == "PENDING" else None,
            recipient_active=bool(r[17]), jira_issue=r[18],
        ).model_dump(mode="json"))
    return {"deliveries": out,
            "next": _encode_cursor(rows[-1][19], rows[-1][0]) if more and rows else None}


@router.get("/deliveries/summary", response_model=dict,
            dependencies=[Depends(rate_limit("request"))])
def deliveries_summary(
    hours: int = Query(24, ge=1, le=720),
    _: CurrentUser = Depends(require_global("integration.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Per-channel health over a window, and the outbox (F8). Counts
    only: no subject, no recipient."""
    from noctornal_api import jira, transports

    window = conn.execute(
        f"""SELECT d.channel, d.state, d.cause, count(*)
              FROM notify.delivery d
             WHERE d.channel <> 'IN_APP'
               AND {_LEDGER_ORDER} >= now() - make_interval(hours => %s)
             GROUP BY 1, 2, 3""", (hours,)).fetchall()
    channels: dict = {}
    for name in ("SMTP", "WEBHOOK", "JIRA"):
        if name == "JIRA":
            dest = jira.live_destination(conn)
            state = (jira.route_state(conn, dest.base_url, dest.host, dest.port)
                     if dest else None)
            route = state.as_dict() if state else {
                "name": "jira", "ok": False, "proxied": False,
                "why": "No Jira destination is configured."}
            available = bool(dest and dest.state == "ACTIVE" and state and state.ok)
            why = None if available else (
                "No Jira destination is active." if not dest or dest.state != "ACTIVE"
                else state.why)
        else:
            state = transports.route_state(name, conn)
            route = state.as_dict()
            available, why = state.ok, state.why
        states: dict = {}
        causes: dict = {}
        for ch, st, ca, n in window:
            if ch != name:
                continue
            states[st] = states.get(st, 0) + int(n)
            if ca:
                causes[ca] = causes.get(ca, 0) + int(n)
        last_sent = conn.execute(
            "SELECT max(sent_at) FROM notify.delivery WHERE channel = %s AND state = 'SENT'",
            (name,)).fetchone()[0]
        failure = conn.execute(
            """SELECT last_attempt_at, detail FROM notify.delivery
                WHERE channel = %s AND (state = 'FAILED' OR cause IN
                      ('TRANSPORT_ERROR', 'RATE_LIMITED'))
                ORDER BY last_attempt_at DESC NULLS LAST LIMIT 1""", (name,)).fetchone()
        channels[name] = {
            "available": available, "why": why, "route": route, "states": states,
            "causes": causes,
            "last_sent_at": last_sent.isoformat() if last_sent else None,
            "last_failure": ({"at": failure[0].isoformat() if failure[0] else None,
                              "detail": failure[1]} if failure else None)}
    outbox = conn.execute(
        """SELECT count(*) FILTER (WHERE deliver_after <= now()),
                  min(deliver_after) FILTER (WHERE deliver_after <= now()),
                  count(*) FILTER (WHERE deliver_after > now())
             FROM notify.delivery WHERE state = 'PENDING' AND channel <> 'IN_APP'""").fetchone()
    held = {}
    for name in ("SMTP", "WEBHOOK", "JIRA"):
        if not channels[name]["available"]:
            held[name] = int(conn.execute(
                """SELECT count(*) FROM notify.delivery
                    WHERE state = 'PENDING' AND channel = %s AND deliver_after <= now()""",
                (name,)).fetchone()[0])
    return {"window_hours": hours, "channels": channels,
            "outbox": {"due_now": int(outbox[0]),
                       "oldest_due_at": outbox[1].isoformat() if outbox[1] else None,
                       "deferred_future": int(outbox[2]), "held": held,
                       "overdue_after_minutes": 30}}


_REQUEUE_REFUSALS = {
    "REFUSED": ("The egress gate refused this content. A requeue cannot change that "
                "decision; if the refusal was wrong, change the destination's ceiling "
                "and the next notification will go."),
    "SUPPRESSED": ("Nothing was attempted: the recipient's choice, a revoked clearance "
                   "or a routing decision settled this, and a requeue cannot override "
                   "any of them."),
    "SENT": "It was delivered.",
}

#: A Jira row whose link's create, or whose event's post, is unsettled is
#: not due again until Jira's index has had two minutes (F8).
_SETTLE_SQL = """
CASE WHEN d.channel = 'JIRA' AND d.jira_link_id IS NOT NULL THEN greatest(
    now(),
    (SELECT l.create_attempted_at + interval '2 minutes' FROM notify.jira_link l
      WHERE l.id = d.jira_link_id AND l.state = 'CREATING'
        AND l.create_attempted_at IS NOT NULL),
    (SELECT e.attempted_at + interval '2 minutes' FROM notify.jira_event e
      WHERE e.link_id = d.jira_link_id AND e.state = 'POSTING'
        AND e.event_id = coalesce(n.event_id, n.id)))
ELSE now() END"""

#: A Jira row whose recipient has since stopped receiving Jira work items
#: cannot be revived by a requeue: the opt-in is
#: what justified sending it.
_OPTED_IN = """(d.channel <> 'JIRA' OR coalesce((
    SELECT p.enabled FROM notify.preference p
     WHERE p.user_id = n.recipient_id AND p.channel = 'JIRA'), false))"""


@router.post("/deliveries/{delivery_id}/requeue", response_model=DeliveryOut,
             dependencies=[Depends(rate_limit("integration.write"))])
def requeue(
    delivery_id: UUID,
    user: CurrentUser = Depends(require_global("integration.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> DeliveryOut:
    """Put a FAILED or backing-off delivery back in the outbox (F8).
    Attempts start again at zero, because a requeue after a fix that kept
    its attempts would burn out on the first try. The drain re-applies
    readable_predicate, the egress gate and Jira's routing, so a requeue
    can never widen exposure; REFUSED and SUPPRESSED are never
    requeueable."""
    before = conn.execute(
        """SELECT d.state, d.attempts, d.cause, d.channel FROM notify.delivery d
            WHERE d.id = %s""", (delivery_id,)).fetchone()
    if before is None:
        raise Problem(404, "Not found", "no such delivery")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    with conn.transaction():
        row = conn.execute(
            f"""UPDATE notify.delivery d
                   SET state = 'PENDING', attempts = 0, cause = 'REQUEUED',
                       deliver_after = {_SETTLE_SQL},
                       detail = left('requeued by an administrator at {stamp}; before: '
                                     || coalesce(d.detail, ''), 500)
                  FROM notify.notification n
                 WHERE d.id = %s AND n.id = d.notification_id
                   AND (d.state = 'FAILED' OR (d.state = 'PENDING' AND d.attempts > 0))
                   AND {_OPTED_IN}
                RETURNING d.id""", (delivery_id,)).fetchone()
        if row is None:
            state = before[0]
            if state in ("FAILED", "PENDING") and before[3] == "JIRA":
                raise Problem(409, "Conflict",
                              "The recipient has stopped receiving Jira work items, so "
                              "this cannot be sent to Jira again.")
            raise Problem(409, "Conflict", _REQUEUE_REFUSALS.get(
                state, "Only a failed delivery, or one backing off after a failed "
                       "attempt, can be requeued."))
        _audit(conn, user.user_id, "NOTIFY_DELIVERY_REQUEUED", "delivery", delivery_id,
               {"channel": before[3], "from_state": before[0],
                "from_attempts": before[1], "from_cause": before[2]})
    got = deliveries_row(conn, delivery_id)
    return got


def deliveries_row(conn, delivery_id: UUID) -> DeliveryOut:
    from noctornal_api.transports import cause_text

    r = conn.execute(
        """SELECT d.id, d.notification_id, n.kind, d.channel, n.recipient_id,
                  u.email, d.sent_to, d.state, d.detail, d.redacted, d.attempts,
                  coalesce(d.last_attempt_at, d.sent_at), n.created_at, d.cause,
                  d.exposure, d.queued_at, d.deliver_after, u.is_active, l.issue_key
             FROM notify.delivery d
             JOIN notify.notification n ON n.id = d.notification_id
             JOIN iam.app_user u ON u.id = n.recipient_id
             LEFT JOIN notify.jira_link l ON l.id = d.jira_link_id
            WHERE d.id = %s""", (delivery_id,)).fetchone()
    return DeliveryOut(
        id=str(r[0]), notification_id=str(r[1]), kind=r[2], channel=r[3],
        recipient_id=str(r[4]), recipient=r[5], address=r[6], outcome=r[7],
        reason=r[8], redacted=r[9], attempts=r[10], attempted_at=r[11],
        raised_at=r[12], cause=r[13],
        cause_text=cause_text(r[13], channel=r[3], detail=r[8], exposure=r[14]),
        left=_left(r[7], r[3], r[13], r[14]), queued_at=r[15],
        next_attempt_at=r[16] if r[7] == "PENDING" else None,
        recipient_active=bool(r[17]), jira_issue=r[18])


class BulkRequeueIn(BaseModel):
    channel: str
    since: datetime


#: Bounds on a bulk requeue (F8): one channel, thirty days, a thousand rows.
BULK_REQUEUE_DAYS = 30
BULK_REQUEUE_MAX = 1000


@router.post("/deliveries/requeue", response_model=dict,
             dependencies=[Depends(rate_limit("integration.write"))])
def requeue_bulk(
    body: BulkRequeueIn,
    user: CurrentUser = Depends(require_global("integration.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every FAILED delivery of one channel since a time, at most thirty
    days back and a thousand rows, by the same rule as one requeue."""
    if body.channel not in ("SMTP", "WEBHOOK", "JIRA"):
        raise Problem(400, "Invalid request", "channel is SMTP, WEBHOOK or JIRA")
    since = body.since if body.since.tzinfo else body.since.replace(tzinfo=timezone.utc)
    if since < datetime.now(timezone.utc) - timedelta(days=BULK_REQUEUE_DAYS):
        raise Problem(400, "Invalid request",
                      f"A bulk retry reaches back at most {BULK_REQUEUE_DAYS} days.")
    with conn.transaction():
        rows = conn.execute(
            f"""UPDATE notify.delivery d
                   SET state = 'PENDING', attempts = 0, cause = 'REQUEUED',
                       deliver_after = {_SETTLE_SQL},
                       detail = left('requeued by an administrator; before: '
                                     || coalesce(d.detail, ''), 500)
                  FROM notify.notification n
                 WHERE n.id = d.notification_id
                   AND d.id IN (SELECT id FROM notify.delivery
                                 WHERE channel = %s AND state = 'FAILED'
                                   AND last_attempt_at >= %s
                                 ORDER BY last_attempt_at DESC LIMIT %s)
                   AND {_OPTED_IN}
                RETURNING d.id""", (body.channel, since, BULK_REQUEUE_MAX)).fetchall()
        _audit(conn, user.user_id, "NOTIFY_DELIVERIES_REQUEUED", "delivery", None,
               {"channel": body.channel, "since": since.isoformat(), "count": len(rows)})
    return {"requeued": len(rows)}
