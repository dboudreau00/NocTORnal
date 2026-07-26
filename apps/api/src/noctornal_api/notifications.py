"""Notification: raising one, deciding which channels get it, and reading
the centre back.

Phase 5. `transports.py` does the actual sending; this module decides
whether anything should be sent at all, which is where the interesting
rules live.

## The rule that shapes everything

docs/07:

    A system that cries wolf gets muted, and then the one alert that
    mattered is also muted.

So the defaults here are conservative in a specific direction: it is better
to under-notify by email and over-notify in-app. In-app is free, sits behind
the access gate, and does not follow anyone home.

## Four suppressions, and why each exists

1. **Never tell someone what they just did.** `actor_id == recipient_id` is
   dropped before a row is written. This is the single commonest reason
   people turn a notification system off.
2. **Never notify someone who could not read it.** The recipient's clearance
   and compartments are checked at WRITE time against the notification's own
   labels. Writing a row nobody may read is not a safe default -- it puts
   case content in a table keyed by a user who has no business with it, and
   relies on the read filter forever after.
3. **Quiet hours defer, they do not drop.** A deferred delivery has a
   `deliver_after` in the future and is still a row. Priority 1 ignores
   them, which is the only reason quiet hours are acceptable at all.
4. **Digest defers too**, to the next digest boundary. Same principle:
   the notification exists, its delivery is later.

## Reading is filtered by CURRENT clearance AND CURRENT assignment

Not the clearance the recipient had when the row was written. A revoked
clearance has to hide old notifications, or the centre quietly becomes a
retention loophole for everything the analyst used to be able to see.

The assignment half was missing until F19 (2026-07-26), and it was the
larger hole of the two: clearance is a property of the person, assignment
is the thing that actually ties them to *this* case, and taking somebody
off a case is far commoner than downgrading their clearance. Every other
"which cases can this caller see" query in the repo carried the
`expires_at` predicate; this one did not, so an analyst removed from a case
kept reading its merges, its approvals and its triage counts from
`/notifications` forever.

`readable_predicate()` is that rule, written once. Three copies of a
predicate is three chances for one of them to be the stale one — which is
exactly how the outbox drain came to disagree with the centre it drains.

## What this module will not do

It does not send. It does not open a socket. `dispatch_due()` in
`transports.py` drains the outbox, so a failing SMTP server can never make
a merge fail -- the graph write and the notification are in the same
transaction, but the notification and its DELIVERY are not.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import psycopg
from psycopg.types.json import Json

from noctornal_api.security.access import (
    AccessResolutionError,
    Tlp,
    tlp_from_name,
)

IN_APP = "IN_APP"
SMTP = "SMTP"
WEBHOOK = "WEBHOOK"
JIRA = "JIRA"

PENDING = "PENDING"
SENT = "SENT"
FAILED = "FAILED"
REFUSED = "REFUSED"
SUPPRESSED = "SUPPRESSED"

# Priority 1 is the only level that overrides quiet hours and skips digest.
# Kept to three levels deliberately: a scale with five gets used as five,
# and then nothing is urgent.
URGENT, NORMAL, LOW = 1, 2, 3


class NotificationError(Exception):
    pass


def readable_predicate(alias: str = "n") -> str:
    """SQL that is true when `alias`'s recipient may STILL read it.

    Both halves of the case gate, against the world as it is NOW:

    - the **labels** — the recipient's current clearance dominates the
      notification's classification, and their current compartments contain
      its compartments;
    - the **assignment** — for a notification that names a case, a live
      `iam.case_assignment` row, unexpired.

    A notification with no `case_id` skips the assignment half because there
    is nothing to be assigned to. Nothing in this build raises one; the
    branch exists so that adding a genuinely case-independent notification
    later is a decision rather than an accident.

    Aliases are deliberately obscure (`ru`, `rca`): this fragment is
    embedded in queries that already join `u` and `c`, and a collision would
    silently re-bind the outer alias rather than fail.
    """
    return f"""
        EXISTS (SELECT 1 FROM iam.app_user ru
                 WHERE ru.id = {alias}.recipient_id AND ru.is_active
                   AND {alias}.classification <= ru.tlp_clearance
                   AND {alias}.compartments <@ ru.compartments)
        AND ({alias}.case_id IS NULL OR EXISTS (
                SELECT 1 FROM iam.case_assignment rca
                 WHERE rca.case_id = {alias}.case_id
                   AND rca.user_id = {alias}.recipient_id
                   AND (rca.expires_at IS NULL OR rca.expires_at > now())))
    """


@dataclass(frozen=True)
class Kind:
    """One notifiable event.

    `default_priority` is what it gets unless a caller overrides. The
    assignment is a judgement about interrupting a person's evening, so it
    is written down in one table rather than passed in at 40 call sites.
    """

    key: str
    default_priority: int
    description: str


KINDS: dict[str, Kind] = {
    # docs/01 requires this one by name: "Merges ... generate an audit event
    # and a case-owner notification."
    "MERGE_PERFORMED": Kind(
        "MERGE_PERFORMED", NORMAL,
        "An entity was merged into another in a case you own"),
    "MERGE_REVERSED": Kind(
        "MERGE_REVERSED", NORMAL, "A merge was reversed"),
    # An approval nobody is told about is an approval nobody gives, and then
    # dual control is just a broken merge button.
    "APPROVAL_REQUESTED": Kind(
        "APPROVAL_REQUESTED", NORMAL,
        "Someone is asking for your second signature"),
    "APPROVAL_DECIDED": Kind(
        "APPROVAL_DECIDED", NORMAL, "Your approval request was decided"),
    "PROPOSAL_QUEUED": Kind(
        "PROPOSAL_QUEUED", LOW, "New proposals are waiting in triage"),
    # Evidence failing its hash re-verification is a tamper alarm. It wakes
    # people up.
    "EVIDENCE_INTEGRITY_ALARM": Kind(
        "EVIDENCE_INTEGRITY_ALARM", URGENT,
        "An exhibit failed its integrity check"),
    # Raised twice with different content: the security officer gets an
    # oversight alert carrying NO case material (they hold no case-content
    # permission), the case owner gets the code and the justification.
    "BREAK_GLASS_INVOKED": Kind(
        "BREAK_GLASS_INVOKED", URGENT,
        "Emergency access was used on a case you own, or needs your review"),
    "CASE_REVIEW_DUE": Kind(
        "CASE_REVIEW_DUE", LOW, "A case you own is due for review"),
}

# Channel defaults when a user has no preference row. IN_APP takes
# everything; email only takes what would justify an interruption. A new
# user who has never opened the settings page still gets the urgent things.
_DEFAULTS = {
    IN_APP: {"enabled": True, "min_priority": LOW, "digest": False},
    SMTP: {"enabled": True, "min_priority": NORMAL, "digest": False},
    WEBHOOK: {"enabled": False, "min_priority": URGENT, "digest": False},
    JIRA: {"enabled": False, "min_priority": URGENT, "digest": False},
}


@dataclass(frozen=True)
class Notification:
    id: UUID
    recipient_id: UUID
    case_id: UUID | None
    kind: str
    priority: int
    subject: str
    summary: str
    body: str
    classification: str
    compartments: frozenset[str]
    object_type: str | None
    object_id: UUID | None
    actor_id: UUID | None
    created_at: datetime
    read_at: datetime | None
    acknowledged_at: datetime | None


@dataclass(frozen=True)
class Preference:
    channel: str
    enabled: bool
    min_priority: int
    digest: bool
    quiet_from: time | None
    quiet_to: time | None
    timezone: str
    address: str | None


class NotificationService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- raising ----------------------------------------------------------

    def notify(self, *, recipient_id: UUID, kind: str, subject: str,
               summary: str, body: str, classification: str,
               case_id: UUID | None = None,
               compartments: frozenset[str] = frozenset(),
               object_type: str | None = None, object_id: UUID | None = None,
               actor_id: UUID | None = None,
               priority: int | None = None,
               element_classification: str | None = None,
               element_compartments: frozenset[str] = frozenset(),
               ) -> Notification | None:
        """Raise one notification and queue its deliveries.

        `classification` / `compartments` are the CASE's. When the
        notification is about a specific element that carries its own labels
        — the nodes in a merge, the exhibit in an integrity alarm — pass
        them as `element_*` and they are composed here: the stricter
        classification, the union of compartments.

        That composition is the same one the access gate performs, and it
        has to happen somewhere. An element may be classified ABOVE its case
        (the floor trigger only stops it going below), so labelling a
        notification with the case's classification alone under-labels every
        notification about a raised element — and the label is what decides
        whether the summary may go out by email.

        Returns None when the notification was suppressed -- which is a
        normal outcome, not an error: telling somebody what they just did,
        or telling somebody something they are not cleared to read, are both
        things this refuses to do.

        Call it INSIDE the transaction that performs the action. A merge
        that succeeded and a notification that did not is a case owner who
        never finds out; a notification that survived a rolled-back merge is
        worse.
        """
        spec = KINDS.get(kind)
        if spec is None:
            raise NotificationError(
                f"unknown notification kind {kind!r}; kinds are registered in "
                f"notifications.KINDS")
        if not subject.strip() or not summary.strip():
            raise NotificationError("subject and summary are mandatory")

        try:
            classification, compartments = effective_labels_for_notification(
                classification, compartments,
                element_classification, element_compartments)
        except AccessResolutionError as exc:
            # Fail closed and loudly. Silently keeping the case's label would
            # send an unlabelled element out by email.
            raise NotificationError(
                f"cannot label this notification: {exc}") from exc

        # Suppression 1: never tell someone what they just did.
        if actor_id is not None and actor_id == recipient_id:
            return None

        # Suppression 2: never write a row the recipient could not read.
        if not self._recipient_may_read(recipient_id, classification,
                                        compartments, case_id):
            return None

        row = self._c.execute(
            """INSERT INTO notify.notification
                   (recipient_id, case_id, kind, priority, subject, summary,
                    body, classification, compartments, object_type, object_id,
                    actor_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING """ + _COLUMNS,
            (recipient_id, case_id, kind, priority or spec.default_priority,
             subject.strip(), summary.strip(), body, classification,
             sorted(compartments), object_type, object_id, actor_id),
        ).fetchone()
        record = _record(row)
        self._queue_deliveries(record)
        return record

    def notify_case_owner(self, case_id: UUID, **kw) -> Notification | None:
        """docs/01 asks for a case-owner notification on merge by name.
        Resolving the owner here rather than at the call site means a caller
        cannot get it subtly wrong -- the deputy is NOT notified, because two
        people told about every merge is two people who mute it."""
        row = self._c.execute(
            'SELECT owner_user_id FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if row is None:
            return None
        return self.notify(recipient_id=row[0], case_id=case_id, **kw)

    # -- reading ----------------------------------------------------------

    def inbox(self, recipient_id: UUID, *, unread_only: bool = False,
              limit: int = 50, case_id: UUID | None = None) -> list[Notification]:
        """Filtered by the caller's CURRENT clearance, compartments AND case
        assignment.

        A revoked clearance hides old notifications, and so does a revoked
        or expired assignment. Doing this in SQL rather than in Python means
        a paginated read cannot return a short page and call it the end of
        the list.
        """
        clauses = ["n.recipient_id = %s"]
        params: list = [recipient_id]
        if unread_only:
            clauses.append("n.read_at IS NULL")
        if case_id is not None:
            clauses.append("n.case_id = %s")
            params.append(case_id)
        clauses.append(readable_predicate("n"))
        params.append(limit)
        rows = self._c.execute(
            f"""SELECT {_N_COLUMNS} FROM notify.notification n
                 WHERE {' AND '.join(clauses)}
                 ORDER BY n.created_at DESC LIMIT %s""",
            params).fetchall()
        return [_record(r) for r in rows]

    def unread_count(self, recipient_id: UUID) -> int:
        """The badge. Filtered by exactly the same rule as `inbox()` — a
        count that disagrees with the list it counts is a badge that never
        clears, and an analyst who learns to ignore the badge has lost the
        notification system."""
        row = self._c.execute(
            f"""SELECT count(*) FROM notify.notification n
                 WHERE n.recipient_id = %s AND n.read_at IS NULL
                   AND {readable_predicate('n')}""",
            (recipient_id,)).fetchone()
        return int(row[0])

    def mark_read(self, notification_id: UUID, recipient_id: UUID) -> bool:
        """Idempotent, and scoped to the owner: reading is a fact about one
        person's inbox, so it cannot be set on somebody else's."""
        row = self._c.execute(
            """UPDATE notify.notification SET read_at = coalesce(read_at, now())
                WHERE id = %s AND recipient_id = %s RETURNING id""",
            (notification_id, recipient_id)).fetchone()
        return row is not None

    def mark_all_read(self, recipient_id: UUID) -> int:
        rows = self._c.execute(
            """UPDATE notify.notification SET read_at = now()
                WHERE recipient_id = %s AND read_at IS NULL RETURNING id""",
            (recipient_id,)).fetchall()
        return len(rows)

    def acknowledge(self, notification_id: UUID, recipient_id: UUID) -> bool:
        """Distinct from reading (docs/07): acknowledgement is the signal
        that stops a thing nagging, and glancing at a list is not that."""
        row = self._c.execute(
            """UPDATE notify.notification
                  SET read_at = coalesce(read_at, now()),
                      acknowledged_at = coalesce(acknowledged_at, now())
                WHERE id = %s AND recipient_id = %s RETURNING id""",
            (notification_id, recipient_id)).fetchone()
        return row is not None

    # -- preferences ------------------------------------------------------

    def preferences(self, user_id: UUID) -> dict[str, Preference]:
        rows = self._c.execute(
            """SELECT channel, enabled, min_priority, digest, quiet_from,
                      quiet_to, timezone, address
                 FROM notify.preference WHERE user_id = %s""",
            (user_id,)).fetchall()
        found = {r[0]: Preference(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7])
                 for r in rows}
        # A missing row means the built-in default, so a user who has never
        # opened the settings page still gets the urgent things.
        for channel, default in _DEFAULTS.items():
            found.setdefault(channel, Preference(
                channel, default["enabled"], default["min_priority"],
                default["digest"], None, None, "UTC", None))
        return found

    def set_preference(self, user_id: UUID, channel: str, **fields) -> Preference:
        """Change one channel's settings.

        `address` is the dangerous field and it is the one that had no
        validation at all (F19). Any authenticated user could PUT
        `{"address": "collector@attacker.example"}` — no permission, no
        step-up, no format check, no confirmation to either mailbox — and
        `transports._DUE_SQL` resolves `coalesce(p.address, u.email)`, so
        every subsequent notification's subject and summary went to a
        mailbox they chose. Subjects carry the case CODE, which this
        codebase argues at length is itself intelligence.

        The egress gate cannot help: `can_egress` reasons about the
        classification and the KIND of destination, so an SMTP send to a
        corporate account and one to a burner are the same decision. The
        control that normally backstops it is the account email, which an
        administrator owns — and `preference.address` handed that to the
        user.

        So: an override is refused unless an operator has declared where
        mail may go, and every accepted change is audited with both the old
        and the new value. Fail closed, because the default has to be the
        one that is safe when nobody has thought about it.
        """
        if channel not in _DEFAULTS:
            raise NotificationError(f"unknown channel {channel!r}")
        current = self.preferences(user_id)[channel]
        if "address" in fields and fields["address"] != current.address:
            self._check_address(user_id, channel, fields["address"],
                                current.address)
        merged = {
            "enabled": fields.get("enabled", current.enabled),
            "min_priority": fields.get("min_priority", current.min_priority),
            "digest": fields.get("digest", current.digest),
            "quiet_from": fields.get("quiet_from", current.quiet_from),
            "quiet_to": fields.get("quiet_to", current.quiet_to),
            "timezone": fields.get("timezone", current.timezone),
            "address": fields.get("address", current.address),
        }
        if (merged["quiet_from"] is None) != (merged["quiet_to"] is None):
            raise NotificationError(
                "a quiet window needs both a start and an end: half a window "
                "is a bug that reads as a working one")
        _validate_timezone(merged["timezone"])
        self._c.execute(
            """INSERT INTO notify.preference
                   (user_id, channel, enabled, min_priority, digest,
                    quiet_from, quiet_to, timezone, address)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (user_id, channel) DO UPDATE SET
                   enabled = EXCLUDED.enabled,
                   min_priority = EXCLUDED.min_priority,
                   digest = EXCLUDED.digest,
                   quiet_from = EXCLUDED.quiet_from,
                   quiet_to = EXCLUDED.quiet_to,
                   timezone = EXCLUDED.timezone,
                   address = EXCLUDED.address""",
            (user_id, channel, merged["enabled"], merged["min_priority"],
             merged["digest"], merged["quiet_from"], merged["quiet_to"],
             merged["timezone"], merged["address"]))
        return self.preferences(user_id)[channel]

    def _check_address(self, user_id: UUID, channel: str,
                       new: str | None, old: str | None) -> None:
        """Decide whether this delivery address may be set, and record it.

        `NOCTORNAL_NOTIFY_ADDRESS_DOMAINS` is a comma-separated list of
        domains a user may redirect their own notifications to. Unset means
        NO override: mail goes to the account email, which an administrator
        controls. That default costs a convenience and closes a
        self-service exfiltration channel, and of the two the default has
        to be the safe one.

        Clearing the override (setting it back to None) is always allowed —
        it can only ever move delivery back to the administrator-owned
        address — but it is still audited, because "when did this stop
        going to the burner" is the same question in reverse.
        """
        if new is not None:
            allowed = {d.strip().lower().lstrip("@")
                       for d in os.environ.get(
                           "NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", "").split(",")
                       if d.strip()}
            if not allowed:
                raise NotificationError(
                    "notifications go to your account email, which an "
                    "administrator controls. Redirecting them is refused "
                    "unless an operator has declared which domains may "
                    "receive case material — set "
                    "NOCTORNAL_NOTIFY_ADDRESS_DOMAINS. A subject line here "
                    "carries the case code, and a case code is "
                    "intelligence.")
            if "@" not in new or new.rsplit("@", 1)[1].lower() not in allowed:
                raise NotificationError(
                    f"{new!r} is not in a domain this deployment permits "
                    f"for notification delivery. Permitted: "
                    f"{', '.join(sorted(allowed))}")
        # Audited whichever way it went. The absence of this row was the
        # sharper half of the finding: changing where a case's
        # notifications are delivered left no trace anywhere in the system.
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    outcome, detail)
               VALUES (%s, 'USER', 'NOTIFY_ADDRESS_CHANGED', 'app_user', %s,
                       'SUCCESS', %s)""",
            (user_id, user_id,
             Json({"channel": channel, "from": old, "to": new})))

    # -- internals --------------------------------------------------------

    def _recipient_may_read(self, recipient_id: UUID, classification: str,
                            compartments: frozenset[str],
                            case_id: UUID | None) -> bool:
        """Suppression 2, at WRITE time: the same rule `readable_predicate`
        applies at read time.

        Both are needed and neither is redundant. The read filter protects
        against a clearance or an assignment revoked *after* the row was
        written; this one stops the row existing at all when the recipient
        already could not read it. Writing a notification nobody may read
        puts case content in a table keyed by a user with no business with
        it and then relies on the read filter forever after — and the read
        filter is precisely the thing that turned out to be missing half its
        rule.
        """
        row = self._c.execute(
            "SELECT tlp_clearance, compartments, is_active "
            "FROM iam.app_user WHERE id = %s", (recipient_id,)).fetchone()
        if row is None or not row[2]:
            return False
        try:
            clearance = tlp_from_name(row[0])
            level = tlp_from_name(classification)
        except Exception:  # noqa: BLE001 - an unparseable label is a denial
            return False
        if level > clearance:
            return False
        if not compartments <= frozenset(row[1] or []):
            return False
        if case_id is None:
            return True
        assigned = self._c.execute(
            """SELECT 1 FROM iam.case_assignment
                WHERE case_id = %s AND user_id = %s
                  AND (expires_at IS NULL OR expires_at > now())""",
            (case_id, recipient_id)).fetchone()
        return assigned is not None

    def _queue_deliveries(self, n: Notification) -> None:
        """One PENDING row per eligible channel. IN_APP is written already
        SENT: the notification row IS the in-app delivery, and a PENDING
        in-app row would be a queue entry for something that has already
        happened."""
        prefs = self.preferences(n.recipient_id)
        now = datetime.now(timezone.utc)
        for channel, pref in prefs.items():
            if channel == IN_APP:
                self._insert_delivery(n.id, IN_APP, SENT, now, sent_at=now)
                continue
            if not pref.enabled:
                self._insert_delivery(
                    n.id, channel, SUPPRESSED, now,
                    detail="channel disabled by the recipient")
                continue
            if n.priority > pref.min_priority:
                self._insert_delivery(
                    n.id, channel, SUPPRESSED, now,
                    detail=f"priority {n.priority} is below the "
                           f"recipient's threshold for {channel}")
                continue
            self._insert_delivery(
                n.id, channel, PENDING, deliver_after(n.priority, pref, now))

    def _insert_delivery(self, notification_id: UUID, channel: str, state: str,
                         after: datetime, *, sent_at: datetime | None = None,
                         detail: str | None = None) -> None:
        self._c.execute(
            """INSERT INTO notify.delivery
                   (notification_id, channel, state, deliver_after, sent_at, detail)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (notification_id, channel) DO NOTHING""",
            (notification_id, channel, state, after, sent_at, detail))


def deliver_after(priority: int, pref: Preference,
                  now: datetime) -> datetime:
    """When this delivery becomes due.

    Quiet hours and digest DEFER; they never drop. A deferred delivery is
    still a row with a due time, so "why did I not get that email" has an
    answer other than a shrug.

    Priority 1 ignores both, which is the only thing that makes quiet hours
    acceptable: the reason it is safe to silence a channel overnight is that
    something can still get through it.
    """
    if priority <= URGENT:
        return now
    due = now
    if pref.digest:
        due = _next_digest_boundary(due, pref)
    if pref.quiet_from is not None and pref.quiet_to is not None:
        due = _after_quiet_hours(due, pref)
    return due


def _zone(pref: Preference) -> ZoneInfo:
    try:
        return ZoneInfo(pref.timezone)
    except (ZoneInfoNotFoundError, ValueError, KeyError):
        # A misconfigured timezone must not silently move somebody's quiet
        # hours by eight time zones. UTC is the honest fallback.
        return ZoneInfo("UTC")


def _next_digest_boundary(due: datetime, pref: Preference) -> datetime:
    """The next hour boundary. Hourly rather than daily because docs/07 asks
    for "hourly or daily rollup" and an hour is the one that still lets
    somebody act on the same shift."""
    return (due.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))


def _after_quiet_hours(due: datetime, pref: Preference) -> datetime:
    """Push `due` past the recipient's quiet window, in THEIR local time.

    Handles a window that wraps midnight (22:00 to 07:00), which is the
    common case and the one a naive `from <= t <= to` gets wrong.
    """
    zone = _zone(pref)
    local = due.astimezone(zone)
    start, end = pref.quiet_from, pref.quiet_to
    if start == end:
        # A zero-length window would otherwise be read as "always quiet",
        # which would defer everything forever.
        return due
    wraps = start > end
    inside = (local.time() >= start or local.time() < end) if wraps \
        else (start <= local.time() < end)
    if not inside:
        return due
    resume = local.replace(hour=end.hour, minute=end.minute, second=0,
                           microsecond=0)
    if resume <= local:
        resume = resume + timedelta(days=1)
    return resume.astimezone(timezone.utc)


def _validate_timezone(name: str) -> None:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, KeyError) as exc:
        raise NotificationError(f"unknown timezone {name!r}") from exc


def effective_labels_for_notification(
    case_classification: str, case_compartments: frozenset[str],
    element_classification: str | None = None,
    element_compartments: frozenset[str] = frozenset(),
) -> tuple[str, frozenset[str]]:
    """The labels a notification carries: the STRICTER classification and the
    UNION of compartments, exactly as `deps.effective_labels` computes them
    for an access decision.

    Duplicated deliberately rather than imported: `deps` is the HTTP layer
    and this runs in services that have no request. The pair is asserted
    equal by a test, so the two cannot drift.

    Called from `NotificationService.notify`, which is the only place it has
    ever needed to be called from. Until F19 (2026-07-26) it was exported,
    tested and called by NOTHING — a correct composition function sitting
    beside a `notify()` that took the case's labels and used them verbatim.
    A function with a test and no call site is the shape a defence takes
    when it was written, reviewed and then never wired in; grep for the
    call sites of anything security-relevant, not just for its definition.
    """
    # The case's label is parsed UNCONDITIONALLY, even when there is no
    # element to compare it against. The first version only parsed inside
    # the `if`, so `notify()`'s "fail closed and loudly" applied to
    # notifications about an element and not to the plain ones — an
    # unparseable classification fell through to the INSERT and surfaced as
    # a psycopg DataError. A validator that only runs on the harder input
    # is not a validator.
    case_level = tlp_from_name(case_classification)
    strictest = case_level
    if element_classification is not None:
        strictest = max(case_level, tlp_from_name(element_classification))
    return strictest.name, case_compartments | element_compartments


# Bare for INSERT ... RETURNING; table-qualified for the reads, which join
# iam.app_user to re-check clearance. Derived from one list so the two
# cannot fall out of step and unpack into the wrong fields.
_COLUMNS = ("id, recipient_id, case_id, kind, priority, subject, summary, "
            "body, classification, compartments, object_type, object_id, "
            "actor_id, created_at, read_at, acknowledged_at")
_N_COLUMNS = ", ".join("n." + c.strip() for c in _COLUMNS.split(","))


def _record(r) -> Notification:
    return Notification(
        id=r[0], recipient_id=r[1], case_id=r[2], kind=r[3], priority=r[4],
        subject=r[5], summary=r[6], body=r[7], classification=r[8],
        compartments=frozenset(r[9] or []), object_type=r[10], object_id=r[11],
        actor_id=r[12], created_at=r[13], read_at=r[14], acknowledged_at=r[15],
    )


__all__ = [
    "IN_APP", "SMTP", "WEBHOOK", "JIRA", "URGENT", "NORMAL", "LOW",
    "KINDS", "Kind", "Notification", "NotificationError",
    "NotificationService", "Preference", "Tlp", "deliver_after",
    "effective_labels_for_notification", "readable_predicate",
]
