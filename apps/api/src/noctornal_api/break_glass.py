"""Break-glass emergency access (Phase 6, docs/05).

docs/05 states the case for it and the constraint in the same breath:

    Break-glass exists because refusing emergency access gets the platform
    bypassed entirely. Make it available, loud and short: mandatory
    justification, hard expiry, immediate alert to the security officer,
    and mandatory post-hoc review. **The access is granted; the visibility
    is what makes it safe.**

The temptation is to make it hard to obtain. That is the wrong lever. A
break-glass nobody can get at 3am is a break-glass that gets replaced by a
shared admin password in a drawer, and then there is no record at all. So
obtaining it is easy, and everything else about it is loud.

## Five properties, each doing real work

**1. It cannot be granted if nobody can review it.** The service refuses
unless some active user holds `SECURITY_OFFICER`. Unreviewed emergency
access is just access, and a control whose oversight is nominal is worse
than none because it produces a record that looks like governance.

**2. It is short by constraint, not by convention.** Migration 0032 caps it
at eight hours in a CHECK. A break-glass that can be granted for a week is
a role with a dramatic name.

**3. The alert is immediate and cannot be quietly deferred.**
`BREAK_GLASS_INVOKED` is a priority-1 notification, which is the only tier
that overrides quiet hours (decision 46). Somebody's evening is interrupted
on purpose.

**4. Use is counted, not just grant.** `used_at` and `action_count` exist
because "was it used" and "was it granted" are different questions, and
the interesting review case is the grant that was never used -- which
usually means the analyst found another way, and the emergency was not one.

**5. Review is mandatory and its absence is visible.** `unreviewed()` is
the queue. An expired grant with no review is an open item forever; it does
not age out, because ageing out is how a review requirement becomes a
formality.

## What break-glass does NOT do here

It does not grant a permission the user could not otherwise be given, and
it does not cross a compartment. It raises a user's *effective clearance*
for one case, for a few hours, with everything above recorded.

Compartments are deliberately excluded: a compartment is need-to-know, and
"there is an emergency" is not knowledge of the need. If somebody genuinely
must be read into a compartment, that is a read-in with a name on it, not
an eight-hour bypass. Recorded here rather than left as an omission for
somebody to "fix" later.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

#: docs/05 says "short". The DB caps at eight hours; this is the default a
#: caller gets if they do not ask, and it is deliberately shorter still.
DEFAULT_DURATION = timedelta(hours=2)
MAX_DURATION = timedelta(hours=8)

#: A justification shorter than this is not one. The DB enforces it too --
#: this is the readable error.
MIN_JUSTIFICATION = 20


class BreakGlassError(Exception):
    pass


@dataclass(frozen=True)
class Grant:
    id: UUID
    user_id: UUID
    case_id: UUID | None
    justification: str
    started_at: datetime
    expires_at: datetime
    granted_classification: str | None
    granted_permissions: list[str]
    used_at: datetime | None
    action_count: int
    revoked_at: datetime | None
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_outcome: str | None

    def is_live(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.revoked_at is None and self.expires_at > now

    @property
    def awaiting_review(self) -> bool:
        return self.reviewed_at is None


class BreakGlassService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def invoke(self, *, user_id: UUID, case_id: UUID | None,
               justification: str,
               classification: str | None = None,
               permissions: list[str] | None = None,
               duration: timedelta = DEFAULT_DURATION) -> Grant:
        """Grant emergency access. Easy to obtain, loud in every other way.

        Refuses if nobody holds `SECURITY_OFFICER`, because the review is
        the control and a grant nobody will review is just access with a
        better story.
        """
        justification = (justification or "").strip()
        if len(justification) < MIN_JUSTIFICATION:
            raise BreakGlassError(
                f"a break-glass justification has to be at least "
                f"{MIN_JUSTIFICATION} characters and say what the emergency "
                f"is: this is the text a security officer reviews, and 'urgent' "
                f"is not reviewable")
        if duration > MAX_DURATION:
            raise BreakGlassError(
                f"break-glass is capped at {MAX_DURATION}: anything longer is "
                f"a role, and roles are granted differently")

        officers = self._security_officers()
        if not officers:
            raise BreakGlassError(
                "no active user holds SECURITY_OFFICER, so nobody can review "
                "this. Unreviewed emergency access is just access -- assign "
                "the role before relying on break-glass in an incident")

        now = datetime.now(timezone.utc)
        row = self._c.execute(
            """INSERT INTO iam.break_glass
                   (user_id, case_id, justification, started_at, expires_at,
                    granted_classification, granted_permissions)
               VALUES (%s, %s, %s, %s, %s, %s, %s)
               RETURNING """ + _COLUMNS,
            (user_id, case_id, justification, now, now + duration,
             classification, permissions or [])).fetchone()
        grant = _record(row)

        self._audit(case_id, user_id, "BREAK_GLASS_INVOKED", grant.id, {
            "justification": justification,
            "expires_at": grant.expires_at.isoformat(),
            "classification": classification,
            "permissions": permissions or [],
        })
        self._alert(grant, officers)
        return grant

    def _alert(self, grant: Grant, officers: list[UUID]) -> None:
        """Priority 1, which is the only tier that overrides quiet hours.

        Somebody's evening is interrupted on purpose: docs/05 calls for an
        "immediate alert to the security officer", and an alert that waits
        until 08:00 is a report.

        ## This alert carries NO case content, and that is the whole design

        The seed is explicit about the role (migration 0017): *"Note
        SECURITY_OFFICER: can read the audit trail but NOT case content."*
        They hold `audit.read`, `break_glass.review` and
        `victim_pii.authorise`, and no case-content permission at all. They
        are normally not assigned to the case either.

        Until F19 (2026-07-26) this alert sent them the case CODE, the case
        CLASSIFICATION and the analyst's JUSTIFICATION verbatim — a free
        text field whose whole purpose is to describe the emergency, which
        means it quotes case facts. Labelled with the case's classification,
        so an officer with a high enough clearance received case material
        the permission model says they may not read, by email.

        Now it is what an oversight alert should be: a grant id, a clock,
        and an instruction to go and look. The justification lives in
        `iam.break_glass` and is read through `break_glass.review`, which is
        the permission that actually authorises reading it. GREEN because it
        contains nothing about the case — deliberately NOT inherited from
        the case, since inheriting a label you are not carrying the content
        of is how a notification ends up over-classified and undeliverable
        or under-classified and leaked.
        """
        from noctornal_api.notifications import URGENT, NotificationService

        svc = NotificationService(self._c)
        for officer in officers:
            svc.notify(
                # No `case_id`: this notification is ABOUT a grant, not
                # about a case, and attaching the case would put it behind
                # an assignment the officer is not supposed to need.
                recipient_id=officer, case_id=None,
                kind="BREAK_GLASS_INVOKED", priority=URGENT,
                subject="Emergency access was used",
                summary=(f"Break-glass access was invoked and expires at "
                         f"{grant.expires_at:%H:%M UTC}. It needs your "
                         f"review."),
                body=(f"An analyst invoked break-glass access.\n\n"
                      f"Grant: {grant.id}\n"
                      f"Expires: {grant.expires_at.isoformat()}\n\n"
                      f"Their justification is held with the grant and is "
                      f"readable with break_glass.review — it is not "
                      f"reproduced here, because it describes the emergency "
                      f"and therefore the case.\n\n"
                      f"Every action taken under this grant is counted and "
                      f"audited. Your review is mandatory and the grant "
                      f"sits in the unreviewed queue until you record one."),
                classification="GREEN", compartments=frozenset(),
                object_type="break_glass", object_id=grant.id,
                actor_id=grant.user_id)

        # The case owner, separately and with the case content the officer
        # does not get. `KINDS["BREAK_GLASS_INVOKED"]` has always described
        # this one -- "Emergency access was used on a case you own" -- and
        # nothing raised it. The owner is assigned and cleared, so they may
        # have the code and the justification; `notify_case_owner` applies
        # the same suppressions, so the analyst who invoked it is not told
        # about their own invocation.
        if grant.case_id is not None:
            row = self._c.execute(
                'SELECT code, classification, compartments FROM core."case" '
                'WHERE id = %s', (grant.case_id,)).fetchone()
            if row:
                svc.notify_case_owner(
                    grant.case_id,
                    kind="BREAK_GLASS_INVOKED", priority=URGENT,
                    subject=f"{row[0]}: emergency access was used",
                    summary=(f"Break-glass access was invoked on {row[0]}. It "
                             f"expires at {grant.expires_at:%H:%M UTC}. A "
                             f"security officer has been alerted."),
                    body=(f"An analyst invoked break-glass access on your "
                          f"case.\n\nTheir justification:\n\n"
                          f"    {grant.justification}\n\n"
                          f"It expires at {grant.expires_at.isoformat()}. A "
                          f"security officer has been alerted independently "
                          f"and their review is mandatory; you are told "
                          f"because it is your case, not because anything "
                          f"is required of you."),
                    classification=row[1],
                    compartments=frozenset(row[2] or []),
                    object_type="break_glass", object_id=grant.id,
                    actor_id=grant.user_id)

    # -- using it ----------------------------------------------------------

    def live_grant(self, user_id: UUID, case_id: UUID | None = None) -> Grant | None:
        """The grant that would apply right now, if any."""
        row = self._c.execute(
            f"""SELECT {_COLUMNS} FROM iam.break_glass
                 WHERE user_id = %s AND revoked_at IS NULL
                   AND expires_at > now()
                   AND (case_id IS NULL OR case_id = %s)
                 ORDER BY expires_at DESC LIMIT 1""",
            (user_id, case_id)).fetchone()
        return _record(row) if row else None

    def record_use(self, grant_id: UUID, *, action: str,
                   case_id: UUID | None = None) -> None:
        """Count an action taken under the grant.

        "Was it granted" and "was it used" are different questions, and the
        interesting review case is the grant that was never used -- which
        usually means the analyst found another way, and the emergency was
        not one.
        """
        self._c.execute(
            """UPDATE iam.break_glass
                  SET used_at = coalesce(used_at, now()),
                      action_count = action_count + 1
                WHERE id = %s""", (grant_id,))
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               SELECT bg.user_id, 'USER', 'BREAK_GLASS_ACTION', 'break_glass',
                      bg.id, %s, %s
                 FROM iam.break_glass bg WHERE bg.id = %s""",
            (case_id, Json({"action": action}), grant_id))

    def revoke(self, grant_id: UUID, *, actor_id: UUID) -> Grant:
        """End it early. Does not remove the review obligation -- a revoked
        grant is still a grant that happened."""
        row = self._c.execute(
            """UPDATE iam.break_glass SET revoked_at = now(), revoked_by = %s
                WHERE id = %s AND revoked_at IS NULL
            RETURNING """ + _COLUMNS, (actor_id, grant_id)).fetchone()
        if row is None:
            raise BreakGlassError("no live grant with that id")
        grant = _record(row)
        self._audit(grant.case_id, actor_id, "BREAK_GLASS_REVOKED", grant_id,
                    {"revoked_by": str(actor_id)})
        return grant

    # -- review ------------------------------------------------------------

    def unreviewed(self, limit: int = 100) -> list[Grant]:
        """The queue. An expired grant with no review is an open item
        forever and does not age out: ageing out is how a review
        requirement becomes a formality."""
        rows = self._c.execute(
            f"""SELECT {_COLUMNS} FROM iam.break_glass
                 WHERE reviewed_at IS NULL
                 ORDER BY started_at DESC LIMIT %s""", (limit,)).fetchall()
        return [_record(r) for r in rows]

    def review(self, grant_id: UUID, *, reviewer_id: UUID,
               outcome: str, note: str | None = None) -> Grant:
        """Record the mandatory post-hoc review.

        The reviewer may not be the person who invoked it. That is the same
        two-distinct-humans principle as four-eyes approval, and for the
        same reason: reviewing your own emergency is not a review.
        """
        if outcome not in {"JUSTIFIED", "UNJUSTIFIED", "INCONCLUSIVE"}:
            raise BreakGlassError(
                "outcome must be JUSTIFIED, UNJUSTIFIED or INCONCLUSIVE")
        current = self.get(grant_id)
        if current is None:
            raise BreakGlassError("no such grant")
        if current.reviewed_at is not None:
            raise BreakGlassError(
                "this grant has already been reviewed; a review cannot be "
                "revisited, and a disagreement is its own record")
        if reviewer_id == current.user_id:
            raise BreakGlassError(
                "you cannot review your own break-glass: reviewing your own "
                "emergency is not a review")

        row = self._c.execute(
            """UPDATE iam.break_glass
                  SET reviewed_by = %s, reviewed_at = now(), review_outcome = %s
                WHERE id = %s AND reviewed_at IS NULL
            RETURNING """ + _COLUMNS,
            (reviewer_id, outcome, grant_id)).fetchone()
        if row is None:
            raise BreakGlassError("this grant was reviewed by someone else first")
        grant = _record(row)
        self._audit(grant.case_id, reviewer_id, "BREAK_GLASS_REVIEWED",
                    grant_id, {"outcome": outcome, "note": note,
                               "invoked_by": str(grant.user_id),
                               "actions_taken": grant.action_count})
        return grant

    def get(self, grant_id: UUID) -> Grant | None:
        row = self._c.execute(
            f"SELECT {_COLUMNS} FROM iam.break_glass WHERE id = %s",
            (grant_id,)).fetchone()
        return _record(row) if row else None

    # -- internals ---------------------------------------------------------

    def _security_officers(self) -> list[UUID]:
        rows = self._c.execute(
            """SELECT DISTINCT ur.user_id
                 FROM iam.user_role ur
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active"""
        ).fetchall()
        return [r[0] for r in rows]

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               grant_id: UUID, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'break_glass', %s, %s, %s)""",
            (actor_id, action, grant_id, case_id, Json(detail)))


_COLUMNS = ("id, user_id, case_id, justification, started_at, expires_at, "
            "granted_classification, granted_permissions, used_at, "
            "action_count, revoked_at, reviewed_by, reviewed_at, "
            "review_outcome")


def _record(r) -> Grant:
    return Grant(
        id=r[0], user_id=r[1], case_id=r[2], justification=r[3],
        started_at=r[4], expires_at=r[5], granted_classification=r[6],
        granted_permissions=list(r[7] or []), used_at=r[8], action_count=r[9],
        revoked_at=r[10], reviewed_by=r[11], reviewed_at=r[12],
        review_outcome=r[13],
    )
