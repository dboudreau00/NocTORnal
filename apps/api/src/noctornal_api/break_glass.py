"""Break-glass emergency access (docs/05).

Refusing emergency access gets the platform bypassed, so break-glass is easy to obtain and loud in
every other way: mandatory justification, a hard expiry, an immediate alert to the security officer
and mandatory post-hoc review. The access is granted; the visibility is what makes it safe.

- It cannot be granted if nobody can review it: the service refuses unless some active user other
  than the invoker holds `SECURITY_OFFICER`. The invoker never counts as a reviewer (`review()`
  refuses them), and a grant nobody can review is just access with a record that looks like
  governance.
- It is short by constraint (migration 0032 caps it at eight hours in a CHECK), and its alert is
  priority 1, the only tier that overrides quiet hours (decision 46).
- Use is counted apart from the grant (`used_at`, `action_count`), because a grant that was never
  used is the interesting review case. `PgAccessResolver.resolve()` (stores.py) counts a request
  once, and only when the grant made the access possible: the gate allowed it and the object's label
  sits above the invoker's own clearance and within the grant's. A second gate on the same request
  is marked `after_case_gate=True` and counts only when the case's gate did not, so the ledger (one
  `BREAK_GLASS_ACTION` row per use, in an append-only table) and `action_count` agree
  (`test_breakglass_count_once_pg.py`).
- Review is mandatory and post-hoc. `unreviewed()` is the queue, and an expired grant with no review
  never ages out of it. A live grant cannot be reviewed: a verdict would take it out of every list
  while the analyst keeps the raised clearance.

A live, unrevoked grant with a `granted_classification` raises the caller's clearance to that level,
for the case the grant names or every case if it names none. `PgAccessResolver.resolve()` applies it
at the gate every case-scoped read and write passes through, and `deps.user_ceiling(..., case_id=)`
applies it wherever a read of one case passes that case. A case-scoped grant does not raise
`user_ceiling()` without a case (label checks on writes, the report builder) or anything on another
case; a global grant raises both. The grant adds no permission (`granted_permissions` is stored and
not consulted) and never crosses a compartment: a compartment is need-to-know, and "there is an
emergency" is not knowledge of the need.
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

        Refuses if nobody but the invoker holds `SECURITY_OFFICER`, because
        the review is the control and a grant nobody will review is just
        access with a better story.
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

        # The invoker is not a reviewer: `review()` refuses their own grant. If they counted, the
        # sole officer could invoke and the grant would sit in a queue nobody could clear, while
        # `_alert` paged only them and notifications drop what you did yourself, so nobody would be
        # told either. The alert goes to the same filtered list.
        everyone = self._security_officers()
        officers = [o for o in everyone if o != user_id]
        if not officers and everyone:
            raise BreakGlassError(
                "the only active SECURITY_OFFICER is you, so nobody can "
                "review this: reviewing your own emergency is not a review. "
                "Unreviewed emergency access is just access, so give "
                "SECURITY_OFFICER to somebody else before relying on "
                "break-glass in an incident")
        if not officers:
            raise BreakGlassError(
                "no active user holds SECURITY_OFFICER, so nobody can review "
                "this. Unreviewed emergency access is just access, so assign "
                "the role before relying on break-glass in an incident")

        now = datetime.now(timezone.utc)
        # The invoker's own clearance at this moment, recorded with the grant so the review card can
        # tell a raise from a grant that raised nothing (the invoker already held that level). The
        # grant row has no column for the level it started from, and the invoker's clearance today
        # may differ from the one the grant was judged against.
        base = self._c.execute(
            "SELECT tlp_clearance FROM iam.app_user WHERE id = %s",
            (user_id,)).fetchone()
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
            "base_clearance": base[0] if base else None,
        })
        # The grant row is committed (autocommit) and raises the caller's effective clearance. A
        # failed notify write that propagated would report a grant that exists, and elevates, as a
        # 500, and an analyst at 3am who believes they were refused stops looking for the access
        # they now hold. The review queue (`unreviewed()`) is the durable half of the control and
        # does not depend on this alert; the failure to be loud is logged.
        try:
            self._alert(grant, officers)
        except Exception:  # noqa: BLE001 - the grant stands; the failure is logged
            import logging
            logging.getLogger("noctornal.break_glass").exception(
                "break-glass grant %s was recorded but its alert failed", grant.id)
        return grant

    def _alert(self, grant: Grant, officers: list[UUID]) -> None:
        """Priority 1, which is the only tier that overrides quiet hours.

        Somebody's evening is interrupted on purpose: docs/05 calls for an "immediate alert to the
        security officer", and an alert that waits until 08:00 is a report.

        The alert carries no case content, by design. The SECURITY_OFFICER role can read the audit
        trail but not case content (migration 0017), and the case code, classification and the
        analyst's justification (free text that quotes case facts) would hand an officer with a high
        enough clearance material the permission model says they may not read. So the alert is a
        grant id, a clock and an instruction to go and look; the justification is read through
        `break_glass.review`. It is GREEN because it contains nothing about the case, and the case's
        label is not inherited: a label for content you do not carry is how a notification ends up
        over-classified and undeliverable, or under-classified and leaked.
        """
        from noctornal_api.notifications import URGENT, NotificationService

        svc = NotificationService(self._c)
        # Converted, not assumed: RETURNING hands back the timestamptz in the session's zone and no
        # connection pins it, so formatting the raw value would print local hours labelled UTC on
        # any Postgres initialised with a local timezone.
        ends = grant.expires_at.astimezone(timezone.utc)
        for officer in officers:
            svc.notify(
                # No `case_id`: this notification is ABOUT a grant, not
                # about a case, and attaching the case would put it behind
                # an assignment the officer is not supposed to need.
                recipient_id=officer, case_id=None,
                kind="BREAK_GLASS_INVOKED", priority=URGENT,
                subject="Emergency access was used",
                summary=(f"Break-glass access was invoked and expires at "
                         f"{ends:%H:%M UTC}. It needs your "
                         f"review."),
                body=(f"An analyst invoked break-glass access.\n\n"
                      f"Grant: {grant.id}\n"
                      # The console's own form, not ISO: a reader sees this text verbatim.
                      f"Expires: {ends:%Y-%m-%d %H:%M UTC}\n\n"
                      f"Their justification is held with the grant and is "
                      f"readable with break_glass.review. It is not "
                      f"reproduced here, because it describes the emergency "
                      f"and therefore the case.\n\n"
                      f"Every action taken under this grant is counted and "
                      f"audited. Your review is mandatory and the grant "
                      f"sits in the unreviewed queue until you record one."),
                classification="GREEN", compartments=frozenset(),
                object_type="break_glass", object_id=grant.id,
                actor_id=grant.user_id)

        # The case owner is told separately, with the case content the officer does not get:
        # `KINDS["BREAK_GLASS_INVOKED"]` describes this one ("Emergency access was used on a case
        # you own"). The owner is assigned and cleared, so they may have the code and the
        # justification; `notify_case_owner` applies the same suppressions, so the analyst who
        # invoked it is not told about their own invocation.
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
                             f"expires at {ends:%H:%M UTC}. A "
                             f"security officer has been alerted."),
                    body=(f"An analyst invoked break-glass access on your "
                          f"case.\n\nTheir justification:\n\n"
                          f"    {grant.justification}\n\n"
                          f"It expires at {ends:%Y-%m-%d %H:%M UTC}. A "
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
        """The grant that would apply right now, if any: the highest live
        level first, as `PgAccessResolver.resolve()` reads them."""
        row = self._c.execute(
            f"""SELECT {_READ_COLUMNS} FROM iam.break_glass
                 WHERE user_id = %s AND revoked_at IS NULL
                   AND expires_at > now()
                   AND (case_id IS NULL OR case_id = %s)
                 ORDER BY granted_classification DESC NULLS LAST,
                          expires_at DESC LIMIT 1""",
            (user_id, case_id)).fetchone()
        return _record(row) if row else None

    def live_grants(self, user_id: UUID) -> list[Grant]:
        """Every grant this user is operating under right now, on any case.

        `live_grant` answers "does a grant apply to THIS case", which is the wrong question for the
        console's header chip: an analyst under a grant scoped to case A who has switched to case B
        is still under break-glass, and the chip that says so must not go dark because the open case
        changed. Highest level first, so the first row is the one the access gate would use wherever
        it applies.
        """
        rows = self._c.execute(
            f"""SELECT {_READ_COLUMNS} FROM iam.break_glass
                 WHERE user_id = %s AND revoked_at IS NULL
                   AND expires_at > now()
                 ORDER BY granted_classification DESC NULLS LAST,
                          expires_at DESC""",
            (user_id,)).fetchall()
        return [_record(r) for r in rows]

    def record_use(self, grant_id: UUID, *, action: str,
                   case_id: UUID | None = None) -> None:
        """Count an action taken under the grant.

        "Was it granted" and "was it used" are different questions, and the interesting review case
        is the grant that was never used, which usually means the analyst found another way and the
        emergency was not one.
        """
        # Through a definer function (0111): the gate counts a use on the request connection, and
        # the request role may not UPDATE the IAM plane (0109), so the counter moves only for the
        # bound actor's own live grant and only upwards. The owner and the system role count as a
        # plain UPDATE would.
        counted = self._c.execute(
            "SELECT iam.rls_record_break_glass_use(%s)", (grant_id,)).fetchone()[0]
        if not counted:
            return
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               SELECT bg.user_id, 'USER', 'BREAK_GLASS_ACTION', 'break_glass',
                      bg.id, %s, %s
                 FROM iam.break_glass bg WHERE bg.id = %s""",
            (case_id, Json({"action": action}), grant_id))

    def revoke(self, grant_id: UUID, *, actor_id: UUID) -> Grant:
        """End it early. Does not remove the review obligation: a revoked grant is still a grant
        that happened."""
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
            f"""SELECT {_READ_COLUMNS} FROM iam.break_glass
                 WHERE reviewed_at IS NULL
                 ORDER BY started_at DESC LIMIT %s""", (limit,)).fetchall()
        return [_record(r) for r in rows]

    def review(self, grant_id: UUID, *, reviewer_id: UUID,
               outcome: str, note: str | None = None) -> Grant:
        """Record the mandatory post-hoc review.

        The reviewer may not be the person who invoked it: the same two-distinct-humans principle as
        four-eyes approval, and for the same reason, since reviewing your own emergency is not a
        review.

        Nor may the grant still be live (see the module docstring): a verdict on a live grant would
        remove it from the only list and the only revoke control while the raise went on.
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
        if current.is_live():
            raise BreakGlassError(_STILL_LIVE)

        # Ended is decided by the database's clock, not this process's, so
        # an app server running ahead cannot review a grant a few seconds
        # before it has actually stopped raising anything.
        row = self._c.execute(
            """UPDATE iam.break_glass
                  SET reviewed_by = %s, reviewed_at = now(), review_outcome = %s
                WHERE id = %s AND reviewed_at IS NULL
                  AND (revoked_at IS NOT NULL OR expires_at <= now())
            RETURNING """ + _COLUMNS,
            (reviewer_id, outcome, grant_id)).fetchone()
        if row is None:
            latest = self.get(grant_id)
            if latest is not None and latest.reviewed_at is None:
                raise BreakGlassError(_STILL_LIVE)
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
        # The one reader the screening alert shares.
        from noctornal_api.iam_admin import active_role_holders
        return active_role_holders(self._c, "SECURITY_OFFICER")

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               grant_id: UUID, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'break_glass', %s, %s, %s)""",
            (actor_id, action, grant_id, case_id, Json(detail)))


_STILL_LIVE = (
    "this grant is still live, so it cannot be reviewed yet: end it now, or "
    "wait for it to expire, then review it. A review judges everything done "
    "under the grant, and while it is live that is still growing")


_COLUMNS = ("id, user_id, case_id, justification, started_at, expires_at, "
            "granted_classification, granted_permissions, used_at, "
            "action_count, revoked_at, reviewed_by, reviewed_at, "
            "review_outcome")
#: The same list for the reads a request makes (the holder's own grants, the officer's queue): the
#: request role cannot read `justification` (0177), and the definer answers it to the grant's holder
#: and to `break_glass.review` alone. The system paths keep `_COLUMNS`.
_READ_COLUMNS = _COLUMNS.replace("justification",
                                 "iam.break_glass_justification(id)", 1)


def _record(r) -> Grant:
    return Grant(
        id=r[0], user_id=r[1], case_id=r[2], justification=r[3],
        started_at=r[4], expires_at=r[5], granted_classification=r[6],
        granted_permissions=list(r[7] or []), used_at=r[8], action_count=r[9],
        revoked_at=r[10], reviewed_by=r[11], reviewed_at=r[12],
        review_outcome=r[13],
    )
