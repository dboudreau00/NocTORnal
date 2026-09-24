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
unless some active user OTHER THAN THE INVOKER holds `SECURITY_OFFICER`.
Unreviewed emergency access is just access, and a control whose oversight
is nominal is worse than none because it produces a record that looks like
governance. The invoker never counted as a reviewer (`review()` refuses
them), but until final review C6 (2026-09-23) they counted here, so the
sole officer, who on a fresh install is also the operator holding
`break_glass.invoke` through SYS_ADMIN and CASE_OWNER, could create a grant
nobody could ever review, and whose alert went nowhere because nobody is
told what they just did.

**2. It is short by constraint, not by convention.** Migration 0032 caps it
at eight hours in a CHECK. A break-glass that can be granted for a week is
a role with a dramatic name.

**3. The alert is immediate and cannot be quietly deferred.**
`BREAK_GLASS_INVOKED` is a priority-1 notification, which is the only tier
that overrides quiet hours (decision 46). Somebody's evening is interrupted
on purpose.

**4. Use is counted, not just grant.** `used_at` and `action_count`
exist because "was it used" and "was it granted" are different questions,
and the interesting review case is the grant that was never used -- which
usually means the analyst found another way, and the emergency was not one.

> **WIRED 2026-09-01.** `PgAccessResolver.resolve()` (stores.py) calls
> `record_use()` from the access path -- and only when the grant is what
> made the access possible: base clearance below the object, granted
> clearance at or above it. A read the analyst could already make is not
> a use of the grant. From 2026-08-10 until then both columns were
> structurally zero and were deliberately NOT published, because a zero
> that cannot be anything else answers "was this used?" in the wrong
> direction. They are published again now, together, as that note said
> they should be.
>
> **What one use is, since final review U19 (2026-09-23).** One request
> the grant let through: the gate ALLOWED it, and the object's label sat
> above the invoker's own clearance and within the grant's. A request the
> gate then refused (a missing permission, a compartment, no assignment)
> used to be counted, because the count was taken while the context was
> being built, before `evaluate()` ran. A gate asked as a QUESTION is
> not counted either: `search._allowed_on_case` (what a response may
> name), `ingest._case_allows` (which rows a queue listing shows) and
> `live._recheck` (whether a socket already opened may keep streaming).
>
> **Where that leaves the count.** On a case at or below the invoker's
> clearance every request is gated at the case's labels, which the grant
> is not needed for, so the graph, the inspector, lists and search are
> widened without being counted. What counts there is a gate that sees an
> item's OWN labels above that clearance: any exhibit route
> (`evidence._authorize_exhibit`), a deception capture, screenshot or
> message opened, and a change to a node or edge (the graph writes and
> curation). An entity READ is not among them: the node and edge reads
> gate at the case's labels, and the fix round of 2026-09-23 corrected an
> invoke notice that said otherwise. On a case classified above the
> invoker's clearance every request on it passes the case's gate only
> through the grant, so every request counts, once. A request that then
> passes a second gate (the exhibit routes, a capture, screenshot or
> message opened, an entity write, a tag or set change on a node, an
> approval raised or decided, a proposal accepted onto an entity, a
> PURGED transition) used to be counted there again, so one exhibit
> opened read as two accesses. `deps.authorize_object` now passes
> `count_use` through to the resolver, and a second gate is marked
> `after_case_gate=True`: it counts only when the case's gate did not
> (sec-breakglass-double-count, 2026-09-23). On a case within the
> invoker's clearance nothing changes, because the case's gate never
> counted there and the item's gate still counts an item above it.
>
> **What the one row says.** Each use writes one `BREAK_GLASS_ACTION`
> audit row, naming the verb of the gate that counted it. Where the two
> gates ask different verbs, that is the case's: an approval raised or
> decided reads `case.read`, a PURGED transition `case.close`, a capture
> filed `evidence.upload`, where before the fix a second row also named
> the operation's own. Nothing is lost by it. What the request then did
> is its own audit event, by the same actor on the same case
> (`APPROVAL_REQUESTED`, `APPROVAL_GRANTED` or `APPROVAL_REFUSED` on the
> request, which names the operation; `CASE_STATUS_CHANGED` to PURGED;
> `CAPTURE_RECORDED`), and
> `audit.event` is append-only, so the second gate cannot add its verb to
> the first's row, and a row of its own would be the double count again
> (the ledger and `action_count` agree, row for use;
> `test_breakglass_count_once_pg.py` holds both).

**5. Review is mandatory and its absence is visible.** `unreviewed()` is
the queue. An expired grant with no review is an open item forever; it does
not age out, because ageing out is how a review requirement becomes a
formality. The review is POST-HOC: a grant that is still live cannot be
reviewed (final review U2, 2026-09-23). The queue lists only unreviewed
grants and the console's End it now sits on those cards, so a verdict on a
live grant took it out of every list while the analyst kept the raised
clearance for the rest of its hours, and every access after it was counted
against a grant nobody would look at again. End it, or let it expire, then
judge the whole of it.

## What break-glass does NOT do here

It does not grant a permission the user could not otherwise be given, and
it does not cross a compartment.

It DOES raise the user's effective clearance for one case, for a few
hours -- **since 2026-09-01.** A live, unrevoked grant carrying a
`granted_classification` is read by `PgAccessResolver.resolve()`
(stores.py), the single construction site of the five-part gate's
`AccessContext`, and the caller's clearance is raised to that level for
the case the grant names (or every case, if it names none). That is the
change the paragraph below said should be made on purpose, made on
purpose.

> **History.** From 2026-08-10 to 2026-09-01 this docstring said the
> opposite -- "AND IT DOES NOT CURRENTLY RAISE ANYTHING" -- because it
> was true: `invoke()` wrote the row and no access decision read it, so an
> analyst who invoked break-glass at 3am got a loud, audited, reviewable
> record and exactly the access they already had. The claim was withdrawn
> then rather than implemented, on the grounds that a wrong statement about
> an emergency control is the more urgent half. It is implemented now.
>
> **Scope of the raise, stated exactly.** It applies at the gate every
> case-scoped read and write passes through, and, since 2026-09-23, to
> `deps.user_ceiling(..., case_id=)` wherever a read of ONE case passes
> that case: the graph, the entity and exhibit lists and the inspector,
> case search, comms, analytics, tags and sets, deception captures and
> watch hits. Until then a case-scoped grant opened an exhibit by id and
> every list still hid it, while the console announced emergency access
> as live (ux15 breakglass-grant-raises-nothing, verifier follow-up).
>
> What a case-scoped grant still does NOT raise: `user_ceiling()` without
> a case, which is what the label checks on writes and the report
> builder use, so the analyst still creates material and builds reports
> at their own clearance; and anything on another case. A GLOBAL grant
> raises both, as it always has. The invoke notice says which applies.
>
> `granted_permissions` is stored and still NOT consulted: this module has
> always said break-glass "does not grant a permission the user could not
> otherwise be given", and that stays true.

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

        # The invoker is not a reviewer: `review()` refuses their own grant.
        # Counted here, the sole officer could invoke, and the grant then
        # sat in a queue nobody could clear, while `_alert` paged only them
        # and notifications drop what you did yourself, so nobody was told
        # either (final review C6, 2026-09-23). The alert goes to the same
        # filtered list.
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
        # The invoker's own clearance at this moment, recorded with the
        # grant. The review card said "raised to RED" for any grant naming
        # RED, including one invoked by somebody who already held RED and
        # so raised nothing; the grant row has no column for the level it
        # started from, and today's clearance is not the one it was judged
        # against (ux15 glass-review-queue-uninformative follow-up,
        # 2026-09-23).
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
        # N1 (2026-09-02). The grant row is committed (autocommit) and, since
        # 2026-09-01, RAISES the caller's effective clearance. Letting a
        # failed notify write propagate reported a grant that exists -- and
        # elevates -- as a 500, and an analyst at 3am who believes they were
        # refused stops looking for the access they now hold. The review
        # queue (`unreviewed()`) is the durable half of the control and does
        # not depend on this alert; the failure to be loud is logged.
        try:
            self._alert(grant, officers)
        except Exception:  # noqa: BLE001 - the grant stands; the failure is logged
            import logging
            logging.getLogger(__name__).exception(
                "break-glass grant %s was recorded but its alert failed", grant.id)
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
        # Converted, not assumed. RETURNING hands back the timestamptz in the
        # SESSION's zone and no connection pins it, so formatting the raw
        # value printed local hours labelled UTC on any Postgres initialised
        # with a local timezone (2026-09-23).
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
                      # The console's own form, not ISO: a reader sees
                      # this text verbatim (README screenshot set
                      # review, 2026-09-23).
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
            f"""SELECT {_COLUMNS} FROM iam.break_glass
                 WHERE user_id = %s AND revoked_at IS NULL
                   AND expires_at > now()
                   AND (case_id IS NULL OR case_id = %s)
                 ORDER BY granted_classification DESC NULLS LAST,
                          expires_at DESC LIMIT 1""",
            (user_id, case_id)).fetchone()
        return _record(row) if row else None

    def live_grants(self, user_id: UUID) -> list[Grant]:
        """Every grant this user is operating under right now, on any case.

        `live_grant` answers "does a grant apply to THIS case", which is the
        wrong question for the console's header chip: an analyst under a
        grant scoped to case A who has switched to case B is still under
        break-glass, and the chip that says so must not go dark because
        the open case changed (ux15 breakglass-grant-raises-nothing,
        2026-09-22). Highest level first, so the first row is the one the
        access gate would use wherever it applies.
        """
        rows = self._c.execute(
            f"""SELECT {_COLUMNS} FROM iam.break_glass
                 WHERE user_id = %s AND revoked_at IS NULL
                   AND expires_at > now()
                 ORDER BY granted_classification DESC NULLS LAST,
                          expires_at DESC""",
            (user_id,)).fetchall()
        return [_record(r) for r in rows]

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

        Nor may the grant still be live. See property 5 in the module
        docstring: a verdict on a live grant removed it from the only list
        and the only revoke control while the raise went on (final review
        U2, 2026-09-23).
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


#: The refusal for a verdict on a live grant (final review U2, 2026-09-23).
_STILL_LIVE = (
    "this grant is still live, so it cannot be reviewed yet: end it now, or "
    "wait for it to expire, then review it. A review judges everything done "
    "under the grant, and while it is live that is still growing")


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
