"""Case CRUD: the unit of access control and governance (docs/09).

A case cannot exist without a lawful basis, a retention date and a review date (the schema makes all
three NOT NULL; this service adds that the review date must fall on or before retention). Creating a
case is atomic with granting its owner CASE_OWNER access, otherwise the owner could not act on their
own case: the five-part gate reads a user's role off case_assignment, not off case.owner_user_id.

Status moves along a validated lifecycle; every create, metadata edit, status change and access
grant or revoke is written to the hash-chained audit log (docs/05).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security.access import Tlp
from noctornal_api.wording import agree

# Valid case_status transitions. PURGED is terminal and only marks intent; closed_at is stamped on
# CLOSED.
_TRANSITIONS: dict[str, set[str]] = {
    "DRAFT": {"ACTIVE", "ARCHIVED"},
    "ACTIVE": {"DORMANT", "CLOSED"},
    "DORMANT": {"ACTIVE", "CLOSED"},
    "CLOSED": {"ACTIVE", "ARCHIVED"},   # reopen or archive
    "ARCHIVED": {"PURGED"},
    "PURGED": set(),
}

#: The states in which a case's content is read-only: the graph, assertions, evidence and its links,
#: captures, proposals, comms, ACH and assumptions, tags and sets, and samples attached to it.
#: Governance is not content and keeps working in them: the status move (reopen included), legal
#: holds, retention and purge, sharing and assignments, break-glass, report builds and releases
#: (which write no content), and comms minimisation, which docs/16 L4 performs at closure.
#:
#: Material added after `closed_at` matters for disclosure, so `http/deps.py` enforces this set at
#: the one gate every content write passes; the console reads it as the case record's `read_only`
#: rather than keeping a second copy. PURGED is in it because it only follows ARCHIVED and is marked
#: for destruction.
CONTENT_READ_ONLY_STATES: frozenset[str] = frozenset(
    {"CLOSED", "ARCHIVED", "PURGED"})


#: The order a person reads the lifecycle in.
_LIFECYCLE_ORDER = ("DRAFT", "ACTIVE", "DORMANT", "CLOSED", "ARCHIVED", "PURGED")


def allowed_transitions(status: str) -> list[str]:
    """The statuses a case in `status` may move to, in lifecycle order.

    Read out through `CaseOut.allowed_transitions` so the console's Status dialog offers only the
    legal moves. `transition_status` still decides; this is the same table, read."""
    allowed = _TRANSITIONS.get(status, set())
    return [s for s in _LIFECYCLE_ORDER if s in allowed]


class CaseError(Exception):
    pass


#: Roles an account holds on ONE case at a time. docs/05: the external
#: liaison reads a single case, time-boxed, and the role is the leak path
#: that model exists to keep narrow. `_grant` refuses a second live
#: assignment of a role in this set.
SINGLE_CASE_ROLES = frozenset({"LIAISON"})


class RoleHeldOnAnotherCase(CaseError):
    """A grant of a single-case role to an account that already holds a live
    assignment of it on another case. Its own class so the sharing route can
    word the refusal without naming the fact when the colleague was named by
    an address, which anyone with `case.grant` can guess."""


@dataclass(frozen=True)
class CaseRow:
    id: UUID
    code: str
    title: str
    summary: str | None
    status: str
    classification: str
    compartments: list[str]
    owner_user_id: UUID
    deputy_user_id: UUID | None
    legal_basis: str
    authority_ref: str | None
    retention_until: date
    review_due: date
    created_at: datetime
    closed_at: datetime | None
    #: Whether the case is under a legal hold, and the reason for it. The reason is for those who
    #: hold `retention.manage` on the case, and the route that draws the record decides who they
    #: are.
    legal_hold: bool = False
    legal_hold_reason: str | None = None


class CaseService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def create(
        self,
        *,
        code: str,
        title: str,
        legal_basis: str,
        retention_until: date,
        review_due: date,
        owner_user_id: UUID,
        created_by: UUID,
        classification: str = "AMBER",
        compartments: list[str] | None = None,
        summary: str | None = None,
        authority_ref: str | None = None,
        deputy_user_id: UUID | None = None,
    ) -> UUID:
        if not legal_basis or not legal_basis.strip():
            raise CaseError("a case requires a lawful basis")
        if review_due > retention_until:
            raise CaseError("review_due must be on or before retention_until")
        # An owner cleared below the case classification could never see
        # their own case (clearance is a hard ceiling, docs/05). Catch that
        # misconfiguration at creation rather than at first denied access.
        self._require_clearance(owner_user_id, classification, "owner")
        if deputy_user_id is not None:
            self._require_clearance(deputy_user_id, classification, "deputy")
        # Compartments are need-to-know locks. A key must exist in the registry first (0057), or a
        # typo'd compartment is a lock nobody holds and the case vanishes from every listing. Then
        # the creator must be read into it, or they would be locked out of the case they just made.
        self._require_registered(compartments or [])
        self._require_compartments(owner_user_id, compartments or [], "owner")
        if deputy_user_id is not None:
            self._require_compartments(deputy_user_id, compartments or [], "deputy")
        try:
            with self._c.transaction():
                case_id = self._c.execute(
                    """INSERT INTO core."case"
                           (code, title, summary, status, classification,
                            compartments, owner_user_id, deputy_user_id,
                            legal_basis, authority_ref, retention_until, review_due)
                       VALUES (%s,%s,%s,'DRAFT',%s,%s,%s,%s,%s,%s,%s,%s)
                       RETURNING id""",
                    (code, title, summary, classification, compartments or [],
                     owner_user_id, deputy_user_id, legal_basis, authority_ref,
                     retention_until, review_due),
                ).fetchone()[0]
                # The owner (and deputy) must be able to act on the case, so
                # grant CASE_OWNER access in the same transaction.
                self._grant(case_id, owner_user_id, "CASE_OWNER", created_by)
                if deputy_user_id is not None:
                    self._grant(case_id, deputy_user_id, "CASE_OWNER", created_by)
                self._audit("CASE_CREATED", created_by, case_id,
                            {"code": code, "classification": classification})
            return case_id
        except psycopg.errors.UniqueViolation as exc:
            raise CaseError(f"case code {code!r} is already in use") from exc
        except psycopg.Error as exc:
            raise CaseError(str(exc)) from exc

    def get(self, case_id: UUID) -> CaseRow | None:
        row = self._c.execute(
            """SELECT id, code, title, summary, status, classification, compartments,
                      owner_user_id, deputy_user_id, legal_basis, authority_ref,
                      retention_until, review_due, created_at, closed_at,
                      legal_hold, legal_hold_reason
                 FROM core."case" WHERE id = %s""",
            (case_id,),
        ).fetchone()
        return _row(row) if row else None

    def update_metadata(
        self, case_id: UUID, *, updated_by: UUID,
        title: str | None = None, summary: str | None = None,
        authority_ref: str | None = None, review_due: date | None = None,
        retention_until: date | None = None, classification: str | None = None,
    ) -> None:
        """Edit governance/descriptive metadata. Every field that changes is
        audited. Retention/review keep the review<=retention invariant."""
        current = self.get(case_id)
        if current is None:
            raise CaseError(f"case {case_id} not found")
        new_review = review_due or current.review_due
        new_retention = retention_until or current.retention_until
        if new_review > new_retention:
            raise CaseError("review_due must be on or before retention_until")
        sets, params, changed = [], [], {}
        for col, val in (("title", title), ("summary", summary),
                         ("authority_ref", authority_ref), ("review_due", review_due),
                         ("retention_until", retention_until),
                         ("classification", classification)):
            if val is not None:
                sets.append(f"{col} = %s")
                params.append(val)
                changed[col] = str(val)
        if not sets:
            return
        params.append(case_id)
        with self._c.transaction():
            self._c.execute(
                f'UPDATE core."case" SET {", ".join(sets)} WHERE id = %s', params
            )
            self._audit("CASE_UPDATED", updated_by, case_id, {"changed": changed})

    def transition_status(self, case_id: UUID, new_status: str, *, actor_id: UUID) -> None:
        current = self.get(case_id)
        if current is None:
            raise CaseError(f"case {case_id} not found")
        allowed = _TRANSITIONS.get(current.status, set())
        if new_status not in allowed:
            allowed_text = (sorted(allowed) if allowed else
                            f"none, because {current.status} is terminal")
            raise CaseError(
                f"illegal status transition {current.status} -> {new_status} "
                f"(allowed: {allowed_text})"
            )
        closed_clause = ", closed_at = now()" if new_status == "CLOSED" else ""
        with self._c.transaction():
            self._c.execute(
                f'UPDATE core."case" SET status = %s{closed_clause} WHERE id = %s',
                (new_status, case_id),
            )
            self._audit("CASE_STATUS_CHANGED", actor_id, case_id,
                        {"from": current.status, "to": new_status})

    def assign_user(
        self, case_id: UUID, user_id: UUID, role_key: str, *,
        granted_by: UUID, expires_at: datetime | None = None,
    ) -> None:
        with self._c.transaction():
            self._grant(case_id, user_id, role_key, granted_by, expires_at)
            self._audit("CASE_ACCESS_GRANTED", granted_by, case_id,
                        {"user_id": str(user_id), "role": role_key})

    def revoke_user(self, case_id: UUID, user_id: UUID, *, revoked_by: UUID) -> None:
        if user_id == self._owner(case_id):
            raise CaseError("cannot revoke the case owner's access")
        with self._c.transaction():
            cur = self._c.execute(
                "DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                (case_id, user_id),
            )
            if cur.rowcount == 0:
                raise CaseError("no such assignment")
            self._audit("CASE_ACCESS_REVOKED", revoked_by, case_id,
                        {"user_id": str(user_id)})

    def list_for_user(self, user_id: UUID) -> list[CaseRow]:
        """Cases the user may actually read: exactly the set for which the five-part gate would
        allow case.read, or the list becomes a disclosure channel for cases the detail endpoint
        denies. All four applicable checks are in the SQL: the verb (via the assignment's role), the
        unexpired assignment, clearance dominance and compartment subset. (Step-up does not apply:
        case.read is not a step-up permission.)

        Clearance dominance counts a live break-glass grant, as the gate does
        (`PgAccessResolver.resolve`): one on this case or a global one, at its level. Otherwise an
        analyst assigned to a case above their own clearance could have the gate opened by a grant
        and still not find the case to open, since the list is the console's only way in.
        Compartments are not widened, by a grant or here."""
        rows = self._c.execute(
            """SELECT c.id, c.code, c.title, c.summary, c.status, c.classification,
                      c.compartments, c.owner_user_id, c.deputy_user_id, c.legal_basis,
                      c.authority_ref, c.retention_until, c.review_due, c.created_at,
                      c.closed_at, c.legal_hold, c.legal_hold_reason
                 FROM core."case" c
                 JOIN iam.case_assignment a ON a.case_id = c.id
                 JOIN iam.app_user u ON u.id = a.user_id
                WHERE a.user_id = %s
                  AND (a.expires_at IS NULL OR a.expires_at > now())
                  AND u.is_active
                  AND c.classification <= GREATEST(u.tlp_clearance, COALESCE(
                        (SELECT max(bg.granted_classification)
                           FROM iam.break_glass bg
                          WHERE bg.user_id = u.id AND bg.revoked_at IS NULL
                            AND bg.expires_at > now()
                            AND (bg.case_id IS NULL OR bg.case_id = c.id)),
                        u.tlp_clearance))
                  AND c.compartments <@ u.compartments
                  AND EXISTS (SELECT 1 FROM iam.role_permission rp
                               WHERE rp.role_key = a.role_key
                                 AND rp.permission_key = 'case.read')
                ORDER BY c.created_at DESC""",
            (user_id,),
        ).fetchall()
        return [_row(r) for r in rows]

    # -- internal --------------------------------------------------------
    def _grant(self, case_id, user_id, role_key, granted_by, expires_at=None):
        """Grant or re-grant a case role.

        An omitted expiry preserves the existing time-box (`COALESCE` on `expires_at`) rather than
        removing it. Re-granting without naming an expiry is ordinary (changing a colleague's role,
        re-running a grant that appeared not to take), and silently turning a time-boxed assignment
        permanent fails open and is invisible until an audit asks why a secondment from March still
        reads the case in November, whereas keeping a limit fails safe. So this path cannot clear an
        expiry; removing a time limit is a deliberate act and deserves its own verb.

        A role in `SINGLE_CASE_ROLES` is refused while the account holds a live assignment of it on
        another case (docs/17 "LIAISON is not single-case"). Re-granting on the same case still
        works, so a liaison's end date can be moved. "Live" is the gate's own test
        (`CHECK_ASSIGNMENT`). The check and the write are one transaction under a lock per account
        and role, or two leads granting the same liaison at the same moment would each find nothing
        held and each write.
        """
        with self._c.transaction():
            if role_key in SINGLE_CASE_ROLES:
                self._refuse_second_live(case_id, user_id, role_key)
            self._c.execute(
                """INSERT INTO iam.case_assignment
                       (case_id, user_id, role_key, granted_by, expires_at)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (case_id, user_id)
                       DO UPDATE SET role_key = EXCLUDED.role_key,
                                     granted_by = EXCLUDED.granted_by,
                                     expires_at = COALESCE(
                                         EXCLUDED.expires_at,
                                         iam.case_assignment.expires_at),
                                     granted_at = now()""",
                (case_id, user_id, role_key, granted_by, expires_at),
            )

    def _refuse_second_live(self, case_id: UUID, user_id: UUID,
                            role_key: str) -> None:
        """Raise `RoleHeldOnAnotherCase` if `user_id` holds a live `role_key`
        assignment on a case other than `case_id`. Called inside `_grant`'s
        transaction, which the advisory lock below lives and dies with."""
        self._c.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            (f"iam.case_assignment.single_case:{role_key}:{user_id}",))
        held = self._c.execute(
            """SELECT 1 FROM iam.case_assignment
                WHERE user_id = %s AND role_key = %s AND case_id <> %s
                  AND (expires_at IS NULL OR expires_at > now())
                LIMIT 1""",
            (user_id, role_key, case_id)).fetchone()
        if held is not None:
            # The other case is not named: the person granting may not be
            # on it, and which case it is is not theirs to learn here.
            role = role_key.lower()
            raise RoleHeldOnAnotherCase(
                f"that account already holds a live {role} assignment on "
                f"another case. A {role} holds one case at a time: the other "
                f"assignment has to end, or be revoked, before this one can "
                f"be made.")

    def _require_clearance(self, user_id: UUID, classification: str, who: str) -> None:
        row = self._c.execute(
            "SELECT tlp_clearance FROM iam.app_user WHERE id = %s", (user_id,)
        ).fetchone()
        if row is None:
            raise CaseError(f"{who} user {user_id} not found")
        if Tlp[row[0]] < Tlp[classification]:
            raise CaseError(
                f"{who} clearance {row[0]} is below the case classification "
                f"{classification}, so they could not see the case"
            )

    def _require_registered(self, compartments: list[str]) -> None:
        """Every key must be in `iam.compartment` (0057), and the refusal names the unknown ones: a
        wrong key otherwise produces a correct-looking denial with no indication of why.

        `create` is the only write site. `update_metadata` deliberately has no `compartments`
        parameter (its router body says why: adding a compartment locks out every assignee not read
        into it, and needs its own endpoint with "who loses access" reporting), and a test pins that
        absence, so whoever adds it must bring this check along.
        """
        if not compartments:
            return
        known = {r[0] for r in self._c.execute(
            "SELECT key FROM iam.compartment WHERE key = ANY(%s)",
            (list(compartments),)).fetchall()}
        unknown = sorted(set(compartments) - known)
        if unknown:
            # Agreed with the keys it names rather than hedged with a bracketed plural, which the
            # console prints verbatim.
            n = len(unknown)
            raise CaseError(
                f"{agree(n, 'compartment', 'compartments')} "
                f"{', '.join(unknown)} {agree(n, 'is', 'are')} not "
                f"registered. A compartment "
                # The route is spelled with its mount prefix (`/api/v1`) because the operator pastes
                # it. `test_compartment_binding_pg.py` holds all three refusals to the migration
                # constant and the route table.
                f"must be registered (POST /api/v1/compartments, user.manage) "
                f"before "
                f"a case can be filed under it, because an unregistered key "
                f"is a typo, and a typo in a need-to-know lock is a case "
                f"nobody can see")

    def _require_compartments(
        self, user_id: UUID, compartments: list[str], who: str
    ) -> None:
        row = self._c.execute(
            "SELECT compartments FROM iam.app_user WHERE id = %s", (user_id,)
        ).fetchone()
        if row is None:
            raise CaseError(f"{who} user {user_id} not found")
        missing = set(compartments) - set(row[0] or [])
        if missing:
            raise CaseError(
                f"{who} is not read into "
                f"{agree(len(missing), 'compartment', 'compartments')} "
                f"{', '.join(sorted(missing))}, so they could not see the case"
            )

    def assign_user_checked(
        self, case_id: UUID, user_id: UUID, role_key: str, *,
        granted_by: UUID, expires_at: datetime | None = None,
    ) -> None:
        """assign_user, but refusing an assignee who could never read the
        case. An under-cleared or non-compartmented assignee is otherwise a
        reachable state that the listing/search filters then silently hide."""
        case = self.get(case_id)
        if case is None:
            raise CaseError(f"case {case_id} not found")
        self._require_clearance(user_id, case.classification, "assignee")
        self._require_compartments(user_id, case.compartments, "assignee")
        self.assign_user(case_id, user_id, role_key, granted_by=granted_by,
                         expires_at=expires_at)

    def _owner(self, case_id: UUID) -> UUID | None:
        row = self._c.execute(
            'SELECT owner_user_id FROM core."case" WHERE id = %s', (case_id,)
        ).fetchone()
        return row[0] if row else None

    def _audit(self, action, actor_id, case_id, detail):
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
               VALUES (%s, 'USER', %s, 'case', %s, %s, %s)""",
            (actor_id, action, case_id, case_id, Json(detail)),
        )


def _row(r) -> CaseRow:
    return CaseRow(
        id=r[0], code=r[1], title=r[2], summary=r[3], status=r[4], classification=r[5],
        compartments=list(r[6] or []), owner_user_id=r[7], deputy_user_id=r[8],
        legal_basis=r[9], authority_ref=r[10], retention_until=r[11], review_due=r[12],
        created_at=r[13], closed_at=r[14], legal_hold=bool(r[15]),
        legal_hold_reason=r[16],
    )
