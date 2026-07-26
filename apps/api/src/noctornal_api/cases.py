"""Case CRUD — the unit of access control and governance (docs/09 Phase 1).

A case cannot exist without a lawful basis, a retention date and a review
date (the schema makes all three NOT NULL; this service adds the sanity
that a review must fall on or before retention). Creating a case is atomic
with granting its owner CASE_OWNER access — otherwise the owner could not
act on their own case, because the five-part gate reads a user's role off
case_assignment, not off case.owner_user_id.

Status moves along a validated lifecycle; every create, metadata edit,
status change and access grant/revoke is written to the hash-chained audit
log (docs/05: every case mutation is audited).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security.access import Tlp

# Valid case_status transitions. PURGED is terminal (the actual data purge
# is Phase 6; this only marks intent). closed_at is stamped on -> CLOSED.
_TRANSITIONS: dict[str, set[str]] = {
    "DRAFT": {"ACTIVE", "ARCHIVED"},
    "ACTIVE": {"DORMANT", "CLOSED"},
    "DORMANT": {"ACTIVE", "CLOSED"},
    "CLOSED": {"ACTIVE", "ARCHIVED"},   # reopen or archive
    "ARCHIVED": {"PURGED"},
    "PURGED": set(),
}


class CaseError(Exception):
    pass


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
        # Compartments are need-to-know locks, so a creator cannot put a case
        # into a compartment they are not read into — they would be locked out
        # of the case they just made (and a typo'd compartment would do the
        # same silently).
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
                      retention_until, review_due, created_at, closed_at
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
            raise CaseError(
                f"illegal status transition {current.status} -> {new_status} "
                f"(allowed: {sorted(allowed) or 'none — terminal'})"
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
        """Cases the user may actually READ — the listing must return exactly
        the set for which the five-part gate would allow case.read, or the
        list becomes a disclosure channel for cases the detail endpoint
        denies. All four applicable checks are in the SQL: the verb (via the
        assignment's role), the unexpired assignment, clearance dominance,
        and compartment subset. (Step-up does not apply: case.read is not a
        step-up permission.)"""
        rows = self._c.execute(
            """SELECT c.id, c.code, c.title, c.summary, c.status, c.classification,
                      c.compartments, c.owner_user_id, c.deputy_user_id, c.legal_basis,
                      c.authority_ref, c.retention_until, c.review_due, c.created_at,
                      c.closed_at
                 FROM core."case" c
                 JOIN iam.case_assignment a ON a.case_id = c.id
                 JOIN iam.app_user u ON u.id = a.user_id
                WHERE a.user_id = %s
                  AND (a.expires_at IS NULL OR a.expires_at > now())
                  AND u.is_active
                  AND c.classification <= u.tlp_clearance
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
        self._c.execute(
            """INSERT INTO iam.case_assignment
                   (case_id, user_id, role_key, granted_by, expires_at)
               VALUES (%s, %s, %s, %s, %s)
               ON CONFLICT (case_id, user_id)
                   DO UPDATE SET role_key = EXCLUDED.role_key,
                                 granted_by = EXCLUDED.granted_by,
                                 expires_at = EXCLUDED.expires_at,
                                 granted_at = now()""",
            (case_id, user_id, role_key, granted_by, expires_at),
        )

    def _require_clearance(self, user_id: UUID, classification: str, who: str) -> None:
        row = self._c.execute(
            "SELECT tlp_clearance FROM iam.app_user WHERE id = %s", (user_id,)
        ).fetchone()
        if row is None:
            raise CaseError(f"{who} user {user_id} not found")
        if Tlp[row[0]] < Tlp[classification]:
            raise CaseError(
                f"{who} clearance {row[0]} is below the case classification "
                f"{classification} — they could not see the case"
            )

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
                f"{who} is not read into compartment(s) {sorted(missing)} — "
                "they could not see the case"
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
        created_at=r[13], closed_at=r[14],
    )
