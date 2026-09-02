"""The assumptions register (docs/08 Phase 6, migration 0056).

docs/08 defines it in one paragraph: per case, list the load-bearing
assumptions explicitly, with a review flag, so that "the same PGP key
means the same operator" is written down where it can be challenged.
Nothing existed for it until 2026-09-02, and the report stated its
conclusions without stating what they rested on.

## A register, not a to-do list

The difference is that a register's flags cannot be flipped without a
trace. Every change writes an audit row (ASSUMPTION_MADE, _REVIEWED,
_WITHDRAWN) and stamps who and when on the row itself, and two transitions
are guarded on top of that:

- REFUTED is a FINDING -- somebody established that a premise was false.
  Re-opening or confirming it without a note would erase the finding
  while leaving the assumption load-bearing again, which is the exact
  move the register exists to make visible. So that transition demands a
  review note saying why the refutation no longer stands.
- WITHDRAWN is terminal. It means the row was entered in error; it is not
  a judgement about the assumption, and a withdrawn row that could be
  revived would be a way to park an inconvenient premise out of the
  default listing and bring it back later.

## Who may write

Access is the router's job: listing is `case.read`, every write is
`case.update`, both through the five-part gate. This service does not
re-decide that. What it DOES enforce is that every write is keyed on
(case_id, id), so an id from another case is "no such assumption" rather
than a cross-case edit -- the gate decided the caller may update THIS
case, and a guessed id must not extend that to another.

## What the report includes

`REPORTABLE_STATUSES` is ONE constant read by `reports.py`, so the
document cannot quietly disagree with the register about what "still
assumed" means.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

#: Every status the schema admits (0056's CHECK), in lifecycle order.
STATUSES = ("OPEN", "CONFIRMED", "REFUTED", "WITHDRAWN")

#: The statuses a REVIEW may set. WITHDRAWN is reached only through
#: `withdraw()`: it is not a judgement about the assumption, it is a
#: statement that the row should never have been made.
REVIEW_STATUSES = ("OPEN", "CONFIRMED", "REFUTED")

#: What the report states: the assumptions the case still rests on.
#: REFUTED is excluded because a report that lists a premise it has
#: already found false is presenting a premise it knows to be false;
#: WITHDRAWN because it was never a premise. Read by `reports.py` and
#: pinned by the tests from both sides.
REPORTABLE_STATUSES = ("OPEN", "CONFIRMED")


class AssumptionError(Exception):
    pass


@dataclass(frozen=True)
class AssumptionRow:
    id: UUID
    case_id: UUID
    statement: str
    basis: str | None
    status: str
    made_by: UUID
    made_at: datetime
    #: Whoever last changed the status -- a reviewer, or the person who
    #: withdrew the row -- and when. One fact; the schema forbids one
    #: half without the other.
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_note: str | None

    def as_dict(self) -> dict:
        return {
            "id": str(self.id),
            "case_id": str(self.case_id),
            "statement": self.statement,
            "basis": self.basis,
            "status": self.status,
            "made_by": str(self.made_by),
            "made_at": self.made_at.isoformat(),
            "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "review_note": self.review_note,
        }


_COLUMNS = ("id, case_id, statement, basis, status, made_by, made_at, "
            "reviewed_by, reviewed_at, review_note")


def _row(r) -> AssumptionRow:
    return AssumptionRow(*r)


class AssumptionService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def list(self, case_id: UUID, *,
             include_withdrawn: bool = False) -> list[AssumptionRow]:
        """In the order they were made. Withdrawn rows are hidden by default
        -- they were entered in error and are noise in a working register
        -- and stay in the table because the audit trail refers to them."""
        wanted = [s for s in STATUSES if include_withdrawn or s != "WITHDRAWN"]
        rows = self._c.execute(
            f"""SELECT {_COLUMNS} FROM core.assumption
                 WHERE case_id = %s AND status = ANY(%s)
                 ORDER BY made_at, id""",
            (case_id, wanted)).fetchall()
        return [_row(r) for r in rows]

    def create(self, case_id: UUID, *, statement: str, basis: str | None,
               made_by: UUID) -> UUID:
        statement = (statement or "").strip()
        if not statement:
            raise AssumptionError("an assumption needs a statement")
        basis = (basis or "").strip() or None
        try:
            with self._c.transaction():
                assumption_id = self._c.execute(
                    """INSERT INTO core.assumption (case_id, statement, basis, made_by)
                       VALUES (%s, %s, %s, %s) RETURNING id""",
                    (case_id, statement, basis, made_by)).fetchone()[0]
                self._audit("ASSUMPTION_MADE", made_by, case_id, assumption_id,
                            {"statement": statement, "basis": basis})
        except psycopg.errors.ForeignKeyViolation as exc:
            raise AssumptionError("case or user does not exist") from exc
        return assumption_id

    def update_status(self, case_id: UUID, assumption_id: UUID, *, status: str,
                      reviewed_by: UUID, note: str | None) -> AssumptionRow:
        """A review: OPEN, CONFIRMED or REFUTED, with the reviewer's name,
        time and (optionally, except where it is a finding being undone)
        reason written on the row."""
        if status not in REVIEW_STATUSES:
            raise AssumptionError(
                f"a review sets one of {', '.join(REVIEW_STATUSES)}; "
                f"withdrawing is its own verb")
        note = (note or "").strip() or None
        with self._c.transaction():
            current = self._lock(case_id, assumption_id)
            if current.status == "WITHDRAWN":
                raise AssumptionError(
                    "this assumption is withdrawn, and a withdrawn assumption "
                    "stays withdrawn: make a new one")
            if current.status == "REFUTED" and status != "REFUTED" and note is None:
                raise AssumptionError(
                    "a refuted assumption cannot be re-opened without a review "
                    "note saying why the refutation no longer stands: refuting "
                    "it was a finding, and un-refuting it in silence erases one")
            row = self._c.execute(
                f"""UPDATE core.assumption
                       SET status = %s, reviewed_by = %s, reviewed_at = now(),
                           review_note = %s
                     WHERE id = %s AND case_id = %s
                 RETURNING {_COLUMNS}""",
                (status, reviewed_by, note, assumption_id, case_id)).fetchone()
            self._audit("ASSUMPTION_REVIEWED", reviewed_by, case_id, assumption_id,
                        {"from": current.status, "to": status, "note": note})
        return _row(row)

    def withdraw(self, case_id: UUID, assumption_id: UUID, *, withdrawn_by: UUID,
                 note: str | None) -> AssumptionRow:
        """Terminal. The row leaves the default listing and stays in the
        table; `reviewed_by`/`reviewed_at` record who withdrew it and when,
        because "entered in error, by whom" is part of the record too."""
        note = (note or "").strip() or None
        with self._c.transaction():
            current = self._lock(case_id, assumption_id)
            if current.status == "WITHDRAWN":
                raise AssumptionError("this assumption is already withdrawn")
            row = self._c.execute(
                f"""UPDATE core.assumption
                       SET status = 'WITHDRAWN', reviewed_by = %s,
                           reviewed_at = now(), review_note = %s
                     WHERE id = %s AND case_id = %s
                 RETURNING {_COLUMNS}""",
                (withdrawn_by, note, assumption_id, case_id)).fetchone()
            self._audit("ASSUMPTION_WITHDRAWN", withdrawn_by, case_id, assumption_id,
                        {"from": current.status, "note": note})
        return _row(row)

    # -- the report's view --------------------------------------------------

    def for_report(self, case_id: UUID) -> list[dict]:
        """The still-standing assumptions, with the author's display name:
        a report names people, not ids."""
        rows = self._c.execute(
            f"""SELECT {', '.join('a.' + c.strip() for c in _COLUMNS.split(','))},
                       u.display_name
                  FROM core.assumption a
                  JOIN iam.app_user u ON u.id = a.made_by
                 WHERE a.case_id = %s AND a.status = ANY(%s)
                 ORDER BY a.made_at, a.id""",
            (case_id, list(REPORTABLE_STATUSES))).fetchall()
        return [{**_row(r[:10]).as_dict(), "made_by_name": r[10]} for r in rows]

    def count_reportable(self, case_id: UUID) -> int:
        """How many the report WOULD have stated. Used when the case header
        is withheld, so the redaction statement can count what it left out
        without the builder ever reading the text it must not include."""
        return self._c.execute(
            """SELECT count(*) FROM core.assumption
                WHERE case_id = %s AND status = ANY(%s)""",
            (case_id, list(REPORTABLE_STATUSES))).fetchone()[0]

    # -- internals ------------------------------------------------------------

    def _lock(self, case_id: UUID, assumption_id: UUID) -> AssumptionRow:
        """The row, locked for the rest of the transaction so two reviews
        racing each other serialise on it; keyed on BOTH ids (see the
        module docstring)."""
        row = self._c.execute(
            f"""SELECT {_COLUMNS} FROM core.assumption
                 WHERE id = %s AND case_id = %s FOR UPDATE""",
            (assumption_id, case_id)).fetchone()
        if row is None:
            raise AssumptionError("no such assumption in this case")
        return _row(row)

    def _audit(self, action: str, actor_id: UUID, case_id: UUID,
               assumption_id: UUID, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'assumption', %s, %s, %s)""",
            (actor_id, action, assumption_id, case_id, Json(detail)))
