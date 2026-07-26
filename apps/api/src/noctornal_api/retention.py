"""Retention and purge (Phase 6, docs/08).

    Purge writes a tombstone to the audit log: what was destroyed, under
    what authority, by whom. The record of destruction survives the data.

That sentence is the design. A purge that leaves nothing behind is
indistinguishable from data that was never collected and from data somebody
deleted to hide it, and in a system whose premise is that "who did what" is
answerable, that ambiguity is the failure.

## Four rules

**1. Legal hold beats everything, at three levels.** Case, exhibit and
document each carry one, because a court naming a single exhibit should not
require freezing a whole case. Purge checks all three and refuses on any.

**2. A category clock may only ever be SHORTER than the case's.** A stealer
log inside a two-year case is third-party personal data belonging to
thousands of people who are not the subject; it must not inherit that
case's authority. A rule that could EXTEND would let an ingest category
quietly outlive the basis the case was opened under, so `effective_deadline`
takes the earlier of the two and there is a test that it cannot be talked
out of it.

**3. Out-of-schedule purge needs four eyes.** docs/08 says so and
`evidence.purge` was registered as an unconditional dual-control operation
in decision 44. This is that mechanism's first real user: the approval is
consumed inside the purge transaction, so a crash cannot leave a spent
approval with nothing destroyed or a destruction with a reusable approval.

**4. What actually happened to the bytes is recorded, not assumed.**
Evidence sits in MinIO COMPLIANCE-mode object lock, which cannot be deleted
before its retention expires **even to satisfy a deletion order**. That is a
real, unresolved tension between two obligations (docs/16 C2), and the
honest response is a `storage_outcome` on the tombstone rather than a purge
that reports success because the database row changed. `LOCKED_UNTIL_RETENTION`
means: the record says destroyed, the object store disagrees, and somebody
needs to know that before they tell a court otherwise.

## What this module will not do

It does not run itself. There is no scheduler here, following decision 30's
precedent — `due()` reports what is expired and `purge_due()` acts, and both
are called by an operator, a cron entry or a test. A purge job that runs
itself on a timer nobody watches is how data disappears on a Sunday.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

#: A category with no rule falls back to the case's own retention. Never
#: to "forever" and never to a default period -- an unknown category is a
#: gap in the taxonomy, and inventing a clock for it would hide that.
DEFAULT_CATEGORY = "UNKNOWN"

STORAGE_DELETED = "DELETED"
STORAGE_LOCKED = "LOCKED_UNTIL_RETENTION"
STORAGE_FAILED = "FAILED"
STORAGE_NA = "NOT_APPLICABLE"


class RetentionError(Exception):
    pass


@dataclass(frozen=True)
class Rule:
    category: str
    retain_days: int
    rationale: str
    confirmed_by: UUID | None
    confirmed_at: datetime | None

    @property
    def is_placeholder(self) -> bool:
        """True while nobody has confirmed this number.

        Purge WARNS on a placeholder rather than refusing. Refusing would
        make the first purge the moment somebody discovers the question,
        which is exactly when they are least able to answer it -- but
        running silently on a guessed retention period is how a guess
        becomes policy.
        """
        return self.confirmed_at is None


@dataclass
class DueItem:
    object_type: str
    object_id: UUID
    case_id: UUID | None
    deadline: datetime
    rule: str | None
    held: bool = False
    hold_reason: str | None = None


@dataclass
class PurgeResult:
    tombstones: list[UUID] = field(default_factory=list)
    evidence_purged: int = 0
    documents_purged: int = 0
    #: Ingest, added 2026-07-25 (docs/17 F17(a)). Counted SEPARATELY rather
    #: than folded into a total: an exhibit and a partner's raw record have
    #: different authority behind their destruction, and a single number
    #: would hide which of the two an operator just destroyed.
    records_purged: int = 0
    dead_letters_purged: int = 0
    held_back: int = 0
    storage_locked: int = 0
    warnings: list[str] = field(default_factory=list)


class RetentionService:
    def __init__(self, conn: psycopg.Connection, storage=None):
        self._c = conn
        self._storage = storage

    # -- rules -------------------------------------------------------------

    def rules(self) -> dict[str, Rule]:
        rows = self._c.execute(
            """SELECT category, retain_days, rationale, confirmed_by,
                      confirmed_at
                 FROM core.retention_rule ORDER BY category""").fetchall()
        return {r[0]: Rule(r[0], r[1], r[2], r[3], r[4]) for r in rows}

    def confirm_rule(self, category: str, *, retain_days: int, rationale: str,
                     confirmed_by: UUID) -> Rule:
        """Record that a human has actually decided this number.

        The point of the confirmation is not the number -- it is that
        somebody's id is attached to it. docs/16 D3 is the register entry
        this closes, and it closes only when the row says who.
        """
        if retain_days <= 0:
            raise RetentionError("a retention period has to be positive")
        self._c.execute(
            """INSERT INTO core.retention_rule
                   (category, retain_days, rationale, confirmed_by,
                    confirmed_at, updated_at)
               VALUES (%s, %s, %s, %s, now(), now())
               ON CONFLICT (category) DO UPDATE SET
                   retain_days = EXCLUDED.retain_days,
                   rationale = EXCLUDED.rationale,
                   confirmed_by = EXCLUDED.confirmed_by,
                   confirmed_at = EXCLUDED.confirmed_at,
                   updated_at = now()""",
            (category, retain_days, rationale, confirmed_by))
        self._audit(None, confirmed_by, "RETENTION_RULE_CONFIRMED",
                    {"category": category, "retain_days": retain_days})
        return self.rules()[category]

    def effective_deadline(self, case_retention: date | datetime,
                           category: str, captured_at: datetime) -> datetime:
        """The EARLIER of the case's own retention and the category's.

        A category rule may only shorten. Allowing it to extend would let
        an ingest category outlive the authority the case was opened
        under, which is the one direction that is never acceptable --
        holding something longer than your basis is the failure that ends
        up in a regulator's letter.
        """
        if isinstance(case_retention, date) and not isinstance(
                case_retention, datetime):
            case_deadline = datetime.combine(
                case_retention, datetime.min.time(), tzinfo=timezone.utc)
        else:
            case_deadline = case_retention
        rule = self.rules().get(category)
        if rule is None:
            return case_deadline
        category_deadline = captured_at + timedelta(days=rule.retain_days)
        return min(case_deadline, category_deadline)

    # -- what is expired ---------------------------------------------------

    def due(self, *, case_id: UUID | None = None,
            as_of: datetime | None = None, limit: int = 500) -> list[DueItem]:
        """Everything past its retention, INCLUDING what is held.

        Held items are returned flagged rather than filtered out, because
        "nothing is due" and "eleven things are due and all of them are
        frozen by a court order" are different answers and an operator
        needs the second one.
        """
        now = as_of or datetime.now(timezone.utc)
        items: list[DueItem] = []

        evidence = self._c.execute(
            """SELECT e.id, e.case_id, c.retention_until, e.legal_hold,
                      e.legal_hold_reason, c.legal_hold
                 FROM core.evidence e
                 JOIN core."case" c ON c.id = e.case_id
                WHERE e.purged_at IS NULL
                  AND c.retention_until <= %s::date
                  AND (%s::uuid IS NULL OR e.case_id = %s)
                ORDER BY c.retention_until LIMIT %s""",
            (now, case_id, case_id, limit)).fetchall()
        for row in evidence:
            items.append(DueItem(
                object_type="evidence", object_id=row[0], case_id=row[1],
                deadline=datetime.combine(row[2], datetime.min.time(),
                                          tzinfo=timezone.utc),
                rule="case.retention_until",
                held=bool(row[3] or row[5]),
                hold_reason=row[4] or ("case-level legal hold" if row[5] else None)))

        documents = self._c.execute(
            """SELECT d.id, d.retain_until, d.legal_hold, d.category
                 FROM collect.document d
                WHERE d.purged_at IS NULL AND d.retain_until IS NOT NULL
                  AND d.retain_until <= %s
                ORDER BY d.retain_until LIMIT %s""",
            (now, limit)).fetchall()
        for row in documents:
            items.append(DueItem(
                object_type="document", object_id=row[0], case_id=None,
                deadline=row[1], rule=f"retention_rule[{row[3]}]",
                held=bool(row[2]),
                hold_reason="document-level legal hold" if row[2] else None))

        # Ingest. docs/17 F17(a): `ingest.record.retain_until` has carried a
        # clock since migration 0033 and `ingest.dead_letter.retain_until`
        # since 0040, and until now NOTHING read either. The labels and the
        # gating shipped; the expiry did not. The 90-day dead-letter default
        # was chosen precisely because unassessed third-party victim data
        # deserves the shortest rule, and a clock nobody reads delivers the
        # longest possible one instead.
        #
        # A case legal hold covers ingest records attached to that case: a
        # hold that stopped at the schema boundary would be a hold with a
        # gap in it, and the material on the ingest side is the material
        # most likely to be the subject of one.
        records = self._c.execute(
            """SELECT r.id, r.case_id, r.retain_until, r.category,
                      coalesce(c.legal_hold, false)
                 FROM ingest.record r
                 LEFT JOIN core."case" c ON c.id = r.case_id
                WHERE r.purged_at IS NULL AND r.retain_until IS NOT NULL
                  AND r.retain_until <= %s
                  AND (%s::uuid IS NULL OR r.case_id = %s)
                ORDER BY r.retain_until LIMIT %s""",
            (now, case_id, case_id, limit)).fetchall()
        for row in records:
            items.append(DueItem(
                object_type="ingest_record", object_id=row[0], case_id=row[1],
                deadline=row[2], rule=f"retention_rule[{row[3]}]",
                held=bool(row[4]),
                hold_reason="case-level legal hold" if row[4] else None))

        # Dead letters have no case, so no case hold can reach them. They
        # are scoped out entirely when a case_id is named rather than
        # silently included in every case's sweep.
        if case_id is None:
            dead = self._c.execute(
                """SELECT dl.id, dl.retain_until, dl.redacted
                     FROM ingest.dead_letter dl
                    WHERE dl.purged_at IS NULL AND dl.retain_until IS NOT NULL
                      AND dl.retain_until <= %s
                    ORDER BY dl.retain_until LIMIT %s""",
                (now, limit)).fetchall()
            for row in dead:
                items.append(DueItem(
                    object_type="dead_letter", object_id=row[0], case_id=None,
                    deadline=row[1], rule="dead_letter[90d default]",
                    held=False,
                    hold_reason=None if row[2] else
                    "predates the redactor: still verbatim on disk"))
        return items

    # -- purge -------------------------------------------------------------

    def purge_due(self, *, actor_id: UUID, authority: str,
                  case_id: UUID | None = None,
                  as_of: datetime | None = None,
                  dry_run: bool = False) -> PurgeResult:
        """Destroy what is expired and not held, and write the tombstone.

        `authority` is mandatory and free text: the schedule, the policy
        reference, the instruction. A destruction whose authority nobody
        recorded cannot be defended later, and "the job ran" is not an
        authority.
        """
        if not authority or not authority.strip():
            raise RetentionError(
                "a purge has to record its authority: the tombstone is the "
                "only thing that survives, and an unattributed destruction "
                "cannot be defended")

        result = PurgeResult()
        for category, rule in self.rules().items():
            if rule.is_placeholder:
                result.warnings.append(
                    f"retention for {category} is running on the placeholder "
                    f"shipped by migration 0032 ({rule.retain_days} days) and "
                    f"has never been confirmed by a human. See docs/16 D3.")

        items = self.due(case_id=case_id, as_of=as_of)
        actionable = [i for i in items if not i.held]
        result.held_back = len(items) - len(actionable)

        if dry_run or not actionable:
            return result

        evidence_ids = [i.object_id for i in actionable
                        if i.object_type == "evidence"]
        document_ids = [i.object_id for i in actionable
                        if i.object_type == "document"]
        record_ids = [i.object_id for i in actionable
                      if i.object_type == "ingest_record"]
        dead_ids = [i.object_id for i in actionable
                    if i.object_type == "dead_letter"]

        with self._c.transaction():
            if evidence_ids:
                outcome = self._purge_evidence(evidence_ids)
                result.evidence_purged = len(evidence_ids)
                if outcome == STORAGE_LOCKED:
                    result.storage_locked = len(evidence_ids)
                    result.warnings.append(
                        "evidence rows are marked purged but the objects are "
                        "under COMPLIANCE-mode object lock and could not be "
                        "deleted. The record says destroyed; the object store "
                        "disagrees. See docs/16 C2 before telling anybody "
                        "the bytes are gone.")
                result.tombstones.append(self._tombstone(
                    case_id=case_id, object_type="evidence",
                    ids=evidence_ids, authority=authority, actor_id=actor_id,
                    rule="case.retention_until", storage_outcome=outcome))

            if document_ids:
                # The row survives; the CONTENT does not. Keeping the row
                # is what lets a later question about coverage be answered
                # ("we held 40 documents from that source and destroyed
                # them on this date") without holding the documents.
                self._c.execute(
                    """UPDATE collect.document
                          SET purged_at = now(), body_text = NULL,
                              body_html_key = NULL, search_tsv = NULL,
                              embedding = NULL
                        WHERE id = ANY(%s)""",
                    (document_ids,))
                result.documents_purged = len(document_ids)
                result.tombstones.append(self._tombstone(
                    case_id=case_id, object_type="document",
                    ids=document_ids, authority=authority, actor_id=actor_id,
                    rule="retention_rule", storage_outcome=STORAGE_NA))

            # Ingest records. The PAYLOAD goes; the row stays, exactly as
            # for a document. Keeping the row is what lets "we held 4,000
            # records from that feed and destroyed them on this date" be
            # answered without holding them -- and the victim credentials
            # attached to the record have to go with it, or the payload is
            # destroyed and the credential it named is not.
            if record_ids:
                self._c.execute(
                    "DELETE FROM ingest.victim_credential "
                    "WHERE record_id = ANY(%s)", (record_ids,))
                self._c.execute(
                    """UPDATE ingest.record
                          SET purged_at = now(), payload = '{}'::jsonb,
                              priority_detail = '{}'::jsonb
                        WHERE id = ANY(%s)""", (record_ids,))
                result.records_purged = len(record_ids)
                result.tombstones.append(self._tombstone(
                    case_id=case_id, object_type="ingest_record",
                    ids=record_ids, authority=authority, actor_id=actor_id,
                    rule="retention_rule", storage_outcome=STORAGE_NA))

            if dead_ids:
                # `raw_fragment` is NOT NULL (0033), so it is replaced
                # rather than blanked -- and `redacted` is set true in the
                # same statement, because migration 0040's CHECK is
                # re-evaluated on every UPDATE and a pre-redactor row would
                # otherwise be the ONE thing a purge cannot destroy.
                self._c.execute(
                    """UPDATE ingest.dead_letter
                          SET purged_at = now(),
                              raw_fragment = '[purged on retention]',
                              error_detail = NULL,
                              redacted = true
                        WHERE id = ANY(%s)""", (dead_ids,))
                result.dead_letters_purged = len(dead_ids)
                result.tombstones.append(self._tombstone(
                    case_id=None, object_type="dead_letter",
                    ids=dead_ids, authority=authority, actor_id=actor_id,
                    rule="dead_letter[90d default]",
                    storage_outcome=STORAGE_NA))
        return result

    def purge_out_of_schedule(self, *, actor_id: UUID, authority: str,
                              approval_request_id: UUID,
                              case_id: UUID,
                              evidence_ids: list[UUID]) -> PurgeResult:
        """Destroy specific exhibits BEFORE their retention expires.

        docs/08 requires dual control for this, and decision 44 registered
        `evidence.purge` as an unconditional four-eyes operation. The
        approval is consumed INSIDE this transaction: split them and a
        crash leaves either a spent approval with nothing destroyed, or a
        destruction with a reusable approval still outstanding. The second
        is the bad direction.
        """
        from noctornal_api.approvals import ApprovalError, ApprovalService

        if not evidence_ids:
            raise RetentionError("nothing selected")
        held = self._c.execute(
            """SELECT count(*) FROM core.evidence e
                 JOIN core."case" c ON c.id = e.case_id
                WHERE e.id = ANY(%s) AND (e.legal_hold OR c.legal_hold)""",
            (evidence_ids,)).fetchone()[0]
        if held:
            # Checked BEFORE the approval is consumed, so a refused purge
            # does not also burn somebody's signature.
            raise RetentionError(
                f"{held} of the selected exhibits are under legal hold. A "
                f"hold overrides all deletion, everywhere (docs/08) -- lift "
                f"the hold first, with its own authority.")

        payload = {"case_id": str(case_id),
                   "evidence_ids": sorted(str(e) for e in evidence_ids),
                   "authority": authority.strip()}
        result = PurgeResult()
        try:
            with self._c.transaction():
                ApprovalService(self._c).consume(
                    approval_request_id, actor_id=actor_id,
                    operation="evidence.purge", case_id=case_id,
                    payload=payload)
                outcome = self._purge_evidence(evidence_ids)
                result.evidence_purged = len(evidence_ids)
                if outcome == STORAGE_LOCKED:
                    result.storage_locked = len(evidence_ids)
                result.tombstones.append(self._tombstone(
                    case_id=case_id, object_type="evidence",
                    ids=evidence_ids, authority=authority, actor_id=actor_id,
                    rule="out-of-schedule",
                    approval_request_id=approval_request_id,
                    storage_outcome=outcome))
        except ApprovalError as exc:
            raise RetentionError(str(exc)) from exc
        return result

    # -- internals ---------------------------------------------------------

    def _purge_evidence(self, ids: list[UUID]) -> str:
        """Mark the rows and try the object store.

        The row is marked either way. If the object cannot go, that is the
        object store's answer and it belongs on the tombstone -- pretending
        the purge succeeded because the database row changed is how
        somebody ends up telling a court the material was destroyed when it
        is sitting under a compliance lock for another eighteen months.
        """
        rows = self._c.execute(
            "SELECT storage_key FROM core.evidence WHERE id = ANY(%s)",
            (ids,)).fetchall()
        self._c.execute(
            "UPDATE core.evidence SET purged_at = now() WHERE id = ANY(%s)",
            (ids,))
        if self._storage is None:
            return STORAGE_NA
        outcome = STORAGE_DELETED
        for (key,) in rows:
            try:
                self._storage.delete(key)
            except Exception:  # noqa: BLE001 - the store's refusal IS the answer
                outcome = STORAGE_LOCKED
        return outcome

    def _tombstone(self, *, case_id: UUID | None, object_type: str,
                   ids: list[UUID], authority: str, actor_id: UUID,
                   rule: str | None, storage_outcome: str,
                   approval_request_id: UUID | None = None) -> UUID:
        row = self._c.execute(
            """INSERT INTO core.purge_tombstone
                   (case_id, object_type, object_count, rule, authority,
                    approval_request_id, purged_by, storage_outcome, detail)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (case_id, object_type, len(ids), rule, authority.strip(),
             approval_request_id, actor_id, storage_outcome,
             # Counts and shape only. A tombstone that quoted what it
             # destroyed would be a copy of it.
             Json({"object_count": len(ids)}))).fetchone()
        self._audit(case_id, actor_id, "PURGE_EXECUTED", {
            "object_type": object_type, "count": len(ids), "rule": rule,
            "authority": authority.strip(), "storage_outcome": storage_outcome,
        })
        return row[0]

    def tombstones(self, case_id: UUID | None = None,
                   limit: int = 100) -> list[dict]:
        """The record of destruction. Readable long after the data is not."""
        if case_id is None:
            rows = self._c.execute(
                """SELECT id, case_id, object_type, object_count, rule,
                          authority, purged_by, purged_at, storage_outcome
                     FROM core.purge_tombstone
                    ORDER BY purged_at DESC LIMIT %s""", (limit,)).fetchall()
        else:
            rows = self._c.execute(
                """SELECT id, case_id, object_type, object_count, rule,
                          authority, purged_by, purged_at, storage_outcome
                     FROM core.purge_tombstone WHERE case_id = %s
                    ORDER BY purged_at DESC LIMIT %s""",
                (case_id, limit)).fetchall()
        return [{"id": str(r[0]),
                 "case_id": str(r[1]) if r[1] else None,
                 "object_type": r[2], "object_count": r[3], "rule": r[4],
                 "authority": r[5], "purged_by": str(r[6]),
                 "purged_at": r[7].isoformat(), "storage_outcome": r[8]}
                for r in rows]

    def set_legal_hold(self, evidence_id: UUID, *, actor_id: UUID,
                       on: bool, reason: str | None) -> None:
        """A hold overrides all deletion, everywhere. Lifting one is as
        consequential as applying one, so both are audited and applying one
        requires a reason."""
        if on and not (reason or "").strip():
            raise RetentionError(
                "a legal hold has to say what it rests on: a hold nobody can "
                "attribute is a hold nobody can lift")
        self._c.execute(
            "UPDATE core.evidence SET legal_hold = %s, legal_hold_reason = %s "
            "WHERE id = %s",
            (on, (reason or "").strip() or None if on else None, evidence_id))
        self._audit(None, actor_id,
                    "LEGAL_HOLD_APPLIED" if on else "LEGAL_HOLD_LIFTED",
                    {"evidence_id": str(evidence_id), "reason": reason})

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'retention', NULL, %s, %s)""",
            (actor_id, action, case_id, Json(detail)))
