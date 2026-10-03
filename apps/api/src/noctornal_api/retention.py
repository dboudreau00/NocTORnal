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
means: the schedule says destroy, the object store refused, and somebody
needs to know that before they tell a court otherwise. Since 2026-09-02 a
refused exhibit is also NOT marked purged. On the SCHEDULED path that
means it stays due, and the sweep after the lock expires destroys it and
writes its own DELETED record. On `purge_out_of_schedule` there is no such
sweep -- `due()` only ever returns evidence whose case retention has
expired, and that path is for exhibits whose retention has not -- so it
warns instead that nothing will retry the row and that the four-eyes
approval has been spent. Before all this the row was marked on the
refusal and dropped out of every sweep, so the bytes outlived the lock
under a tombstone saying they were locked; and the purge asked the store
with a keyless delete that a versioned bucket answers with a delete
marker and success, so the tombstone said DELETED while every byte stayed
retrievable by version id.

The counts that go with it (`storage_deleted` / `storage_locked` /
`storage_failed`) are EXHIBIT ROWS, the unit the tombstone's
`object_count` and the governance router speak, and they add up to what
was attempted. Per-key object VERSION counts live in the warnings.

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

from noctornal_api.evidence import is_retention_refusal
from noctornal_api.wording import agree, count_of

#: A category with no rule falls back to the case's own retention. Never
#: to "forever" and never to a default period -- an unknown category is a
#: gap in the taxonomy, and inventing a clock for it would hide that.
DEFAULT_CATEGORY = "UNKNOWN"

STORAGE_DELETED = "DELETED"
STORAGE_LOCKED = "LOCKED_UNTIL_RETENTION"
STORAGE_FAILED = "FAILED"
STORAGE_NA = "NOT_APPLICABLE"

def _is_retention_refusal(exc: Exception) -> bool:
    """Is this exception the store saying "the object is under a retention
    lock" -- and nothing else?

    One classifier, shared with `EvidenceStorage.delete_all_versions`; the
    rule and its live measurement are on `evidence.is_retention_refusal`.
    Kept under this name because it is the purge's half of a contract that
    `tests/test_evidence_lock_live_pg.py` reads from both sides.

    What was wrong until 2026-09-02: this module kept its own set of codes,
    returned True on a bare `AccessDenied` or `InvalidRequest`, and listed
    `ObjectLockConfigurationNotFoundError` -- which means the bucket has NO
    lock configuration -- as a lock. A read-only key, or a bucket policy
    denying `s3:DeleteObject`, was therefore written into an append-only
    tombstone as LOCKED_UNTIL_RETENTION: the specific claim that the bytes
    will become deletable when a retention expires, which they will not.
    """
    return is_retention_refusal(exc)


@dataclass(frozen=True)
class _StorageOutcome:
    """Per-EXHIBIT-ROW counts, not one verdict for a batch.

    `outcome` keeps the single string the tombstone column takes, and the
    counts are what the caller reports -- so a partial refusal stops being
    indistinguishable from a total one. Every row lands in exactly one of
    the three, so `deleted + locked + failed == len(rows)`: rows is the
    unit the tombstone's `object_count` and the governance router already
    speak, and a counter that does not add up to the batch cannot tell an
    operator whether the rest went or were never tried.

    Between two commits on 2026-09-02 `deleted` and `locked` were sums of
    `versions_removed` / `versions_locked` across keys instead. One
    exhibit with one version removed and one refused then answered
    `evidence_purged: 1, storage_deleted: 1, storage_locked: 1` with zero
    rows marked purged -- an operator-facing claim that an object was
    destroyed for an exhibit that was entirely intact and still readable.
    That is this module's signature defect, "a failure reported as the
    wrong thing", restated in a different unit.

    `warnings` (added 2026-09-02) names the keys the store had nothing
    under, refused for a reason that is not a lock, or refused under a
    lock -- and carries the VERSION counts, which belong in prose beside
    the key they describe rather than in a counter published next to a row
    count. A bare count of failures does not tell an operator WHICH
    exhibit the store disagrees about.
    """
    outcome: str
    deleted: int = 0
    locked: int = 0
    failed: int = 0
    warnings: tuple[str, ...] = ()
    #: Exhibits that came under a legal hold, their own or their case's,
    #: between the sweep and the purge's row locks, and were not touched
    #: (evidence-purge-hold-race, 2026-10-03). Not in the three counts.
    held: tuple = ()
    #: Exhibits another purge destroyed first, found under the same locks.
    gone: tuple = ()


#: The most exhibits one out-of-schedule purge may name. Its rows and their
#: case stay locked while the object store deletes them one by one
#: (evidence-purge-stalls-audit-chain, 2026-10-03).
MAX_OUT_OF_SCHEDULE = 200


class RetentionError(Exception):
    pass


#: The clock an ingest record gets when its category has NO rule at all.
#: `ingest.py:_retain_until` stamps it; the retention panel names it, so a
#: category running on a period nobody chose is on screen beside the rules
#: somebody did (ux15-report:unruled-categories-invisible, 2026-09-23).
#: Until then the fallback was a literal in ingest.py and no screen said
#: IOC_FEED and RANSOM_LEAK_POST material was on it.
UNRULED_RETAIN_DAYS = 365


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
    #: The ingest or document category whose rule set the deadline. The
    #: due list printed "ingest_record, id 3f2a91bc", which told nobody
    #: what was about to go (ux15-report:due-list-no-forward-view-no-names,
    #: 2026-09-23). Exhibits carry none: their deadline is the case's.
    category: str | None = None


@dataclass
class PurgeResult:
    tombstones: list[UUID] = field(default_factory=list)
    #: Exhibits the purge ATTEMPTED, not the number destroyed. Since
    #: 2026-09-02 only a row whose object the store confirmed removed is
    #: marked `purged_at`; `storage_deleted` is that number, and the two
    #: differ by exactly `storage_locked + storage_failed`. Kept as the
    #: attempt count because the tombstone's `object_count` is the
    #: attempt too, and the two must agree.
    evidence_purged: int = 0
    documents_purged: int = 0
    #: Ingest, added 2026-07-25 (docs/17 F17(a)). Counted SEPARATELY rather
    #: than folded into a total: an exhibit and a partner's raw record have
    #: different authority behind their destruction, and a single number
    #: would hide which of the two an operator just destroyed.
    records_purged: int = 0
    dead_letters_purged: int = 0
    held_back: int = 0
    #: EXHIBIT ROWS the store refused because at least one version of the
    #: object is under a retention lock -- the same unit as
    #: `evidence_purged`, not object versions. This is the refusal count;
    #: it used to be the batch size, so one refusal in a hundred and a
    #: hundred refusals wrote the same number into an append-only
    #: tombstone. It was briefly a version count on 2026-09-02, which
    #: broke the arithmetic above; the per-key version detail is in
    #: `warnings`.
    storage_locked: int = 0
    #: EXHIBIT ROWS that failed to delete for a reason that is NOT a
    #: retention lock. Previously collapsed into `storage_locked` by a bare
    #: `except Exception`, which turned "the store did not answer" into the
    #: specific and defensible claim "the object is under a lock".
    storage_failed: int = 0
    #: EXHIBIT ROWS the store confirmed it removed -- exactly the rows this
    #: purge marked `purged_at`. Reported so the three add up to what was
    #: attempted: without it an operator reading `evidence_purged: 100,
    #: storage_locked: 3` cannot tell whether the other 97 went or were
    #: never tried. Never counts a row whose object was partly refused:
    #: a version removed from a key whose other version is locked destroys
    #: nothing, because the exhibit is still readable.
    storage_deleted: int = 0
    # F15.3 and F15.4 (2026-09-24): lookups, their answers
    # and batches, emptied by the case clock and never deleted. Counted
    # apart, like records: a vendor's answer and an exhibit have different
    # authority behind them.
    lookups_purged: int = 0
    lookup_results_purged: int = 0
    lookup_batches_purged: int = 0
    #: Lab samples of an expired case taken out of the working store the way
    #: the deployment disposes of a rejected sample (lab-4, 2026-10-03).
    samples_purged: int = 0
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Collected documents: what cites them, what holds them (2026-09-24;
# docs/00 decision 74)
# ---------------------------------------------------------------------------
#
# The collector now writes `collect.document.retain_until` for documents whose
# category has a retention rule, which arms the document leg of the purge for
# the first time. Decision 74: no code arms it without honouring legal hold on the
# document AND its case. A collected document has no case_id, so its cases
# are the cases that CITE it, through the foreign keys below. One registry,
# so the due list and the purge read the same predicate, and a catalogue test
# (test_collected_document_retention_pg.py) fails on any foreign key onto
# collect.document, or onto a run or a source from a case table, that is in
# none of these maps.
#
# A hold on, or a citation of, ANY version of a post holds every version: a
# court naming a post names its history.

#: (foreign key, SELECT document_id, case_id, pins). `pins` is true for a
#: citation that pins the document whatever the holds say: an assertion that
#: has not been retracted (docs/04, "documents supporting an accepted
#: assertion are pinned regardless of retention"). A retracted or
#: superseded assertion still cites for the case hold. APPEND-ONLY, marked.
DOCUMENT_CITATIONS: tuple[tuple[str, str], ...] = (
    ("core.assertion.document_id",
     "SELECT a.document_id, a.case_id, a.retracted_at IS NULL "
     "FROM core.assertion a WHERE a.document_id IS NOT NULL"),
    ("collect.proposal.document_id",
     "SELECT p.document_id, p.case_id, false "
     "FROM collect.proposal p WHERE p.document_id IS NOT NULL"),
    ("comms.contact_block.document_id",
     "SELECT b.document_id, b.case_id, false "
     "FROM comms.contact_block b WHERE b.document_id IS NOT NULL"),
    ("core.tag_assignment.document_id",
     "SELECT ta.document_id, t.case_id, false FROM core.tag_assignment ta "
     "JOIN core.tag t ON t.id = ta.tag_id "
     "WHERE ta.document_id IS NOT NULL AND t.case_id IS NOT NULL"),
    ("collect.watch_hit.document_id",
     "SELECT h.document_id, w.case_id, false FROM collect.watch_hit h "
     "JOIN collect.watch w ON w.id = h.watch_id WHERE w.case_id IS NOT NULL"),
    # A document collected under a case's watch.
    ("collect.document.watch_id",
     "SELECT d2.id, w.case_id, false FROM collect.document d2 "
     "JOIN collect.watch w ON w.id = d2.watch_id WHERE w.case_id IS NOT NULL"),
)

#: Foreign keys onto a RUN or a SOURCE from a table that has a case_id, which
#: cite every document that run or source produced. Each is ALSO a leg of the
#: hold (2026-09-24): registered and not followed was a hold
#: that silently missed the documents of a run a held case cites as evidence
#: the day something writes the column. APPEND-ONLY, marked.
DOCUMENT_RUN_AND_SOURCE_CITATIONS: dict[str, str] = {
    "core.evidence.collection_run_id": (
        "SELECT d3.id, e.case_id, false FROM core.evidence e "
        "JOIN collect.document d3 ON d3.collection_run_id = e.collection_run_id "
        "WHERE e.collection_run_id IS NOT NULL"),
}

#: Foreign keys onto a run or a source from a case table that do NOT cite
#: its documents, each with why. APPEND-ONLY, marked.
RUN_AND_SOURCE_REFERENCES_NOT_CITATIONS: dict[str, str] = {
    "core.assertion.source_id": (
        "names the source a claim came from, not a document; an assertion "
        "that rests on a document cites it through core.assertion.document_id"),
    "collect.watch.source_id": (
        "names the source a watch reads; the watch's hits and the documents "
        "collected under it are citation legs already"),
    "ingest.api_key.source_id": (
        "names the source a partner key submits as; ingest records are not "
        "collected documents"),
}

#: Foreign keys onto collect.document that are not case material, each with
#: why. APPEND-ONLY, marked: a side table (the forum adapters' forum_post and
#: forum_member, Telegram's telegram_message, the embeddings table) registers
#: here AND in DOCUMENT_PURGE_SCRUBS.
DOCUMENT_REFERENCES_NOT_CASE_MATERIAL: dict[str, str] = {
    "collect.document.supersedes_id": "the version chain itself",
    "collect.extraction.document_id": (
        "machine output about the document; it names no case"),
    # F6.1 (2026-09-25).
    "collect.document_embedding.document_id": (
        "the document's similarity vectors; they name no case"),
    # F3 and F4 (2026-09-24).
    "collect.forum_post.document_id": (
        "a forum post's signature, the posts it quotes and its reactions; "
        "they name no case"),
    "collect.forum_member.document_id": (
        "a forum member's profile fields; they name no case"),
    # F5.3 (telegram, 2026-09-24).
    "collect.telegram_message.document_id": (
        "the capture record of a Telegram message; it names no case"),
}

#: Foreign key -> the statement that empties that side table's personal data
#: for purged documents (placeholder %(ids)s), or a reason starting
#: "holds no personal data". Every entry of DOCUMENT_REFERENCES_NOT_CASE_MATERIAL
#: except the version chain needs one. APPEND-ONLY, marked.
DOCUMENT_PURGE_SCRUBS: dict[str, str] = {
    # The selectors taken from the document (raw_value, norm_value) are the
    # document's personal data restated.
    "collect.extraction.document_id":
        "DELETE FROM collect.extraction WHERE document_id = ANY(%(ids)s)",
    # F6.1 (2026-09-25). The vectors are derived from the content,
    # so they go with it. The trigger on purged_at has already removed them
    # in this transaction; this states it where the rule is read.
    "collect.document_embedding.document_id":
        "DELETE FROM collect.document_embedding WHERE document_id = ANY(%(ids)s)",
    # F3 and F4 (2026-09-24). A signature, reactor names and profile
    # fields are the author's personal data, so they go with the text.
    "collect.forum_post.document_id":
        "DELETE FROM collect.forum_post WHERE document_id = ANY(%(ids)s)",
    "collect.forum_member.document_id":
        "DELETE FROM collect.forum_member WHERE document_id = ANY(%(ids)s)",
    # F5.3 (telegram, 2026-09-24). The typed ids and names of the
    # people a message names: its guard (0106) allows exactly this, and
    # only for a purged document. The capture record itself stays.
    "collect.telegram_message.document_id":
        "UPDATE collect.telegram_message SET sender_uid = NULL, "
        "sender_handle_at_capture = NULL, post_author = NULL, "
        "fwd_from_uid = NULL, fwd_from_name = NULL, via_bot_uid = NULL "
        "WHERE document_id = ANY(%(ids)s)",
}

#: The version chain is exempt from the scrub rule by name.
_SCRUB_EXEMPT = frozenset({"collect.document.supersedes_id"})

_HOLD_REASON_DOCUMENT = "document-level legal hold"
_HOLD_REASON_CASE = "cited by a case under legal hold"
_HOLD_REASON_PIN = "supports an assertion that has not been retracted"


def _citations_sql() -> str:
    """Every citation leg as one relation (document_id, case_id, pins),
    each leg's columns named by position so a leg written with other
    names (or an expression) still lines up."""
    legs = [sql for _key, sql in DOCUMENT_CITATIONS]
    legs.extend(DOCUMENT_RUN_AND_SOURCE_CITATIONS.values())
    return " UNION ALL ".join(
        f"SELECT * FROM ({leg}) AS leg{i}(document_id, case_id, pins)"
        for i, leg in enumerate(legs))


def _versions_sql(alias: str, other: str = "v") -> str:
    """True when `other` is a version of the document `alias`: the same
    source and external id, or the document itself when it has none. One
    spelling for the hold predicate and the case-hold lift gate, so the two
    cannot disagree about which rows a citation holds."""
    return (f"(({alias}.external_id IS NULL AND {other}.id = {alias}.id) OR "
            f"({alias}.external_id IS NOT NULL "
            f"AND {other}.source_id = {alias}.source_id "
            f"AND {other}.external_id = {alias}.external_id))")


def _held_sql(alias: str = "d") -> str:
    """The hold reason of the document `alias`, or NULL: over EVERY version
    of it (the same source and external id; the document itself when it
    has none), a document-level hold, then a citing case under hold, then an
    unretracted assertion's pin. The case is never named or counted."""
    versions = _versions_sql(alias)
    cited = _citations_sql()
    return (
        f"CASE WHEN EXISTS (SELECT 1 FROM collect.document v WHERE {versions} "
        f"AND v.legal_hold) THEN '{_HOLD_REASON_DOCUMENT}' "
        f"WHEN EXISTS (SELECT 1 FROM collect.document v JOIN ({cited}) c "
        f"ON c.document_id = v.id JOIN core.\"case\" k ON k.id = c.case_id "
        f"WHERE {versions} AND k.legal_hold) THEN '{_HOLD_REASON_CASE}' "
        f"WHEN EXISTS (SELECT 1 FROM collect.document v JOIN ({cited}) c "
        f"ON c.document_id = v.id WHERE {versions} AND c.pins) "
        f"THEN '{_HOLD_REASON_PIN}' END")


#: ONE hold predicate over the alias `d`, built once at import from the
#: registries above: `due()` and the purge's recheck both read it, so the
#: list and the act cannot disagree and there is no second predicate.
_DOCUMENT_HELD_SQL = _held_sql("d")

#: The one refusal for due raw markup with no store to delete it from,
#: said before the purge's transaction and again under its locks.
_NO_DOCUMENT_RAW_STORE = (
    "no store for collected raw markup is configured, so the markup of due "
    "documents cannot be destroyed. Refusing rather than marking them purged "
    "while their markup stays in the bucket.")


def _ceiling_parts(ceiling: tuple) -> tuple[str, list[str]]:
    """(clearance name, sorted compartments) of a (clearance, compartments)
    ceiling. An unknown label raises rather than passes: a ceiling that
    cannot be read covers nothing."""
    from noctornal_api.security.access import tlp_from_name

    clearance, held = ceiling
    clearance = clearance if isinstance(clearance, str) else clearance.name
    tlp_from_name(clearance)
    return clearance, sorted(set(held or ()))


class RetentionNotFound(RetentionError):
    """The document does not exist, is purged, or sits above the caller's
    labels, indistinguishably: a 404."""


class RetentionConflict(RetentionError):
    """The request is valid and cannot be done by this caller: a 409."""


class RetentionService:
    def __init__(self, conn: psycopg.Connection, storage=None,
                 document_raw=None, sample_stores=None):
        self._c = conn
        self._storage = storage
        # The store collected raw markup is deleted from when its
        # document is purged. None refuses a purge whose documents carry
        # markup, rather than recording a destruction that did not happen.
        self._document_raw = document_raw
        # lab-4 (2026-10-03): a zero-argument callable returning (sample
        # store, preservation store or None), called only when a purge has
        # samples to dispose of, so a case without any needs no sample
        # credentials. None leaves due samples due, and says so.
        self._sample_stores = sample_stores

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

        # `collect.document` has NO case_id -- a document hangs off a source
        # and is material in however many cases cite it. So a case-scoped
        # sweep must not touch documents AT ALL: the query took no case
        # filter, so `purge_due(case_id=X)` counted and would have destroyed
        # deployment-wide documents and written the tombstone under case X.
        # That is precisely the cross-case destruction the out-of-schedule
        # router refuses by name, arriving through the scheduled path.
        #
        # Decision 74 (2026-09-24): a due document is HELD when any
        # version of it carries a document-level hold, is cited by a case
        # under legal hold, or supports an assertion that has not been
        # retracted (`_DOCUMENT_HELD_SQL`, the one predicate the purge
        # rechecks under its locks). Held ones are ordered AFTER the unheld,
        # so a backlog of held documents cannot fill the limit and starve
        # the sweep; purge_due counts them with a query of its own.
        if case_id is None:
            documents = self._c.execute(
                f"""SELECT d.id, d.retain_until, d.category, held.reason
                     FROM collect.document d
                     CROSS JOIN LATERAL (SELECT {_DOCUMENT_HELD_SQL} AS reason) held
                    WHERE d.purged_at IS NULL AND d.retain_until IS NOT NULL
                      AND d.retain_until <= %s
                    ORDER BY (held.reason IS NOT NULL), d.retain_until
                    LIMIT %s""",
                (now, limit)).fetchall()
            for row in documents:
                items.append(DueItem(
                    object_type="document", object_id=row[0], case_id=None,
                    deadline=row[1], rule=f"retention_rule[{row[2]}]",
                    held=row[3] is not None, hold_reason=row[3],
                    category=row[2]))

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
        #
        # A category clock only ever SHORTENS (rule 2 above): a record
        # attached to a case falls due at the earlier of its category stamp
        # and the case's own retention instant, 00:00 UTC on that day.
        # evidence-category-clock-outlives-case (2026-10-03): the sweep read
        # the stamp alone and the stamp was the rule alone, so a CHAT_EXPORT
        # in a case kept two more months was held 670 days past it. Read
        # here, so a record attached later, or a case whose date is brought
        # forward, is covered too.
        records = self._c.execute(
            """SELECT r.id, r.case_id, d.deadline, r.category,
                      coalesce(c.legal_hold, false),
                      d.deadline < r.retain_until
                 FROM ingest.record r
                 LEFT JOIN core."case" c ON c.id = r.case_id
                 CROSS JOIN LATERAL (
                   SELECT CASE WHEN c.retention_until IS NULL THEN r.retain_until
                               ELSE least(r.retain_until,
                                          c.retention_until::timestamp
                                            AT TIME ZONE 'UTC') END AS deadline) d
                WHERE r.purged_at IS NULL AND r.retain_until IS NOT NULL
                  AND d.deadline <= %s
                  AND (%s::uuid IS NULL OR r.case_id = %s)
                ORDER BY d.deadline LIMIT %s""",
            (now, case_id, case_id, limit)).fetchall()
        for row in records:
            items.append(DueItem(
                object_type="ingest_record", object_id=row[0], case_id=row[1],
                deadline=row[2],
                rule=("case.retention_until" if row[5]
                      else f"retention_rule[{row[3]}]"),
                held=bool(row[4]),
                hold_reason="case-level legal hold" if row[4] else None,
                category=row[3]))

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
        # F15.3 and F15.4 (2026-09-24): lookups, answers and batches
        # follow the CASE clock and the case's legal hold, as exhibits do.
        # A provider test (no case) is never selected.
        for object_type, table in (("lookup", "ingest.lookup"),
                                   ("lookup_result", "ingest.lookup_result"),
                                   ("lookup_batch", "ingest.lookup_batch")):
            rows = self._c.execute(
                f"""SELECT x.id, x.case_id, c.retention_until, c.legal_hold
                      FROM {table} x JOIN core."case" c ON c.id = x.case_id
                     WHERE x.purged_at IS NULL AND c.retention_until <= %s::date
                       AND (%s::uuid IS NULL OR x.case_id = %s)
                     ORDER BY c.retention_until LIMIT %s""",
                (now, case_id, case_id, limit)).fetchall()
            for row in rows:
                items.append(DueItem(
                    object_type=object_type, object_id=row[0], case_id=row[1],
                    deadline=datetime.combine(row[2], datetime.min.time(),
                                              tzinfo=timezone.utc),
                    rule="case.retention_until", held=bool(row[3]),
                    hold_reason="case-level legal hold" if row[3] else None))
        items.extend(self._due_samples(case_id, now, limit))
        return items

    def _due_samples(self, case_id: UUID | None, now: datetime,
                     limit: int) -> list[DueItem]:
        """Lab samples still in the working store whose case's retention has
        expired, held ones flagged. lab-4 (2026-10-03): docs/11 says a record
        case's sample leaves only through the retention purge, and nothing
        here selected one, so a purged case's live malware stayed
        downloadable for ever. A sample with no case has no case clock."""
        rows = self._c.execute(
            """SELECT s.id, s.case_id, c.retention_until, s.legal_hold,
                      c.legal_hold
                 FROM lab.sample s JOIN core."case" c ON c.id = s.case_id
                WHERE s.state <> 'REJECTED' AND c.retention_until <= %s::date
                  AND (%s::uuid IS NULL OR s.case_id = %s)
                ORDER BY c.retention_until LIMIT %s""",
            (now, case_id, case_id, limit)).fetchall()
        return [DueItem(
            object_type="sample", object_id=r[0], case_id=r[1],
            deadline=datetime.combine(r[2], datetime.min.time(),
                                      tzinfo=timezone.utc),
            rule="case.retention_until", held=bool(r[3] or r[4]),
            hold_reason=("sample-level legal hold" if r[3]
                         else "case-level legal hold" if r[4] else None))
            for r in rows]

    # -- purge -------------------------------------------------------------

    def purge_due(self, *, actor_id: UUID, authority: str,
                  case_id: UUID | None = None,
                  as_of: datetime | None = None,
                  dry_run: bool = False,
                  kinds: frozenset[str] | None = None) -> PurgeResult:
        """Destroy what is expired and not held, and write the tombstone.

        `authority` is mandatory and free text: the schedule, the policy
        reference, the instruction. A destruction whose authority nobody
        recorded cannot be defended later, and "the job ran" is not an
        authority.

        `kinds` (F30, 2026-10-02) narrows the sweep to the named
        `DueItem.object_type` values and nothing else; None, the default,
        is every family exactly as before. It exists for
        `retention_sweep.py`, which must reach collected documents (the one
        family no case-scoped route can) without also destroying every
        case's exhibits under a tombstone that names no case.
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
                    f"period this software shipped with ({rule.retain_days} "
                    f"days) and has never been confirmed by a human. Confirm "
                    f"it on the Records pane, under Retention.")

        # A purge that reports `documents_purged: 0` without saying why is
        # reporting a gap in the wiring as a fact about the data. Until the
        # collection foundation (2026-09-24) nothing wrote
        # `collect.document.retain_until` at all.
        # Since then the collector sets it at insert, and only for a
        # document whose adapter keeps a clock and whose category has a
        # retention rule; RSS items and documents of an unruled category
        # still have none, and a rule added later does not reach documents
        # collected before it (a backfill is a destruction decision,
        # docs/17). Deliberately NOT derived here: that would arm a
        # destruction path over every document already collected, on the
        # one code path whose mistakes are irreversible.
        unclocked = self._c.execute(
            "SELECT count(*) FROM collect.document "
            "WHERE purged_at IS NULL AND retain_until IS NULL").fetchone()[0]
        if unclocked:
            # Counts and pronouns agreed rather than a bracketed plural;
            # every warning in this module is printed to the operator
            # verbatim (README screenshot set review, 2026-09-23).
            one = unclocked == 1
            result.warnings.append(
                f"{count_of(unclocked, 'collected document', 'collected documents')} "
                f"{agree(unclocked, 'has', 'have')} no retention clock (RSS "
                f"items, and documents whose category has no retention "
                f"rule), so {'it is' if one else 'they are'} invisible to "
                f"this sweep and never {agree(unclocked, 'expires', 'expire')}. "
                f"`documents_purged` counts only documents that have a "
                f"clock.")

        items = self.due(case_id=case_id, as_of=as_of)
        if kinds is not None:
            items = [i for i in items if i.object_type in kinds]
        actionable = [i for i in items if not i.held]
        result.held_back = sum(1 for i in items
                               if i.held and i.object_type != "document")
        if case_id is None:
            # From its own count, not from the LIMITed list.
            result.held_back += self._held_document_count(
                as_of or datetime.now(timezone.utc))

        evidence_ids = [i.object_id for i in actionable
                        if i.object_type == "evidence"]
        document_ids = [i.object_id for i in actionable
                        if i.object_type == "document"]
        record_ids = [i.object_id for i in actionable
                      if i.object_type == "ingest_record"]
        dead_ids = [i.object_id for i in actionable
                    if i.object_type == "dead_letter"]
        # F15.3 and F15.4, and F7's Jira warning.
        lookup_ids = [i.object_id for i in actionable if i.object_type == "lookup"]
        result_ids = [i.object_id for i in actionable
                      if i.object_type == "lookup_result"]
        batch_ids = [i.object_id for i in actionable
                     if i.object_type == "lookup_batch"]
        # lab-4 (2026-10-03).
        sample_ids = [i.object_id for i in actionable
                      if i.object_type == "sample"]
        touched = ([case_id] if case_id else
                   [i.case_id for i in actionable if i.case_id is not None])

        if dry_run:
            # THE COUNTS ARE THE WHOLE POINT OF A DRY RUN. This used to
            # return here with every counter still at zero, having done the
            # full sweep and thrown the answer away -- so a preview of a
            # case with twelve exhibits about to be destroyed was
            # byte-identical to a preview of a case with nothing due, and
            # the pane rendered both as "Nothing would be destroyed."
            #
            # `held_back` was the only non-zero number a dry run could
            # produce, which made it worse than silent: the sole figure on
            # screen counted the items being SPARED.
            #
            # This is the control whose entire purpose is to be read before
            # an irreversible action, and `dry_run` defaults to TRUE
            # precisely because the router treats destruction-by-default as
            # the thing to design against.
            result.evidence_purged = len(evidence_ids)
            result.documents_purged = len(document_ids)
            result.records_purged = len(record_ids)
            result.dead_letters_purged = len(dead_ids)
            # The dry run counts lookups and says what Jira keeps.
            result.lookups_purged = len(lookup_ids)
            result.lookup_results_purged = len(result_ids)
            result.lookup_batches_purged = len(batch_ids)
            result.samples_purged = len(sample_ids)
            self._jira_note(result, touched, actor_id=actor_id, dry_run=True)
            return result
        if not actionable:
            return result
        # BEFORE the transaction, and before the evidence leg asks the
        # object store to delete anything (2026-09-25): the
        # document leg's refusal used to come after `_purge_evidence` had
        # already deleted exhibit bytes in the same transaction, and its
        # rollback would unmark rows whose bytes were gone. Every due
        # document is asked, held or not, so the refusal cannot depend on
        # a race it has not seen yet; the document leg keeps its own check
        # under its locks.
        if document_ids and self._document_raw is None:
            keyed = self._c.execute(
                """SELECT count(*) FROM collect.document
                    WHERE id = ANY(%s) AND body_html_key IS NOT NULL""",
                (document_ids,)).fetchone()[0]
            if keyed:
                raise RetentionError(_NO_DOCUMENT_RAW_STORE)

        with self._c.transaction():
            if case_id is not None and self._case_held_now(case_id):
                # The case's hold, read under a share lock on its row, so a
                # case hold placed since the sweep keeps everything the case
                # clock governs; a hold placed after this waits for the
                # purge to commit (evidence-purge-hold-race,
                # evidence-case-hold-unreachable, 2026-10-03).
                kept = (len(evidence_ids) + len(record_ids) + len(lookup_ids)
                        + len(result_ids) + len(batch_ids) + len(sample_ids))
                result.held_back += kept
                result.warnings.append(
                    f"the case came under a legal hold between the sweep and "
                    f"the purge, so nothing it holds was destroyed "
                    f"({count_of(kept, 'item', 'items')} kept).")
                evidence_ids, record_ids, sample_ids = [], [], []
                lookup_ids, result_ids, batch_ids = [], [], []
            if evidence_ids:
                storage = self._purge_evidence(evidence_ids)
                outcome = storage.outcome
                if storage.held:
                    # Reread under the rows' locks (evidence-purge-hold-race,
                    # 2026-10-03): a hold placed since the sweep keeps its
                    # exhibit, and is never acknowledged on one destroyed.
                    kept = len(storage.held)
                    result.held_back += kept
                    result.warnings.append(
                        f"{count_of(kept, 'exhibit', 'exhibits')} came under a "
                        f"legal hold between the sweep and the purge and "
                        f"{agree(kept, 'was', 'were')} kept.")
                    held_ids = set(storage.held)
                    evidence_ids = [i for i in evidence_ids if i not in held_ids]
                if storage.gone:
                    gone = set(storage.gone)
                    result.warnings.append(
                        f"{count_of(len(gone), 'exhibit was', 'exhibits were')} "
                        f"already destroyed by another purge and "
                        f"{agree(len(gone), 'was', 'were')} skipped.")
                    evidence_ids = [i for i in evidence_ids if i not in gone]
                result.evidence_purged = len(evidence_ids)
                # All three counts, always. Until 2026-09-02 `storage_failed`
                # was only copied when the batch verdict was FAILED, so a
                # batch with one lock and one transport failure reported the
                # lock and lost the failure -- the verdict is the WORST
                # outcome, not the only one.
                result.storage_deleted = storage.deleted
                result.storage_locked = storage.locked
                result.storage_failed = storage.failed
                result.warnings.extend(storage.warnings)
                if storage.locked:
                    # The REFUSAL count in EXHIBIT ROWS, not the batch size
                    # and not the number of object versions -- see
                    # `_StorageOutcome`. The per-key version detail is in
                    # the warnings copied above.
                    result.warnings.append(
                        f"{storage.locked} of {len(evidence_ids)} evidence "
                        f"rows are under a retention lock and could not be "
                        f"deleted. The retention schedule says destroy; the "
                        f"object store disagrees. Those rows are NOT marked "
                        f"purged and stay due, so the sweep after the lock "
                        f"expires finishes the job. Check the lock's expiry "
                        f"on the object store before telling anybody the "
                        f"bytes are gone.")
                if storage.failed:
                    # Distinct from LOCKED on purpose: a lock is a lawful
                    # refusal that will expire, a failure is a store that
                    # did not answer -- or had nothing under the key -- and
                    # somebody has to look before the next sweep retries it.
                    result.warnings.append(
                        f"{storage.failed} of {len(evidence_ids)} evidence "
                        f"objects could not be deleted, and NOT because of a "
                        f"retention lock. Those rows are NOT marked purged. "
                        f"The bytes may still be there; do not report this "
                        f"as a completed destruction.")
                if outcome == STORAGE_NA:
                    # NO OBJECT STORE WAS CONTACTED AT ALL, and the caller
                    # has to be told. `RetentionService(conn)` takes
                    # `storage=None` and the HTTP routers construct it that
                    # way, so every purge through the API marks the rows
                    # purged and never reaches the bytes. The tombstone
                    # records NOT_APPLICABLE, which is honest, but the
                    # RESPONSE said `evidence_purged: N`, `storage_locked:
                    # 0` and nothing else -- which reads as "destroyed, no
                    # problems" to anyone who is not reading tombstones.
                    #
                    # This is the same class of lie the LOCKED branch below
                    # already guards against, and the more dangerous one:
                    # LOCKED at least says the store disagreed. This said
                    # nothing.
                    result.warnings.append(
                        "evidence rows are marked purged but NO OBJECT "
                        "STORE WAS CONFIGURED for this purge, so the bytes "
                        "were never touched. The record says destroyed; "
                        "nothing asked the object store. Do not report this "
                        "as a destruction.")

                if evidence_ids:
                    result.tombstones.append(self._tombstone(
                        case_id=case_id, object_type="evidence",
                        ids=evidence_ids, authority=authority,
                        actor_id=actor_id, rule="case.retention_until",
                        storage_outcome=outcome))

            if document_ids:
                # The row survives; the CONTENT does not. Keeping the row
                # is what lets a later question about coverage be answered
                # ("we held 40 documents from that source and destroyed
                # them on this date") without holding the documents.
                # `body_text` is NOT NULL (0011), so it is emptied rather
                # than nulled, and `purged_at` is what marks it destroyed.
                # Since 2026-09-24 the holds are rechecked under locks,
                # the raw markup and the identities of uninvolved people go
                # with the content, and the tombstone says what happened to
                # the markup (`_purge_documents`).
                self._purge_documents(document_ids, authority=authority,
                                      actor_id=actor_id, result=result)
                # No `embedding = NULL` (F6.1, 2026-09-24): migration 0094
                # drops that column. The vectors live in
                # collect.document_embedding, whose trigger deletes them in
                # the purge's own transaction when purged_at changes.

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
            # Lookups, answers and batches are emptied, never deleted.
            self._purge_lookups(result, lookup_ids, result_ids, batch_ids,
                                case_id=case_id, authority=authority,
                                actor_id=actor_id)
        if sample_ids:
            # After the transaction, each sample in its own: the disposition
            # is a network copy and delete, and must not run while this
            # purge's audit rows hold the chain's global lock (lab-4,
            # 2026-10-03).
            self._purge_samples(sample_ids, authority=authority,
                                actor_id=actor_id, case_id=case_id,
                                result=result)
        self._jira_note(result, touched, actor_id=actor_id, dry_run=False)
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
        if len(evidence_ids) > MAX_OUT_OF_SCHEDULE:
            raise RetentionError(
                f"an out-of-schedule purge names at most {MAX_OUT_OF_SCHEDULE} "
                f"exhibits, because their rows stay locked while each is "
                f"destroyed. Split the destruction into several approvals.")
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
                f"hold overrides all deletion, everywhere. Lift the hold "
                f"first: that takes a written reason from somebody cleared "
                f"for the exhibit, and it is audited.")

        payload = {"case_id": str(case_id),
                   "evidence_ids": sorted(str(e) for e in evidence_ids),
                   "authority": authority.strip()}
        result = PurgeResult()
        try:
            with self._c.transaction():
                # The order is the fix for two findings (2026-10-03).
                # evidence-purge-hold-race: the rows and their case are
                # locked and the holds reread before any byte is destroyed,
                # and a hold that arrived since the check above refuses the
                # whole purge. evidence-purge-stalls-audit-chain: the
                # approval used to be spent FIRST, and spending it writes an
                # audit row, which holds the chain's global lock to COMMIT,
                # so every audited write in the deployment waited out the
                # store deletes. Now the approval is checked and locked
                # without an audit row, the bytes go, and the spend and the
                # tombstone, the only audited writes, come last. The spend
                # still commits with the destruction, and cannot fail once
                # its row is locked.
                self._lock_approval(approval_request_id, actor_id=actor_id,
                                    case_id=case_id, payload=payload)
                storage = self._purge_evidence(evidence_ids, refuse_held=True)
                ApprovalService(self._c).consume(
                    approval_request_id, actor_id=actor_id,
                    operation="evidence.purge", case_id=case_id,
                    payload=payload)
                if storage.gone:
                    gone = set(storage.gone)
                    result.warnings.append(
                        f"{count_of(len(gone), 'exhibit was', 'exhibits were')} "
                        f"already destroyed by another purge and "
                        f"{agree(len(gone), 'was', 'were')} skipped.")
                    evidence_ids = [i for i in evidence_ids if i not in gone]
                result.evidence_purged = len(evidence_ids)
                # Refusal counts, not the batch size -- and on the one path
                # that writes an out-of-schedule tombstone, which is the
                # most consequential record this module produces.
                result.storage_locked = storage.locked
                result.storage_failed = storage.failed
                result.storage_deleted = storage.deleted
                result.warnings.extend(storage.warnings)
                if storage.locked or storage.failed:
                    # THIS PATH HAS NO NEXT SWEEP. `_purge_evidence` leaves
                    # a refused row unmarked and `purge_due` tells the
                    # operator it "stays due, so the sweep after the lock
                    # expires finishes the job". That is true of the
                    # scheduled path and FALSE here: `due()` gates evidence
                    # on `case.retention_until <= now`, and an
                    # out-of-schedule purge is by definition of exhibits
                    # whose retention has NOT expired.
                    #
                    # Until 2026-09-02 this path copied `purge_due`'s counts
                    # and its per-key warnings but not its "the rows are NOT
                    # marked purged" warning, so a court-ordered early
                    # destruction refused by a COMPLIANCE lock returned
                    # `evidence_purged: 1, storage_locked: N, warnings: []`,
                    # left every byte in the bucket, left the row visible
                    # and off every sweep, and consumed the four-eyes
                    # approval -- changing nothing while reporting a purge.
                    # Before the row-marking change it was at least marked;
                    # the change altered what this response means and said
                    # nothing on this path.
                    kept = storage.locked + storage.failed
                    one = kept == 1
                    result.warnings.append(
                        f"{kept} of "
                        f"{count_of(len(evidence_ids), 'exhibit', 'exhibits')} "
                        f"still {'has its' if one else 'have their'} "
                        f"bytes in the object store, so "
                        f"{'that row is' if one else 'those rows are'} NOT "
                        f"marked purged. Unlike the scheduled sweep, nothing "
                        f"will retry {'it' if one else 'them'}: `due()` "
                        f"returns only evidence whose case retention has "
                        f"expired, and this purge is out of schedule, so "
                        f"{'that exhibit is' if one else 'those exhibits are'} "
                        f"not due and will not come back due when the lock "
                        f"lifts. "
                        f"The four-eyes approval has been CONSUMED and "
                        f"cannot be reused: a second attempt needs a new "
                        f"one. A tombstone recording the refusal was "
                        f"written. Do not report this as a completed "
                        f"destruction.")
                if evidence_ids:
                    result.tombstones.append(self._tombstone(
                        case_id=case_id, object_type="evidence",
                        ids=evidence_ids, authority=authority,
                        actor_id=actor_id, rule="out-of-schedule",
                        approval_request_id=approval_request_id,
                        storage_outcome=storage.outcome))
        except ApprovalError as exc:
            raise RetentionError(str(exc)) from exc
        # F7: the early destruction most likely
        # to follow a court order says what Jira keeps too.
        self._jira_note(result, [case_id], actor_id=actor_id, dry_run=False)
        return result

    # -- internals ---------------------------------------------------------

    def _jira_note(self, result: PurgeResult, case_ids, *, actor_id: UUID,
                   dry_run: bool) -> None:
        """F7 (2026-09-24): Jira issues outlive NocTORnal's retention.
        When the cases a purge touched have issues there, the purge says so
        (dry runs included) and a real purge records it."""
        from noctornal_api import jira
        note = jira.purge_note(self._c, case_ids, actor_id=actor_id, dry_run=dry_run)
        if note:
            result.warnings.append(note)

    def _case_held_now(self, case_id: UUID) -> bool:
        """The case's legal hold, read under a share lock on its row: a hold
        written before this waited for nobody and is seen, one written after
        waits for the caller's transaction to commit (evidence-purge-hold-race,
        2026-10-03). Only inside a transaction."""
        row = self._c.execute(
            'SELECT legal_hold FROM core."case" WHERE id = %s FOR SHARE',
            (case_id,)).fetchone()
        return bool(row and row[0])

    def _lock_approval(self, request_id: UUID, *, actor_id: UUID,
                       case_id: UUID, payload: dict) -> None:
        """The out-of-schedule approval, verified and locked FOR UPDATE
        without spending it, so nothing is destroyed on an approval that
        would then fail to spend, and no audit row (and so no chain lock) is
        written before the store deletes (evidence-purge-stalls-audit-chain,
        2026-10-03). A request that does not qualify is handed to `consume`,
        which refuses with its one sentence and records why on a connection
        of its own: this transaction has audited nothing yet."""
        from noctornal_api.approvals import ApprovalService, payload_hash

        row = self._c.execute(
            """SELECT 1 FROM core.approval_request
                WHERE id = %s AND state = 'APPROVED' AND expires_at > now()
                  AND requested_by = %s AND operation = 'evidence.purge'
                  AND case_id IS NOT DISTINCT FROM %s AND payload_hash = %s
                FOR UPDATE""",
            (request_id, actor_id, case_id,
             payload_hash("evidence.purge", case_id, payload))).fetchone()
        if row is None:
            ApprovalService(self._c).consume(
                request_id, actor_id=actor_id, operation="evidence.purge",
                case_id=case_id, payload=payload)
            raise RetentionError("this approval cannot be used for this "
                                 "operation")

    def _purge_samples(self, sample_ids: list[UUID], *, authority: str,
                       actor_id: UUID, case_id: UUID | None,
                       result: PurgeResult) -> None:
        """lab-4 (2026-10-03): an expired case's samples leave the working
        store the way this deployment disposes of a rejected sample
        (`NOCTORNAL_REJECTED_SAMPLE_DISPOSITION`: preserved under a legal
        hold by default, or destroyed), through `SampleService.reject`, the
        one path that disposes of a sample, which rereads every hold under
        the sample's row lock. Its refusal for a read-only case does not
        apply here: docs/11 names this purge as the way a closed case's
        material leaves. A sample that cannot be disposed of stays due and
        is named in a warning; one tombstone per disposition records the
        rest."""
        from noctornal_api.samples import (
            DESTROY,
            SampleError,
            SampleService,
            rejected_sample_disposition,
        )

        class _ForRetention(SampleService):
            def _refuse_if_case_read_only(self, sample_id):  # noqa: ARG002
                return None

        try:
            disposition = rejected_sample_disposition()
            if self._sample_stores is None:
                raise SampleError("no sample store is configured for this purge")
            storage, preservation = self._sample_stores()
        except Exception as exc:  # noqa: BLE001 - reported, and the samples stay due
            result.warnings.append(
                f"{count_of(len(sample_ids), 'sample', 'samples')} of this "
                f"case {agree(len(sample_ids), 'is', 'are')} due and "
                f"{agree(len(sample_ids), 'was', 'were')} not disposed of: "
                f"{exc} {agree(len(sample_ids), 'It stays', 'They stay')} in "
                f"the Lab and due, so the next purge tries again.")
            return
        service = _ForRetention(self._c, storage, preservation)
        reason = f"Retention purge under: {authority.strip()}"
        done: list[UUID] = []
        for sample_id in sample_ids:
            try:
                service.reject(sample_id, actor_id=actor_id, reason=reason,
                               purge_bytes=True)
            except SampleError as exc:
                result.warnings.append(
                    f"sample {sample_id} was not disposed of and stays due: "
                    f"{exc}")
                continue
            done.append(sample_id)
        result.samples_purged = len(done)
        if not done:
            return
        destroyed = disposition == DESTROY
        if not destroyed:
            result.warnings.append(
                f"{count_of(len(done), 'sample was', 'samples were')} moved "
                f"into the preservation store under a legal hold, as this "
                f"deployment disposes of rejected samples: out of the Lab "
                f"and no longer downloadable, but not destroyed.")
        result.tombstones.append(self._tombstone(
            case_id=case_id, object_type="sample", ids=done,
            authority=authority, actor_id=actor_id,
            rule="case.retention_until",
            storage_outcome=STORAGE_DELETED if destroyed else STORAGE_NA))

    def _purge_lookups(self, result: PurgeResult, lookup_ids, result_ids, batch_ids,
                       *, case_id, authority: str, actor_id: UUID) -> None:
        """F15.3 and F15.4 (2026-09-24). A lookup still waiting or queued
        is first cancelled, so an emptied row can never be sent; a SENDING
        row is left until it settles. Values, notes and bodies go; every
        row, fingerprint and attempt stays, with one tombstone per type."""
        if lookup_ids:
            self._c.execute(
                """UPDATE ingest.lookup SET state = 'CANCELLED', refusal = 'purged'
                    WHERE id = ANY(%s) AND state IN ('AWAITING_SIGNOFF', 'QUEUED')""",
                (lookup_ids,))
            done = self._c.execute(
                """UPDATE ingest.lookup
                      SET query_value = '',
                          authorisation_note = CASE WHEN authorisation_note IS NULL
                                                    THEN NULL ELSE '' END,
                          signoff_note = CASE WHEN signoff_note IS NULL THEN NULL
                                              ELSE '' END,
                          error_detail = NULL,
                          refusal = CASE WHEN refusal IS NULL THEN NULL
                                         ELSE 'purged' END,
                          purged_at = now()
                    WHERE id = ANY(%s) AND state <> 'SENDING' RETURNING id""",
                (lookup_ids,)).fetchall()
            ids = [r[0] for r in done]
            result.lookups_purged = len(ids)
            if ids:
                result.tombstones.append(self._tombstone(
                    case_id=case_id, object_type="lookup", ids=ids,
                    authority=authority, actor_id=actor_id,
                    rule="case.retention_until", storage_outcome=STORAGE_NA))
        if result_ids:
            self._c.execute(
                """UPDATE ingest.lookup_result
                      SET raw_body = ''::bytea, summary = '{}'::jsonb,
                          interpret_error = NULL, purged_at = now()
                    WHERE id = ANY(%s)""", (result_ids,))
            result.lookup_results_purged = len(result_ids)
            result.tombstones.append(self._tombstone(
                case_id=case_id, object_type="lookup_result", ids=result_ids,
                authority=authority, actor_id=actor_id,
                rule="case.retention_until", storage_outcome=STORAGE_NA))
        if batch_ids:
            self._c.execute(
                """UPDATE ingest.lookup_batch
                      SET note = '', cancel_reason = CASE WHEN cancel_reason IS NULL
                                                         THEN NULL ELSE '' END,
                          purged_at = now()
                    WHERE id = ANY(%s)""", (batch_ids,))
            result.lookup_batches_purged = len(batch_ids)
            result.tombstones.append(self._tombstone(
                case_id=case_id, object_type="lookup_batch", ids=batch_ids,
                authority=authority, actor_id=actor_id,
                rule="case.retention_until", storage_outcome=STORAGE_NA))

    def _purge_evidence(self, ids: list[UUID], *,
                        refuse_held: bool = False) -> "_StorageOutcome":
        """Ask the object store, then mark ONLY the rows whose bytes went.

        ## The holds are reread under locks (evidence-purge-hold-race, 2026-10-03)

        The holds were read once, by `due()` or the out-of-schedule check,
        before this ran; then every object was deleted and the rows marked,
        and a hold placed in between was acknowledged to the officer and
        destroyed anyway. Now each exhibit is locked FOR UPDATE, with its
        case FOR SHARE, and its holds are reread under those locks BEFORE its
        delete (`_claim_for_destruction`): a hold already written keeps its
        exhibit (returned in `held`, or the whole call refused when
        `refuse_held`), and a hold written later waits for this transaction
        and then finds the exhibit destroyed (`set_legal_hold` refuses a
        purged row; 0142 refuses it in the database too). The document leg
        has done the same since decision 74.

        Until 2026-09-02 this marked every row `purged_at` up front and
        then asked the store, on the theory that the store's answer
        belonged on the tombstone and the row was the database's business.
        Two things were wrong with that at once:

        1. The store was asked through `EvidenceStorage.delete()`, a
           keyless delete. The evidence bucket is versioned (forced by
           `--with-lock`), so a keyless delete inserts a delete marker and
           returns success with every version still retrievable by version
           id. The tombstone said DELETED; the bytes were all there.
           `delete_all_versions()` -- which enumerates the versions and
           reports a refusal as a refusal -- existed, was verified live,
           and had a test asserting that nothing called it. It is what
           this calls now, whenever the store offers it.

        2. A row marked purged on a REFUSAL vanished from every read path
           and from `due()`, so nothing ever retried it: the lock expired
           and the bytes sat in the bucket forever under a tombstone saying
           LOCKED_UNTIL_RETENTION. Now only a row whose object the store
           confirmed removed is marked.

           WHEN THE CALLER IS `purge_due`, a refused or failed row stays
           due, and the sweep after the lock expires finishes the job and
           writes its own DELETED record. That is not true of
           `purge_out_of_schedule`, the other caller: `due()` gates
           evidence on `case.retention_until <= now`, and an
           out-of-schedule purge exists precisely for exhibits whose
           retention has NOT expired, so a row it leaves unmarked is on no
           sweep at all and nothing will retry it. That path says so in a
           warning of its own -- added 2026-09-02, because for one commit
           it inherited this justification without the fact that makes it
           true.

        The COUNTS are per EXHIBIT ROW, and are mapped, never
        `VersionedDeleteResult.outcome`: that property says DESTROYED /
        NOTHING_TO_DELETE, and the tombstone CHECK (migration 0032) takes
        only the `STORAGE_*` words in this module. A key with any locked
        version -> locked (the exhibit is still readable, so nothing was
        destroyed for it however many other versions went); a key with
        nothing locked and nothing removed -> failed, because "the row says
        an exhibit was written and the store has nothing" is a disagreement
        to investigate, not a destruction to record; a key the store
        emptied -> deleted, and only those rows are marked. Anything
        `delete_all_versions` raises is a failure it did not recognise as a
        lock, and is counted as one. Every row lands in exactly one
        counter, so the three add up to the batch -- the arithmetic
        `PurgeResult.evidence_purged` and the governance router both state
        in prose, and which summing object VERSIONS into `deleted` and
        `locked` broke for one commit on 2026-09-02. The version counts
        are kept, in the warning that names the key they belong to.

        A store without `delete_all_versions` (the test stubs; nothing in
        production) is asked through `delete()`, and its exception, if any,
        is classified by `_is_retention_refusal`.
        """
        if self._storage is None and ids:
            # REFUSE. NOT_APPLICABLE is a lie for evidence.
            # (`and ids`: with nothing to destroy there is nothing to
            # lie about, and the caller already guards on a non-empty
            # list — but a refusal for a no-op would be its own small
            # confusion.)
            #
            # `core.evidence.storage_key` is NOT NULL and `EvidenceService
            # .ingest` commits a row only with its bytes stored, so every
            # exhibit HAS an object and the question always applies. This
            # branch used to `return STORAGE_NA`, and because both
            # governance routers construct `RetentionService(conn)` with no
            # storage, that was 100% of production purges: rows marked
            # `purged_at`, exhibit gone from every read path, bytes intact
            # in MinIO, and the tombstone — the record designed to outlive
            # the data — asserting the object store was not applicable.
            #
            # NOT_APPLICABLE remains correct for documents, ingest records
            # and dead letters further down, whose content is nulled in the
            # database and never had an object. That is why the wrong value
            # did not look wrong.
            #
            # Refusing rather than degrading follows `ingest.py:_with_raw`,
            # which 503s when the raw store is missing instead of accepting
            # bytes it will drop. `rawstore.py`'s docstring records that
            # exact bug being found and fixed once on the ingest side; this
            # is the same shape on the destructive side, where the cost is
            # a false record of destruction rather than lost intake.
            raise RetentionError(
                "no evidence object store is configured, so the exhibit "
                "bytes cannot be destroyed. Refusing rather than marking "
                "the rows purged and writing a tombstone that says the "
                "material is gone while it is still in the bucket.")
        # Locked, then reread, before EACH exhibit is destroyed (see the
        # docstring): `rows` claims them one at a time, so the check and
        # the delete it permits sit under one lock.
        held_ids: list[UUID] = []
        gone_ids: list[UUID] = []
        rows = self._claim_for_destruction(ids, refuse_held=refuse_held,
                                           held=held_ids, gone=gone_ids)
        # COUNTED, not collapsed. This loop used to set a single verdict for
        # the whole batch and the caller then recorded
        # `storage_locked = len(evidence_ids)` -- the BATCH SIZE. One refusal
        # in a hundred wrote "100 objects locked" into an append-only
        # tombstone, and a hundred refusals wrote the same number, so the
        # figure could not distinguish them and could not be corrected
        # afterwards.
        #
        # The bare `except Exception` also mapped every failure class to
        # LOCKED_UNTIL_RETENTION, which is a specific and defensible claim
        # about a retention lock. A connection reset is not that claim, and
        # STORAGE_FAILED existed for it and was dead code.
        deleted = locked = failed = 0
        destroyed_ids: list[UUID] = []
        warnings: list[str] = []
        for evidence_id, key in rows:
            if hasattr(self._storage, "delete_all_versions"):
                try:
                    r = self._storage.delete_all_versions(key)
                except Exception as exc:  # noqa: BLE001 - counted, not hidden
                    # Not a lock (the method returns those as a count) and
                    # not a deletion: an unrecognised refusal or a store
                    # that did not answer. The key is named because on the
                    # scheduled path the next sweep will retry it and
                    # somebody should know why -- and on the out-of-schedule
                    # path nothing will, which is worse and is why that
                    # caller adds a warning of its own.
                    failed += 1
                    warnings.append(
                        f"object store refused storage_key {key!r} for a "
                        f"reason that is not a retention lock "
                        f"({type(exc).__name__}: {exc}); the row is not "
                        f"marked purged")
                    continue
                if r.versions_locked:
                    # Bytes remain, so this ROW is a refusal whatever else
                    # went: locked wins over removed. Between two commits
                    # on 2026-09-02 `deleted += r.versions_removed` ran
                    # BEFORE this check, so an exhibit with one version
                    # removed and one refused reported
                    # `storage_deleted: 1` beside `evidence_purged: 1`
                    # while its row stayed unpurged and every byte stayed
                    # readable -- "one object deleted" for an exhibit that
                    # is entirely intact.
                    #
                    # The VERSION counts are not lost, they are put where
                    # they are honest: in a warning naming the key, rather
                    # than in a counter the router publishes next to a row
                    # count.
                    locked += 1
                    warnings.append(
                        f"{r.versions_locked} of "
                        f"{count_of(r.versions_seen, 'version', 'versions')} "
                        f"of storage_key {key!r} "
                        f"{agree(r.versions_locked, 'is', 'are')} under a "
                        f"retention lock "
                        f"({r.versions_removed} removed); the exhibit's bytes "
                        f"remain, so nothing was destroyed for it and the row "
                        f"is not marked purged")
                    continue
                if r.versions_removed == 0:
                    failed += 1
                    warnings.append(
                        f"no object found for storage_key {key!r}: the store "
                        f"holds no bytes under it "
                        f"({count_of(r.versions_seen, 'version', 'versions')} "
                        f"listed, "
                        f"{agree(r.versions_seen, 'not', 'none of them')} an "
                        f"object), so "
                        f"nothing was destroyed and the row is not marked "
                        f"purged. The database says an exhibit was written; "
                        f"the object store has nothing.")
                    continue
                # One row, one count. `deleted` is len(destroyed_ids) by
                # construction, which is what makes it the number of rows
                # this method marked `purged_at`.
                deleted += 1
                destroyed_ids.append(evidence_id)
                continue
            try:
                self._storage.delete(key)
            except Exception as exc:  # noqa: BLE001 - a refusal IS the answer
                if _is_retention_refusal(exc):
                    locked += 1
                else:
                    failed += 1
                continue
            deleted += 1
            destroyed_ids.append(evidence_id)
        if destroyed_ids:
            # ONLY these. A row marked purged while its bytes are in the
            # bucket is the false record this method exists to end. A row
            # left unmarked is simply due again on the next SCHEDULED
            # sweep; `purge_out_of_schedule` has no such sweep behind it
            # and warns instead, because `due()` will never return an
            # exhibit whose case retention has not expired.
            self._c.execute(
                "UPDATE core.evidence SET purged_at = now() WHERE id = ANY(%s)",
                (destroyed_ids,))
        if locked:
            outcome = STORAGE_LOCKED
        elif failed:
            outcome = STORAGE_FAILED
        else:
            outcome = STORAGE_DELETED
        return _StorageOutcome(outcome=outcome, deleted=deleted,
                               locked=locked, failed=failed,
                               warnings=tuple(warnings), held=tuple(held_ids),
                               gone=tuple(gone_ids))

    def _claim_for_destruction(self, ids: list[UUID], *, refuse_held: bool,
                               held: list, gone: list):
        """Yield `(id, storage_key)` for each exhibit that may be destroyed
        now, having locked it and its case and read its holds under those
        locks (evidence-purge-hold-race, 2026-10-03). The caller destroys
        what it is handed before asking for the next, so every delete is
        preceded by a read of the holds that nobody can change until the
        transaction ends: a hold already written is seen and keeps its
        exhibit, one written after waits for the transaction and then finds
        the exhibit destroyed (`set_legal_hold` refuses a purged row, and
        0142 refuses it in the database).

        Scheduled sweep (`refuse_held` False): one exhibit at a time, in id
        order. A court order entered while the sweep is part way through
        lands at once on every exhibit the sweep has not reached, and is
        honoured there; it waits only on the exhibits already locked.

        Out-of-schedule purge (`refuse_held` True): every row and case
        locked first, in the same order, and the whole batch refused if any
        of it came under a hold since the check that preceded the approval,
        so nothing is destroyed and the approval is not spent. Case rows
        before exhibit rows, each in id order, so two transactions never
        take them in opposite orders. `core.evidence.case_id` is fixed once
        lodged (0140), so reading it unlocked to find the cases is safe."""
        wanted = sorted(set(ids))
        batches = [wanted] if refuse_held else [[i] for i in wanted]
        for batch in batches:
            self._c.execute(
                """SELECT c.id FROM core."case" c
                    WHERE c.id IN (SELECT e.case_id FROM core.evidence e
                                    WHERE e.id = ANY(%s))
                    ORDER BY c.id FOR SHARE""", (batch,))
            self._c.execute(
                "SELECT id FROM core.evidence WHERE id = ANY(%s) "
                "ORDER BY id FOR UPDATE", (batch,))
            current = self._c.execute(
                """SELECT e.id, e.storage_key, e.purged_at IS NOT NULL,
                          e.legal_hold OR c.legal_hold
                     FROM core.evidence e JOIN core."case" c ON c.id = e.case_id
                    WHERE e.id = ANY(%s) ORDER BY e.id""", (batch,)).fetchall()
            gone.extend(r[0] for r in current if r[2])
            held.extend(r[0] for r in current if r[3] and not r[2])
            if held and refuse_held:
                raise RetentionError(
                    f"{len(held)} of the selected exhibits came under a legal "
                    f"hold since this purge was checked. A hold "
                    f"overrides all deletion: nothing was destroyed and the "
                    f"approval was not spent.")
            for r in current:
                if not r[2] and not r[3]:
                    yield r[0], r[1]

    # -- collected documents (2026-09-24; docs/00 decision 74) --------------

    def _held_document_count(self, now: datetime) -> int:
        """Due documents that a hold keeps, counted on their own rather than
        from the LIMITed due list, so a backlog of held documents is
        reported in full and cannot hide in the limit."""
        return self._c.execute(
            f"""SELECT count(*) FROM collect.document d
                 WHERE d.purged_at IS NULL AND d.retain_until IS NOT NULL
                   AND d.retain_until <= %s
                   AND ({_DOCUMENT_HELD_SQL}) IS NOT NULL""",
            (now,)).fetchone()[0]

    def document_backlog(self, as_of: datetime | None = None
                         ) -> tuple[int, int, datetime | None]:
        """(collected documents past their clock, how many of those no hold
        keeps, the oldest deadline among those), counts and a date only
        (F30, 2026-10-02).

        The hold is `_DOCUMENT_HELD_SQL`, the one predicate `due()` and the
        purge's recheck read, so what the sweep's dry run and the readiness
        row report is what the sweep would act on: a second statement of the
        rule could drift from it, and a count that disagrees with the act is
        the failure this module is written against. Uncapped on purpose (a
        LIMITed list would hide a backlog in its limit); the predicate is
        evaluated only for rows already past their clock, so a deployment
        with nothing due pays for one index range scan."""
        now = as_of or datetime.now(timezone.utc)
        row = self._c.execute(
            f"""SELECT count(*), count(*) FILTER (WHERE held.reason IS NULL),
                       min(d.retain_until) FILTER (WHERE held.reason IS NULL)
                  FROM collect.document d
                  CROSS JOIN LATERAL (SELECT {_DOCUMENT_HELD_SQL} AS reason) held
                 WHERE d.purged_at IS NULL AND d.retain_until IS NOT NULL
                   AND d.retain_until <= %s""", (now,)).fetchone()
        return int(row[0]), int(row[1]), row[2]

    def _purge_documents(self, ids: list[UUID], *, authority: str,
                         actor_id: UUID, result: "PurgeResult") -> None:
        """The document leg, inside purge_due's transaction.

        (a) EVERY version of every candidate is locked FOR UPDATE, the mode
        that conflicts with the key-share lock a new citation's foreign key
        takes on the version it cites (FOR NO KEY UPDATE does not), then the
        cases citing any of them FOR SHARE, so a hold placed on a document
        or on a citing case, or a new citation of any version, waits for
        this transaction and a purge cannot race a hold; (b) the hold is
        rechecked under those locks and anything now held is kept; (c) raw
        markup is deleted with its document unless another unpurged
        document still names the object, a failed delete keeps the document
        (it stays due) and names the key, and raw markup due with no store
        configured is refused rather than recorded as destroyed; (d) the row
        survives with its content, digest, title, address and author
        identities emptied; (e) every registered side table is scrubbed;
        (f) identity watch matches are scrubbed; (g) the tombstone names
        only what was purged and what happened to its markup."""
        versions = self._c.execute(
            """SELECT v.id FROM collect.document v
                WHERE EXISTS (
                        SELECT 1 FROM collect.document d
                         WHERE d.id = ANY(%s)
                           AND ((d.external_id IS NULL AND v.id = d.id)
                                OR (d.external_id IS NOT NULL
                                    AND v.source_id = d.source_id
                                    AND v.external_id = d.external_id)))
                ORDER BY v.id FOR UPDATE""", (ids,)).fetchall()
        version_ids = [r[0] for r in versions]
        self._c.execute(
            f"""SELECT k.id FROM core."case" k
                 WHERE k.id IN (SELECT c.case_id FROM ({_citations_sql()}) c
                                 WHERE c.document_id = ANY(%s))
                 ORDER BY k.id FOR SHARE""", (version_ids,))
        unheld = [r[0] for r in self._c.execute(
            f"""SELECT d.id FROM collect.document d
                 WHERE d.id = ANY(%s) AND d.purged_at IS NULL
                   AND ({_DOCUMENT_HELD_SQL}) IS NULL""", (ids,)).fetchall()]
        kept = len(ids) - len(unheld)
        if kept:
            result.held_back += kept
            result.warnings.append(
                f"{count_of(kept, 'collected document', 'collected documents')} "
                f"came under a legal hold between the sweep and the purge and "
                f"{agree(kept, 'was', 'were')} kept.")
        keys = self._c.execute(
            """SELECT d.id, d.body_html_key FROM collect.document d
                WHERE d.id = ANY(%s) AND d.body_html_key IS NOT NULL""",
            (unheld,)).fetchall()
        failed_ids: set[UUID] = set()
        deleted = failed = shared = 0
        if keys and self._document_raw is None:
            raise RetentionError(_NO_DOCUMENT_RAW_STORE)
        for document_id, key in keys:
            still = self._c.execute(
                """SELECT 1 FROM collect.document d
                    WHERE d.body_html_key = %s AND d.purged_at IS NULL
                      AND NOT (d.id = ANY(%s)) LIMIT 1""",
                (key, unheld)).fetchone()
            if still is not None:
                shared += 1
                continue
            try:
                self._document_raw.delete(key)
                deleted += 1
            except Exception as exc:  # noqa: BLE001 - counted, and the row kept
                failed += 1
                failed_ids.add(document_id)
                result.warnings.append(
                    f"the object store refused to delete collected markup "
                    f"{key!r} ({type(exc).__name__}); its document is not "
                    f"marked purged and stays due, so the next sweep retries.")
        if shared:
            result.warnings.append(
                f"{count_of(shared, 'markup object is', 'markup objects are')} "
                f"still used by other documents and "
                f"{agree(shared, 'was', 'were')} kept.")
        targets = [i for i in unheld if i not in failed_ids]
        if not targets:
            return
        purged = [r[0] for r in self._c.execute(
            """UPDATE collect.document
                  SET purged_at = now(),
                      content_sha256 = sha256(convert_to('purged:' || id::text, 'UTF8')),
                      body_text = '', title = NULL, external_url = NULL,
                      author_handle = NULL, author_uid = NULL,
                      body_html_key = NULL, search_tsv = NULL
                WHERE id = ANY(%s) AND purged_at IS NULL
            RETURNING id""", (targets,)).fetchall()]
        if not purged:
            return
        for statement in DOCUMENT_PURGE_SCRUBS.values():
            if statement.lstrip().upper().startswith("HOLDS NO PERSONAL DATA"):
                continue
            self._c.execute(statement, {"ids": purged})
        self._c.execute(
            """UPDATE collect.watch_hit h
                  SET matched_on = (
                        SELECT coalesce(jsonb_agg(
                                 CASE WHEN e.v ~ '^(keyword|selector|regex|signature_keyword|signature_selector|signature_regex|chat):'
                                      THEN to_jsonb(e.v)
                                      ELSE to_jsonb(split_part(e.v, ':', 1)
                                                    || ':[purged]') END
                                 ORDER BY e.o), '[]'::jsonb)
                          FROM jsonb_array_elements_text(h.matched_on)
                               WITH ORDINALITY AS e(v, o))
                WHERE h.document_id = ANY(%s)
                  AND jsonb_typeof(h.matched_on) = 'array'""", (purged,))
        result.documents_purged += len(purged)
        outcome = (STORAGE_FAILED if failed else STORAGE_DELETED if deleted
                   else STORAGE_NA)
        result.tombstones.append(self._tombstone(
            case_id=None, object_type="document", ids=purged,
            authority=authority, actor_id=actor_id, rule="retention_rule",
            storage_outcome=outcome))

    def set_document_legal_hold(self, document_id: UUID, *, actor_id: UUID,
                                on: bool, reason: str | None, clearance: str,
                                compartments: frozenset[str] = frozenset()
                                ) -> dict:
        """A hold a person places on a collected document, and every earlier
        version of it. The named document must be unpurged and within
        the caller's labels, on its own label, its source's and its
        compartments, or it is RetentionNotFound (a 404 indistinguishable
        from a missing id): a document the caller may not see is not merely
        hidden but unholdable. When any version is above the caller, nothing
        is written (409): labels gate writes too. Placing OR lifting needs a
        reason, and the audit keeps the prior reason and placer.

        Every version is locked FOR UPDATE, in the purge's order, BEFORE
        the named document is read and before anything is written
        (2026-09-25). A hold that waited on a purge's version locks
        used to go on to write, and report, a hold on the row the purge had
        just destroyed: the answer said held and the audit said applied on
        content that no longer existed. Read after the wait, a destroyed
        document is the same 404 as a missing one, and only unpurged
        versions are written or counted."""
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise RetentionError(
                "a legal hold has to say what it rests on: a hold nobody can "
                "attribute is a hold nobody can lift")
        held = sorted(compartments)
        with self._c.transaction():
            return self._document_hold_locked(
                document_id, actor_id=actor_id, on=on, reason=reason,
                clearance=clearance, held=held)

    def _document_hold_locked(self, document_id: UUID, *, actor_id: UUID,
                              on: bool, reason: str, clearance: str,
                              held: list[str]) -> dict:
        # The versions this caller could write, locked: the compartments are
        # the reader's (L1), and a version outside them is left unlocked
        # because the count below refuses the whole write over it. Nothing
        # is returned from here; the label checks below decide what the
        # caller is told.
        self._c.execute(
            """SELECT v.id FROM collect.document v
                WHERE v.compartments <@ %(held)s::text[]
                  AND (v.id = %(id)s
                       OR EXISTS (SELECT 1 FROM collect.document d
                                   WHERE d.id = %(id)s
                                     AND d.external_id IS NOT NULL
                                     AND d.compartments <@ %(held)s::text[]
                                     AND v.source_id = d.source_id
                                     AND v.external_id = d.external_id))
                ORDER BY v.id FOR UPDATE""", {"id": document_id, "held": held})
        row = self._c.execute(
            """SELECT d.id, d.source_id, d.external_id, d.legal_hold,
                      d.legal_hold_reason, d.legal_hold_by
                 FROM collect.document d
                 JOIN collect.source s ON s.id = d.source_id
                WHERE d.id = %s AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND s.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]""",
            (document_id, clearance, clearance, held)).fetchone()
        if row is None:
            raise RetentionNotFound(
                "no such document, or it is above your clearance")
        _id, source_id, external_id, prior_on, prior_reason, prior_by = row
        counts = self._c.execute(
            """SELECT count(*),
                      count(*) FILTER (WHERE v.classification <= %s::core.tlp
                                         AND v.compartments <@ %s::text[])
                 FROM collect.document v
                WHERE v.purged_at IS NULL
                  AND ((%s::text IS NULL AND v.id = %s)
                       OR (%s::text IS NOT NULL AND v.source_id = %s
                           AND v.external_id = %s))""",
            (clearance, held, external_id, document_id, external_id,
             source_id, external_id)).fetchone()
        if counts[0] != counts[1]:
            raise RetentionConflict(
                "An earlier version of this document is above your clearance, "
                "so somebody cleared for it places or lifts the hold.")
        written = self._c.execute(
            """UPDATE collect.document v
                  SET legal_hold = %s,
                      legal_hold_reason = CASE WHEN %s THEN %s ELSE NULL END,
                      legal_hold_by = %s
                WHERE ((%s::text IS NULL AND v.id = %s)
                       OR (%s::text IS NOT NULL AND v.source_id = %s
                           AND v.external_id = %s))
                  AND v.purged_at IS NULL
                  AND v.classification <= %s::core.tlp
                  AND v.compartments <@ %s::text[]""",
            (bool(on), bool(on), reason, actor_id, external_id, document_id,
             external_id, source_id, external_id, clearance, held)).rowcount
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, detail)
               VALUES (%s, 'USER', %s, 'document', %s, %s)""",
            (actor_id, "LEGAL_HOLD_APPLIED" if on else "LEGAL_HOLD_LIFTED",
             document_id,
             Json({"document_id": str(document_id), "versions": written,
                   "reason": reason, "prior_reason": prior_reason,
                   "prior_placed_by": str(prior_by) if prior_by else None,
                   "prior_on": bool(prior_on)})))
        return {"document_id": str(document_id), "legal_hold": bool(on),
                "legal_hold_reason": reason if on else None,
                "versions": written}

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
        consequential as applying one: it is what makes a later purge
        lawful. So both need a reason, as a document hold does, and the
        audit keeps the reason it replaces.

        evidence-hold-lift-below-label (2026-10-03): a lift needed no reason
        at all, and the route did not look at the exhibit's own labels, so a
        lead cleared below an exhibit could release a court hold on it in
        one request. The route now gates a lift on the exhibit's labels;
        this refuses a lift without a reason.

        evidence-purge-hold-race (2026-10-03): the row is locked first, so a
        hold sent while a purge holds the row waits for it, and a destroyed
        exhibit is refused rather than reported held."""
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise RetentionError(
                "a legal hold has to say what it rests on, placed or lifted: "
                "a hold nobody can attribute is a hold nobody can lift, and "
                "a lift nobody can attribute makes a purge nobody can defend")
        with self._c.transaction():
            prior = self._c.execute(
                """SELECT case_id, legal_hold, legal_hold_reason
                     FROM core.evidence WHERE id = %s FOR UPDATE""",
                (evidence_id,)).fetchone()
            cur = self._c.execute(
                "UPDATE core.evidence SET legal_hold = %s, legal_hold_reason = %s "
                "WHERE id = %s AND purged_at IS NULL",
                (on, reason if on else None, evidence_id))
            # A hold that changed no row is refused, never audited as
            # applied (S1, 2026-09-25). Under row-level security a blind
            # UPDATE on a row the connection cannot see changes nothing and
            # reports nothing; the route now runs this on a system
            # connection, and this check is what keeps "held" from ever
            # being said of an exhibit that is not, or that a purge has
            # destroyed.
            if cur.rowcount != 1:
                raise RetentionError(
                    "no such exhibit, or it has been destroyed, so no legal "
                    "hold was placed or lifted")
            self._audit(prior[0], actor_id,
                        "LEGAL_HOLD_APPLIED" if on else "LEGAL_HOLD_LIFTED",
                        {"evidence_id": str(evidence_id), "reason": reason,
                         "prior_on": bool(prior[1]),
                         "prior_reason": prior[2]})

    def set_case_legal_hold(self, case_id: UUID, *, actor_id: UUID,
                            on: bool, reason: str | None,
                            lifter_ceiling: tuple | None = None,
                            document_ceiling: tuple | None = None) -> dict:
        """Hold, or release, everything a case governs: its exhibits (those
        lodged later too), the ingest records attached to it, its lookups,
        answers and batches, its samples, and the collected documents it
        cites. Every leg of the purge already reads `core.case.legal_hold`.

        evidence-case-hold-unreachable (2026-10-03): nothing in the product
        wrote the column, so a preservation order covering a case could not
        be honoured; only the tests set it. A reason is required both ways,
        the audit keeps the one replaced, and the row is locked first, so a
        hold sent while a purge of the case runs waits for it (the purge
        holds the row FOR SHARE).

        PLACING a hold is open to whoever holds `retention.manage` on the
        case: preservation never waits for a clearance. LIFTING one is what
        makes everything under it destroyable, so `lifter_ceiling`, the
        lifter's (clearance, compartments) on this case, must cover
        everything the case holds; with none given, or with anything above
        it, the hold stays and nothing is changed. Otherwise a lead cleared
        below an exhibit could release a court hold on it through the case,
        which is what evidence-hold-lift-below-label closed for the exhibit
        itself. The refusal says the same thing whatever lies above the
        lifter, and names nothing of it.

        g44-case-hold-lift-documents (2026-10-03): the collected documents
        the case cites are held only through the case, and carry labels of
        their own, so they count too. `document_ceiling` is the lifter's
        ceiling OUTSIDE this case (no case-scoped break-glass grant): a
        collected document is read under the account's own clearance, never
        the case's, so a grant scoped to this case must not let somebody
        release a document they cannot open. Left out it is the case
        ceiling, which can only be the wider of the two."""
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise RetentionError(
                "a legal hold has to say what it rests on, placed or lifted: "
                "a hold nobody can attribute is a hold nobody can lift")
        with self._c.transaction():
            prior = self._c.execute(
                """SELECT legal_hold, legal_hold_reason FROM core."case"
                    WHERE id = %s FOR UPDATE""", (case_id,)).fetchone()
            if prior is None:
                raise RetentionNotFound("no such case")
            if not on and not self._ceiling_covers_case(
                    case_id, lifter_ceiling, document_ceiling):
                raise RetentionError(
                    "a case-level hold is lifted only by somebody cleared for "
                    "everything the case holds, and you are not. The hold "
                    "stays; ask a colleague cleared for the whole case. "
                    "Nothing was changed.")
            self._c.execute(
                """UPDATE core."case" SET legal_hold = %s, legal_hold_reason = %s
                    WHERE id = %s""", (on, reason if on else None, case_id))
            self._audit(case_id, actor_id,
                        "LEGAL_HOLD_APPLIED" if on else "LEGAL_HOLD_LIFTED",
                        {"case_id": str(case_id), "scope": "case",
                         "reason": reason, "prior_on": bool(prior[0]),
                         "prior_reason": prior[1]})
        return {"case_id": str(case_id), "legal_hold": bool(on),
                "legal_hold_reason": reason if on else None}

    def _ceiling_covers_case(self, case_id: UUID, ceiling: tuple | None,
                             document_ceiling: tuple | None = None) -> bool:
        """Whether a (clearance, compartments) ceiling covers every live
        exhibit, ingest record, sample, lookup and lookup answer the case
        holds, and `document_ceiling` (the ceiling when none is given) every
        live collected document it cites. Read on the connection this
        service runs on, which is a system connection: the point is to see
        what is above the lifter. No ceiling is False (fail closed).

        g44-case-hold-lift-documents (2026-10-03): the documents were left
        out ("held through the case that cites them, not by labels here"),
        so a lead cleared below a RED document lifted the case hold alone and
        the deployment-wide document sweep could then destroy it. A document
        counts when the case cites it through any registered citation
        (`_citations_sql`, the one list the hold predicate reads) or cites
        another version of it: a citation of any version holds them all
        (`_versions_sql`). Cited and not above the ceiling, or already
        purged, is not counted."""
        if ceiling is None:
            return False
        clearance, held = _ceiling_parts(ceiling)
        doc_clearance, doc_held = (
            (clearance, held) if document_ceiling is None
            else _ceiling_parts(document_ceiling))
        above = self._c.execute(
            f"""WITH cited AS (
                  SELECT DISTINCT c.document_id AS id
                    FROM ({_citations_sql()}) c WHERE c.case_id = %(c)s),
                held_documents AS (
                  SELECT v.id FROM collect.document v
                    JOIN cited ON cited.id = v.id
                  UNION
                  SELECT s.id FROM collect.document v
                    JOIN cited ON cited.id = v.id
                    JOIN collect.document s ON {_versions_sql("v", "s")})
               SELECT
                 (SELECT count(*) FROM core.evidence e
                   WHERE e.case_id = %(c)s AND e.purged_at IS NULL
                     AND (e.classification > %(l)s::core.tlp
                          OR NOT e.compartments <@ %(h)s::text[]))
               + (SELECT count(*) FROM ingest.record r
                   WHERE r.case_id = %(c)s AND r.purged_at IS NULL
                     AND (r.classification > %(l)s::core.tlp
                          OR NOT r.compartments <@ %(h)s::text[]))
               + (SELECT count(*) FROM lab.sample s
                   WHERE s.case_id = %(c)s AND s.state <> 'REJECTED'
                     AND (s.classification > %(l)s::core.tlp
                          OR NOT s.compartments <@ %(h)s::text[]))
               + (SELECT count(*) FROM ingest.lookup k
                   WHERE k.case_id = %(c)s AND k.purged_at IS NULL
                     AND k.classification > %(l)s::core.tlp)
               + (SELECT count(*) FROM ingest.lookup_result k
                   WHERE k.case_id = %(c)s AND k.purged_at IS NULL
                     AND k.classification > %(l)s::core.tlp)
               + (SELECT count(*) FROM collect.document d
                   WHERE d.id IN (SELECT id FROM held_documents)
                     AND d.purged_at IS NULL
                     AND (d.classification > %(dl)s::core.tlp
                          OR NOT d.compartments <@ %(dh)s::text[]))""",
            {"c": case_id, "l": clearance, "h": held,
             "dl": doc_clearance, "dh": doc_held}).fetchone()[0]
        return above == 0

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'retention', NULL, %s, %s)""",
            (actor_id, action, case_id, Json(detail)))
