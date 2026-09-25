"""Evidence: WORM storage, hashing at ingest, and the chain of custody.

Prosecution-grade (decision 13, US + Canada). The load-bearing properties:

- The SHA-256 is computed from the ORIGINAL bytes at ingest and stored;
  integrity verification re-reads from the object store and recomputes,
  never trusting a mutated copy.
- Bytes land in a MinIO bucket with object-lock retention (WORM), so the
  exhibit cannot be altered or deleted before its retention expires — the
  API process included.
- Every touch — ACQUIRED, VIEWED, EXPORTED, HASH_VERIFIED — is written to
  the append-only custody ledger AND to the hash-chained audit log, so
  "who looked at this exhibit, and when" is answerable and tamper-evident
  (docs/05: reads matter as much as writes).

Object-store and DB config come from the environment (no default
secrets). `export()` goes through the shared TLP egress gate
(`noctornal_api.egress`, Phase 5) — the same one function SMTP, Jira and
webhooks call, so invariant 8 has exactly one implementation to keep
right.

Destruction goes through `EvidenceStorage.delete_all_versions()`, which
`retention._purge_evidence` has called since 2026-09-02. The keyless
`delete()` is NOT a destruction path on this bucket: the bucket is
versioned (forced by `--with-lock`), so a keyless delete inserts a delete
marker and returns success with every byte still retrievable by version
id — measured live on 2026-08-10 and again on 2026-09-02. It is kept only
so `tests/test_evidence_lock_live_pg.py` can keep demonstrating that.
`is_retention_refusal()` is the ONE classifier both this module and
`retention` use to tell a lock refusal from a plain failure.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import logging
import os
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from uuid import UUID

import blake3 as _blake3
import psycopg
from minio import Minio
from minio.commonconfig import COMPLIANCE
from minio.error import S3Error
from minio.retention import Retention

from noctornal_api.egress import NEVER_EGRESS
# The Lab's ticket, reused for an exhibit (0068): its lifetime, and its
# sampled counter for strings that match no ticket. Private to samples.py
# and imported rather than copied, so the two tickets cannot drift apart.
from noctornal_api.samples import DOWNLOAD_TICKET_TTL_SECONDS, _SampledWarning

#: How long the storage layer's COMPLIANCE lock holds an exhibit, counted
#: from the moment the server LODGES the bytes (the put in `ingest`), not
#: from the acquisition time the uploader states. Once it ends the object
#: store no longer refuses a delete, and what protects the bytes is the
#: case's retention date, any legal hold and the dual-control purge
#: (`retention.py`). The day is kept per exhibit in
#: `core.evidence.retention_until`, the exact instant in the custody row
#: that set it (`lock_ends_at`), and the console shows it on the chip
#: (ux07-evidence:worm-chip-outlives-lock, 2026-09-23): a flag that said
#: "cannot be replaced or deleted" for ever was a claim an analyst could
#: repeat under oath and be wrong about from day 366.
#:
#: Since 2026-09-24 (x-lock-extension) this is the SHORTEST lock, not the
#: only one: `ingest` locks to the case's retention date when that is later
#: (`lock_target`), and extending the case's date lengthens every live
#: exhibit's lock to it (`EvidenceService.extend_locks`). Until then
#: nothing did, so a case kept for longer kept its exhibits deletable at
#: the store from day 366 while every other record said they were held.
#: Nothing shortens a lock, because nothing can: COMPLIANCE only lengthens.
DEFAULT_RETENTION = timedelta(
    days=int(os.environ.get("EVIDENCE_RETENTION_DAYS", "365"))
)

#: The furthest ahead of NOW one step sets a lock that follows the case's
#: retention date: at lodging, on an extension, or when the Evidence pane
#: lengthens older locks. Ten years unless the deployment says otherwise.
#:
#: A bound because a COMPLIANCE lock is a commitment nobody can take back,
#: an administrator and the dual-control purge included, while the case's
#: date is one field that one `case.update` holder types (x-lock-extension,
#: verifier, 2026-09-24: a mistyped year such as 2208 would have made every
#: exhibit undeletable at the store for good). The DATE is kept as typed:
#: it is what the purge reads, and a database row can be corrected where
#: a lock cannot. Only the lock stops here, and a case retained past the horizon has its locks
#: offered for lengthening again as they fall behind (`lock_short_before`).
#: `tests/conftest.py` sets it to one day, as it does the default lock,
#: so test runs do not lock objects in the dev bucket to test cases' dates.
LOCK_HORIZON = timedelta(
    days=int(os.environ.get("EVIDENCE_LOCK_HORIZON_DAYS", "3650"))
)


def case_lock_start(case_retention: date) -> datetime:
    """00:00 UTC on the case's retention day: the instant `retention.due`
    starts treating the case as due (`c.retention_until <= today`), so a
    lock that ends there covers the case's whole retention and not a
    second of the purge's."""
    return datetime.combine(case_retention, time.min, tzinfo=timezone.utc)


def lock_target(case_retention: date, now: datetime) -> tuple[datetime, bool]:
    """(the instant a lock that follows the case should end, whether the
    horizon cut it short of the case's date). In whole seconds, rounded
    up, because that is how a retention date travels: the custody row then
    records the instant the store holds, not one a fraction earlier."""
    start = case_lock_start(case_retention)
    furthest = now + LOCK_HORIZON
    if furthest.microsecond:
        furthest = furthest.replace(microsecond=0) + timedelta(seconds=1)
    return (start, False) if start <= furthest else (furthest, True)


def lock_short_before(case_retention: date | None,
                      now: datetime) -> datetime | None:
    """A live exhibit's lock that ends before this instant is SHORT of its
    case: the store would let its bytes be deleted while the case still
    holds them, and lengthening would change that. None when nothing can
    be lengthened, because the case is already due.

    Within the horizon that is the case's own retention instant. Past it,
    a lock is only as long as the horizon allowed when it was set, so it
    counts as short once it has fallen a whole default lock period behind
    the horizon: a case retained for decades is asked about once a year,
    not every day its horizon moves on (x-lock-extension, 2026-09-24)."""
    if case_retention is None:
        return None
    start = case_lock_start(case_retention)
    if start <= now:
        return None
    if start <= now + LOCK_HORIZON:
        return start
    return now + LOCK_HORIZON - DEFAULT_RETENTION

# Classifications that must never cross the boundary via export (invariant
# 8). Derived from egress.NEVER_EGRESS rather than restated: a second copy
# of the rule is how the copies drift, and the one that drifts is the leak.
# Kept as a name here only so existing importers keep working.
_NO_EGRESS = frozenset(t.name for t in NEVER_EGRESS)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _blake3d(data: bytes) -> bytes:
    return _blake3.blake3(data).digest()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceError(Exception):
    pass


@dataclass(frozen=True)
class VersionedDeleteResult:
    """What a versioned delete actually did, per key.

    Three counts rather than a boolean, because "the bytes are gone" and
    "the store refused" are different facts that a caller has to record
    differently — and merging them into a single success is precisely how
    `delete()` came to report destructions it had not performed.

    `versions_seen` includes delete markers; `versions_removed` never
    does. Removing a marker is tidying up after a keyless delete, not
    destruction, and counting it as one would restate the original defect
    in the new method's own numbers.
    """
    key: str
    versions_seen: int
    versions_removed: int
    versions_locked: int

    @property
    def fully_destroyed(self) -> bool:
        """Every real version is gone. FALSE while anything is locked —
        this is the value a tombstone may be written from."""
        return self.versions_locked == 0

    @property
    def outcome(self) -> str:
        """A one-word summary for logs and tests. NOT the tombstone vocabulary.

        Until 2026-09-02 this docstring claimed to match
        `retention.STORAGE_*`. It never did: retention's words — and the
        CHECK on `core.purge_tombstone.storage_outcome` (migration 0032) —
        are DELETED / LOCKED_UNTIL_RETENTION / FAILED / NOT_APPLICABLE, and
        two of the three values here, DESTROYED and NOTHING_TO_DELETE,
        would be refused by that CHECK. Only LOCKED_UNTIL_RETENTION
        coincides, which is what made the claim look true. So
        `retention._purge_evidence` maps the three COUNTS above onto its
        own vocabulary and never writes this string anywhere;
        `tests/test_evidence_versioned_delete.py` reads both sides and the
        migration to keep it that way.
        """
        if self.versions_locked:
            return "LOCKED_UNTIL_RETENTION"
        return "DESTROYED" if self.versions_removed else "NOTHING_TO_DELETE"


#: Codes that mean "the object is under retention" and nothing else. The
#: S3 vendors do not agree on one, so there are two.
_RETENTION_REFUSAL_CODES = frozenset({"RetentionPeriodNotMet", "MethodNotAllowed"})
#: Codes that mean "there is NO lock configuration", whatever the message
#: says — and MinIO's message for the first one contains "Object Lock".
_NOT_A_LOCK_CODES = frozenset({
    "ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration",
})
#: What a store says when a retention lock is the reason. MinIO:
#: "Object is WORM protected and cannot be overwritten".
_LOCK_WORDS = ("worm", "retention", "object lock")


def is_retention_refusal(exc: Exception) -> bool:
    """True only when the store said the object is under a retention lock.

    LOCKED_UNTIL_RETENTION is a specific claim — "the bytes will become
    deletable when a retention expires" — and it is written into an
    append-only tombstone. So this errs towards FAILED: a failure an
    operator investigates is recoverable; a permissions refusal recorded
    as a lawful lock is a false record nobody revisits.

    What was wrong until 2026-09-02: `retention._is_retention_refusal`
    returned True on a bare `AccessDenied` or `InvalidRequest`, so a
    read-only key or a bucket policy denying `s3:DeleteObject` was
    recorded as a retention lock — and it listed
    `ObjectLockConfigurationNotFoundError`, which means the bucket has NO
    lock configuration, as one. Meanwhile `delete_all_versions` kept its
    own code-only tuple with the same defect. Both halves now share this
    one function so they cannot drift: `delete_all_versions` uses it to
    decide locked-versus-raise, and retention uses it to classify what a
    store without version enumeration raises.

    `AccessDenied` and `InvalidRequest` therefore need the MESSAGE to say
    worm / retention / object lock. The message is read, not `str(exc)`:
    minio's `S3Error.__str__` quotes the resource and object name, and an
    exhibit whose key contains the word "retention" must not turn a
    policy denial into a lock. Message-only refusals from clients that
    carry no code (the governance test stubs raise
    RuntimeError("object is under a retention lock")) still count.

    Measured against the live MinIO 2026-09-02: a COMPLIANCE-locked
    version is refused with code `InvalidRequest` and message "Object is
    WORM protected and cannot be overwritten" — not `AccessDenied`, as the
    docstring below said until then. `tests/test_evidence_lock_live_pg.py`
    re-measures that on every run so a vocabulary drift shows up here
    rather than in a tombstone.
    """
    code = getattr(exc, "code", None)
    if code in _NOT_A_LOCK_CODES:
        return False
    if code in _RETENTION_REFUSAL_CODES:
        return True
    message = getattr(exc, "message", None)
    text = str(message if message else exc).lower()
    return any(word in text for word in _LOCK_WORDS)


class EvidenceStorage:
    """Thin MinIO wrapper. Config from the environment: MINIO_ENDPOINT
    (host:port), MINIO_ACCESS_KEY, MINIO_SECRET_KEY, MINIO_SECURE
    ('true'/'false'), EVIDENCE_BUCKET (default 'noctornal-evidence')."""

    def __init__(self) -> None:
        endpoint = os.environ.get("MINIO_ENDPOINT")
        access = os.environ.get("MINIO_ACCESS_KEY")
        secret = os.environ.get("MINIO_SECRET_KEY")
        if not (endpoint and access and secret):
            raise EvidenceError(
                "MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY must be set"
            )
        secure = os.environ.get("MINIO_SECURE", "false").lower() == "true"
        self._bucket = os.environ.get("EVIDENCE_BUCKET", "noctornal-evidence")
        self._client = Minio(endpoint, access_key=access, secret_key=secret, secure=secure)

    @property
    def bucket(self) -> str:
        return self._bucket

    def put(self, key: str, data: bytes, *, media_type: str, retain_until: datetime) -> None:
        # COMPLIANCE (not GOVERNANCE) object lock: not even a root MinIO
        # principal can delete or overwrite the exhibit before retain_until,
        # so the WORM guarantee holds against the API's own credentials.
        # (GOVERNANCE is bypassable by anyone with BypassGovernanceRetention.)
        self._client.put_object(
            self._bucket, key, io.BytesIO(data), length=len(data),
            content_type=media_type,
            retention=Retention(COMPLIANCE, retain_until),
        )

    def delete(self, key: str) -> None:
        """Keyless delete. On this bucket it destroys NOTHING — read on.

        Not a destruction path and not called by production code since
        2026-09-02; `retention._purge_evidence` calls
        `delete_all_versions()` instead, and
        `tests/test_evidence_versioned_delete.py` asserts that it does.
        This method survives only so `tests/test_evidence_lock_live_pg.py`
        can keep measuring the defect below against the live store. The
        two paragraphs that follow are what it was believed to do; the
        section after them is what it does.

        THIS CLASS HAD NO `delete` AT ALL until 2026-08-07, and nothing
        else in the repository removed an evidence object either — only
        `SampleStorage` could. `RetentionService` has always looped over
        `self._storage.delete(key)`, and every production caller
        constructed it with `storage=None`, so `_purge_evidence` took its
        `return STORAGE_NA` branch and the bytes were never touched. The
        row was marked `purged_at`, the exhibit vanished from every read
        path, and the tombstone — the record that is supposed to outlive
        the data — recorded NOT_APPLICABLE.

        **The refusal is not swallowed here.** Evidence is written under a
        COMPLIANCE-mode object lock, so a delete before `retain_until` is
        expected to fail and that failure is the honest answer: the caller
        records STORAGE_LOCKED and warns that the object store disagrees
        with the database. Catching it here would turn "the bytes are
        still there" into silence, which is the whole defect this method
        exists to end.

        ## AND IT DOES NOT DO WHAT IT SAYS. Measured 2026-08-10.

        The evidence bucket is created `--with-lock`, which forces
        VERSIONING on. `remove_object(bucket, key)` with no `version_id`
        does not remove anything on a versioned bucket: it inserts a
        DELETE MARKER and returns success. Reproduced against this stack —
        an object written under a COMPLIANCE lock, then:

            remove_object(key)      -> returned normally, no exception
            list(include_version)   -> the real version is STILL THERE
            get_object(version_id)  -> returned the original bytes

        So the refusal this docstring promises never arrives, because
        there is nothing to refuse. `RetentionService` records
        `evidence_purged`, the tombstone — the record that is supposed to
        outlive the data — says DESTROYED, and the bytes are sitting in
        the store, retrievable by anyone who can name a version.

        That is the same defect a third time: `retention._purge_evidence`
        and `ingest._with_raw` both reported a destruction they had not
        performed, and both were fixed. This one reports it while holding
        the object.

        `delete_all_versions()` below is the honest version, and since
        2026-09-02 it is the one the purge calls. Re-measured that day
        against the live stack with the same result:
        `tests/test_evidence_lock_live_pg.py::
        test_the_old_keyless_delete_returns_success_while_holding_the_bytes`
        asserts this behaviour STILL happens, so a change in MinIO's
        semantics shows up as a test failure rather than a silent change
        in what a tombstone means.
        """
        self._client.remove_object(self._bucket, key)

    # ---------------------------------------------------------------
    # The destruction path. `retention._purge_evidence` calls this
    # since 2026-09-02, and nothing else does.
    # ---------------------------------------------------------------
    def delete_all_versions(self, key: str) -> "VersionedDeleteResult":
        """Remove every version of `key`, reporting refusals as refusals.

        Enumerate every version under the key, delete each by
        `version_id`, and separate the two outcomes that `delete()` merges
        into silence — bytes actually gone, versus the store refusing
        because a retention has not expired. A refusal is RETURNED as a
        count, not raised, because the caller (`retention._purge_evidence`)
        has to record it against the tombstone rather than abort a batch;
        anything that is neither a deletion nor a recognised lock refusal
        raises, because an unrecognised storage failure is not an outcome
        to write down as a lock. `is_retention_refusal` is the one
        classifier for that, shared with retention.

        ## Written 2026-08-10, deliberately held back, wired 2026-09-02

        It was held back because enabling it changed what the system does
        to evidence and what it records having done. What was decided,
        item by item, when it was enabled:

        1. **It flips production outcomes.** A purge under an unexpired
           COMPLIANCE lock used to record DELETED; now it records
           `LOCKED_UNTIL_RETENTION`, leaves the row unpurged and due, and
           warns that the store refused. Previously-quiet purges now
           report refusals. That is the point.

        2. **Tombstones already written are wrong and cannot be fixed.**
           `core.purge_tombstone` is append-only. Every DELETED tombstone
           written between 2026-08-07 and 2026-09-02 for an object that
           was still locked is a false record and remains one. Whether
           those are reportable is a docs/18 question, not a code one;
           nothing here rewrites history.

        3. **It genuinely destroys bytes.** `delete()` never did. Its
           first live run was `tests/test_evidence_lock_live_pg.py` on
           2026-09-02, against throwaway `_itest-lock/` keys with
           seconds-long locks — not against an exhibit.

        4. **Its integration test creates objects nobody can delete
           early.** A COMPLIANCE retention cannot be shortened, lifted or
           overridden by any credential. The live test therefore uses
           `put(retain_until=)` with a lock of seconds, sweeps its own
           prefix on the next run, and FAILS (not skips) unless the
           bucket's object-lock configuration and versioning are on:
           against a bucket where locking is off, every assertion about a
           refusal passes for the wrong reason. `tests/conftest.py` also
           caps `EVIDENCE_RETENTION_DAYS` at 1 for every other test that
           ingests, so runs stop adding 365-day objects to the dev bucket.

        5. **On the shipped configuration a purge refuses for the object's
           whole retention.** `infra/docker-compose.yml` sets a bucket
           DEFAULT of `GOVERNANCE 365d` and `put()` applies COMPLIANCE for
           `DEFAULT_RETENTION` per object, so a purge before that expires
           records `LOCKED_UNTIL_RETENTION` — which is *correct*, and is
           why the row now stays due: the sweep after expiry finishes the
           job. This method deliberately does NOT send the
           GOVERNANCE-bypass header; acquiring that power silently is not
           a decision to make in a helper, and COMPLIANCE ignores it
           anyway.

        Both branches are measured against a live MinIO on every run of
        the live test: a COMPLIANCE-locked object reports a locked version
        with its bytes intact, and a versioned object with no lock is
        removed, every version.
        """
        removed, locked = 0, 0
        # `include_version=True` is the whole fix. Without it the listing
        # hides exactly the versions that survive a keyless delete.
        versions = [
            v for v in self._client.list_objects(
                self._bucket, prefix=key, include_version=True)
            if v.object_name == key
        ]
        for v in versions:
            if v.is_delete_marker:
                # A marker left by an earlier keyless delete. Removing it
                # is not destruction and must not be counted as any.
                self._client.remove_object(
                    self._bucket, key, version_id=v.version_id)
                continue
            try:
                self._client.remove_object(
                    self._bucket, key, version_id=v.version_id)
                removed += 1
            except S3Error as exc:
                # MinIO answers a locked version with InvalidRequest and
                # "Object is WORM protected and cannot be overwritten"
                # (measured 2026-09-02; this comment said AccessDenied
                # before, and the code-only tuple it guarded counted a
                # plain policy denial as a lock). The shared classifier
                # decides; anything it does not recognise as a refusal
                # raises, because treating an unknown failure as either
                # a lock or a successful delete is the failure this
                # method exists to end.
                if is_retention_refusal(exc):
                    locked += 1
                else:
                    raise
        return VersionedDeleteResult(
            key=key, versions_seen=len(versions),
            versions_removed=removed, versions_locked=locked)

    def get(self, key: str) -> bytes:
        resp = self._client.get_object(self._bucket, key)
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()

    def extend_lock(self, key: str, until: datetime) -> "LockExtension":
        """Lengthen the COMPLIANCE lock on every stored version of `key` so
        the store refuses a delete until `until`, and prove it did.

        Every version rather than the latest, for `delete_all_versions`'
        reason: the bucket is versioned, a keyless delete leaves the real
        version behind a marker, and a lock on the marker's side of that
        is a lock on nothing. Markers are skipped, since they hold no
        bytes and take no retention.

        A version already held that long is left alone, because it has to
        be: COMPLIANCE only lengthens, and asking for an earlier date is
        refused. A version held only under GOVERNANCE (the bucket default,
        never what `put` writes) is raised to COMPLIANCE, no earlier than
        it was already held. Each write is read back, and a store that
        answers success without holding the date raises: that store is
        the SeaweedFS case decision 64 names, reporting a lock it does not
        enforce, and a custody row written from its word would be false.
        """
        # A retention date travels in whole seconds, so a fraction is rounded
        # UP: rounding down would ask for a lock a moment short of `until`,
        # and the read-back below would then call the store a liar.
        if until.microsecond:
            until = until.replace(microsecond=0) + timedelta(seconds=1)
        versions = [
            v for v in self._client.list_objects(
                self._bucket, prefix=key, include_version=True)
            if v.object_name == key and not v.is_delete_marker
        ]
        if not versions:
            raise EvidenceError(f"no stored version of {key} to lock")
        ends: list[datetime | None] = []
        extended = 0
        for v in versions:
            held = self._client.get_object_retention(
                self._bucket, key, version_id=v.version_id)
            held_until = held.retain_until_date if held is not None else None
            ends.append(held_until)
            if (held is not None and held.mode == COMPLIANCE
                    and held_until >= until):
                continue
            target = until if held_until is None else max(until, held_until)
            self._client.set_object_retention(
                self._bucket, key, Retention(COMPLIANCE, target),
                version_id=v.version_id)
            now_held = self._client.get_object_retention(
                self._bucket, key, version_id=v.version_id)
            if (now_held is None or now_held.mode != COMPLIANCE
                    or now_held.retain_until_date < until):
                raise EvidenceError(
                    f"the store accepted a lock on {key} until "
                    f"{until.isoformat()} and does not hold it")
            extended += 1
        # The weakest version is what the exhibit was protected until.
        previous = None if None in ends else min(ends)
        return LockExtension(key=key, versions=len(versions),
                             extended=extended, previous=previous)


@dataclass(frozen=True)
class LockExtension:
    """What `EvidenceStorage.extend_lock` did to one exhibit's object."""
    key: str
    #: Stored versions under the key (delete markers not counted).
    versions: int
    #: Of those, how many had their lock lengthened. 0: already held.
    extended: int
    #: The earliest lock end among the versions before, which is what the
    #: exhibit was protected until; None when a version held no lock.
    previous: datetime | None


class IntegrityError(EvidenceError):
    """Stored bytes do not match the recorded hash — a tamper alarm. Read
    paths fail closed on this rather than serving the mismatched bytes."""


log = logging.getLogger("noctornal.evidence")

#: The purpose a ticket naming an exhibit carries (0068). The Lab's two are
#: `samples.TICKET_DOWNLOAD` and `samples.TICKET_RETRIEVAL`; the table
#: refuses this one on a row that names a sample and the others on a row
#: that names an exhibit.
TICKET_PRODUCTION = "exhibit_production"

#: The verb a production is gated on at the mint (the route's gate, as
#: `POST /export`) and re-read on the sample origin at redemption.
EXPORT_PERMISSION = "evidence.export"


class NotProducible(EvidenceError):
    """The exhibit cannot leave through the sample origin, for a reason
    about the exhibit or the deployment rather than the caller: it is not
    attacker markup, it was purged, or this process is not the origin that
    serves it. The router answers 409 with the sentence."""


class ProductionRefused(EvidenceError):
    """A production ticket could not be spent. ONE sentence for every
    reason, as the Lab's (`samples._TICKET_REFUSED`), so a holder of a
    stolen ticket learns nothing about why; the audit row says which."""


#: Why a non-hostile exhibit is not produced this way. It has a way out
#: already, from the application origin, and a second one for the same
#: bytes would be two custody stories for one exhibit.
NOT_HOSTILE_DETAIL = (
    "this exhibit is not attacker markup, so the application origin serves "
    "it: export it for disclosure from its card. The sample origin produces "
    "attacker markup only.")

#: Why a purged exhibit is not produced at all.
PURGED_DETAIL = (
    "this exhibit was purged under the case's retention: its bytes are gone, "
    "and its record, digest and custody are all that remain.")

_PRODUCTION_REFUSED = (
    "this production ticket is not valid: it has been used, it has expired, "
    "it was not issued for this exhibit, or the account it was issued to may "
    "no longer export it. A ticket is good for one production within "
    f"{DOWNLOAD_TICKET_TTL_SECONDS} seconds. Ask the console for another.")

#: The unknown-ticket counter, the Lab's mechanism in its own instance so
#: the two logs count their own origins' strings.
_unknown_production_tickets = _SampledWarning()


@dataclass(frozen=True)
class ProductionTicket:
    """What a production mint hands back. `raw` exists here and in the
    response that carries it, nowhere else: the row holds its SHA-256
    (0061's rule for the Lab's ticket)."""
    id: UUID
    raw: str
    evidence_id: UUID
    user_id: UUID
    expires_at: datetime


@dataclass(frozen=True)
class IngestResult:
    evidence_id: UUID
    sha256_hex: str
    deduplicated: bool  # True if identical bytes were already in the case


@dataclass(frozen=True)
class CustodyEntry:
    action: str
    actor_id: UUID
    occurred_at: datetime
    hash_verified: bool | None
    #: Who, as a person: the log answers "who touched this exhibit", and
    #: an eight-hex id ("actor fcfd6f27") answered it for nobody (README
    #: screenshot review, 2026-09-23). None only for an account row that
    #: no longer resolves; the id is still there.
    actor_name: str | None = None
    #: What the row itself says: how an exhibit was acquired, that bytes
    #: already held were re-acquired, what a check found. Returned so two
    #: ACQUIRED rows can be told apart (ux07-evidence:custody-rows-not-
    #: court-legible, 2026-09-23); the route decides what leaves.
    detail: dict | None = None


class EvidenceService:
    def __init__(self, conn: psycopg.Connection, storage: EvidenceStorage, *, now=_utcnow):
        self._c = conn
        self._s = storage
        self._now = now

    def ingest(
        self,
        *,
        case_id: UUID,
        title: str,
        media_type: str,
        data: bytes,
        acquired_by: UUID,
        acquisition_method: str,
        acquired_at: datetime | None = None,
        classification: str = "AMBER",
        compartments: list[str] | None = None,
        source_url: str | None = None,
        description: str | None = None,
        retain_until: datetime | None = None,
        is_hostile_markup: bool | None = None,
        authority_ref: str | None = None,
    ) -> IngestResult:
        """Store bytes as an exhibit.

        `is_hostile_markup` (migration 0046, docs/19) marks attacker-authored
        markup — a captured phishing DOM, a HAR, a `.eml`. Left as None it
        is DERIVED from the media type, so a caller cannot forget it; pass
        True explicitly to mark something the type does not reveal. Passing
        False overrides the derivation and is the only way to un-mark a
        hostile type, which is deliberately the awkward direction.

        `acquired_at` is when the material was OBTAINED, which the caller
        states; the row's `created_at` is when the server received it, and
        the two are shown apart. `authority_ref` names the warrant or
        production order a legal-process acquisition rests on. Both, and
        whether a time was stated at all, are written into the ACQUIRED
        custody row, the record that goes to court (ux07-evidence:upload-
        drops-provenance, 2026-09-23: the form recorded the upload moment
        as "acquired" and had nowhere to put the authority).
        """
        from noctornal_api.deception import is_hostile_media_type

        if is_hostile_markup is None:
            is_hostile_markup = is_hostile_media_type(media_type)
        digest = _sha256(data)
        blake = _blake3d(data)
        shahex = digest.hex()
        # acquired_at, when the caller gives none, is stamped by the
        # DATABASE inside the INSERT below: COALESCE(..., now()) in the same
        # transaction as the ACQUIRED custody row, whose occurred_at the
        # custody trigger pins to now() (migration 0024). Both are then the
        # one transaction timestamp. Until 2026-09-23 it was self._now(),
        # the API host's clock, read before the object store put: a
        # database clock behind the host showed an exhibit "acquired" a
        # minute AFTER its own ACQUIRED, VIEWED and HASH_VERIFIED rows
        # (README screenshot set review, 03-evidence).
        acquired = acquired_at
        retain = retain_until or self._lodging_lock(case_id)
        # What the ACQUIRED row says about how the material came in. Keys
        # with no value are left out rather than written as null, so a
        # row reads as what was stated.
        provenance = {"acquisition_method": acquisition_method,
                      "acquired_at_stated": acquired_at is not None}
        if acquired_at is not None:
            provenance["acquired_at"] = acquired_at.isoformat()
        if source_url:
            provenance["source_url"] = source_url
        if authority_ref:
            provenance["authority_ref"] = authority_ref

        # Dedup within the case (UNIQUE(case_id, sha256)): identical bytes
        # are one exhibit. Every ingest attempt — including a deduplicated
        # re-acquisition — leaves a custody trail; the caller's authority to
        # SEE the existing exhibit is the endpoint's access-gate decision
        # (this layer is below it).
        existing = self._c.execute(
            "SELECT id FROM core.evidence WHERE case_id = %s AND sha256 = %s",
            (case_id, digest),
        ).fetchone()
        if existing is not None:
            with self._c.transaction():
                self._custody(existing[0], "ACQUIRED", acquired_by,
                              detail={"sha256": shahex, "deduplicated": True,
                                      **provenance})
                self._audit("EVIDENCE_REACQUIRED", acquired_by, existing[0], case_id,
                            {"sha256": shahex})
            return IngestResult(existing[0], shahex, deduplicated=True)

        storage_key = f"{case_id}/{shahex}"
        self._s.put(storage_key, data, media_type=media_type, retain_until=retain)
        # Read-back verify: confirm the object landed byte-exact before we
        # commit a row that claims it did (catches a store-side short-write).
        if _sha256(self._s.get(storage_key)) != digest:
            raise IntegrityError(f"stored object {storage_key} does not match its hash")

        try:
            with self._c.transaction():
                evidence_id = self._c.execute(
                    """INSERT INTO core.evidence
                           (case_id, title, description, media_type, byte_size,
                            sha256, blake3, storage_key, storage_bucket, is_worm_locked,
                            acquired_at, acquired_by, acquisition_method, source_url,
                            classification, compartments, retention_until,
                            is_hostile_markup)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,true,
                               COALESCE(%s::timestamptz, now()),
                               %s,%s,%s,%s,%s,%s,%s)
                       RETURNING id""",
                    (case_id, title, description, media_type, len(data), digest, blake,
                     storage_key, self._s.bucket, acquired, acquired_by,
                     acquisition_method, source_url, classification,
                     compartments or [], retain.date(), is_hostile_markup),
                ).fetchone()[0]
                # hash_verified=True because the read-back above has just
                # confirmed the STORED object hashes to the digest recorded
                # here. Until 2026-09-22 this row said NULL, which the
                # custody view rendered as "hash not checked" on every clean
                # acquisition: a lapse in custody that never happened, on
                # the record that goes to court (ux07 custody-failed-hash-
                # shown-as-not-checked). The deduplicated branch above stays
                # NULL: it stored nothing and read nothing back.
                # The lock's exact end, which `retention_until` (a date)
                # cannot carry: the store's COMPLIANCE lock ends at this
                # instant, part way through that day, and a register that
                # counted the whole day overstated the storage guarantee by
                # up to 24 hours (ux07-evidence:worm-chip-outlives-lock,
                # verifier, 2026-09-23). Only on the original row: a
                # deduplicated re-acquisition stores nothing and locks
                # nothing.
                self._custody(evidence_id, "ACQUIRED", acquired_by,
                              detail={"sha256": shahex, "bytes": len(data),
                                      "lock_ends_at": retain.isoformat(),
                                      **provenance},
                              hash_verified=True)
                self._audit("EVIDENCE_ACQUIRED", acquired_by, evidence_id, case_id,
                            {"sha256": shahex})
            return IngestResult(evidence_id, shahex, deduplicated=False)
        except psycopg.errors.UniqueViolation:
            # A concurrent ingest of identical bytes won the race.
            row = self._c.execute(
                "SELECT id FROM core.evidence WHERE case_id = %s AND sha256 = %s",
                (case_id, digest),
            ).fetchone()
            return IngestResult(row[0], shahex, deduplicated=True)

    def view(self, evidence_id: UUID, actor_id: UUID) -> bytes:
        # Every read re-verifies the fetched bytes against the stored hash
        # and fails closed on mismatch, so a swapped object version cannot
        # be served with a clean custody entry.
        data, case_id = self._fetch_verified(evidence_id, actor_id)
        with self._c.transaction():
            self._custody(evidence_id, "VIEWED", actor_id)
            self._audit("EVIDENCE_VIEWED", actor_id, evidence_id, case_id, {})
        return data

    def verify_integrity(self, evidence_id: UUID, actor_id: UUID) -> bool:
        row = self._c.execute(
            "SELECT storage_key, sha256, blake3, case_id FROM core.evidence WHERE id = %s",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError(f"evidence {evidence_id} not found")
        key, stored_sha, stored_blake, case_id = row
        data = self._s.get(key)
        sha_ok = _sha256(data) == bytes(stored_sha)
        # blake3 is a second independent anchor: if sha256 is ever weakened,
        # or a hash column is doctored, the two must still agree.
        blake_ok = stored_blake is None or _blake3d(data) == bytes(stored_blake)
        ok = sha_ok and blake_ok
        with self._c.transaction():
            self._custody(evidence_id, "HASH_VERIFIED", actor_id,
                          detail={"sha256_ok": sha_ok, "blake3_ok": blake_ok},
                          hash_verified=ok)
            self._audit("EVIDENCE_HASH_VERIFIED", actor_id, evidence_id, case_id,
                        {"ok": ok})
            if not ok:
                # N2 (2026-09-02). The explicit verify wrote only
                # HASH_VERIFIED on a mismatch; only the incidental read path
                # wrote EVIDENCE_INTEGRITY_ALARM. Same event, two names, and
                # the one an auditor greps for was missing from the path an
                # auditor would use.
                self._audit("EVIDENCE_INTEGRITY_ALARM", actor_id, evidence_id,
                            case_id, {"sha256_ok": sha_ok, "blake3_ok": blake_ok,
                                      "on_read": False})
        if not ok:
            # After the transaction, not inside it: the custody and audit
            # rows are the record, and a failed notify write must neither
            # roll them back nor turn a correctly detected mismatch into a
            # 500. Function-local imports keep this hunk inside the method;
            # another group owns the delete region and both must merge.
            import logging

            from noctornal_api import notify_events
            try:
                notify_events.evidence_integrity_alarm(
                    self._c, case_id=case_id, evidence_id=evidence_id,
                    actor_id=actor_id, on_read=False)
            except Exception:  # noqa: BLE001 - audited already; the alarm is logged
                logging.getLogger(__name__).exception(
                    "integrity alarm for exhibit %s was audited but its "
                    "notification failed", evidence_id)
        return ok

    def export(self, evidence_id: UUID, actor_id: UUID,
               destination: str = "export",
               destination_ceiling: str | None = None) -> bytes:
        """Release bytes across the boundary, through the ONE egress gate.

        Invariant 8 used to be enforced by a local frozenset here. It now
        goes through `egress.can_egress`, which is the single function
        docs/07 requires every outbound path to share — export, SMTP, Jira
        and webhooks alike. A second copy of this rule is how the copies
        drift apart, and the one that drifts is the leak.

        Bytes are re-verified before release, so a swapped object can never
        be exported with a clean log.

        ## The gate is fed the EFFECTIVE labels, not the exhibit's own

        F19, 2026-07-26. This used to pass `core.evidence.compartments`
        alone. That column defaults to `'{}'`, and — unlike classification,
        which has `core.enforce_tlp_floor` — **no trigger propagates the
        case's compartments to it and no code path sets it**. So it was
        empty on essentially every row, `DENY_COMPARTMENTED` could never
        fire for evidence, and the one control that says "compartmented
        material does not cross the boundary at all" was decorative on the
        exhibit path.

        The access gate has always composed the two (`deps.effective_labels`:
        stricter classification, union of compartments). Egress now composes
        them the same way. Doing it here rather than adding a trigger is
        deliberate: composing at read time is what every other gate in the
        system does, and a trigger would have to backfill every existing row
        to be worth anything.
        """
        from noctornal_api.egress import can_egress
        from noctornal_api.security.access import tlp_from_name

        row = self._c.execute(
            """SELECT e.classification, e.case_id, e.compartments,
                      c.classification, c.compartments
                 FROM core.evidence e
                 JOIN core."case" c ON c.id = e.case_id
                WHERE e.id = %s""",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError(f"evidence {evidence_id} not found")
        classification, case_id, compartments, case_cls, case_comp = row
        classification = max(tlp_from_name(classification),
                             tlp_from_name(case_cls)).name
        decision = can_egress(
            classification, destination,
            compartments=(frozenset(compartments or [])
                          | frozenset(case_comp or [])),
            destination_ceiling=destination_ceiling,
        )
        if decision.denied:
            self._audit("EVIDENCE_EGRESS_REFUSED", actor_id, evidence_id, case_id,
                        {"reason": decision.reason, "destination": destination})
            raise EvidenceError(f"export refused: {decision.explain()}")
        data, _ = self._fetch_verified(evidence_id, actor_id)
        with self._c.transaction():
            self._custody(evidence_id, "EXPORTED", actor_id)
            self._audit("EVIDENCE_EXPORTED", actor_id, evidence_id, case_id, {})
        return data

    def _fetch_verified(self, evidence_id: UUID, actor_id: UUID) -> tuple[bytes, UUID]:
        """Fetch the object and confirm it still matches the recorded hash,
        recording a failed HASH_VERIFIED and raising IntegrityError on
        mismatch — so a tampered/ swapped object is never served."""
        row = self._c.execute(
            "SELECT storage_key, sha256, case_id FROM core.evidence WHERE id = %s",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise EvidenceError(f"evidence {evidence_id} not found")
        key, stored_sha, case_id = row
        data = self._s.get(key)
        if _sha256(data) != bytes(stored_sha):
            with self._c.transaction():
                self._custody(evidence_id, "HASH_VERIFIED", actor_id,
                              detail={"on_read": True}, hash_verified=False)
                self._audit("EVIDENCE_INTEGRITY_ALARM", actor_id, evidence_id,
                            case_id, {"on_read": True})
            # N2 (2026-09-02): this path wrote the AUDIT row and never raised
            # the URGENT notification the kind promises. After the
            # transaction and before the raise, for the reasons given in
            # `verify_integrity`: the record is committed, and a failure to
            # notify must not change what the caller is told.
            import logging

            from noctornal_api import notify_events
            try:
                notify_events.evidence_integrity_alarm(
                    self._c, case_id=case_id, evidence_id=evidence_id,
                    actor_id=actor_id, on_read=True)
            except Exception:  # noqa: BLE001 - audited already; the alarm is logged
                logging.getLogger(__name__).exception(
                    "integrity alarm for exhibit %s was audited but its "
                    "notification failed", evidence_id)
            raise IntegrityError(
                f"evidence {evidence_id} bytes do not match the recorded hash"
            )
        return data, case_id

    def link_to_node(self, *, evidence_id: UUID, node_id: UUID, created_by: UUID,
                     relevance: str | None = None, page_ref: str | None = None) -> None:
        self._link(evidence_id, created_by, node_id=node_id,
                   relevance=relevance, page_ref=page_ref)

    def link_to_edge(self, *, evidence_id: UUID, edge_id: UUID, created_by: UUID,
                     relevance: str | None = None, page_ref: str | None = None) -> None:
        self._link(evidence_id, created_by, edge_id=edge_id,
                   relevance=relevance, page_ref=page_ref)

    def _link(self, evidence_id, created_by, *, node_id=None, edge_id=None,
              relevance=None, page_ref=None):
        # Attaching an exhibit to a node/edge is an evidentiary act — it
        # asserts relevance to a person or relationship — so it is audited.
        case_id = self._c.execute(
            "SELECT case_id FROM core.evidence WHERE id = %s", (evidence_id,)
        ).fetchone()
        if case_id is None:
            raise EvidenceError(f"evidence {evidence_id} not found")
        with self._c.transaction():
            self._c.execute(
                """INSERT INTO core.evidence_link
                       (evidence_id, node_id, edge_id, relevance, page_ref, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (evidence_id, node_id, edge_id, relevance, page_ref, created_by),
            )
            self._audit("EVIDENCE_LINKED", created_by, evidence_id, case_id[0],
                        {"node_id": str(node_id) if node_id else None,
                         "edge_id": str(edge_id) if edge_id else None})

    def custody_log(self, evidence_id: UUID) -> list[CustodyEntry]:
        rows = self._c.execute(
            """SELECT c.action, c.actor_id, c.occurred_at, c.hash_verified,
                      u.display_name, c.detail
                 FROM core.evidence_custody c
                 LEFT JOIN iam.app_user u ON u.id = c.actor_id
                WHERE c.evidence_id = %s ORDER BY c.occurred_at, c.id""",
            (evidence_id,),
        ).fetchall()
        return [CustodyEntry(r[0], r[1], r[2], r[3], r[4], r[5] or {})
                for r in rows]

    def refuse_if_hostile(self, evidence_id: UUID, actor_id: UUID,
                          *, purpose: str) -> bool:
        """True, with the refusal audited, when the exhibit is attacker-
        authored markup and so may not be served from the API origin.

        docs/19 section 1.1: a DOM, HAR or `.eml` exhibit is download-only,
        and only from the separate sample origin; "the API origin never
        serves those bytes". `GET .../content` and `POST .../export` served
        them anyway until 2026-09-23 (found while answering ux07-evidence:
        no-exhibit-export-control, whose verifier pointed out that the
        flagship case's only exhibit is an `.eml`). Deliberately NOT inside
        `view()`: the seeders read through `view()` below the HTTP layer,
        and the rule is about which origin answers a browser, so the
        routes ask this after their access gate, where a refusal cannot
        tell a caller anything about a row they may not see. Audited
        because a refused egress unrecorded is indistinguishable from
        nobody having tried."""
        row = self._c.execute(
            "SELECT is_hostile_markup, case_id FROM core.evidence WHERE id = %s",
            (evidence_id,),
        ).fetchone()
        if row is None or not row[0]:
            return False
        with self._c.transaction():
            self._audit("EVIDENCE_EGRESS_REFUSED", actor_id, evidence_id, row[1],
                        {"reason": "hostile_markup", "purpose": purpose,
                         "destination": "api_origin"})
        return True

    # -- attacker markup, produced through the sample origin (0068) -------
    #
    # x-hostile-export, 2026-09-24. `refuse_if_hostile` kept the API origin
    # from serving these bytes and nothing let anybody produce them, so an
    # `.eml` exhibit could never leave for a court or a partner. They now
    # leave the way docs/19 section 1.1 says: from the separate sample
    # origin, through the gate a Lab download passes. A one-shot ticket is
    # minted HERE on the application origin under `evidence.export` and a
    # fresh sign-in (the gate `POST /export` applies), and spent THERE,
    # which re-derives the mint's decision before serving the Lab's
    # password-protected archive and writing the EXPORTED custody row.

    def _producible(self, evidence_id: UUID, case_id: UUID, actor_id: UUID,
                    *, stage: str) -> None:
        """Raise unless the exhibit may be produced through the sample
        origin: attacker markup, unpurged, and allowed out by the egress
        gate at its effective labels. Asked at the mint and again at the
        redemption, so a label raised or a purge run inside the ticket's
        minute bites before a byte moves.

        The egress half is `export()`'s, composed the same way (stricter
        classification of exhibit and case, union of compartments) and
        audited the same way, with the stage it refused at."""
        from noctornal_api.egress import can_egress
        from noctornal_api.security.access import tlp_from_name

        row = self._c.execute(
            """SELECT e.is_hostile_markup, e.purged_at, e.classification,
                      e.compartments, c.classification, c.compartments
                 FROM core.evidence e
                 JOIN core."case" c ON c.id = e.case_id
                WHERE e.id = %s AND e.case_id = %s""",
            (evidence_id, case_id),
        ).fetchone()
        if row is None:
            raise EvidenceError(f"evidence {evidence_id} not found")
        hostile, purged_at, cls, comp, case_cls, case_comp = row
        if not hostile:
            raise NotProducible(NOT_HOSTILE_DETAIL)
        if purged_at is not None:
            raise NotProducible(PURGED_DETAIL)
        classification = max(tlp_from_name(cls), tlp_from_name(case_cls)).name
        decision = can_egress(
            classification, "export",
            compartments=frozenset(comp or []) | frozenset(case_comp or []))
        if decision.denied:
            self._audit("EVIDENCE_EGRESS_REFUSED", actor_id, evidence_id, case_id,
                        {"reason": decision.reason, "destination": "export",
                         "purpose": "production", "stage": stage})
            raise EvidenceError(f"export refused: {decision.explain()}")

    def issue_production_ticket(self, evidence_id: UUID, *, case_id: UUID,
                                actor_id: UUID, session_id: UUID | None = None,
                                ip_hash: bytes | None = None,
                                request_origin: str | None = None,
                                ) -> "ProductionTicket":
        """Mint a one-shot, sixty-second authority to produce ONE exhibit
        of attacker markup from the sample origin.

        The caller's gate is the route's (`evidence.export` on the case and
        the exhibit, with a fresh sign-in, as `POST /export`). This makes
        the two configuration refusals every Lab mint makes
        (`samples._mint_split`: a split that cannot serve, or this process
        being the sample origin, where no session may run) and the
        exhibit's own (`_producible`), then writes the row 0068 allows. The
        raw ticket leaves in the return value only; the row holds its
        SHA-256, and the expiry is the DATABASE clock's, which the
        redemption compares against (0061)."""
        from noctornal_api.samples import _mint_split, new_download_ticket
        from noctornal_api.security.tokens import hash_token

        split = _mint_split(request_origin)
        self._producible(evidence_id, case_id, actor_id, stage="mint")
        raw = new_download_ticket()
        row = self._c.execute(
            """INSERT INTO lab.download_ticket
                   (token_hash, evidence_id, user_id, session_id, expires_at,
                    ip_hash, purpose)
               VALUES (%s, %s, %s, %s, now() + %s, %s, %s)
               RETURNING id, expires_at""",
            (hash_token(raw), evidence_id, actor_id, session_id,
             timedelta(seconds=DOWNLOAD_TICKET_TTL_SECONDS), ip_hash,
             TICKET_PRODUCTION)).fetchone()
        self._audit("EVIDENCE_PRODUCTION_TICKET_ISSUED", actor_id, evidence_id,
                    case_id, {"ticket_id": str(row[0]),
                              "expires_at": row[1].isoformat(),
                              "ttl_seconds": DOWNLOAD_TICKET_TTL_SECONDS,
                              "sample_origin": split.sample},
                    session_id=session_id, ip_hash=ip_hash)
        return ProductionTicket(id=row[0], raw=raw, evidence_id=evidence_id,
                                user_id=actor_id, expires_at=row[1])

    def redeem_production_ticket(self, presented: str, *, case_id: UUID,
                                 evidence_id: UUID, ip_hash: bytes | None = None,
                                 ) -> tuple[UUID, UUID]:
        """Spend a production ticket. Returns `(holder, ticket_id)`; raises
        `ProductionRefused`, with one sentence whatever the reason, on
        anything else. `samples.redeem_download_ticket`'s shape, for its
        reasons:

        - ONE `UPDATE ... RETURNING` decides it, so two presentations of
          one ticket cannot both succeed;
        - the exhibit, its case and the purpose are in the predicate, so a
          ticket presented on another exhibit's path (or a Lab ticket on
          this one) matches nothing and is not burnt;
        - an unknown string is counted in a sampled log line and never
          written to the audit chain, because that refusal needs no
          credential at all; the other reasons name a real ticket and a
          real person and are audited;
        - the holder's authority is RE-DERIVED here: an active account
          holding `evidence.export` on this case at the exhibit's live
          labels. Asked with `count_use=False`, since the mint already
          counted any break-glass use and one request is one use, and with
          the step-up satisfied at the ticket's issue, which the mint
          demanded no more than sixty seconds ago. The SESSION is not
          re-read: the residual 0061 states, unchanged.
        """
        from noctornal_api.security.access import (
            AccessResolutionError,
            evaluate,
            tlp_from_name,
        )
        from noctornal_api.security.tokens import hash_token
        from noctornal_api.stores import PgAccessResolver

        digest = hash_token(presented or "")
        # The exhibit's case through `iam.element_facts` (S1,
        # 2026-09-25). The sample origin spends the ticket BEFORE anybody is
        # bound, and an unbound connection sees no exhibit under row-level
        # security, so an EXISTS on core.evidence here refused every valid
        # ticket.
        row = self._c.execute(
            """UPDATE lab.download_ticket
                  SET redeemed_at = now()
                WHERE token_hash = %s
                  AND evidence_id = %s
                  AND purpose = %s
                  AND redeemed_at IS NULL
                  AND expires_at > now()
                  AND (SELECT f.case_id FROM iam.element_facts('evidence', %s) f)
                      = %s
            RETURNING id, user_id, session_id, token_hash, issued_at""",
            (digest, evidence_id, TICKET_PRODUCTION, evidence_id, case_id),
        ).fetchone()
        if row is None:
            reason, holder, named = self._production_refusal(
                digest, evidence_id, case_id)
            if reason == "unknown_ticket":
                counted = _unknown_production_tickets.note()
                if counted is not None:
                    log.warning(
                        "production ticket presented that matches no row (%d "
                        "since the last line). Unaudited by design: this "
                        "refusal needs no credential.", counted)
            else:
                self._audit("EVIDENCE_PRODUCTION_TICKET_REFUSED", holder,
                            named[0], named[1], {"reason": reason},
                            outcome="DENIED", ip_hash=ip_hash)
            raise ProductionRefused(_PRODUCTION_REFUSED)
        if not hmac.compare_digest(bytes(row[3]), digest):
            # Cannot fire against the predicate above; there for the
            # reason the Lab's is (`redeem_download_ticket`).
            self._audit("EVIDENCE_PRODUCTION_TICKET_REFUSED", row[1],
                        evidence_id, case_id,
                        {"reason": "hash_mismatch_after_lookup"},
                        outcome="DENIED", ip_hash=ip_hash)
            raise ProductionRefused(_PRODUCTION_REFUSED)
        ticket_id, holder, session_id, issued_at = row[0], row[1], row[2], row[4]
        failed: list[str]
        # The effective labels, composed as `deps.effective_labels` does
        # (stricter classification, union of compartments), read live.
        # As lock facts (`iam.element_facts`, `iam.case_facts`), because
        # this connection is not bound yet and must still decide (S1).
        labels = self._c.execute(
            """SELECT e.classification, e.compartments,
                      c.classification, c.compartments
                 FROM iam.element_facts('evidence', %s) e
                 CROSS JOIN LATERAL iam.case_facts(e.case_id) c""",
            (evidence_id,)).fetchone()
        try:
            eff_cls = max(tlp_from_name(labels[0]), tlp_from_name(labels[2])).name
            eff_comp = frozenset(labels[1] or []) | frozenset(labels[3] or [])
            decision = evaluate(PgAccessResolver(self._c).resolve(
                user_id=holder, case_id=case_id,
                permission_key=EXPORT_PERMISSION,
                object_classification=eff_cls, object_compartments=eff_comp,
                mfa_satisfied_at=issued_at, count_use=False))
            failed = list(decision.failed_checks)
        except AccessResolutionError:
            failed = ["account_inactive"]
        if failed:
            self._audit("EVIDENCE_PRODUCTION_TICKET_REFUSED", holder,
                        evidence_id, case_id,
                        {"reason": "authority_withdrawn", "failed_checks": failed,
                         "ticket_id": str(ticket_id), "spent": True},
                        outcome="DENIED", session_id=session_id, ip_hash=ip_hash)
            raise ProductionRefused(_PRODUCTION_REFUSED)
        self._audit("EVIDENCE_PRODUCTION_TICKET_REDEEMED", holder, evidence_id,
                    case_id, {"ticket_id": str(ticket_id)},
                    session_id=session_id, ip_hash=ip_hash)
        return holder, ticket_id

    def _production_refusal(self, digest: bytes, evidence_id: UUID,
                            case_id: UUID,
                            ) -> tuple[str, UUID | None, tuple[UUID, UUID | None]]:
        """Why a presentation matched nothing, for the audit row only: the
        reason, the holder, and the (exhibit, case) the row is filed under,
        which is the ticket's own exhibit when it names one."""
        # The exhibit's case as a fact (S1): unbound here, see above.
        row = self._c.execute(
            """SELECT t.user_id, t.evidence_id, t.redeemed_at,
                      t.expires_at <= now(),
                      (SELECT f.case_id FROM iam.element_facts('evidence', t.evidence_id) f)
                 FROM lab.download_ticket t
                WHERE t.token_hash = %s""",
            (digest,)).fetchone()
        if row is None:
            return "unknown_ticket", None, (evidence_id, None)
        named = (row[1] or evidence_id, row[4])
        if row[2] is not None:
            return "already_redeemed", row[0], named
        if row[3]:
            return "expired", row[0], named
        if row[1] is None:
            return "issued_for_a_sample", row[0], named
        if row[1] != evidence_id or row[4] != case_id:
            return "issued_for_another_exhibit", row[0], named
        return "redeemed_concurrently", row[0], named

    def produce(self, evidence_id: UUID, *, case_id: UUID, actor_id: UUID,
                ticket_id: UUID, request_origin: str | None = None,
                ) -> tuple[bytes, str]:
        """The exhibit's bytes in the Lab's archive (ZIP, password
        `infected`), on the sample origin only, for a holder whose ticket
        was just spent. Returns `(archive, sha256 hex)`.

        Refuses on any process that is not the sample origin, for the
        reason `SampleService.download` does and from the same
        configuration (`samples.origin_split`). Then the exhibit's own
        decision again (`_producible`), then the bytes, re-verified against
        the recorded digest and refused on a mismatch as every read is
        (`_fetch_verified`). The EXPORTED custody row names the ticket and
        the origin, so the record says how the exhibit left."""
        from noctornal_api.samples import archive, origin_split

        split = origin_split(this=request_origin)
        if not split.serves_here:
            raise NotProducible(split.refusal)
        self._producible(evidence_id, case_id, actor_id, stage="redemption")
        data, _ = self._fetch_verified(evidence_id, actor_id)
        digest = _sha256(data).hex()
        with self._c.transaction():
            self._custody(evidence_id, "EXPORTED", actor_id,
                          detail={"via": "sample_origin",
                                  "origin": split.sample,
                                  "ticket_id": str(ticket_id),
                                  "archive_format": "ZIP_INFECTED"})
            self._audit("EVIDENCE_EXPORTED", actor_id, evidence_id, case_id,
                        {"via": "sample_origin", "ticket_id": str(ticket_id)})
        return archive(data, digest, what="exhibit"), digest

    # -- the storage lock follows the case's retention --------------------

    def _lodging_lock(self, case_id: UUID) -> datetime:
        """The lock a newly lodged exhibit gets: the default period from
        now, or the case's retention date when that is later, up to the
        horizon (`lock_target`).

        x-lock-extension, verifier, 2026-09-24. Only an EXTENSION followed
        the case, so an exhibit lodged into a case already retained past a
        year kept the year: OP-NIGHTJAR-26 is retained to 2028-12-31 and
        its .eml was locked to 2027-09-23, while the policy said the lock
        followed the case. Asked at the put, as the case stands then."""
        now = self._now()
        shortest = now + DEFAULT_RETENTION
        row = self._c.execute(
            'SELECT retention_until FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if row is None or row[0] is None:
            return shortest
        target, _ = lock_target(row[0], now)
        return max(shortest, target)

    def extend_locks(self, case_id: UUID, retention_until: date,
                     actor_id: UUID, *,
                     ceiling: tuple[str, list[str]] | None = None) -> dict:
        """Lengthen every live exhibit's storage lock in the case toward the
        start of `retention_until`, UTC: the instant the purge starts
        treating the case as due (`retention.due` selects on
        `c.retention_until <= today`, deadline midnight UTC). No further
        than `LOCK_HORIZON` from now, which the report says (`capped`).

        x-lock-extension, 2026-09-24. The lock was fixed at lodging, so a
        case whose retention was extended past it kept exhibits the store
        would let anyone with the bucket's credentials delete, while the
        register and the chip read as held. Called by `PATCH /cases/{id}`
        AFTER the case's new date has committed, and by the Evidence pane's
        "Lengthen" for locks set before they followed the case; it never
        undoes the date: a lock that could not be lengthened is reported
        and audited per exhibit, and the date stands, because the date is
        what the purge reads and a date refused over a storage outage would
        leave the case due sooner, the opposite of what was asked.

        Each lengthened exhibit gets a LOCK_EXTENDED custody row carrying
        the new `lock_ends_at` (the register reads the newest one) and the
        previous end, and its `retention_until` day moves to the lock's.
        An exhibit already held that long is left alone and counted.
        Purged exhibits have no bytes to lock.

        EVERY live exhibit is locked, and the report counts only those
        within `ceiling`, the caller's (clearance, compartments), when one
        is given (verifier, 2026-09-24): `case.update` says nothing about
        exhibits above the caller, and a count that included them told an
        AMBER owner a case held three exhibits where their register showed
        one, as often as they cared to save the date. Which exhibits failed
        is in the audit log, never in the answer."""
        now = self._now()
        until, capped = lock_target(retention_until, now)
        clr, comp = ceiling if ceiling is not None else (None, None)
        rows = self._c.execute(
            """SELECT id, storage_key,
                      (%(clr)s::text IS NULL
                       OR (classification <= %(clr)s::core.tlp
                           AND compartments <@ %(comp)s::text[])) AS counted
                 FROM core.evidence
                WHERE case_id = %(case)s AND purged_at IS NULL AND is_worm_locked
                ORDER BY acquired_at, id""",
            {"case": case_id, "clr": clr, "comp": comp}).fetchall()
        report = {"lock_ends_at": until.isoformat(), "capped": capped,
                  "exhibits": sum(1 for r in rows if r[2]),
                  "extended": 0, "already_held": 0, "failed": 0,
                  "date_passed": until <= now}
        if not rows or report["date_passed"]:
            # A lock cannot be set in the past, and the case is due on its
            # own date whatever the store says, so there is nothing to do.
            return report
        for evidence_id, key, counted in rows:
            tally = report if counted else {"extended": 0, "already_held": 0,
                                            "failed": 0}
            try:
                if self._s is None:
                    raise EvidenceError("the evidence store is not configured")
                done = self._s.extend_lock(key, until)
            except Exception as exc:  # noqa: BLE001 - reported per exhibit, never raised
                tally["failed"] += 1
                reason = (getattr(exc, "code", None) or type(exc).__name__)
                log.warning("storage lock on exhibit %s not extended to %s: %s",
                            evidence_id, until.isoformat(), reason)
                self._audit("EVIDENCE_LOCK_EXTENSION_FAILED", actor_id,
                            evidence_id, case_id,
                            {"lock_ends_at": until.isoformat(), "reason": reason},
                            outcome="FAILED")
                continue
            if not done.extended:
                tally["already_held"] += 1
                continue
            with self._c.transaction():
                self._c.execute(
                    """UPDATE core.evidence SET retention_until = %s
                        WHERE id = %s
                          AND (retention_until IS NULL OR retention_until < %s)""",
                    (until.date(), evidence_id, until.date()))
                self._custody(evidence_id, "LOCK_EXTENDED", actor_id, detail={
                    "lock_ends_at": until.isoformat(),
                    "previous_lock_ends_at": (done.previous.isoformat()
                                              if done.previous else None),
                    "case_retention_until": retention_until.isoformat(),
                    "capped_at_horizon": capped,
                    "versions": done.versions})
                self._audit("EVIDENCE_LOCK_EXTENDED", actor_id, evidence_id,
                            case_id, {"lock_ends_at": until.isoformat()})
            tally["extended"] += 1
        return report

    # -- internal --------------------------------------------------------
    def _custody(self, evidence_id, action, actor_id, *, detail=None, hash_verified=None):
        from psycopg.types.json import Json
        self._c.execute(
            """INSERT INTO core.evidence_custody
                   (evidence_id, action, actor_id, detail, hash_verified)
               VALUES (%s, %s, %s, %s, %s)""",
            (evidence_id, action, actor_id, Json(detail or {}), hash_verified),
        )

    def _audit(self, action, actor_id, object_id, case_id, detail, *,
               outcome="SUCCESS", session_id=None, ip_hash=None):
        """`outcome`, `session_id` and `ip_hash` since 0068: a production
        ticket's issue, redemption and refusals carry them as the Lab's
        ticket events do. A refusal naming no holder is SYSTEM, not a USER
        row with no actor (`deps.audit_auth_event`'s rule)."""
        from psycopg.types.json import Json
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, case_id,
                    outcome, detail, session_id, ip_hash)
               VALUES (%s, %s, %s, 'evidence', %s, %s, %s, %s, %s, %s)""",
            (actor_id, "USER" if actor_id else "SYSTEM", action, object_id,
             case_id, outcome, Json(detail), session_id, ip_hash),
        )
