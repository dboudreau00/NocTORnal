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
import io
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import blake3 as _blake3
import psycopg
from minio import Minio
from minio.commonconfig import COMPLIANCE
from minio.error import S3Error
from minio.retention import Retention

from noctornal_api.egress import NEVER_EGRESS

DEFAULT_RETENTION = timedelta(
    days=int(os.environ.get("EVIDENCE_RETENTION_DAYS", "365"))
)

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


class IntegrityError(EvidenceError):
    """Stored bytes do not match the recorded hash — a tamper alarm. Read
    paths fail closed on this rather than serving the mismatched bytes."""


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
    ) -> IngestResult:
        """Store bytes as an exhibit.

        `is_hostile_markup` (migration 0046, docs/19) marks attacker-authored
        markup — a captured phishing DOM, a HAR, a `.eml`. Left as None it
        is DERIVED from the media type, so a caller cannot forget it; pass
        True explicitly to mark something the type does not reveal. Passing
        False overrides the derivation and is the only way to un-mark a
        hostile type, which is deliberately the awkward direction.
        """
        from noctornal_api.deception import is_hostile_media_type

        if is_hostile_markup is None:
            is_hostile_markup = is_hostile_media_type(media_type)
        digest = _sha256(data)
        blake = _blake3d(data)
        shahex = digest.hex()
        acquired = acquired_at or self._now()
        retain = retain_until or (self._now() + DEFAULT_RETENTION)

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
                                      "acquisition_method": acquisition_method,
                                      "source_url": source_url})
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
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,true,%s,%s,%s,%s,%s,%s,%s,%s)
                       RETURNING id""",
                    (case_id, title, description, media_type, len(data), digest, blake,
                     storage_key, self._s.bucket, acquired, acquired_by,
                     acquisition_method, source_url, classification,
                     compartments or [], retain.date(), is_hostile_markup),
                ).fetchone()[0]
                self._custody(evidence_id, "ACQUIRED", acquired_by,
                              detail={"sha256": shahex, "bytes": len(data)})
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
            """SELECT action, actor_id, occurred_at, hash_verified
                 FROM core.evidence_custody
                WHERE evidence_id = %s ORDER BY occurred_at, id""",
            (evidence_id,),
        ).fetchall()
        return [CustodyEntry(r[0], r[1], r[2], r[3]) for r in rows]

    # -- internal --------------------------------------------------------
    def _custody(self, evidence_id, action, actor_id, *, detail=None, hash_verified=None):
        from psycopg.types.json import Json
        self._c.execute(
            """INSERT INTO core.evidence_custody
                   (evidence_id, action, actor_id, detail, hash_verified)
               VALUES (%s, %s, %s, %s, %s)""",
            (evidence_id, action, actor_id, Json(detail or {}), hash_verified),
        )

    def _audit(self, action, actor_id, object_id, case_id, detail):
        from psycopg.types.json import Json
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
               VALUES (%s, 'USER', %s, 'evidence', %s, %s, %s)""",
            (actor_id, action, object_id, case_id, Json(detail)),
        )
