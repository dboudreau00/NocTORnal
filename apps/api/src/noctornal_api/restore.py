"""Re-lodge mirrored exhibits and preserved samples into an object store that never held them, and say where
they now live (decision 240).

A backup mirror keeps the bytes of an exhibit and not the version the store gave them, and an upload cannot
choose its version id. An exhibit names the version it was lodged as and every read asks for it, so evidence
restored into a new store read as missing, and a preserved sample's retrieval read a version of the
preservation bucket the same way. This module puts each exhibit's mirrored bytes into the new store under a
COMPLIANCE lock, proves they are the exhibit's, and appends one hash-chained `RESTORED` custody row naming the
version the store gave them. Nothing is rewritten: the exhibit keeps its hashes, its key and the version it
was lodged as, and a read resolves where the bytes live now through `core.evidence_current_version` (0198).
A preserved sample goes the same way into the preservation bucket under a legal hold set in the put, proved
by opening its ciphertext with its own data key, and is recorded as one `RESTORED` access row that
`lab.sample_current_preserved_version` (0199) resolves. `scripts/restore_object_versions.py` is the one
command that runs it.

What it never does, because a lock cannot be taken back:

- put anything before the bytes verify. The mirror file is hashed (SHA-256 and BLAKE3) and compared with the
  exhibit's row AND with the hash-chained ACQUIRED custody row; any difference, in the size or either digest,
  is a refusal that writes nothing to the store or the database. A preserved sample's file is opened with the
  sample's data key and its plaintext compared with the row's size, SHA-256 and the SHA-1 and MD5 it records
  (a sample has no BLAKE3); the plaintext exists in memory for the length of the hashes and nowhere else;
- put a second locked version of bytes the store already holds. The store is asked first whether the recorded
  version is there and verifies (a replicated store), then whether some version of the key already does (a
  rerun after a failure between the put and the database write), and adopts it instead;
- write the database before the object is read back by its own version id and both digests are recomputed;
- hold a network call inside a transaction that audits: the object is written first, then one short
  transaction appends the custody row, the audit row and, when the new lock is later, the day on the row,
  exactly as a lock extension does;
- lock for less than the exhibit was already locked, or for longer than the lodging rule asks. A preserved
  sample is protected by a legal hold set in the put, which has no end to choose;
- restore a preserved sample into a bucket other than the one its row names: moving a sample between buckets
  is a separate decision, so it is refused and said;
- restore an exhibit that was purged. The mirror may still hold bytes the product destroyed on purpose; they
  are counted and named, never written back;
- delete, lift or place a hold on an object it did not put, or shorten a lock. There is no method for any of
  them here, and the restore account's policy (infra/production/README.md) grants none.

A dry run, the default, reads the store and the mirror and writes nothing anywhere. `--apply` is explicit and
names the account that answers for the run (an active holder of `retention.manage` through a global role) and
the authority it ran under (a reference an auditor can follow, recorded and not verifiable, as for the
retention sweep).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import blake3 as _blake3
import psycopg
from psycopg.types.json import Json

from noctornal_api.objectstore.custody import restricted_refusal
from noctornal_api.objectstore.errors import (
    ObjectMissing,
    StoreError,
    StoreRefusal,
    StoreUnreachable,
)
from noctornal_api.objectstore.types import COMPLIANCE
from noctornal_api.samples import (
    HeldKeyUnavailable,
    PreservationUnconfirmed,
    PreservationUnverified,
    SampleError,
    held_ciphertext_differs,
)

log = logging.getLogger("noctornal.restore")

#: The permission of the account that answers for a run: the one whose holders already decide the fate of
#: stored evidence (holds, retention). One constant, so a deployment that wants SYS_ADMIN only changes one line.
PERMISSION = "retention.manage"

EVENT_RUN = "RESTORE_RUN"
EVENT_EXHIBIT = "EVIDENCE_RESTORED"
EVENT_EXHIBIT_REFUSED = "EVIDENCE_RESTORE_REFUSED"
EVENT_SAMPLE = "SAMPLE_PRESERVED_RESTORED"
EVENT_SAMPLE_REFUSED = "SAMPLE_PRESERVED_RESTORE_REFUSED"

#: What a run reports for one object.
RESTORED, WOULD_RESTORE, ALREADY_PRESENT = "RESTORED", "WOULD_RESTORE", "ALREADY_PRESENT"
REFUSED, FAILED, PURGED, UNPINNED = "REFUSED", "FAILED", "PURGED", "UNPINNED"
#: The outcomes that leave something for the operator to do: the exit code is 1 while any exists.
LEFT = (REFUSED, FAILED)

#: Why an object was refused. Words, so a report and an audit row can be searched.
MIRROR_MISSING = "mirror_missing"
HASH_MISMATCH = "hash_mismatch"
SIZE_MISMATCH = "size_mismatch"
ANCHOR_MISMATCH = "anchor_mismatch"
STORE_REFUSED = "store_refused"
PATH_REFUSED = "path_refused"
CUSTODY_UNDECLARED = "custody_undeclared"
CURRENT_FAILS = "current_version_fails"
BUCKET_DIFFERS = "bucket_differs"
HOLD_MISSING = "hold_missing"
KEY_UNAVAILABLE = "data_key_unavailable"

RUN_LOCK = "noctornal.restore_object_versions"


class RestoreRefused(Exception):
    """The restore will not run as asked, said in one sentence for the operator. Nothing was restored."""


def validate_authority(value: str | None) -> str:
    """The authority reference, or a refusal: the retention sweep's rule (a reference an auditor can follow,
    not a placeholder and not an answer), in this tool's words."""
    from noctornal_api.retention_sweep import SweepRefused, validate_reference

    try:
        return validate_reference(value)
    except SweepRefused:
        raise RestoreRefused(
            "--authority is not a reference an auditor can follow. Name the restore ticket, incident "
            "or instruction the run rests on, not a placeholder or an answer; the software records it "
            "and cannot verify it. Nothing was restored.") from None


def resolve_actor(conn: psycopg.Connection, email: str | None) -> UUID:
    """The active account that answers for the run, or a refusal. One sentence for every way it can fail,
    so the tool is not a way to learn which addresses are accounts."""
    email = (email or "").strip()
    if not email:
        raise RestoreRefused(
            "a real restore names the account that answers for it: pass --actor EMAIL. The custody "
            "rows record who restored what. Nothing was restored.")
    row = conn.execute(
        """SELECT u.id FROM iam.app_user u
            WHERE u.email = %s AND u.is_active
              AND EXISTS (SELECT 1 FROM iam.user_role ur
                            JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                           WHERE ur.user_id = u.id AND rp.permission_key = %s)""",
        (email, PERMISSION)).fetchone()
    if row is None:
        raise RestoreRefused(
            f"no active account with that email holds {PERMISSION} through a global role. Name the "
            f"account that answers for the restore. Nothing was restored.")
    return row[0]


# ---------------------------------------------------------------------------
# The mirror
# ---------------------------------------------------------------------------

class MirrorMissing(Exception):
    """Nothing at the key under the mirror's root."""


class PathRefused(Exception):
    """A key that would leave the mirror's root, or a path with a link on it. `why` is a fixed word."""

    def __init__(self, why: str) -> None:
        super().__init__(why)
        self.why = why


_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _is_link(st: os.stat_result) -> bool:
    """A symbolic link, or a Windows junction or other reparse point, which `lstat` reports as neither a
    plain file nor a plain directory the mirror wrote."""
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE)


def locate(root: Path, key: str) -> tuple[Path, int]:
    """The mirror file for an object key, and its size, or `MirrorMissing` / `PathRefused`.

    The key is data from a database a restore is repairing, so it is not trusted to stay inside the mirror:
    an empty key, a NUL, a backslash, a colon (a drive or a stream on Windows), a leading slash and any
    empty, `.` or `..` segment are refused before the disk is touched, then every component below the root is
    read with `lstat`, and a link or reparse point anywhere on the way is refused, and the file must be a
    regular one. The resolved path must lie under the resolved root. The root itself is the operator's: it
    may be a link they chose."""
    if (not key or "\x00" in key or "\\" in key or ":" in key or key.startswith("/")
            or any(part in ("", ".", "..") for part in key.split("/"))):
        raise PathRefused("the key is not a plain relative path")
    base = Path(root)
    try:
        resolved_root = base.resolve(strict=True)
    except OSError:
        raise MirrorMissing from None
    if not resolved_root.is_dir():
        raise MirrorMissing
    parts = key.split("/")
    here = resolved_root
    st = None
    for i, part in enumerate(parts):
        here = here / part
        try:
            st = os.lstat(here)
        except FileNotFoundError:
            raise MirrorMissing from None
        except OSError:
            raise PathRefused("the path cannot be read") from None
        if _is_link(st):
            raise PathRefused("a link is on the path")
        last = i == len(parts) - 1
        if last and not stat.S_ISREG(st.st_mode):
            raise PathRefused("the mirror's entry is not a regular file")
        if not last and not stat.S_ISDIR(st.st_mode):
            raise PathRefused("a directory on the path is not one")
    try:
        here.resolve(strict=True).relative_to(resolved_root)
    except (OSError, ValueError):
        raise PathRefused("the path leaves the mirror") from None
    return here, st.st_size


def read_mirror_file(path: Path, size: int) -> bytes:
    """The file's bytes, refusing one that is not the size `lstat` reported (it changed under us)."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(size + 1)
    if len(data) != size:
        raise PathRefused("the file changed while it was read")
    return data


# ---------------------------------------------------------------------------
# What a run says
# ---------------------------------------------------------------------------

@dataclass
class Outcome:
    """One object's result. `detail` holds words and counts, never a credential and never a key."""
    kind: str
    id: str
    code: str
    reason: str | None = None
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        out = {"kind": self.kind, "id": self.id, "outcome": self.code}
        if self.reason:
            out["reason"] = self.reason
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Report:
    run_id: str
    apply: bool
    outcomes: list[Outcome] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    #: Why the run stopped before it was done, if it did.
    stopped: str | None = None

    def add(self, outcome: Outcome) -> Outcome:
        self.outcomes.append(outcome)
        return outcome

    def count(self, code: str, kind: str | None = None) -> int:
        return sum(1 for o in self.outcomes
                   if o.code == code and (kind is None or o.kind == kind))

    @property
    def left(self) -> int:
        return sum(1 for o in self.outcomes if o.code in LEFT)

    def counts(self) -> dict:
        codes = (RESTORED, WOULD_RESTORE, ALREADY_PRESENT, REFUSED, FAILED, PURGED, UNPINNED)
        return {c.lower(): self.count(c) for c in codes}

    def counters(self) -> str:
        parts = [f"{name}={n}" for name, n in self.counts().items()]
        return f"restore {'apply' if self.apply else 'dry run'} {self.run_id}: " + " ".join(parts)

    def as_dict(self) -> dict:
        return {"run_id": self.run_id, "apply": self.apply, "counts": self.counts(),
                "stopped": self.stopped, "warnings": self.warnings,
                "outcomes": [o.as_dict() for o in self.outcomes]}


def write_report(path: str | os.PathLike, report: Report) -> None:
    """The JSON report, mode 0600, never over a file that exists. Counts and outcome words only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report.as_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")


# ---------------------------------------------------------------------------
# The restore
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _blake3d(data: bytes) -> bytes:
    return _blake3.blake3(data).digest()


def _whole_seconds(moment: datetime) -> datetime:
    """A retention date travels in whole seconds, so a fraction rounds UP: rounding down would ask for a
    lock a moment short of the one the rule set."""
    if moment.microsecond:
        return moment.replace(microsecond=0) + timedelta(seconds=1)
    return moment


def _aware(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _parse_time(raw) -> datetime | None:
    try:
        return _aware(datetime.fromisoformat(str(raw)))
    except ValueError:
        return None


EXHIBITS_SQL = """
SELECT id, case_id, storage_key, storage_bucket, sha256, blake3, byte_size, media_type,
       classification::text, storage_version_id, purged_at, core.evidence_current_version(id)
  FROM core.evidence
 WHERE (%(everything)s OR case_id = ANY(%(cases)s::uuid[]))
 ORDER BY created_at, id
"""


SAMPLES_SQL = """
SELECT id, case_id, preserved_bucket, preserved_key, preserved_version_id, byte_size,
       classification::text, lab.sample_current_preserved_version(id), sha256,
       sha1 IS NOT NULL, md5 IS NOT NULL
  FROM lab.sample
 WHERE preserved_key IS NOT NULL
   AND (%(everything)s OR case_id = ANY(%(cases)s::uuid[]))
 ORDER BY preserved_at, id
"""


class Restore:
    """One run. `evidence` is anything with `.store` (an `ObjectStore`) and `.bucket`, which is
    `EvidenceStorage`; `preserved` is `PreservationStorage` (the same two attributes, and `preserve`, `get` and
    `is_held`); `lock_until(case_id, recorded, now)` returns `(instant, reason)` and exists so a test or a
    live proof can ask for seconds, never a day: no command-line option shortens a lock."""

    def __init__(self, conn: psycopg.Connection, *, apply: bool = False,
                 actor_id: UUID | None = None, authority: str | None = None,
                 where: dict | None = None, evidence=None,
                 evidence_mirror: Path | str | None = None, preserved=None,
                 preserved_mirror: Path | str | None = None,
                 cases: Sequence[UUID] = (), limit: int | None = None, adopt: bool = True,
                 now: Callable[[], datetime] | None = None,
                 lock_until: Callable[[UUID, list, datetime], tuple[datetime, str]] | None = None,
                 run_id: str | None = None) -> None:
        if apply and (actor_id is None or not authority):
            raise RestoreRefused(
                "a real restore names the account that answers for it and the authority it ran "
                "under. Nothing was restored.")
        self._c = conn
        self.apply = apply
        self.actor_id = actor_id
        self.authority = authority
        self.where = dict(where or {})
        self.evidence = evidence
        self.evidence_mirror = Path(evidence_mirror) if evidence_mirror else None
        self.preserved = preserved
        self.preserved_mirror = Path(preserved_mirror) if preserved_mirror else None
        self.cases = list(cases)
        self.limit = limit
        self.adopt = adopt
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.lock_until = lock_until
        self.report = Report(run_id=run_id or str(uuid4()), apply=apply)

    # -- the run ------------------------------------------------------------------------------------

    def run(self) -> Report:
        locked = False
        if self.apply:
            locked = self._c.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                                     (RUN_LOCK,)).fetchone()[0]
            if not locked:
                raise RestoreRefused(
                    "another restore is running against this database. Wait for it, then run "
                    "again. Nothing was restored.")
        try:
            if self.evidence_mirror is not None:
                if self.evidence is None:
                    raise RestoreRefused("--evidence-mirror needs the evidence object store, which "
                                         "is not configured. Nothing was restored.")
                self._exhibits()
            if self.preserved_mirror is not None:
                if self.preserved is None:
                    raise RestoreRefused("--preserved-mirror needs the preservation object store, which "
                                         "is not configured. Nothing was restored.")
                self._samples()
            if self.apply:
                self._record_run()
        finally:
            if locked:
                self._c.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (RUN_LOCK,))
        return self.report

    # -- exhibits -----------------------------------------------------------------------------------

    def _exhibits(self) -> None:
        rows = self._c.execute(EXHIBITS_SQL, {"everything": not self.cases,
                                              "cases": self.cases}).fetchall()
        live = []
        for row in rows:
            eid, purged_at, lodged = row[0], row[10], row[9]
            if purged_at is not None:
                self._purged(eid, row[2])
            elif lodged is None:
                self.report.add(Outcome("exhibit", str(eid), UNPINNED, detail={
                    "note": "recorded with no version: reads take the latest, nothing to restore"}))
            else:
                live.append(row)
        self._take("exhibit", live, self._exhibit)

    def _take(self, kind: str, rows: list, work: Callable) -> None:
        """Work through `rows` in their stable order until `--limit` objects have been restored (or, in a dry
        run, would be). An object already in place, one refused and one that failed do not use the limit up:
        they are reported by every run, so a limit counted against them would hand the same first objects
        to every batch and never reach the rest."""
        taken = 0
        for row in rows:
            if self.limit is not None and taken >= self.limit:
                break
            before = len(self.report.outcomes)
            self._attempt(kind, row, work)
            if any(o.code in (RESTORED, WOULD_RESTORE) for o in self.report.outcomes[before:]):
                taken += 1

    def _attempt(self, kind: str, row, work: Callable) -> None:
        """One object's work, with every way it can fail said in words and none of them stopping the rest.
        `row` starts with the object's id and its case."""
        try:
            work(row)
        except _ListingRefused as exc:
            self._refuse(kind, row[0], row[1], STORE_REFUSED, store_code=exc.code,
                         note="the store would not list versions, so a version left by an "
                              "interrupted run cannot be found. Give the restore account "
                              "list-versions (infra/production/README.md), or pass --no-adopt to "
                              "put without looking, which an interrupted run can follow with a "
                              "second locked or held version")
        except StoreUnreachable as exc:
            if exc.never_reached:
                self._refuse(kind, row[0], row[1], STORE_REFUSED, store_code=type(exc).__name__)
            else:
                self.report.add(Outcome(kind, str(row[0]), FAILED, reason=STORE_REFUSED,
                                        detail={"note": "the store did not answer after the "
                                                "request went out, so an object may be stored "
                                                "under a lock or a hold. Run again: it adopts one "
                                                "it finds"}))
        except StoreError as exc:
            self._refuse(kind, row[0], row[1], STORE_REFUSED,
                         store_code=exc.code or type(exc).__name__)
        except Exception as exc:  # noqa: BLE001 - one object's failure never stops the rest
            log.warning("restore of %s %s failed: %s", kind, row[0], type(exc).__name__)
            self.report.add(Outcome(kind, str(row[0]), FAILED, reason=type(exc).__name__))

    def _purged(self, evidence_id: UUID, key: str) -> None:
        """Never restored. When the mirror still holds the file, say so: the product destroyed those bytes on
        purpose and the mirror is not under its tombstone."""
        detail = {}
        try:
            locate(self.evidence_mirror, key)
            detail["mirror_still_holds_bytes"] = True
            self.report.warnings.append(
                f"exhibit {evidence_id} was purged, and the mirror still holds its bytes. They were "
                f"not restored. Remove them under the purge's authority.")
        except (MirrorMissing, PathRefused):
            pass
        self.report.add(Outcome("exhibit", str(evidence_id), PURGED, detail=detail))

    def _exhibit(self, row) -> None:
        (eid, case_id, key, lodged_bucket, sha, blake, size, media_type, classification,
         lodged_version, _purged_at, current) = row
        store, bucket = self.evidence.store, self.evidence.bucket
        sha, blake = bytes(sha), bytes(blake) if blake is not None else None

        # 1. The bytes may already be where reads look: a store whose replication kept version ids, or a
        #    rerun of a restore that finished. Nothing is written.
        found = self._read_version(store, bucket, key, current)
        if found is not None:
            if self._differs(found, sha, blake, size) is None:
                self.report.add(Outcome("exhibit", str(eid), ALREADY_PRESENT))
                return
            self._refuse("exhibit", eid, case_id, CURRENT_FAILS,
                         note="the version reads are asking for is in the store and its bytes do not "
                              "verify: an integrity alarm to investigate, which a restore does not "
                              "paper over")
            return

        # 2. A store operated outside the deployment holds no AMBER_STRICT or RED until counsel's
        #    declaration is recorded (invariant 8): the same refusal lodging makes.
        if restricted_refusal("evidence", classification):
            self._refuse("exhibit", eid, case_id, CUSTODY_UNDECLARED)
            return

        # 3. The mirror's file, proved before anything is written anywhere.
        try:
            path, on_disk = locate(self.evidence_mirror, key)
        except MirrorMissing:
            self._refuse("exhibit", eid, case_id, MIRROR_MISSING)
            return
        except PathRefused as exc:
            self._refuse("exhibit", eid, case_id, PATH_REFUSED, why=exc.why)
            return
        if on_disk != size:
            self._refuse("exhibit", eid, case_id, SIZE_MISMATCH, mirror_bytes=on_disk,
                         recorded_bytes=size)
            return
        try:
            data = read_mirror_file(path, on_disk)
        except PathRefused as exc:
            self._refuse("exhibit", eid, case_id, PATH_REFUSED, why=exc.why)
            return
        which = self._differs(data, sha, blake, size)
        if which is not None:
            self._refuse("exhibit", eid, case_id,
                         SIZE_MISMATCH if which == "size" else HASH_MISMATCH, which=which)
            return
        from noctornal_api.evidence import EvidenceService

        anchor = EvidenceService(self._c, None)._acquired_anchor_ok(eid, sha)
        if anchor is not True:
            self._refuse("exhibit", eid, case_id, ANCHOR_MISMATCH,
                         which="no ACQUIRED custody row" if anchor is None
                         else "the ACQUIRED custody row's digest")
            return

        # 4. How long the new object is locked: never shorter than the exhibit was.
        target, lock_reason = self._lock_target(eid, case_id)

        if not self.apply:
            self.report.add(Outcome("exhibit", str(eid), WOULD_RESTORE, detail={
                "lock_ends_at": target.isoformat(), "lock_reason": lock_reason}))
            return

        # 5. Adopt a version of the key that already verifies, else put one; read it back by its own
        #    version id and recompute both digests before the database hears of it.
        new_version = self._adopt(store, bucket, key,
                                  lambda held: self._differs(held, sha, blake, size) is None)
        adopted = new_version is not None
        if new_version is None:
            result = store.put(bucket, key, data, media_type=media_type, retain_until=target)
            new_version = result.version_id
            if not new_version:
                self.report.add(Outcome("exhibit", str(eid), FAILED, reason=STORE_REFUSED, detail={
                    "note": "the store kept the object and gave no version id, so nothing can name "
                            "it. It is a store without versioning, which evidence needs",
                    "bucket": bucket, "key": key}))
                return
        orphan = {"bucket": bucket, "key": key, "version_id": new_version}
        back = store.get(bucket, key, version_id=new_version)
        if self._differs(back, sha, blake, size) is not None:
            self.report.add(Outcome("exhibit", str(eid), FAILED, reason=HASH_MISMATCH, detail={
                "note": "the object was written and does not read back as the exhibit; it is locked "
                        "and nothing records it",
                **orphan}))
            return
        lock_ends = self._ensure_lock(store, bucket, key, new_version, target)
        if lock_ends is None:
            self.report.add(Outcome("exhibit", str(eid), FAILED, reason=STORE_REFUSED, detail={
                "note": "the store does not report the COMPLIANCE lock the restore asked for, so "
                        "nothing records the object. Run again: it adopts this version and lengthens "
                        "its lock",
                **orphan}))
            return

        # 6. One short transaction, no network inside it.
        detail = {
            "old_version_id": current, "new_version_id": new_version, "bucket": bucket,
            "sha256": sha.hex(), "blake3": blake.hex() if blake is not None else None,
            "byte_size": size, "lock_ends_at": lock_ends.isoformat(), "lock_reason": lock_reason,
            "adopted": adopted, "run_id": self.report.run_id, "source": "mirror",
            "authority": self.authority, **self.where,
            "store_profile": getattr(store, "profile", None), "store_host": getattr(store, "host", None),
        }
        if lodged_bucket != bucket:
            detail["lodged_bucket"] = lodged_bucket
        try:
            with self._c.transaction():
                gone = self._c.execute(
                    "SELECT purged_at FROM core.evidence WHERE id = %s FOR SHARE", (eid,)).fetchone()
                if gone is None or gone[0] is not None:
                    raise _PurgedMeanwhile
                self._c.execute(
                    """INSERT INTO core.evidence_custody
                           (evidence_id, action, actor_id, detail, hash_verified)
                       VALUES (%s, 'RESTORED', %s, %s, true)""",
                    (eid, self.actor_id, Json(detail)))
                # The day the exhibit's lock ends moves forward as a lock extension moves it, so the
                # register's day and its instant agree. No anchor is touched (0140).
                self._c.execute(
                    """UPDATE core.evidence SET retention_until = %s
                        WHERE id = %s AND (retention_until IS NULL OR retention_until < %s)""",
                    (lock_ends.date(), eid, lock_ends.date()))
                self._audit(EVENT_EXHIBIT, "evidence", eid, case_id,
                            {"run_id": self.report.run_id, "adopted": adopted,
                             "authority": self.authority, **self.where})
        except _PurgedMeanwhile:
            self.report.warnings.append(
                f"exhibit {eid} was purged while the restore ran; its restored object is locked in "
                f"{bucket} as version {new_version} and nothing records it.")
            self.report.add(Outcome("exhibit", str(eid), PURGED, detail=orphan))
            return
        except Exception as exc:  # noqa: BLE001 - the object exists whatever the database said
            log.warning("restore of exhibit %s wrote its object and not its record: %s", eid,
                        type(exc).__name__)
            self.report.add(Outcome("exhibit", str(eid), FAILED, reason=type(exc).__name__, detail={
                "note": "the object is stored and locked and the database did not record it. Run "
                        "again: the run adopts this version and records it. Nothing is deleted to "
                        "put it right",
                **orphan}))
            return
        self.report.add(Outcome("exhibit", str(eid), RESTORED, detail={
            "new_version_id": new_version, "adopted": adopted,
            "lock_ends_at": lock_ends.isoformat()}))

    # -- preserved samples --------------------------------------------------------------------------

    def _samples(self) -> None:
        rows = self._c.execute(SAMPLES_SQL, {"everything": not self.cases,
                                             "cases": self.cases}).fetchall()
        live = []
        for row in rows:
            if row[4] is None:
                self.report.add(Outcome("sample", str(row[0]), UNPINNED, detail={
                    "note": "preserved with no version: a retrieval takes the latest, nothing to "
                            "restore"}))
            else:
                live.append(row)
        self._take("sample", live, self._sample)

    def _sample(self, row) -> None:
        (sid, case_id, lodged_bucket, key, _lodged_version, size, classification, current,
         sha, has_sha1, has_md5) = row
        store, bucket = self.preserved.store, self.preserved.bucket
        digests = ["sha256"] + (["sha1"] if has_sha1 else []) + (["md5"] if has_md5 else [])

        # 1. Only into the bucket the row names, which must be the configured one: moving a sample between
        #    buckets is a decision of its own, and a bucket this account does not read has nothing to probe.
        if lodged_bucket != bucket:
            self._refuse("sample", sid, case_id, BUCKET_DIFFERS, lodged_bucket=lodged_bucket,
                         configured_bucket=bucket)
            return

        # 2. The held copy may already be where retrievals look. Nothing is written. A copy that opens to
        #    the sample and carries no hold is not protected, and the product places no hold on an object
        #    it did not put.
        found = self._read_version(store, bucket, key, current)
        if found is not None:
            try:
                differs = held_ciphertext_differs(self._c, sid, found)
            except HeldKeyUnavailable as exc:
                self._key_unavailable(sid, exc)
                return
            if differs is not None:
                self._refuse("sample", sid, case_id, CURRENT_FAILS, which=differs,
                             note="the version retrievals are asking for is in the store and its "
                                  "bytes do not open to the sample: an integrity alarm to "
                                  "investigate, which a restore does not paper over")
            elif not store.legal_hold_is_on(bucket, key, current):
                self._refuse("sample", sid, case_id, HOLD_MISSING,
                             note="the version retrievals are asking for is in the store and opens "
                                  "to the sample, and no legal hold is on it. The product places no "
                                  "hold on an object it did not put: place it at the store under "
                                  "counsel's instruction")
            else:
                self.report.add(Outcome("sample", str(sid), ALREADY_PRESENT))
            return

        # 3. A store operated outside the deployment holds no AMBER_STRICT or RED until counsel's
        #    declaration is recorded (invariant 8).
        if restricted_refusal("preserve", classification):
            self._refuse("sample", sid, case_id, CUSTODY_UNDECLARED)
            return

        # 4. The mirror's file, proved before anything is written anywhere.
        try:
            path, on_disk = locate(self.preserved_mirror, key)
        except MirrorMissing:
            self._refuse("sample", sid, case_id, MIRROR_MISSING)
            return
        except PathRefused as exc:
            self._refuse("sample", sid, case_id, PATH_REFUSED, why=exc.why)
            return
        if on_disk != size:
            self._refuse("sample", sid, case_id, SIZE_MISMATCH, mirror_bytes=on_disk,
                         recorded_bytes=size)
            return
        try:
            ciphertext = read_mirror_file(path, on_disk)
        except PathRefused as exc:
            self._refuse("sample", sid, case_id, PATH_REFUSED, why=exc.why)
            return
        try:
            differs = held_ciphertext_differs(self._c, sid, ciphertext)
        except HeldKeyUnavailable as exc:
            self._key_unavailable(sid, exc)
            return
        if differs is not None:
            self._refuse("sample", sid, case_id,
                         SIZE_MISMATCH if differs == "size" else HASH_MISMATCH, which=differs)
            return

        if not self.apply:
            self.report.add(Outcome("sample", str(sid), WOULD_RESTORE, detail={
                "hold": "set in the put and read back", "digests": digests}))
            return

        # 5. Adopt a held version that already opens to the sample, else put one under a hold; read it
        #    back by its own version id and prove it again before the database hears of it.
        new_version = self._adopt(
            store, bucket, key,
            lambda there: held_ciphertext_differs(self._c, sid, there) is None, held=True)
        adopted = new_version is not None
        if new_version is None:
            try:
                made = self.preserved.preserve(key, ciphertext)
            except PreservationUnverified as exc:
                self.report.add(Outcome("sample", str(sid), FAILED, reason=STORE_REFUSED, detail={
                    "note": "the held copy was written and the store could not confirm what it "
                            "holds, so nothing records it. Run again: it adopts this version once "
                            "it reads back as held",
                    "store_said": str(exc), "bucket": exc.copy.bucket, "key": exc.copy.key,
                    "version_id": exc.copy.version_id}))
                return
            except PreservationUnconfirmed as exc:
                self.report.add(Outcome("sample", str(sid), FAILED, reason=STORE_REFUSED, detail={
                    "note": "the store did not answer the held copy, so one may exist. Run again: "
                            "it adopts one it finds",
                    "store_said": str(exc), "bucket": exc.bucket, "key": exc.key}))
                return
            except SampleError as exc:
                self._refuse("sample", sid, case_id, STORE_REFUSED, store_said=str(exc))
                return
            new_version = made.version_id
            if not new_version:
                self.report.add(Outcome("sample", str(sid), FAILED, reason=STORE_REFUSED, detail={
                    "note": "the store kept the object and gave no version id, so nothing can name "
                            "it. It is a store without versioning, which a preserved sample needs",
                    "bucket": bucket, "key": key}))
                return
        orphan = {"bucket": bucket, "key": key, "version_id": new_version}
        back = store.get(bucket, key, version_id=new_version)
        if held_ciphertext_differs(self._c, sid, back) is not None:
            self.report.add(Outcome("sample", str(sid), FAILED, reason=HASH_MISMATCH, detail={
                "note": "the object was written and does not read back as the sample; it is held "
                        "and nothing records it",
                **orphan}))
            return
        if not store.legal_hold_is_on(bucket, key, new_version):
            self.report.add(Outcome("sample", str(sid), FAILED, reason=HOLD_MISSING, detail={
                "note": "the store does not report the legal hold on the object, so nothing "
                        "records it. Run again: it adopts this version once the hold reads back",
                **orphan}))
            return

        # 6. One short transaction, no network inside it.
        detail = {
            "old_version_id": current, "new_version_id": new_version, "bucket": bucket,
            "sha256": bytes(sha).hex(), "byte_size": size, "verified": True,
            "hold_confirmed": True, "digests": digests, "adopted": adopted,
            "run_id": self.report.run_id, "source": "mirror", "authority": self.authority,
            **self.where, "store_profile": getattr(store, "profile", None),
            "store_host": getattr(store, "host", None),
        }
        try:
            with self._c.transaction():
                self._c.execute(
                    """INSERT INTO lab.sample_access (sample_id, actor_id, actor_kind, action, detail)
                       VALUES (%s, %s, 'USER', 'RESTORED', %s)""",
                    (sid, self.actor_id, Json(detail)))
                self._audit(EVENT_SAMPLE, "sample", sid, case_id,
                            {"run_id": self.report.run_id, "adopted": adopted,
                             "authority": self.authority, **self.where})
        except Exception as exc:  # noqa: BLE001 - the object exists whatever the database said
            log.warning("restore of sample %s wrote its object and not its record: %s", sid,
                        type(exc).__name__)
            self.report.add(Outcome("sample", str(sid), FAILED, reason=type(exc).__name__, detail={
                "note": "the object is stored under a hold and the database did not record it. "
                        "Run again: the run adopts this version and records it. Nothing is deleted "
                        "to put it right",
                **orphan}))
            return
        self.report.add(Outcome("sample", str(sid), RESTORED, detail={
            "new_version_id": new_version, "adopted": adopted}))

    def _key_unavailable(self, sample_id: UUID, exc: Exception) -> None:
        """The sample's data key would not open: the key ring in this environment is not the one that sealed
        it. Nothing can be proved, so nothing is written, and the object is not called refused: the fault
        is the environment's."""
        self.report.add(Outcome("sample", str(sample_id), FAILED, reason=KEY_UNAVAILABLE, detail={
            "note": f"the sample's data key could not be opened ({exc}). Run where the key ring "
                    f"that sealed it is configured. Nothing was written"}))

    # -- steps --------------------------------------------------------------------------------------

    @staticmethod
    def _differs(data: bytes, sha: bytes, blake: bytes | None, size: int) -> str | None:
        """Which recorded fact the bytes disagree with, or None when they match every one."""
        if len(data) != size:
            return "size"
        if _sha256(data) != sha:
            return "sha256"
        if blake is not None and _blake3d(data) != blake:
            return "blake3"
        return None

    @staticmethod
    def _read_version(store, bucket: str, key: str, version: str | None) -> bytes | None:
        """The bytes at `version`, None when the store holds nothing there. Every other answer is raised.

        A store answers a version id of a shape it never issues, which is what an exhibit lodged in another
        store carries, with `InvalidArgument` (HTTP 400) and not `NoSuchVersion`; the conformance suite
        accepts either as a store's word for an absent version. On a read that names a version it means
        the same thing here: nothing is there, and the restore goes on to put the bytes."""
        try:
            return store.get(bucket, key, version_id=version)
        except ObjectMissing:
            return None
        except StoreRefusal as exc:
            if version is not None and exc.code == "InvalidArgument" and exc.status in (None, 400):
                return None
            raise

    def _adopt(self, store, bucket: str, key: str, verifies: Callable[[bytes], bool], *,
               held: bool = False) -> str | None:
        """The version of `key` already in the store whose bytes `verifies`, and which is under a legal hold
        when `held` is asked, or None. A rerun after a failure between the put and the database write finds
        its own object here and puts nothing: a second locked version of the same bytes could never be
        removed. Raises `_ListingRefused` when the store will not list versions, which the caller says in
        words."""
        if not self.adopt:
            return None
        try:
            listed = list(store.list_versions(bucket, key))
        except StoreError as exc:
            raise _ListingRefused(exc.code or type(exc).__name__) from exc
        versions = sorted(
            (v for v in listed if v.key == key and not v.is_delete_marker),
            key=lambda v: v.last_modified or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        for v in versions:
            there = self._read_version(store, bucket, key, v.version_id)
            if there is not None and verifies(there) and (
                    not held or store.legal_hold_is_on(bucket, key, v.version_id)):
                return v.version_id
        return None

    @staticmethod
    def _ensure_lock(store, bucket: str, key: str, version: str, target: datetime) -> datetime | None:
        """The COMPLIANCE lock the store reports on `version`, lengthened to `target` when it holds less,
        and read back. None when the store does not report a lock that long: a store can accept a lock it
        does not enforce (docs/17 F24), and a custody row written from its word would be false."""
        held = store.get_retention(bucket, key, version)
        until = _aware(held.until) if held is not None and held.until is not None else None
        if held is None or held.mode != COMPLIANCE or until is None or until < target:
            store.set_compliance_retention(bucket, key, version,
                                           target if until is None else max(until, target))
            held = store.get_retention(bucket, key, version)
            until = _aware(held.until) if held is not None and held.until is not None else None
        if held is None or held.mode != COMPLIANCE or until is None or until < target:
            return None
        return until.astimezone(timezone.utc)

    def _lock_target(self, evidence_id: UUID, case_id: UUID) -> tuple[datetime, str]:
        """The instant the new object's lock ends: the later of the longest lock the exhibit's custody
        records (acquisition, extensions, an earlier restore) and what a lodging would be given now, in whole
        seconds. The reason is a sentence the custody row keeps. A lock that had already ended is not a
        lock to preserve: the exhibit was unlocked at the store, and a fresh default period starts."""
        from noctornal_api.evidence import EvidenceService

        now = self.now()
        recorded = [t for t in (
            _parse_time(r[0]) for r in self._c.execute(
                """SELECT detail ->> 'lock_ends_at' FROM core.evidence_custody
                    WHERE evidence_id = %s AND action IN ('ACQUIRED', 'LOCK_EXTENDED', 'RESTORED')
                      AND detail ? 'lock_ends_at'""", (evidence_id,)).fetchall()) if t is not None]
        if self.lock_until is not None:
            instant, reason = self.lock_until(case_id, recorded, now)
            return _whole_seconds(_aware(instant)), reason
        lodging = EvidenceService(self._c, None, now=self.now)._lodging_lock(case_id)
        latest = max(recorded) if recorded else None
        if latest is None:
            instant, reason = lodging, "no lock was recorded, so the lodging rule applies"
        elif latest <= now:
            instant = lodging
            reason = ("the recorded lock had already ended, so a fresh default period was used "
                      "and not the lock that lapsed")
        elif latest >= lodging:
            instant, reason = latest, "the recorded lock, which had not ended"
        else:
            instant, reason = lodging, "the lodging rule, which is longer than the recorded lock"
        return _whole_seconds(_aware(instant)), reason

    # -- the record ---------------------------------------------------------------------------------

    def _refuse(self, kind: str, object_id: UUID, case_id: UUID | None, reason: str,
                **detail) -> Outcome:
        outcome = self.report.add(Outcome(kind, str(object_id), REFUSED, reason, detail))
        event, object_type = ((EVENT_SAMPLE_REFUSED, "sample") if kind == "sample"
                              else (EVENT_EXHIBIT_REFUSED, "evidence"))
        if self.apply:
            try:
                with self._c.transaction():
                    self._audit(event, object_type, object_id, case_id,
                                {"reason": reason, "run_id": self.report.run_id,
                                 "authority": self.authority, **detail, **self.where},
                                outcome="DENIED")
            except Exception as exc:  # noqa: BLE001 - the refusal stands; say the row is missing
                self.report.warnings.append(
                    f"the refusal of {kind} {object_id} could not be written to the audit log "
                    f"({type(exc).__name__}).")
        return outcome

    def _audit(self, action: str, object_type: str, object_id: UUID | None, case_id: UUID | None,
               detail: dict, *, outcome: str = "SUCCESS") -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, case_id, outcome, detail)
               VALUES (%s, 'USER', %s, %s, %s, %s, %s, %s)""",
            (self.actor_id, action, object_type, object_id, case_id, outcome, Json(detail)))

    def _record_run(self) -> None:
        """One RESTORE_RUN row of counts: the run, the authority and where it ran. Written also when
        nothing was restored, so the log shows that a restore was tried."""
        detail = {"run_id": self.report.run_id, "authority": self.authority, **self.where,
                  "counts": self.report.counts(), "adopt": self.adopt, "limit": self.limit,
                  "cases_named": len(self.cases),
                  "evidence_mirror": self.evidence_mirror is not None,
                  "preserved_mirror": self.preserved_mirror is not None}
        try:
            with self._c.transaction():
                self._audit(EVENT_RUN, "restore_run", UUID(self.report.run_id), None, detail)
        except Exception as exc:  # noqa: BLE001
            self.report.warnings.append(
                f"the run's summary could not be written to the audit log ({type(exc).__name__}).")


class _PurgedMeanwhile(Exception):
    """The exhibit was purged between the first read of its row and the record."""


class _ListingRefused(Exception):
    """The store would not list the versions of a key, so an earlier run's object cannot be found."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
