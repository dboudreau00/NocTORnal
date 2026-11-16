"""How a refused delete is read: a lock, or something else.

Two rules, one per profile (`settings.PROFILES`), and every reader of a refused delete (the purge, the evidence
store, the working-bucket deletes and the readiness register) asks this module, so they cannot drift.

- `minio`, the default: `is_retention_refusal`, the code-and-message rule the bundled MinIO was measured with
  (`evidence.is_retention_refusal` is this function, kept importable under its old name). Nothing about it
  changed when the seam came in.
- `s3`: AWS answers a version-addressed delete of a locked object with `AccessDenied` "Access Denied", the
  same code and words as a policy denial, and Ceph RGW answers `AccessDenied` too. Words cannot tell the two
  apart, so this profile never reads a message: a refusal whose code could be a lock is resolved by STATE,
  reading the version's retention and legal hold back. It is LOCKED only when a hold is on or a retention is
  unexpired, DENIED when the state read is itself denied or shows no lock, and UNKNOWN otherwise; only
  LOCKED is ever recorded as a lock, so a policy denial stays a failure (docs/17 F24's safe direction).

State alone cannot credit a store, because a credential whose policy denies the delete and an object that is
genuinely locked give the same picture. So before the register credits a refused delete on the s3 profile it
runs `delete_control`: a keyless DELETE of a key nothing uses, which on a versioned bucket adds a delete
marker, and the removal of that marker by its version id. Both succeeding shows this credential may delete
versions in this bucket, so a refusal of the locked canary is the lock's and not the policy's. A marker is not
retention-protected, so the control works under a bucket default of COMPLIANCE 365 days and leaves nothing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from noctornal_api.objectstore.errors import StoreError, StoreRefusal
from noctornal_api.objectstore.settings import S3

#: What a refused delete of one version was, on either profile.
LOCKED, DENIED, UNKNOWN = "LOCKED", "DENIED", "UNKNOWN"
#: Codes a store has been seen to answer a delete of a locked version with: AWS and Ceph `AccessDenied`,
#: MinIO `InvalidRequest`, others `MethodNotAllowed`, `ObjectLocked` or a 409 conflict. On the s3 profile
#: only these are resolved by state; any other refusal of a version delete stays a failure.
LOCK_CANDIDATE_CODES = frozenset({"AccessDenied", "InvalidRequest", "MethodNotAllowed",
                                  "ObjectLocked", "OperationAborted", "Conflict"})
#: The key the permission control deletes. Never written: a keyless DELETE of it only adds a marker.
DELETE_CONTROL_KEY = ".noctornal-delete-control"

#: Codes that mean "the object is under retention" and nothing else. The
#: S3 vendors do not agree on one, so there are two.
_RETENTION_REFUSAL_CODES = frozenset({"RetentionPeriodNotMet", "MethodNotAllowed"})
#: Codes that mean "there is NO lock configuration", whatever the message
#: says, and MinIO's message for the first one contains "Object Lock".
_NOT_A_LOCK_CODES = frozenset({
    "ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration",
})
#: What a store says when a retention lock is the reason. MinIO:
#: "Object is WORM protected and cannot be overwritten".
_LOCK_WORDS = ("worm", "retention", "object lock")


def is_retention_refusal(exc: Exception) -> bool:
    """True only when the store said the object is under a retention lock.

    LOCKED_UNTIL_RETENTION is a specific claim ("the bytes will become deletable when a retention expires") and
    it is written into an append-only tombstone. So this errs towards FAILED: a failure an operator investigates
    is recoverable; a permissions refusal recorded as a lawful lock is a false record nobody revisits.

    A bare `AccessDenied` or `InvalidRequest` is not enough, since a read-only key or a bucket policy denying
    `s3:DeleteObject` would be recorded as a retention lock, and `ObjectLockConfigurationNotFoundError` means the
    bucket has NO lock configuration. `delete_every_version` and retention share this one function so they
    cannot drift: `delete_every_version` uses it to decide locked-versus-raise, and retention uses it to
    classify what a store without version enumeration raises.

    `AccessDenied` and `InvalidRequest` therefore need the MESSAGE to say worm / retention / object lock. The
    message is read, not `str(exc)`: a store's error could quote the resource and object name, and an exhibit
    whose key contains the word "retention" must not turn a policy denial into a lock (`errors.StoreRefusal`
    never quotes either). Message-only refusals from clients that carry no code (the governance test stubs
    raise RuntimeError("object is under a retention lock")) still count.

    MinIO refuses a COMPLIANCE-locked version with code `InvalidRequest` and message "Object is WORM protected
    and cannot be overwritten", not `AccessDenied`. `tests/test_evidence_lock_live_pg.py` re-measures that on
    every run so a vocabulary drift shows up here rather than in a tombstone.
    """
    code = getattr(exc, "code", None)
    if code in _NOT_A_LOCK_CODES:
        return False
    if code in _RETENTION_REFUSAL_CODES:
        return True
    message = getattr(exc, "message", None)
    text = str(message if message else exc).lower()
    return any(word in text for word in _LOCK_WORDS)


def _is_candidate(exc: Exception) -> bool:
    return (getattr(exc, "code", None) in LOCK_CANDIDATE_CODES
            or getattr(exc, "status", None) == 409)


def _aware(moment: datetime | None) -> datetime | None:
    if moment is None:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def lock_state(store, bucket: str, key: str, version_id: str | None,
               now: datetime | None = None) -> str:
    """LOCKED when the version reads back under a legal hold or an unexpired retention, DENIED when the read
    itself is denied or shows no lock, UNKNOWN when the store would not say. Never reads a message."""
    now = now or datetime.now(timezone.utc)
    try:
        retention = store.get_retention(bucket, key, version_id)
    except StoreRefusal as exc:
        return DENIED if exc.code == "AccessDenied" else UNKNOWN
    except StoreError:
        return UNKNOWN
    until = _aware(getattr(retention, "until", None)) if retention is not None else None
    if until is not None and until > now:
        return LOCKED
    try:
        held = store.legal_hold_is_on(bucket, key, version_id)
    except StoreRefusal as exc:
        return DENIED if exc.code == "AccessDenied" else UNKNOWN
    except StoreError:
        return UNKNOWN
    return LOCKED if held else DENIED


def classify_version_delete_refusal(store, bucket: str, key: str, version_id: str | None,
                                    exc: Exception, now: datetime | None = None) -> str:
    """LOCKED, DENIED or UNKNOWN for a refused delete of one version, by the store's profile (see above).
    The minio profile makes no extra call, so its answer is today's rule exactly."""
    if getattr(store, "profile", None) != S3:
        if is_retention_refusal(exc):
            return LOCKED
        return DENIED if getattr(exc, "code", None) == "AccessDenied" else UNKNOWN
    if not isinstance(exc, StoreRefusal) or not _is_candidate(exc):
        return UNKNOWN
    return lock_state(store, bucket, key, version_id, now)


def version_delete_is_locked(store, bucket: str, key: str, version_id: str | None,
                             exc: Exception) -> bool:
    """Whether a refused delete of one version was the store holding it under a lock. The one question
    `versions.delete_every_version` asks of a refusal."""
    return classify_version_delete_refusal(store, bucket, key, version_id, exc) == LOCKED


#: What the permission control found.
CONTROL_ALLOWED, CONTROL_DENIED, CONTROL_NO_MARKER, CONTROL_REFUSED = (
    "ALLOWED", "DENIED", "NO_MARKER", "REFUSED")


@dataclass(frozen=True)
class ControlResult:
    """`outcome` is one of the CONTROL_ words; `refusal` the store's answer where there was one, and `step`
    the refused step in a few words."""
    outcome: str
    refusal: StoreRefusal | None = None
    step: str = ""


def delete_control(store, bucket: str) -> ControlResult:
    """Whether this credential may delete versions in `bucket`, shown without touching anything that matters:
    a keyless DELETE of `DELETE_CONTROL_KEY`, then the removal of the marker it added by its version id. The
    marker's id comes from the DELETE's own answer, or from a listing when the store does not give it. A store
    that adds no marker for an absent key cannot run the control, and the caller fails closed (docs/22)."""
    try:
        answer = store.delete_key(bucket, DELETE_CONTROL_KEY)
    except StoreRefusal as exc:
        if exc.code == "AccessDenied":
            return ControlResult(CONTROL_DENIED, exc, "delete an object")
        return ControlResult(CONTROL_REFUSED, exc, "delete an object")
    marker = answer.version_id if answer.delete_marker else None
    if marker is None:
        try:
            marker = next((v.version_id for v in store.list_versions(bucket, DELETE_CONTROL_KEY)
                           if v.key == DELETE_CONTROL_KEY and v.is_delete_marker), None)
        except StoreRefusal as exc:
            if exc.code == "AccessDenied":
                return ControlResult(CONTROL_DENIED, exc, "list versions")
            return ControlResult(CONTROL_REFUSED, exc, "list versions")
    if marker is None:
        return ControlResult(CONTROL_NO_MARKER)
    try:
        store.delete_version(bucket, DELETE_CONTROL_KEY, marker)
    except StoreRefusal as exc:
        if exc.code == "AccessDenied":
            return ControlResult(CONTROL_DENIED, exc, "delete a version")
        return ControlResult(CONTROL_REFUSED, exc, "delete a version")
    return ControlResult(CONTROL_ALLOWED)
