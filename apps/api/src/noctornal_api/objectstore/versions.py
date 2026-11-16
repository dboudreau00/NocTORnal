"""Removing every version of a key, reporting a refusal as a refusal.

One function for every bucket, so the evidence purge and the working-bucket deletes cannot read a refusal
two ways. On a versioned bucket a DELETE that names no version removes nothing: it adds a delete marker and
returns success while every byte stays retrievable by version id. Destruction therefore enumerates the
versions and deletes each by its id, and says which were removed and which the store refused for a lock.
"""
from __future__ import annotations

from dataclasses import dataclass

from noctornal_api.objectstore.classify import version_delete_is_locked
from noctornal_api.objectstore.errors import StoreRefusal


@dataclass(frozen=True)
class VersionedDeleteResult:
    """What a versioned delete actually did, per key.

    Three counts rather than a boolean, because "the bytes are gone" and "the store refused" are different facts
    that a caller has to record differently, and merging them into one success is how a keyless `delete()`
    reports destructions it has not performed.

    `versions_seen` includes delete markers; `versions_removed` never does. Removing a marker is tidying up after
    a keyless delete, not destruction, and counting it as one would report a destruction that did not happen.
    """
    key: str
    versions_seen: int
    versions_removed: int
    versions_locked: int

    @property
    def fully_destroyed(self) -> bool:
        """Every real version is gone. FALSE while anything is locked:
        this is the value a tombstone may be written from."""
        return self.versions_locked == 0

    @property
    def outcome(self) -> str:
        """A one-word summary for logs and tests. NOT the tombstone vocabulary.

        The tombstone words (the CHECK on `core.purge_tombstone.storage_outcome`, migration 0032) are DELETED /
        LOCKED_UNTIL_RETENTION / FAILED / NOT_APPLICABLE, and two of the three values here, DESTROYED and
        NOTHING_TO_DELETE, would be refused by that CHECK. Only LOCKED_UNTIL_RETENTION coincides. So
        `retention._purge_evidence` maps the three COUNTS above onto its own vocabulary and never writes this
        string anywhere; `tests/test_evidence_versioned_delete.py` reads both sides and the migration to keep it
        that way.
        """
        if self.versions_locked:
            return "LOCKED_UNTIL_RETENTION"
        return "DESTROYED" if self.versions_removed else "NOTHING_TO_DELETE"


def delete_every_version(store, bucket: str, key: str) -> VersionedDeleteResult:
    """Remove every version of `key` in `bucket`, reporting refusals as refusals.

    Enumerate every version under the key, delete each by `version_id`, and separate the two outcomes that a
    keyless delete merges into silence: bytes actually gone, versus the store refusing because a lock holds
    them. A refusal is RETURNED as a count, not raised, because a caller (the purge) has to record it rather
    than abort a batch; anything that is neither a deletion nor a recognised lock refusal raises, because an
    unrecognised storage failure is not an outcome to write down as a lock (`classify`).

    The listing is a PREFIX match, so only versions of exactly `key` are touched. A marker left by an earlier
    keyless delete is removed and never counted. This deliberately does NOT send the GOVERNANCE-bypass header:
    acquiring that power silently is not a decision to make in a helper, and COMPLIANCE ignores it anyway.
    """
    removed, locked = 0, 0
    versions = [v for v in store.list_versions(bucket, key) if v.key == key]
    for v in versions:
        if v.is_delete_marker:
            store.delete_version(bucket, key, v.version_id)
            continue
        try:
            store.delete_version(bucket, key, v.version_id)
            removed += 1
        except StoreRefusal as exc:
            if version_delete_is_locked(store, bucket, key, v.version_id, exc):
                locked += 1
            else:
                raise
    return VersionedDeleteResult(
        key=key, versions_seen=len(versions),
        versions_removed=removed, versions_locked=locked)


class BytesKept(RuntimeError):
    """A working-bucket delete that left bytes behind: the store refused a version for a lock. A working
    bucket is never locked (docs/22), so this is a misconfigured bucket, and a caller must not record the
    object as gone."""


def delete_working_object(store, bucket: str, key: str) -> None:
    """Delete `key` from a working bucket (raw ingest, collected markup, samples) so that no byte is left.

    A plain DELETE first, which on an unversioned bucket removes the object and needs no permission beyond
    s3:DeleteObject, so a deployment whose working buckets are unversioned (the bundled stack) behaves as it
    always did. When the store answers that the DELETE only added a delete marker (`x-amz-delete-marker`), the
    bucket is versioned (AWS organisations often enforce it) and every byte is still retrievable by version
    id, so every version is then removed by its id (`delete_every_version`), which needs s3:ListBucketVersions
    and s3:DeleteObjectVersion on that bucket (docs/22). Raises `BytesKept` when a version stays."""
    answer = store.delete_key(bucket, key)
    if not answer.delete_marker:
        return
    result = delete_every_version(store, bucket, key)
    kept = result.versions_locked
    if kept:
        raise BytesKept(
            f"{bucket}/{key}: {kept} {'version is' if kept == 1 else 'versions are'} held by "
            f"a lock on a working bucket, which must be created without object lock")
