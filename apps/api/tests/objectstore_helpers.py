"""An in-process S3 store with AWS's semantics, for the conformance suite's self-test.

`FakeS3` speaks the seam's interface (`objectstore.store.ObjectStore`) and behaves as AWS documents a bucket with
object lock: versions, delete markers, COMPLIANCE retention a version delete cannot defeat, legal holds, and the
`AccessDenied` "Access Denied" a locked version's delete is refused with, which is the same answer a policy denial
gets. Each flag breaks it in one of the ways real stores have been seen to, so the self-test can show the named
check catches it:

- `deletes_locked`: accepts a COMPLIANCE retention and lets the version delete succeed (SeaweedFS 8350, 11333);
- `marker_on_version_delete`: answers a version delete of a locked version with success and only adds a marker;
- `records_governance`: records GOVERNANCE whatever was asked;
- `ignores_legal_hold`: reads a hold back ON and deletes the version anyway;
- `lets_retention_shorten`: lets a COMPLIANCE retention be moved earlier;
- `no_marker_for_absent_key`: a keyless delete of an absent key adds no marker;
- `no_version_id`: keeps versions and answers a put with no version id.

It is an emulator: it proves the suite, never a store.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from noctornal_api.objectstore import errors
from noctornal_api.objectstore.types import (
    COMPLIANCE,
    GOVERNANCE,
    BucketCaps,
    DefaultRetention,
    KeylessDelete,
    ObjectInfo,
    PutResult,
    RetentionInfo,
    VersionInfo,
)

DENIED = ("AccessDenied", "Access Denied")


@dataclass
class _Version:
    id: str
    data: bytes
    retention: RetentionInfo | None = None
    hold: bool = False
    marker: bool = False
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class _Bucket:
    lock: bool
    objects: dict[str, list[_Version]] = field(default_factory=dict)
    default_days: int | None = None

    @property
    def versioned(self) -> bool:
        return self.lock


class FakeS3:
    """See the module. `account(delete_denied=True)` is a second credential on the same store."""

    def __init__(self, *, profile: str = "s3", deletes_locked=False, marker_on_version_delete=False,
                 records_governance=False, ignores_legal_hold=False, lets_retention_shorten=False,
                 no_marker_for_absent_key=False, no_version_id=False) -> None:
        self.profile, self.host = profile, "fake-s3:0"
        self.deletes_locked = deletes_locked
        self.marker_on_version_delete = marker_on_version_delete
        self.records_governance = records_governance
        self.ignores_legal_hold = ignores_legal_hold
        self.lets_retention_shorten = lets_retention_shorten
        self.no_marker_for_absent_key = no_marker_for_absent_key
        self.no_version_id = no_version_id
        self.delete_denied = False
        self.buckets: dict[str, _Bucket] = {}

    def account(self, *, delete_denied: bool) -> FakeS3:
        other = FakeS3.__new__(FakeS3)
        other.__dict__.update(self.__dict__)
        other.delete_denied = delete_denied
        return other

    # -- helpers -------------------------------------------------------------------------------------

    def _bucket(self, name: str) -> _Bucket:
        if name not in self.buckets:
            raise errors.refusal("NoSuchBucket", "The specified bucket does not exist", status=404)
        return self.buckets[name]

    def _version(self, bucket: str, key: str, version_id: str | None) -> _Version:
        versions = self._bucket(bucket).objects.get(key, [])
        if version_id is None:
            if not versions or versions[-1].marker:
                raise errors.refusal("NoSuchKey", "The specified key does not exist.", status=404)
            return versions[-1]
        for v in versions:
            if v.id == version_id:
                return v
        raise errors.refusal("NoSuchVersion", "The specified version does not exist.", status=404)

    def _mode(self) -> str:
        return GOVERNANCE if self.records_governance else COMPLIANCE

    @staticmethod
    def _locked_by_retention(v: _Version) -> bool:
        return (v.retention is not None and v.retention.until is not None
                and v.retention.until > datetime.now(timezone.utc))

    # -- objects -------------------------------------------------------------------------------------

    def put(self, bucket, key, data, *, media_type="application/octet-stream", retain_until=None,
            legal_hold=False):
        b = self._bucket(bucket)
        if (retain_until is not None or legal_hold) and not b.lock:
            raise errors.refusal("InvalidRequest", "Bucket is missing Object Lock Configuration",
                                 status=400)
        retention = RetentionInfo(self._mode(), retain_until) if retain_until is not None else None
        if b.versioned:
            v = _Version(uuid.uuid4().hex, bytes(data), retention, legal_hold)
            b.objects.setdefault(key, []).append(v)
            return PutResult(None if self.no_version_id else v.id)
        b.objects[key] = [_Version("null", bytes(data))]
        return PutResult(None)

    def get(self, bucket, key, *, version_id=None):
        return self._version(bucket, key, version_id).data

    def head(self, bucket, key, *, version_id=None):
        v = self._version(bucket, key, version_id)
        return ObjectInfo(size=len(v.data), version_id=None if v.id == "null" else v.id,
                          last_modified=v.at)

    def list_versions(self, bucket, prefix):
        b = self._bucket(bucket)
        for key in sorted(k for k in b.objects if k.startswith(prefix)):
            versions = b.objects[key]
            for i, v in enumerate(reversed(versions)):
                yield VersionInfo(key=key, version_id=v.id, is_delete_marker=v.marker,
                                  is_latest=i == 0, last_modified=v.at,
                                  size=None if v.marker else len(v.data))

    def get_retention(self, bucket, key, version_id):
        return self._version(bucket, key, version_id).retention

    def set_compliance_retention(self, bucket, key, version_id, until):
        v = self._version(bucket, key, version_id)
        held = v.retention
        if (held is not None and held.mode == COMPLIANCE and held.until is not None
                and until < held.until and not self.lets_retention_shorten):
            raise errors.refusal(*DENIED, status=403)
        v.retention = RetentionInfo(self._mode(), until)

    def legal_hold_is_on(self, bucket, key, version_id=None):
        return self._version(bucket, key, version_id).hold

    def set_legal_hold(self, bucket, key, version_id, on):
        self._version(bucket, key, version_id).hold = bool(on)

    def delete_version(self, bucket, key, version_id):
        if not version_id:
            raise ValueError("delete_version needs a version id")
        if self.delete_denied:
            raise errors.refusal(*DENIED, status=403)
        b = self._bucket(bucket)
        v = self._version(bucket, key, version_id)
        locked = ((self._locked_by_retention(v) and not self.deletes_locked)
                  or (v.hold and not self.ignores_legal_hold))
        if locked and not v.marker:
            if self.marker_on_version_delete:
                b.objects[key].append(_Version(uuid.uuid4().hex, b"", marker=True))
                return
            raise errors.refusal(*DENIED, status=403)
        b.objects[key] = [x for x in b.objects[key] if x.id != version_id]
        if not b.objects[key]:
            del b.objects[key]

    def delete_key(self, bucket, key):
        b = self._bucket(bucket)
        if self.delete_denied:
            raise errors.refusal(*DENIED, status=403)
        if not b.versioned:
            b.objects.pop(key, None)
            return KeylessDelete(delete_marker=False, version_id=None)
        if self.no_marker_for_absent_key and key not in b.objects:
            return KeylessDelete(delete_marker=False, version_id=None)
        marker = _Version(uuid.uuid4().hex, b"", marker=True)
        b.objects.setdefault(key, []).append(marker)
        return KeylessDelete(delete_marker=True, version_id=marker.id)

    # -- buckets -------------------------------------------------------------------------------------

    def bucket_exists(self, bucket):
        return bucket in self.buckets

    def make_bucket(self, bucket, *, object_lock):
        if bucket in self.buckets:
            raise errors.refusal("BucketAlreadyOwnedByYou", "exists", status=409)
        self.buckets[bucket] = _Bucket(lock=object_lock)

    def remove_bucket(self, bucket):
        if self._bucket(bucket).objects:
            raise errors.refusal("BucketNotEmpty", "The bucket you tried to delete is not empty",
                                 status=409)
        del self.buckets[bucket]

    def set_default_retention(self, bucket, *, days):
        b = self._bucket(bucket)
        if not b.lock:
            raise errors.refusal("InvalidBucketState", "Object Lock configuration cannot be enabled",
                                 status=409)
        b.default_days = days

    def bucket_capabilities(self, bucket):
        if bucket not in self.buckets:
            return BucketCaps(False, None, None, None)
        b = self.buckets[bucket]
        default = (DefaultRetention(COMPLIANCE, b.default_days, None)
                   if b.default_days is not None else None)
        return BucketCaps(True, "Enabled" if b.versioned else None, b.lock, default)


class Unreachable:
    """A store nothing answers for: every call is a connection refused."""

    profile, host = "s3", "127.0.0.1:1"

    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise errors.StoreUnreachable("ConnectionRefusedError: refused", never_reached=True)
        return call
