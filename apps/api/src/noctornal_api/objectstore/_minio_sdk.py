"""The one module that imports minio: `ObjectStore` over minio-py (pinned in constraints.txt).

minio-py speaks plain S3 (SigV4, object lock, versions, legal holds, a region), not a MinIO protocol, so the
same client serves both profiles. Keeping it behind this one file is what makes a replacement one file:
if the SDK is ever archived or breaks a conformance leg, boto3 would take this module's place and nothing
else would change (docs/22). A bump of the pin is permitted by the conformance suite, run on every store
the deployment supports, and by nothing else.

Every call is translated at this boundary: `S3Error` becomes `errors.StoreRefusal` (keeping the store's
code, message and HTTP status), the SDK's non-S3 answers (`ServerError`, `InvalidResponseError`) become
`errors.StoreBadAnswer`, and a transport failure (urllib3's errors and `OSError`) becomes
`errors.StoreUnreachable`, saying whether the request can have reached the store. A listing is lazy, so
its translation runs at every step of the iteration, not only at the call.

`delete_key` reads the DELETE's own answer through the SDK's request method, because `remove_object`
returns nothing and the answer is the only way to learn, without permission to list versions, whether the
delete removed the object or hid it behind a delete marker on a versioned bucket.
"""
from __future__ import annotations

import io
from collections.abc import Iterator
from datetime import datetime

import urllib3
from minio import Minio
from minio.commonconfig import COMPLIANCE
from minio.error import InvalidResponseError, S3Error, ServerError
from minio.objectlockconfig import DAYS, YEARS, ObjectLockConfig
from minio.retention import Retention

from noctornal_api.objectstore import errors, types
from noctornal_api.objectstore.settings import StoreSettings

#: What a store answers on a bucket that has no lock configuration.
_NO_LOCK_CONFIG = frozenset({"ObjectLockConfigurationNotFoundError",
                             "NoSuchObjectLockConfiguration"})


class _Translated:
    """Turns whatever the SDK or the transport raised inside it into this package's errors."""

    def __init__(self, operation: str) -> None:
        self.operation = operation

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is None:
            return False
        if isinstance(exc, S3Error):
            status = getattr(getattr(exc, "response", None), "status", None)
            raise errors.refusal(exc.code or "UnknownError", exc.message,
                                 status=status, operation=self.operation) from exc
        if isinstance(exc, ServerError):
            raise errors.StoreBadAnswer(
                f"{type(exc).__name__}: {str(exc)[:200]}", status=exc.status_code,
                operation=self.operation) from exc
        if isinstance(exc, InvalidResponseError):
            raise errors.StoreBadAnswer(
                f"{type(exc).__name__}: {str(exc)[:200]}",
                status=getattr(exc, "_code", None), operation=self.operation) from exc
        if isinstance(exc, (urllib3.exceptions.HTTPError, OSError)):
            raise errors.StoreUnreachable(
                f"{type(exc).__name__}: {str(exc)[:200]}",
                never_reached=errors.never_reached_by(exc),
                operation=self.operation) from exc
        return False


def _is_true(value) -> bool:
    return str(value).strip().lower() == "true"


class MinioStore:
    """An `ObjectStore` over one minio-py client. `http` is the caller's pool (`pools`), or None for the
    SDK's own."""

    def __init__(self, settings: StoreSettings, *, http=None) -> None:
        self.settings = settings
        self.profile = settings.profile
        self.host = settings.host
        self._client = Minio(settings.endpoint, access_key=settings.access_key,
                             secret_key=settings.secret_key, secure=settings.secure,
                             region=settings.region, http_client=http)
        if settings.addressing == "virtual":
            self._client.enable_virtual_style_endpoint()
        elif settings.addressing == "path":
            self._client.disable_virtual_style_endpoint()

    def __repr__(self) -> str:
        return f"MinioStore({self.profile} at {self.host})"

    # -- objects ---------------------------------------------------------------

    def put(self, bucket: str, key: str, data: bytes, *,
            media_type: str = "application/octet-stream",
            retain_until: datetime | None = None,
            legal_hold: bool = False) -> types.PutResult:
        retention = (Retention(COMPLIANCE, retain_until)
                     if retain_until is not None else None)
        with _Translated("put"):
            result = self._client.put_object(
                bucket, key, io.BytesIO(data), length=len(data),
                content_type=media_type, retention=retention,
                legal_hold=legal_hold)
        return types.PutResult(version_id=getattr(result, "version_id", None))

    def get(self, bucket: str, key: str, *, version_id: str | None = None) -> bytes:
        with _Translated("get"):
            response = self._client.get_object(bucket, key, version_id=version_id)
            try:
                return response.read()
            finally:
                response.close()
                response.release_conn()

    def head(self, bucket: str, key: str, *,
             version_id: str | None = None) -> types.ObjectInfo:
        with _Translated("head"):
            stat = self._client.stat_object(bucket, key, version_id=version_id)
        return types.ObjectInfo(size=stat.size, version_id=stat.version_id,
                                last_modified=stat.last_modified, etag=stat.etag)

    def list_versions(self, bucket: str, prefix: str) -> Iterator[types.VersionInfo]:
        with _Translated("list_versions"):
            listing = iter(self._client.list_objects(bucket, prefix=prefix,
                                                     include_version=True))
        return self._versions(listing)

    @staticmethod
    def _versions(listing) -> Iterator[types.VersionInfo]:
        while True:
            try:
                with _Translated("list_versions"):
                    item = next(listing)
            except StopIteration:
                return
            if getattr(item, "is_dir", False):
                # A common prefix, not a version: the listing is one level deep, as it always was.
                continue
            yield types.VersionInfo(
                key=item.object_name, version_id=item.version_id,
                is_delete_marker=bool(item.is_delete_marker),
                is_latest=_is_true(item.is_latest),
                last_modified=item.last_modified, size=item.size)

    def get_retention(self, bucket: str, key: str,
                      version_id: str | None) -> types.RetentionInfo | None:
        with _Translated("get_retention"):
            held = self._client.get_object_retention(bucket, key, version_id=version_id)
        if held is None:
            return None
        return types.RetentionInfo(mode=held.mode, until=held.retain_until_date)

    def set_compliance_retention(self, bucket: str, key: str, version_id: str | None,
                                 until: datetime) -> None:
        with _Translated("set_retention"):
            self._client.set_object_retention(bucket, key, Retention(COMPLIANCE, until),
                                              version_id=version_id)

    def legal_hold_is_on(self, bucket: str, key: str,
                         version_id: str | None = None) -> bool:
        with _Translated("legal_hold"):
            return bool(self._client.is_object_legal_hold_enabled(
                bucket, key, version_id=version_id))

    def set_legal_hold(self, bucket: str, key: str, version_id: str | None,
                       on: bool) -> None:
        with _Translated("set_legal_hold"):
            if on:
                self._client.enable_object_legal_hold(bucket, key, version_id=version_id)
            else:
                self._client.disable_object_legal_hold(bucket, key, version_id=version_id)

    def delete_version(self, bucket: str, key: str, version_id: str) -> None:
        if not version_id:
            # A DELETE without a version on a versioned bucket removes nothing; it is `delete_key`, asked
            # for by name, never this by accident.
            raise ValueError("delete_version needs a version id")
        with _Translated("delete_version"):
            self._client.remove_object(bucket, key, version_id=version_id)

    def delete_key(self, bucket: str, key: str) -> types.KeylessDelete:
        with _Translated("delete_key"):
            response = self._client._execute("DELETE", bucket, key)
        marker = response.headers.get("x-amz-delete-marker")
        return types.KeylessDelete(
            delete_marker=_is_true(marker) if marker is not None else False,
            version_id=response.headers.get("x-amz-version-id"))

    # -- buckets ---------------------------------------------------------------

    def bucket_exists(self, bucket: str) -> bool:
        with _Translated("bucket_exists"):
            return bool(self._client.bucket_exists(bucket))

    def make_bucket(self, bucket: str, *, object_lock: bool) -> None:
        with _Translated("make_bucket"):
            self._client.make_bucket(bucket, object_lock=object_lock)

    def remove_bucket(self, bucket: str) -> None:
        with _Translated("remove_bucket"):
            self._client.remove_bucket(bucket)

    def set_default_retention(self, bucket: str, *, days: int) -> None:
        with _Translated("set_default_retention"):
            self._client.set_object_lock_config(
                bucket, ObjectLockConfig(COMPLIANCE, days, DAYS))

    def bucket_capabilities(self, bucket: str) -> types.BucketCaps:
        try:
            exists = self.bucket_exists(bucket)
        except errors.StoreError:
            exists = None
        if exists is False:
            return types.BucketCaps(False, None, None, None)
        versioning = None
        try:
            with _Translated("get_versioning"):
                versioning = self._client.get_bucket_versioning(bucket).status_string
        except errors.StoreError:
            pass
        lock, default = None, None
        try:
            with _Translated("get_lock_config"):
                config = self._client.get_object_lock_config(bucket)
        except errors.StoreRefusal as exc:
            if exc.code in _NO_LOCK_CONFIG:
                lock = False
        except errors.StoreError:
            pass
        else:
            lock = True
            if config.mode is not None:
                default = types.DefaultRetention(
                    mode=config.mode,
                    days=config.duration if config.duration_unit == DAYS else None,
                    years=config.duration if config.duration_unit == YEARS else None)
        return types.BucketCaps(exists, versioning, lock, default)
