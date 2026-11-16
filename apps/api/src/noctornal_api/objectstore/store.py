"""The interface every caller speaks, and the one place a store is built.

Every method takes the bucket, so one store serves a caller that touches two buckets (the readiness probe).
Every failure is an `errors.StoreError`: a refusal in the store's own code, a store that did not answer, or
an answer that is not S3. A retention is only ever COMPLIANCE, and there is no mode argument: GOVERNANCE
yields to anyone holding s3:BypassGovernanceRetention (docs/16 C2).

`set_legal_hold` exists for the conformance suite (`apps/api/store_conformance`), which must lift the holds
it sets to clean up and to prove a hold was the only thing in a delete's way. No product module calls it:
lifting a hold on a preserved sample is an operator's act under counsel's instruction, outside the product
(`samples.PreservationStorage`), and `tests/test_objectstore_boundary.py` holds the tree to that.
`remove_bucket` is for the same suite and the live tests, which make throwaway buckets and remove them.

`bucket_capabilities` is ADVISORY: it lets a failure explain itself in a sentence, and it is never a reason
to pass, because a store can report a lock it does not enforce (docs/17 F24).
"""
from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Protocol

from noctornal_api.objectstore.settings import StoreSettings
from noctornal_api.objectstore.types import (
    BucketCaps,
    KeylessDelete,
    ObjectInfo,
    PutResult,
    RetentionInfo,
    VersionInfo,
)


class ObjectStore(Protocol):
    #: `minio` or `s3` (`settings.PROFILES`): how a refused delete is read.
    profile: str
    #: `host:port` of the endpoint, for evidence and custody rows. Never a credential.
    host: str

    def put(self, bucket: str, key: str, data: bytes, *,
            media_type: str = "application/octet-stream",
            retain_until: datetime | None = None,
            legal_hold: bool = False) -> PutResult: ...

    def get(self, bucket: str, key: str, *, version_id: str | None = None) -> bytes: ...

    def head(self, bucket: str, key: str, *,
             version_id: str | None = None) -> ObjectInfo: ...

    def list_versions(self, bucket: str, prefix: str) -> Iterator[VersionInfo]: ...

    def get_retention(self, bucket: str, key: str,
                      version_id: str | None) -> RetentionInfo | None: ...

    def set_compliance_retention(self, bucket: str, key: str, version_id: str | None,
                                 until: datetime) -> None: ...

    def legal_hold_is_on(self, bucket: str, key: str,
                         version_id: str | None = None) -> bool: ...

    def set_legal_hold(self, bucket: str, key: str, version_id: str | None,
                       on: bool) -> None: ...

    def delete_version(self, bucket: str, key: str, version_id: str) -> None: ...

    def delete_key(self, bucket: str, key: str) -> KeylessDelete: ...

    def bucket_exists(self, bucket: str) -> bool: ...

    def make_bucket(self, bucket: str, *, object_lock: bool) -> None: ...

    def remove_bucket(self, bucket: str) -> None: ...

    def set_default_retention(self, bucket: str, *, days: int) -> None: ...

    def bucket_capabilities(self, bucket: str) -> BucketCaps: ...


def open_store(settings: StoreSettings, *, http=None) -> ObjectStore:
    """The store `settings` names, speaking through `http` (an urllib3 pool from `pools`) when the caller
    bounds its own calls, or the client library's default pool when it does not. The same client for both
    profiles: a profile chooses how a refusal is read, never how a request is made."""
    from noctornal_api.objectstore._minio_sdk import MinioStore

    return MinioStore(settings, http=http)
