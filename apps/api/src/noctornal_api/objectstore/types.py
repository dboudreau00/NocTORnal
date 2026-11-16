"""What a store answers, as plain values that carry no client library's types."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: The two S3 retention modes. Only COMPLIANCE is ever written: GOVERNANCE yields to anyone holding
#: s3:BypassGovernanceRetention, the root credential included (docs/16 C2).
COMPLIANCE = "COMPLIANCE"
GOVERNANCE = "GOVERNANCE"


@dataclass(frozen=True)
class PutResult:
    """The version the store kept, or None on a bucket that is not versioned."""
    version_id: str | None


@dataclass(frozen=True)
class ObjectInfo:
    """A HEAD of one object version."""
    size: int
    version_id: str | None
    last_modified: datetime | None
    etag: str | None = None


@dataclass(frozen=True)
class VersionInfo:
    """One entry of a versioned listing. A delete marker holds no bytes."""
    key: str
    version_id: str | None
    is_delete_marker: bool
    is_latest: bool
    last_modified: datetime | None
    size: int | None = None


@dataclass(frozen=True)
class RetentionInfo:
    """The retention a store reports on one version."""
    mode: str | None
    until: datetime | None


@dataclass(frozen=True)
class KeylessDelete:
    """What a DELETE that named no version did. On a versioned bucket it adds a delete marker and removes
    nothing, so `delete_marker` True means the bytes are still there behind it. None when the store did
    not say."""
    delete_marker: bool | None
    version_id: str | None


@dataclass(frozen=True)
class DefaultRetention:
    """A bucket's default retention, as its lock configuration states it."""
    mode: str | None
    days: int | None
    years: int | None


@dataclass(frozen=True)
class BucketCaps:
    """A bucket's own account of itself. ADVISORY ONLY: it explains a failure in a sentence and is never
    a reason to pass, because a store can report a lock it does not enforce (docs/17 F24). None in a
    field means the store would not say."""
    exists: bool | None
    versioning: str | None
    object_lock: bool | None
    default_retention: DefaultRetention | None
