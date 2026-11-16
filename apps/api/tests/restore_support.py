"""Shared set-up for the restore tests: an exhibit lodged into one in-process store, a second store that
never held it, and the mirror directory a backup would have left. Not a test module.

`FakeS3` (objectstore_helpers) is the store: versions, COMPLIANCE retention and legal holds, with AWS's
vocabulary. `EvidenceStorage` and `PreservationStorage` are built around it without their constructors,
which read the process environment, so no test reaches a real store.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

from objectstore_helpers import FakeS3


def evidence_storage(store: FakeS3, bucket: str = "evidence-b"):
    from noctornal_api.evidence import EvidenceStorage
    if not store.bucket_exists(bucket):
        store.make_bucket(bucket, object_lock=True)
    storage = EvidenceStorage.__new__(EvidenceStorage)
    storage._bucket = bucket
    storage.store = store
    return storage


def preservation_storage(store: FakeS3, bucket: str = "held-b"):
    from noctornal_api.samples import PreservationStorage
    if not store.bucket_exists(bucket):
        store.make_bucket(bucket, object_lock=True)
    storage = PreservationStorage.__new__(PreservationStorage)
    storage.bucket = bucket
    storage.store = store
    return storage


def foreign_version_ids(store: FakeS3) -> FakeS3:
    """The store as MinIO answers a version id another store issued: `InvalidArgument` (HTTP 400), where
    FakeS3 says `NoSuchVersion` for any id it does not hold."""
    from noctornal_api.objectstore import errors
    real = store.get

    def get(bucket, key, *, version_id=None):
        try:
            return real(bucket, key, version_id=version_id)
        except errors.ObjectMissing as exc:
            if version_id is not None and exc.code == "NoSuchVersion":
                raise errors.refusal("InvalidArgument", "Invalid version id specified",
                                     status=400) from None
            raise
    store.get = get
    return store


def write_mirror(root: Path, key: str, data: bytes) -> Path:
    """The file `mc mirror` would have left for `key`: the key's own path under the root."""
    path = root.joinpath(*key.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def soon(seconds: int = 120) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def new_id() -> str:
    return uuid4().hex[:8]


@dataclass
class Lodged:
    id: UUID
    key: str
    data: bytes
    version: str | None


@dataclass
class World:
    """One lost store the exhibits were lodged into, one fresh store that never held them, and the mirror."""
    conn: object
    boss: UUID
    case_id: UUID
    mirror: Path
    lost: FakeS3 = field(default_factory=FakeS3)
    fresh: FakeS3 = field(default_factory=FakeS3)

    def __post_init__(self) -> None:
        from noctornal_api.evidence import EvidenceService
        self.lost_storage = evidence_storage(self.lost)
        self.fresh_storage = evidence_storage(self.fresh)
        self.lost_svc = EvidenceService(self.conn, self.lost_storage)
        self.svc = EvidenceService(self.conn, self.fresh_storage)

    def lodge(self, data: bytes | None = None, *, mirror: bool = True, **ingest) -> Lodged:
        """An exhibit lodged into the lost store, and (by default) the file a mirror of it holds."""
        data = data if data is not None else b"exhibit " + uuid4().hex.encode()
        res = self.lost_svc.ingest(
            case_id=self.case_id, title=f"t-{new_id()}", media_type="image/png", data=data,
            acquired_by=self.boss, acquisition_method="MANUAL_UPLOAD", **ingest)
        key, version = self.conn.execute(
            "SELECT storage_key, storage_version_id FROM core.evidence WHERE id = %s",
            (res.evidence_id,)).fetchone()
        if mirror:
            write_mirror(self.mirror, key, data)
        return Lodged(res.evidence_id, key, data, version)

    def restore(self, **kw):
        """A real run against the fresh store. A lock of two minutes unless the test asks otherwise: no test
        sets a lock a deployment's day long."""
        from noctornal_api.restore import Restore
        kw.setdefault("apply", True)
        if kw["apply"]:
            kw.setdefault("actor_id", self.boss)
            kw.setdefault("authority", "TICKET-2026-1114")
        kw.setdefault("evidence", self.fresh_storage)
        kw.setdefault("evidence_mirror", self.mirror)
        kw.setdefault("where", {"via": "test", "host": "h", "os_user": "u"})
        kw.setdefault("cases", [self.case_id])
        return Restore(self.conn, **kw).run()

    def versions(self, store: FakeS3 | None = None, bucket: str = "evidence-b") -> list:
        store = store or self.fresh
        return [v for v in store.list_versions(bucket, "") if not v.is_delete_marker]

    def count(self, sql: str, *params) -> int:
        return self.conn.execute(sql, params).fetchone()[0]

    def restored_rows(self, evidence_id: UUID) -> list:
        return self.conn.execute(
            "SELECT detail, actor_id, hash_verified FROM core.evidence_custody "
            "WHERE evidence_id = %s AND action = 'RESTORED' ORDER BY id", (evidence_id,)).fetchall()

    def audit(self, action: str, object_id: UUID | None = None) -> list:
        return self.conn.execute(
            "SELECT outcome, detail, actor_id FROM audit.event WHERE action = %s "
            "AND (%s::uuid IS NULL OR object_id = %s) ORDER BY seq",
            (action, object_id, object_id)).fetchall()


HELD = "held-b"


@dataclass
class Preserved:
    """A preserved sample as the lost store left it, and what a test needs to doctor or check it."""
    id: UUID
    key: str
    plaintext: bytes
    ciphertext: bytes
    data_key: bytes
    version: str | None
    bucket: str


@dataclass
class SampleWorld:
    """The preserved-sample twin of `World`: samples preserved into one in-process store under a legal hold,
    a mirror of the preservation bucket, and a second store that never held them."""
    conn: object
    boss: UUID
    case_id: UUID
    mirror: Path
    lost: FakeS3 = field(default_factory=FakeS3)
    fresh: FakeS3 = field(default_factory=FakeS3)

    def __post_init__(self) -> None:
        self.lost_storage = preservation_storage(self.lost, HELD)
        self.fresh_storage = preservation_storage(self.fresh, HELD)

    def preserve(self, plaintext: bytes | None = None, *, mirror: bool = True, bucket: str = HELD,
                 classification: str = "AMBER", sha1: bool = True, md5: bool = True,
                 case_id: UUID | None = None, version: bool = True) -> Preserved:
        """A rejected sample whose ciphertext sits in the lost store under a hold, and (by default) the file a
        mirror of the preservation bucket holds for it. The row is what a rejection writes."""
        import hashlib
        import os

        from noctornal_api.samples import _xor_stream
        from noctornal_api.security import envelope
        plaintext = plaintext if plaintext is not None else b"MZ sample " + uuid4().hex.encode()
        data_key = os.urandom(32)
        blob, key_id = envelope.encrypt(data_key.hex())
        ciphertext = bytes(_xor_stream(plaintext, data_key))
        sha256 = hashlib.sha256(plaintext).digest()
        key = f"preserved/{sha256.hex()[:2]}/{sha256.hex()}"
        if not self.lost.bucket_exists(bucket):
            self.lost.make_bucket(bucket, object_lock=True)
        lodged = self.lost.put(bucket, key, ciphertext, legal_hold=True).version_id
        sid = self.conn.execute(
            """INSERT INTO lab.sample
                   (case_id, sha256, sha1, md5, byte_size, storage_key, storage_bucket,
                    data_key_ciphertext, data_key_id, submitted_by, state, reject_reason,
                    classification, preserved_bucket, preserved_key, preserved_version_id, preserved_at)
               VALUES (%s, %s, %s, %s, %s, %s, 'working-b', %s, %s, %s, 'REJECTED', 'test',
                       %s::core.tlp, %s, %s, %s, now())
               RETURNING id""",
            (case_id or self.case_id, sha256,
             hashlib.sha1(plaintext, usedforsecurity=False).digest() if sha1 else None,
             hashlib.md5(plaintext, usedforsecurity=False).digest() if md5 else None,
             len(plaintext), f"w/{uuid4().hex}", blob, key_id, self.boss, classification, bucket, key,
             lodged if version else None)).fetchone()[0]
        if mirror:
            write_mirror(self.mirror, key, ciphertext)
        return Preserved(sid, key, plaintext, ciphertext, data_key, lodged if version else None, bucket)

    def restore(self, **kw):
        """A real run against the fresh store."""
        from noctornal_api.restore import Restore
        kw.setdefault("apply", True)
        if kw["apply"]:
            kw.setdefault("actor_id", self.boss)
            kw.setdefault("authority", "TICKET-2026-1114")
        kw.setdefault("preserved", self.fresh_storage)
        kw.setdefault("preserved_mirror", self.mirror)
        kw.setdefault("where", {"via": "test", "host": "h", "os_user": "u"})
        kw.setdefault("cases", [self.case_id])
        return Restore(self.conn, **kw).run()

    def versions(self, store: FakeS3 | None = None, bucket: str = HELD) -> list:
        store = store or self.fresh
        if not store.bucket_exists(bucket):
            return []
        return [v for v in store.list_versions(bucket, "") if not v.is_delete_marker]

    def count(self, sql: str, *params) -> int:
        return self.conn.execute(sql, params).fetchone()[0]

    def restored_rows(self, sample_id: UUID) -> list:
        return self.conn.execute(
            "SELECT detail, actor_id, actor_kind FROM lab.sample_access "
            "WHERE sample_id = %s AND action = 'RESTORED' ORDER BY id", (sample_id,)).fetchall()

    def audit(self, action: str, object_id: UUID | None = None) -> list:
        return self.conn.execute(
            "SELECT outcome, detail, actor_id FROM audit.event WHERE action = %s "
            "AND (%s::uuid IS NULL OR object_id = %s) ORDER BY seq",
            (action, object_id, object_id)).fetchall()
