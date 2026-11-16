"""The collected raw markup store.

Its own bucket, content-addressed per source, NO object lock (a retention clock or a deletion order
must be able to remove it), and a delete that says whether an object went. The live leg runs only
against a MinIO this host names in MINIO_ENDPOINT.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest


def test_the_in_memory_store_round_trips_and_says_what_it_deleted():
    from noctornal_api.rawstore import InMemoryDocumentRawStorage, MissingObject

    store = InMemoryDocumentRawStorage()
    store.put("collect/aa/x", b"<p>x</p>")
    assert store.get("collect/aa/x") == b"<p>x</p>" and store.exists("collect/aa/x")
    assert store.delete("collect/aa/x") is True
    assert store.delete("collect/aa/x") is False
    with pytest.raises(MissingObject):
        store.get("collect/aa/x")


def test_the_key_is_the_digest_of_the_source_and_the_fragment():
    from noctornal_api.rawstore import document_raw_key

    a, b = uuid4(), uuid4()
    fragment = b"<article>same words</article>"
    key_a = document_raw_key(a, fragment)
    assert key_a == document_raw_key(a, fragment)
    assert key_a != document_raw_key(b, fragment), (
        "identical fragments from two sources never share an object")
    digest = hashlib.sha256(a.bytes + fragment).hexdigest()
    assert key_a == f"collect/{digest[:2]}/{digest}"


def test_no_store_is_configured_without_minio(monkeypatch):
    from noctornal_api.rawstore import default_document_raw_store

    for var in ("MINIO_ENDPOINT", "MINIO_ACCESS_KEY", "MINIO_SECRET_KEY",
                "OBJECT_STORE_ENDPOINT", "OBJECT_STORE_ACCESS_KEY", "OBJECT_STORE_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert default_document_raw_store() is None, (
        "never the in-memory store, which would lose markup on restart")


def test_the_bucket_name_has_one_default(monkeypatch):
    from noctornal_api.rawstore import COLLECT_RAW_BUCKET_DEFAULT, collect_raw_bucket

    monkeypatch.delenv("COLLECT_RAW_BUCKET", raising=False)
    assert collect_raw_bucket() == COLLECT_RAW_BUCKET_DEFAULT == "noctornal-collect-raw"


def test_the_compose_files_provision_the_bucket_without_a_lock():
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for compose in ("infra/production/compose.yml", "infra/docker-compose.yml"):
        text = (root / compose).read_text(encoding="utf-8")
        line = next((ln for ln in text.splitlines() if "noctornal-collect-raw" in ln),
                    None)
        assert line is not None, f"{compose} does not create the collected-markup bucket"
        assert "--with-lock" not in line, f"{compose} locks the collected-markup bucket"
    example = (root / "infra/production/secrets.env.example").read_text(encoding="utf-8")
    assert "COLLECT_RAW_BUCKET=noctornal-collect-raw" in example


@pytest.mark.skipif(not os.environ.get("MINIO_ENDPOINT"),
                    reason="no MinIO named; the live leg is skipped")
def test_the_live_store_puts_gets_deletes_and_has_no_object_lock(monkeypatch):
    from noctornal_api.rawstore import DocumentRawStorage

    monkeypatch.setenv("COLLECT_RAW_BUCKET", f"b0raw-{uuid4().hex[:8]}")
    store = DocumentRawStorage()
    try:
        store.ensure_bucket()
    except Exception as exc:  # noqa: BLE001 - a MinIO that is down is a skip
        pytest.skip(f"MinIO did not answer: {type(exc).__name__}")
    try:
        store.put("collect/ab/live", b"<p>live</p>")
        assert store.get("collect/ab/live") == b"<p>live</p>"
        assert store.store.bucket_capabilities(store.bucket).object_lock is False
        assert store.delete("collect/ab/live") is True
        assert store.exists("collect/ab/live") is False
    finally:
        for v in store.store.list_versions(store.bucket, "collect/ab/"):
            store.store.delete_version(store.bucket, v.key, v.version_id or "null")
        store.store.remove_bucket(store.bucket)


class _RefusingStore:
    """An `ObjectStore` stand-in whose reads and HEADs raise `exc`; records any delete."""

    profile = "minio"
    host = "stub:9000"

    def __init__(self, exc):
        self.exc = exc
        self.deleted: list[str] = []

    def get(self, bucket, key, *, version_id=None):
        raise self.exc

    def head(self, bucket, key, *, version_id=None):
        raise self.exc

    def delete_key(self, bucket, key):
        self.deleted.append(key)


def _with_store(cls, store):
    obj = cls.__new__(cls)
    obj.store, obj._bucket = store, "b"
    return obj


@pytest.mark.parametrize("cls_name", ["RawBatchStorage", "DocumentRawStorage"])
def test_a_denied_read_is_not_a_missing_object(cls_name):
    """A refusal that is not 'nothing there' (a denied read, a missing bucket) used to become MissingObject,
    whose sentence tells a partner to resend bytes the store still holds. Only a missing key is missing."""
    from noctornal_api import rawstore
    from noctornal_api.objectstore.errors import StoreRefusal, refusal

    for exc in (refusal("AccessDenied", "Access Denied."), refusal("NoSuchBucket", "gone")):
        storage = _with_store(getattr(rawstore, cls_name), _RefusingStore(exc))
        with pytest.raises(StoreRefusal) as info:
            storage.get("ingest/aa/x")
        assert not isinstance(info.value, rawstore.MissingObject)
        assert info.value.code == exc.code
    storage = _with_store(getattr(rawstore, cls_name),
                          _RefusingStore(refusal("NoSuchKey", "none")))
    with pytest.raises(rawstore.MissingObject):
        storage.get("ingest/aa/x")


def test_exists_does_not_swallow_a_refusal_so_a_purge_never_reports_nothing_there():
    """`exists()` answered False on ANY refusal, so a purge on a denied HEAD was told 'nothing there' and
    recorded the markup as gone while the bytes stayed. A denial now raises and nothing is deleted."""
    from noctornal_api.objectstore.errors import refusal
    from noctornal_api.rawstore import DocumentRawStorage

    denied = _RefusingStore(refusal("AccessDenied", "Access Denied."))
    storage = _with_store(DocumentRawStorage, denied)
    with pytest.raises(Exception) as info:
        storage.delete("collect/aa/x")
    assert getattr(info.value, "code", None) == "AccessDenied"
    assert denied.deleted == []
    missing = _with_store(DocumentRawStorage, _RefusingStore(refusal("NoSuchKey", "none")))
    assert missing.exists("collect/aa/x") is False
    assert missing.delete("collect/aa/x") is False


class _VersionedWorkingStore:
    """A versioned working bucket: a keyless DELETE adds a marker and removes nothing, as S3 does."""

    profile = "minio"
    host = "stub:9000"

    def __init__(self, versions, *, locked=()):
        from noctornal_api.objectstore.types import VersionInfo
        self.versions = [VersionInfo(key="k", version_id=v, is_delete_marker=False,
                                     is_latest=False, last_modified=None) for v in versions]
        self.locked = set(locked)

    def head(self, bucket, key, *, version_id=None):
        return object()

    def delete_key(self, bucket, key):
        from noctornal_api.objectstore.types import KeylessDelete, VersionInfo
        self.versions.append(VersionInfo(key=key, version_id="marker", is_delete_marker=True,
                                         is_latest=True, last_modified=None))
        return KeylessDelete(delete_marker=True, version_id="marker")

    def list_versions(self, bucket, prefix):
        return iter(list(self.versions))

    def delete_version(self, bucket, key, version_id):
        from noctornal_api.objectstore.errors import refusal
        if version_id in self.locked:
            raise refusal("InvalidRequest", "Object is WORM protected and cannot be overwritten")
        self.versions = [v for v in self.versions if v.version_id != version_id]


@pytest.mark.parametrize("which", ["DocumentRawStorage", "SampleStorage"])
def test_a_delete_on_a_versioned_working_bucket_removes_every_version(which):
    """A keyless DELETE on a versioned bucket hides the object behind a marker and returns success while every
    byte stays retrievable by version id, so a purge recorded a destruction that had not happened. The
    working-bucket deletes now remove every version when the store says it only added a marker."""
    from noctornal_api import rawstore, samples

    store = _VersionedWorkingStore(["v1", "v2"])
    cls = getattr(rawstore, which, None) or getattr(samples, which)
    obj = _with_store(cls, store)
    obj.delete("k")
    assert store.versions == [], store.versions


@pytest.mark.parametrize("which", ["DocumentRawStorage", "SampleStorage"])
def test_a_working_delete_that_leaves_a_version_raises(which):
    """A locked version on a working bucket is a misconfiguration; the delete says so rather than return as
    if the bytes were gone."""
    from noctornal_api import rawstore, samples

    store = _VersionedWorkingStore(["v1"], locked=["v1"])
    cls = getattr(rawstore, which, None) or getattr(samples, which)
    with pytest.raises((rawstore.RawStoreError, samples.SampleError), match="held by a lock"):
        _with_store(cls, store).delete("k")


@pytest.mark.skipif(not os.environ.get("MINIO_ENDPOINT"),
                    reason="no MinIO named; the live leg is skipped")
def test_the_live_versioned_working_bucket_keeps_no_version_after_a_delete(monkeypatch):
    """Measured on the development MinIO: a bucket made with object lock is versioned, and with no default
    retention its objects are deletable, which is the shape of a versioned working bucket."""
    from noctornal_api.rawstore import DocumentRawStorage

    monkeypatch.setenv("COLLECT_RAW_BUCKET", f"b0ver-{uuid4().hex[:8]}")
    store = DocumentRawStorage()
    try:
        store.store.make_bucket(store.bucket, object_lock=True)
    except Exception as exc:  # noqa: BLE001 - a MinIO that is down is a skip
        pytest.skip(f"MinIO did not answer: {type(exc).__name__}")
    try:
        store.put("collect/ab/v", b"<p>one</p>")
        store.put("collect/ab/v", b"<p>two</p>")
        assert len(list(store.store.list_versions(store.bucket, "collect/ab/v"))) == 2
        assert store.delete("collect/ab/v") is True
        assert list(store.store.list_versions(store.bucket, "collect/ab/v")) == []
    finally:
        for v in store.store.list_versions(store.bucket, "collect/ab/"):
            store.store.delete_version(store.bucket, v.key, v.version_id)
        store.store.remove_bucket(store.bucket)
