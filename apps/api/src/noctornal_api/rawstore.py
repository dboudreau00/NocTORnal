"""Raw ingest batches in object storage, separate from evidence.

docs/12's "raw before parse, always": `accept()` writes the bytes and returns 202 before anything is
parsed, so when the parser turns out to be wrong you re-parse from the original rather than asking a
partner to resend three months of feed.

This is NOT `EvidenceStorage`, for three reasons:

- No object lock. `EvidenceStorage` writes with COMPLIANCE-mode retention, which is right for an
  exhibit and wrong here: a raw batch is somebody else's unvetted bytes arriving on a machine key
  with a SHORT category clock (docs/12), and a COMPLIANCE lock would make an over-retained
  credential dump undeletable by anybody, including in response to a deletion order (docs/00
  decision 50).
- Its own bucket, `INGEST_BUCKET`, defaulting to `noctornal-raw`. An exhibit and a partner's
  submission have different retention, access and evidential weight, and one bucket policy cannot
  express both.
- It is not evidence. A raw batch has no chain of custody, acquisition method or `core.evidence`
  row. Material that becomes evidence is ingested through `EvidenceService` deliberately, by a
  human, with a provenance record, so a partner's HTTP POST cannot create an exhibit.

The key is the SHA-256 of the bytes, so a partner replaying the same batch overwrites itself rather
than accumulating copies, and the digest already stored on the batch row verifies the object without
a second index.
"""
from __future__ import annotations

import hashlib
import os

from noctornal_api.objectstore import errors as store_errors
from noctornal_api.objectstore.settings import StoreConfigError, configured, resolve
from noctornal_api.objectstore.store import ObjectStore, open_store
from noctornal_api.objectstore.versions import BytesKept, delete_working_object

#: The variables a working bucket's store is named by, for the sentences that say what to set.
STORE_VARIABLES = ("OBJECT_STORE_ENDPOINT / OBJECT_STORE_ACCESS_KEY / OBJECT_STORE_SECRET_KEY "
                   "(or MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY)")


class RawStoreError(Exception):
    pass


def _working_store(role: str, purpose: str, *, http=None) -> ObjectStore:
    """The store for a working bucket (`ingest` or `collect_raw`), or `RawStoreError` naming what to set
    when none is configured."""
    try:
        settings = resolve(role)
    except StoreConfigError as exc:
        raise RawStoreError(str(exc)) from exc
    if not settings.configured:
        raise RawStoreError(f"{STORE_VARIABLES} must be set {purpose}")
    return open_store(settings, http=http)


class MissingObject(RawStoreError):
    """The batch row exists and its bytes do not.

    Its own type because the caller's response differs: this is not a
    corrupt object or a bad request, it is a batch accepted before storage
    was configured. Re-parsing it is impossible and asking the partner to
    resend is the only repair -- which the caller has to be told, rather
    than being handed an empty `bytes` that parses to zero records and
    marks the batch PARSED (invariant 12).
    """

    @classmethod
    def for_key(cls, key: str) -> "MissingObject":
        """One message, so the two backends cannot disagree about it.

        The message IS the guidance here, and a caller who gets a
        one-sentence version from the in-memory store and the useful one
        from MinIO has to know which store they are on to know what to do.
        """
        return cls(
            f"the raw payload for this batch is not in object storage "
            f"({key}). A batch accepted before storage was configured "
            f"cannot be re-parsed; the partner has to resend.")


def raw_key(data: bytes) -> str:
    """Content-addressed, two-level prefix.

    The prefix keeps a bucket listing usable at volume; S3 has no
    directories, but every tool that lists one pretends it does.
    """
    digest = hashlib.sha256(data).hexdigest()
    return f"ingest/{digest[:2]}/{digest}"


class RawBatchStorage:
    """Raw ingest payloads through the object store seam (role `ingest`). No object lock, own bucket.
    `store` is the `ObjectStore`."""

    def __init__(self) -> None:
        self.store = _working_store(
            "ingest",
            "to store raw ingest batches. Without them `accept()` would take the "
            "bytes and drop them, which is the failure raw-before-parse exists to "
            "prevent.")
        self._bucket = resolve("ingest").bucket

    @property
    def bucket(self) -> str:
        return self._bucket

    def ensure_bucket(self) -> None:
        """Create the bucket if it is absent.

        Deliberately NOT called from `put`: a create-on-write would mask a
        misconfigured bucket name by silently making a second one, and the
        symptom is a feed that appears to work and cannot be re-parsed.
        """
        if not self.store.bucket_exists(self._bucket):
            self.store.make_bucket(self._bucket, object_lock=False)

    def put(self, key: str, data: bytes) -> None:
        self.store.put(self._bucket, key, data)

    def get(self, key: str) -> bytes:
        """The batch's bytes. Only a key the store says is not there is `MissingObject`, whose sentence
        tells a partner to resend: a denied read, a missing bucket or a store that does not answer
        propagates, because the bytes may well be there and a resend would be the wrong repair."""
        try:
            return self.store.get(self._bucket, key)
        except store_errors.ObjectMissing as exc:
            raise MissingObject.for_key(key) from exc


class InMemoryRawStorage:
    """For tests, and for a dev stack with no MinIO.

    Honest about being in-memory: it does NOT survive a restart, so a
    deployment that ends up on this by accident loses the re-parse
    guarantee. `create_app` never selects it.
    """

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    @property
    def bucket(self) -> str:
        return "in-memory"

    def ensure_bucket(self) -> None:
        return None

    def put(self, key: str, data: bytes) -> None:
        self._objects[key] = data

    def get(self, key: str) -> bytes:
        if key not in self._objects:
            raise MissingObject.for_key(key)
        return self._objects[key]


# Collected raw markup. A forum adapter keeps each item's OWN markup fragment, so a parser that
# turns out to be wrong can re-parse what was read rather than read the site again. Beside the
# ingest store, not in it:
#
# - No object lock. A forum page is unvetted bytes written by the people under investigation, and it
#   holds other people's personal data. A retention clock or a deletion order must be able to remove
#   it, and the purge deletes it with its document (retention.py, docs/00 decision 74), as for the
#   ingest bucket (decision 50).
# - Its own bucket, COLLECT_RAW_BUCKET (default noctornal-collect-raw): collected pages and a
#   partner's submissions have different retention and different access.
# - Content-addressed per source. The key is the SHA-256 of the source's id and the fragment, so
#   identical fragments from two sources never share an object, and a re-fetch of the same fragment
#   overwrites itself.

#: The default name, spelled once for the store, the compose files and the
#: readiness caveat.
COLLECT_RAW_BUCKET_DEFAULT = "noctornal-collect-raw"


def collect_raw_bucket() -> str:
    return os.environ.get("COLLECT_RAW_BUCKET", "").strip() or COLLECT_RAW_BUCKET_DEFAULT


def document_raw_key(source_id, fragment: bytes) -> str:
    """'collect/<h[:2]>/<h>' where h = sha256(source_id.bytes + fragment)."""
    digest = hashlib.sha256(source_id.bytes + bytes(fragment)).hexdigest()
    return f"collect/{digest[:2]}/{digest}"


class DocumentRawStorage:
    """Collected raw markup through the object store seam (role `collect_raw`). No object lock, own
    bucket, and a delete, because the purge must be able to remove it. `store` is the `ObjectStore`."""

    def __init__(self) -> None:
        self.store = _working_store("collect_raw", "to keep collected raw markup.")
        self._bucket = collect_raw_bucket()

    @property
    def bucket(self) -> str:
        return self._bucket

    def ensure_bucket(self) -> None:
        """Create the bucket if it is absent, WITHOUT object lock. Not called
        from `put`, for the reason RawBatchStorage.ensure_bucket gives: a
        create-on-write masks a misconfigured bucket name."""
        if not self.store.bucket_exists(self._bucket):
            self.store.make_bucket(self._bucket, object_lock=False)

    def put(self, key: str, data: bytes) -> None:
        self.store.put(self._bucket, key, data)

    def get(self, key: str) -> bytes:
        try:
            return self.store.get(self._bucket, key)
        except store_errors.ObjectMissing as exc:
            raise MissingObject(f"no collected markup under {key}") from exc

    def exists(self, key: str) -> bool:
        """Whether an object is at `key`. False only when the store says nothing is there; a denial or an
        outage raises, so `delete` never tells a purge 'nothing there' about bytes it could not see."""
        try:
            self.store.head(self._bucket, key)
        except store_errors.ObjectMissing:
            return False
        return True

    def delete(self, key: str) -> bool:
        """Remove the object, every version of it on a versioned bucket; True when one was there. Raises
        when the store refuses or keeps a version, so the purge keeps the document rather than recording
        a destruction that did not happen (`objectstore.versions.delete_working_object`)."""
        if not self.exists(key):
            return False
        try:
            delete_working_object(self.store, self._bucket, key)
        except BytesKept as exc:
            raise RawStoreError(str(exc)) from exc
        return True


class InMemoryDocumentRawStorage:
    """For tests. Never selected by `default_document_raw_store`."""

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    @property
    def bucket(self) -> str:
        return "in-memory"

    def ensure_bucket(self) -> None:
        return None

    def put(self, key: str, data: bytes) -> None:
        self._objects[key] = bytes(data)

    def get(self, key: str) -> bytes:
        if key not in self._objects:
            raise MissingObject(f"no collected markup under {key}")
        return self._objects[key]

    def exists(self, key: str) -> bool:
        return key in self._objects

    def delete(self, key: str) -> bool:
        return self._objects.pop(key, None) is not None


def document_raw_bucket_exists(timeout: float = 2.0) -> bool | None:
    """Whether COLLECT_RAW_BUCKET exists, asked with a short timeout and no
    retries (the readiness row must not hang on a store that does not
    answer). None when no store is configured."""
    settings = resolve("collect_raw")
    if not settings.configured:
        return None
    import urllib3

    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=timeout, read=timeout),
        retries=urllib3.Retry(total=0, connect=0, read=0, redirect=0))
    return open_store(settings, http=http).bucket_exists(collect_raw_bucket())


def default_document_raw_store():
    """DocumentRawStorage when the store variables are set (`objectstore.settings`, role `collect_raw`),
    else None: no store is a recorded gap on every run that keeps markup (RAW_NOT_KEPT), never the
    in-memory store, which would lose it on restart."""
    if not configured("collect_raw"):
        return None
    return DocumentRawStorage()
