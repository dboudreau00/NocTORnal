"""Raw ingest batches in object storage, separate from evidence.

docs/12's "raw before parse, always": `accept()` writes the bytes and
returns 202 before anything is parsed, so when the parser turns out to be
wrong -- and it will -- you re-parse from the original rather than asking a
partner to resend three months of feed.

Until now that was aspirational. `IngestService` took a `storage` argument,
the router constructed it with `None`, and `accept()` skipped the write
silently. The batch row recorded a `raw_key` pointing at nothing, `parse`
had nothing to read, and the dead-letter redactor's claim that "the
verbatim bytes remain in the batch's raw object" was false. Found while
writing that claim down and then checking it.

## Why this is NOT `EvidenceStorage`

Three differences, and each one matters:

**No object lock.** `EvidenceStorage` writes with COMPLIANCE-mode
retention: not even root can delete before the deadline. That is right for
an exhibit and wrong here. A raw batch is somebody else's unvetted bytes
arriving on a machine key, and docs/12 gives it a SHORT category clock;
COMPLIANCE lock would make an over-retained credential dump undeletable by
anybody, including in response to a deletion order. decision 50 already
records that object lock can refuse a lawful delete -- inviting that on a
stealer-log feed would be a choice, not an accident.

**Its own bucket.** `INGEST_BUCKET`, defaulting to `noctornal-raw`. An
exhibit and a partner's submission have different retention, different
access and different evidential weight, and one bucket policy cannot
express both.

**It is not evidence.** A raw batch has no chain of custody, no acquisition
method and no `core.evidence` row. Material that becomes evidence is
ingested through `EvidenceService` deliberately, by a human, with a
provenance record. Blurring that would let a partner's HTTP POST create an
exhibit.

## Content-addressed, so a resend costs nothing

The key is the SHA-256 of the bytes, which means a partner replaying the
same batch overwrites itself rather than accumulating copies -- and the
digest is already stored on the batch row, so the object is verifiable
against it without a second index.
"""
from __future__ import annotations

import hashlib
import io
import os

from minio import Minio


class RawStoreError(Exception):
    pass


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
    """MinIO wrapper for raw ingest payloads. No object lock, own bucket."""

    def __init__(self) -> None:
        endpoint = os.environ.get("MINIO_ENDPOINT")
        access = os.environ.get("MINIO_ACCESS_KEY")
        secret = os.environ.get("MINIO_SECRET_KEY")
        if not (endpoint and access and secret):
            raise RawStoreError(
                "MINIO_ENDPOINT / MINIO_ACCESS_KEY / MINIO_SECRET_KEY must be "
                "set to store raw ingest batches. Without them `accept()` "
                "would take the bytes and drop them, which is the failure "
                "raw-before-parse exists to prevent.")
        secure = os.environ.get("MINIO_SECURE", "false").lower() == "true"
        self._bucket = os.environ.get("INGEST_BUCKET", "noctornal-raw")
        self._client = Minio(endpoint, access_key=access, secret_key=secret,
                             secure=secure)

    @property
    def bucket(self) -> str:
        return self._bucket

    def ensure_bucket(self) -> None:
        """Create the bucket if it is absent.

        Deliberately NOT called from `put`: a create-on-write would mask a
        misconfigured bucket name by silently making a second one, and the
        symptom is a feed that appears to work and cannot be re-parsed.
        """
        if not self._client.bucket_exists(self._bucket):
            self._client.make_bucket(self._bucket)

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(
            self._bucket, key, io.BytesIO(data), length=len(data),
            content_type="application/octet-stream")

    def get(self, key: str) -> bytes:
        from minio.error import S3Error
        try:
            resp = self._client.get_object(self._bucket, key)
        except S3Error as exc:
            raise MissingObject.for_key(key) from exc
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()


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
