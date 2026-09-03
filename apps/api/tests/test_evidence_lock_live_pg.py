"""The COMPLIANCE lock, exercised against the REAL MinIO for the first time.

Until 2026-09-02 the roadmap said `EvidenceStorage.delete()` "has never
been exercised against a live COMPLIANCE lock", and every test of the
purge's storage half used a stub. A stub proves the code maps what it is
told; it cannot prove what the store actually says. Two of those things
matter enough to measure rather than assume:

1. The keyless `delete()` RETURNS SUCCESS on this bucket and destroys
   nothing. The bucket is created `--with-lock`, which forces versioning
   on, and a keyless `remove_object` on a versioned bucket inserts a
   DELETE MARKER. The bytes stay retrievable by version id. This is the
   defect `retention._purge_evidence` reported as DELETED for a month,
   and `test_the_old_keyless_delete_returns_success_while_holding_the_bytes`
   below asserts it STILL happens -- deliberately. It is the documented
   reason the purge now calls `delete_all_versions()`. If that test ever
   fails, MinIO's semantics changed and every docstring that quotes the
   measurement must be re-measured, not deleted.

2. What the refusal actually looks like. `retention._is_retention_refusal`
   was tightened the same day to require a WORM / retention / object-lock
   message on `AccessDenied` and `InvalidRequest` (a plain policy denial
   is not a retention lock). Measured here: MinIO answers a locked-version
   delete with `InvalidRequest` and "Object is WORM protected and cannot
   be overwritten" -- NOT `AccessDenied`, as the evidence module had it.
   The stub tests cannot catch a vocabulary drift between MinIO and the
   classifier; this file can.

## The precondition is a FAILURE, not a skip

Against a bucket where locking is off, every assertion about a refusal
passes for the wrong reason: nothing refuses, `delete_all_versions`
removes everything, and a test written to check the lock would be
checking its absence. So `locked_bucket` FAILS with "lock is off; a pass
here would be for the wrong reason" rather than skipping. Verified by
pointing EVIDENCE_BUCKET at the unlocked samples bucket, 2026-09-02.

## Every object written here is locked for LOCK_SECONDS, permanently

A COMPLIANCE retention cannot be shortened, lifted or overridden by any
credential; that is the entire point of the mode. So the objects are
tiny, the retention is seconds (`put()` takes `retain_until`, so the
365-day default never applies), the keys sit under one prefix, and each
run sweeps the previous run's leftovers once their locks have expired.
Never raise LOCK_SECONDS to something that outlives a working day.

Gated exactly like `test_evidence_pg.py`: DATABASE_URL and MINIO_ENDPOINT.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest
from minio.error import S3Error

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and MINIO),
    reason="DATABASE_URL and MINIO_ENDPOINT required; live lock test is gated",
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

#: Every object this file writes lives here, so a sweep can find them.
PREFIX = "_itest-lock/"
#: Long enough that every delete attempt below happens while the lock
#: still holds on a slow machine; short enough that the next run can
#: sweep what this one left. A COMPLIANCE lock cannot be cut short.
LOCK_SECONDS = 120
EMAIL_LIKE = "lock-%@noctornal.test"
LOCK_OFF = "lock is off; a pass here would be for the wrong reason"


def _versions(storage, key):
    return [v for v in storage._client.list_objects(
                storage.bucket, prefix=key, include_version=True)
            if v.object_name == key]


def _sweep(storage) -> None:
    """Destroy leftovers under PREFIX whose locks have expired.

    Still-locked ones are reported as locked and left -- that is the lock
    working -- and the run after next gets them. Anything else the store
    says is swallowed: a sweep is hygiene, not an assertion.
    """
    keys = {v.object_name for v in storage._client.list_objects(
        storage.bucket, prefix=PREFIX, include_version=True)}
    for key in keys:
        try:
            storage.delete_all_versions(key)
        except S3Error:
            pass


@pytest.fixture(scope="module")
def storage():
    from noctornal_api.evidence import EvidenceStorage
    st = EvidenceStorage()
    _sweep(st)
    yield st
    _sweep(st)


@pytest.fixture(scope="module")
def locked_bucket(storage):
    """FAIL, never skip, when the bucket cannot refuse a delete."""
    try:
        config = storage._client.get_object_lock_config(storage.bucket)
    except S3Error as exc:
        pytest.fail(f"{LOCK_OFF}: get_object_lock_config({storage.bucket!r}) "
                    f"-> {exc.code}")
    versioning = storage._client.get_bucket_versioning(storage.bucket)
    if versioning.status != "Enabled":
        pytest.fail(f"{LOCK_OFF}: bucket versioning is {versioning.status!r}, "
                    f"so a keyless delete would destroy rather than mark")
    return config


def _locked_object(storage, data: bytes):
    """One object under PREFIX with the shortest COMPLIANCE lock this file
    allows itself. Returns (key, version_id, retain_until)."""
    key = f"{PREFIX}{uuid4()}"
    retain_until = datetime.now(timezone.utc) + timedelta(seconds=LOCK_SECONDS)
    storage.put(key, data, media_type="application/octet-stream",
                retain_until=retain_until)
    real = [v for v in _versions(storage, key) if not v.is_delete_marker]
    assert len(real) == 1, real
    return key, real[0].version_id, retain_until


def _get_version(storage, key: str, version_id: str) -> bytes:
    resp = storage._client.get_object(storage.bucket, key,
                                      version_id=version_id)
    try:
        return resp.read()
    finally:
        resp.close()
        resp.release_conn()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.purge_tombstone WHERE purged_by IN {sub}")
        c.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


# ---------------------------------------------------------------------------
# The precondition, and what put() actually writes
# ---------------------------------------------------------------------------

def test_the_bucket_is_lock_enabled_and_versioned(locked_bucket):
    """Documents what the rest of the file rests on. The bucket DEFAULT is
    whatever compose set (GOVERNANCE 365d at the time of writing); the
    per-object lock `put()` applies is asserted separately below."""
    assert locked_bucket.mode in ("GOVERNANCE", "COMPLIANCE"), locked_bucket.mode


def test_put_applies_a_compliance_retention_to_the_object(storage, locked_bucket):
    """`put()` promises COMPLIANCE, not the bucket's GOVERNANCE default.
    GOVERNANCE is bypassable by anyone holding
    s3:BypassGovernanceRetention; COMPLIANCE by nobody. The distinction is
    the whole WORM guarantee, so it is measured rather than trusted."""
    key, version_id, retain_until = _locked_object(storage, b"compliance")
    retention = storage._client.get_object_retention(
        storage.bucket, key, version_id=version_id)
    assert retention.mode == "COMPLIANCE", retention.mode
    # MinIO stores millisecond precision; allow that much slack.
    assert retention.retain_until_date >= retain_until - timedelta(seconds=1)


# ---------------------------------------------------------------------------
# The honest delete
# ---------------------------------------------------------------------------

def test_delete_all_versions_reports_the_lock_and_the_bytes_survive(
        storage, locked_bucket):
    data = b"locked-" + uuid4().bytes
    key, version_id, _ = _locked_object(storage, data)

    r = storage.delete_all_versions(key)

    assert r.versions_seen >= 1
    assert r.versions_locked >= 1, (
        "the store let a COMPLIANCE-locked version go: either the lock is "
        "not enforced or the refusal was not recognised as one")
    assert r.versions_removed == 0
    assert not r.fully_destroyed
    assert _get_version(storage, key, version_id) == data


def test_the_live_refusal_is_recognised_as_a_lock_by_the_classifier(
        storage, locked_bucket):
    """The one thing a stub cannot prove. The classifier now requires the
    WORM / retention / object-lock words on AccessDenied and
    InvalidRequest; if MinIO's real refusal ever stops carrying them, the
    purge would record FAILED for a lawful lock -- wrong in the other
    direction. Measured 2026-09-02: InvalidRequest, "Object is WORM
    protected and cannot be overwritten"."""
    from noctornal_api import retention
    from noctornal_api.evidence import is_retention_refusal

    key, version_id, _ = _locked_object(storage, b"refusal")
    with pytest.raises(S3Error) as info:
        storage._client.remove_object(storage.bucket, key,
                                      version_id=version_id)
    exc = info.value
    assert is_retention_refusal(exc), (exc.code, exc.message)
    assert retention._is_retention_refusal(exc), (exc.code, exc.message)
    assert exc.code in ("InvalidRequest", "AccessDenied", "MethodNotAllowed",
                        "RetentionPeriodNotMet"), exc.code


# ---------------------------------------------------------------------------
# The defect, kept as a measurement
# ---------------------------------------------------------------------------

def test_the_old_keyless_delete_returns_success_while_holding_the_bytes(
        storage, locked_bucket):
    """THIS PASSES TODAY, on purpose. It is the measured reason the purge
    no longer calls `delete()`: the call returns normally, a delete
    marker becomes the latest version, the real version is still listed
    and still served by version id -- and a keyed `get()` now says
    NoSuchKey, which is exactly how the defect hid. Until 2026-09-02 the
    purge took this path, recorded DELETED, and marked the row purged."""
    data = b"held-" + uuid4().bytes
    key, version_id, _ = _locked_object(storage, data)

    storage.delete(key)  # returns without error: nothing to refuse

    versions = _versions(storage, key)
    assert any(v.is_delete_marker for v in versions), (
        "no delete marker was written: MinIO's keyless-delete semantics "
        "changed, re-measure every docstring that quotes this")
    assert any(v.version_id == version_id and not v.is_delete_marker
               for v in versions), "the real version is gone"
    assert _get_version(storage, key, version_id) == data
    with pytest.raises(S3Error) as info:
        storage.get(key)
    assert info.value.code == "NoSuchKey", info.value.code


# ---------------------------------------------------------------------------
# Both halves together, live: RetentionService -> EvidenceStorage -> MinIO
# ---------------------------------------------------------------------------

def test_a_purge_against_the_live_lock_records_locked_and_leaves_the_row(
        conn, storage, locked_bucket):
    """The cross-file contract with nothing stubbed. An expired case, one
    exhibit whose storage_key is a really-locked object, a real purge:
    the store refuses, the tombstone says LOCKED_UNTIL_RETENTION, the row
    stays unpurged and due, and the bytes are still there."""
    from noctornal_api.cases import CaseService
    from noctornal_api.retention import STORAGE_LOCKED, RetentionService
    from noctornal_api.stores import PgUserStore

    owner = PgUserStore(conn).create_user(
        f"lock-{uuid4().hex[:8]}@noctornal.test", "Officer", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (owner,))
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-LOCK-{uuid4().hex[:6]}", title="Live lock",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1),
        owner_user_id=owner, created_by=owner)
    expired = date(2024, 1, 1)
    conn.execute(
        '''UPDATE core."case"
              SET retention_until = %s, review_due = %s,
                  created_at = %s::date - interval '30 days'
            WHERE id = %s''',
        (expired, expired - timedelta(days=1), expired, case_id))

    data = b"exhibit-" + uuid4().bytes
    key, version_id, _ = _locked_object(storage, data)
    ev = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification)
           VALUES (%s, 'exhibit', 'application/octet-stream', %s, %s, %s,
                   %s, %s, %s, now(), 'MANUAL_UPLOAD', 'AMBER')
           RETURNING id""",
        (case_id, len(data), os.urandom(32), os.urandom(32), key,
         storage.bucket, owner)).fetchone()[0]

    result = RetentionService(conn, storage).purge_due(
        actor_id=owner, authority="live lock integration test",
        case_id=case_id)

    assert result.storage_locked >= 1, result
    assert result.storage_deleted == 0
    assert result.storage_failed == 0
    stones = RetentionService(conn).tombstones(case_id)
    assert [s["storage_outcome"] for s in stones] == [STORAGE_LOCKED]
    assert conn.execute("SELECT purged_at FROM core.evidence WHERE id = %s",
                        (ev,)).fetchone()[0] is None, (
        "the row was marked purged while the store still holds the bytes")
    assert _get_version(storage, key, version_id) == data
