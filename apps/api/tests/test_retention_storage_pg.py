"""Purge <-> object store: what the store ANSWERED is what the tombstone says.

Two defects, found 2026-09-02, both of the shape "a failure reported as
the wrong thing, not a crash":

1. `retention._purge_evidence` called `EvidenceStorage.delete()`, which on
   the versioned, lock-enabled evidence bucket inserts a DELETE MARKER and
   returns success. The purge recorded DELETED, marked the row `purged_at`,
   and every byte stayed retrievable by version id. `delete_all_versions`
   -- the method that enumerates versions and reports a refusal as a
   refusal -- existed, was verified live, and had an AST test asserting
   that NOTHING called it. This file is the wiring's regression test; the
   AST guard is inverted in `test_evidence_versioned_delete.py`.

2. `_is_retention_refusal` returned True on a bare `AccessDenied` (and on
   `ObjectLockConfigurationNotFoundError`, which literally means "this
   bucket has NO lock configuration"). A read-only key or a bucket policy
   denying `s3:DeleteObject` was therefore written into an append-only
   tombstone as LOCKED_UNTIL_RETENTION -- a specific claim about a
   retention lock that a permissions failure is not.

Everything here uses a STUB store on purpose: a stub can be scripted to
answer with exactly the counts under test, and it never adds a
COMPLIANCE-locked object to the real bucket. The live half of the same
contract -- that MinIO really does refuse a locked version with
`InvalidRequest` / "Object is WORM protected", and that the keyless delete
really does return success while holding the bytes -- is
`tests/test_evidence_lock_live_pg.py`.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest
from minio.error import S3Error

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; retention tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

from noctornal_api.evidence import VersionedDeleteResult  # noqa: E402
from noctornal_api.retention import (  # noqa: E402
    STORAGE_DELETED, STORAGE_FAILED, STORAGE_LOCKED, RetentionService,
)

EMAIL_LIKE = "rst-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # An approval request notifies the case's reviewers, and the
        # notification carries the case FK.
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE recipient_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub}")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        # purge_tombstone is append-only and FK-bound to the case and the
        # actor; stand the trigger down so the test's own record can go.
        c.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.purge_tombstone WHERE purged_by IN {sub}")
        c.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"rst-{uuid4().hex[:8]}@noctornal.test", "Officer", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _expired_case(conn, owner):
    """A case cannot be CREATED already expired (`case_retention_sane`), so
    it is created live and aged, which is what happens to a real one."""
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-RST-{uuid4().hex[:6]}", title="Storage outcome",
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
    return case_id


def _evidence(conn, case_id, owner):
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification)
           VALUES (%s, 'exhibit', 'text/plain', 10, %s, %s, %s, 'b', %s,
                   now(), 'MANUAL_UPLOAD', 'AMBER')
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32),
         f"{case_id}/{uuid4().hex}", owner)).fetchone()[0]


def _s3_error(code: str, message: str, *, object_name: str | None = None):
    return S3Error(code=code, message=message, resource="r", request_id="1",
                   host_id="1", response=None, object_name=object_name)


class _VersionedStore:
    """Answers the way `EvidenceStorage` does once it can enumerate versions.

    `delete_all_versions` returns the scripted counts. `delete` -- the
    keyless delete -- records the call and RETURNS SUCCESS, because that is
    exactly what a keyless delete on a versioned bucket does: it inserts a
    marker and reports nothing wrong. A purge that falls back to it
    therefore records DELETED while this stub still "holds" every byte,
    which is the defect the wiring exists to end.
    """

    def __init__(self, *, seen: int, removed: int, locked: int):
        self._answer = (seen, removed, locked)
        self.versioned_calls: list[str] = []
        self.keyless_calls: list[str] = []

    def delete_all_versions(self, key: str) -> VersionedDeleteResult:
        self.versioned_calls.append(key)
        seen, removed, locked = self._answer
        return VersionedDeleteResult(key=key, versions_seen=seen,
                                     versions_removed=removed,
                                     versions_locked=locked)

    def delete(self, key: str) -> None:
        self.keyless_calls.append(key)


class _KeylessStore:
    """A store that cannot enumerate versions and refuses with `exc`.

    The legacy branch. `EvidenceStorage` never takes it any more, but the
    classifier that turns an exception into LOCKED or FAILED lives on it,
    and that classifier is defect 2 above.
    """

    def __init__(self, exc: Exception):
        self._exc = exc

    def delete(self, key: str) -> None:
        raise self._exc


def _purge(conn, store, *, owner, case_id):
    return RetentionService(conn, store).purge_due(
        actor_id=owner, authority="test: storage outcome contract",
        case_id=case_id)


def _tombstone_outcome(conn, case_id) -> str:
    stones = RetentionService(conn).tombstones(case_id)
    assert len(stones) == 1, stones
    return stones[0]["storage_outcome"]


def _purged_at(conn, evidence_id):
    return conn.execute(
        "SELECT purged_at FROM core.evidence WHERE id = %s",
        (evidence_id,)).fetchone()[0]


# ---------------------------------------------------------------------------
# Defect 1: the purge must use the versioned delete and map its COUNTS
# ---------------------------------------------------------------------------

def test_a_locked_answer_is_recorded_as_locked_and_the_exhibit_stays(conn):
    """Two versions, both refused. The tombstone says LOCKED_UNTIL_RETENTION,
    `storage_locked` is the refusal count (2, not the batch size 1), and
    the row is NOT marked purged: a row marked purged while its bytes are
    retrievable is precisely the false record this file exists to end,
    and an unmarked row stays due so the next sweep after the lock
    expires actually destroys it."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    store = _VersionedStore(seen=2, removed=0, locked=2)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert store.keyless_calls == [], (
        "the purge used the keyless delete(), which inserts a marker and "
        "destroys nothing on a versioned bucket")
    assert len(store.versioned_calls) == 1
    assert result.storage_locked == 2
    assert result.storage_deleted == 0
    assert result.storage_failed == 0
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED
    assert _purged_at(conn, ev) is None, (
        "the exhibit was marked purged while every version of its object "
        "is still in the store")
    assert any("object store disagrees" in w for w in result.warnings)


def test_a_missing_object_is_a_failure_with_a_warning_never_a_success(conn):
    """A row whose key has NO versions at all is a disagreement between the
    database and the store -- the exhibit was written (the row says so)
    and the store has nothing under that key. That is FAILED, named per
    key, never DELETED: nothing was destroyed, so nothing may be recorded
    as destroyed."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    key = conn.execute("SELECT storage_key FROM core.evidence WHERE id = %s",
                       (ev,)).fetchone()[0]
    store = _VersionedStore(seen=0, removed=0, locked=0)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert result.storage_failed == 1
    assert result.storage_deleted == 0
    assert result.storage_locked == 0
    assert _tombstone_outcome(conn, case_id) == STORAGE_FAILED
    assert any("no object found for storage_key" in w and key in w
               for w in result.warnings), result.warnings
    assert _purged_at(conn, ev) is None


def test_a_removed_version_is_recorded_as_deleted(conn):
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    store = _VersionedStore(seen=1, removed=1, locked=0)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert result.storage_deleted == 1
    assert result.storage_locked == 0 and result.storage_failed == 0
    assert _tombstone_outcome(conn, case_id) == STORAGE_DELETED
    assert _purged_at(conn, ev) is not None


def test_a_partial_refusal_marks_nothing_purged(conn):
    """One version gone, one locked: bytes remain, so the row is not
    purged and the batch is LOCKED. Both counts are reported so the
    operator can see that something DID go."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    store = _VersionedStore(seen=2, removed=1, locked=1)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert (result.storage_deleted, result.storage_locked) == (1, 1)
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED
    assert _purged_at(conn, ev) is None


def test_a_locked_exhibit_stays_due_and_the_next_sweep_finishes_the_job(conn):
    """Why the row is left unmarked. With `purged_at` set on a refusal
    (the behaviour until 2026-09-02) the exhibit vanished from every read
    path and from `due()`, so nothing ever retried it: the lock expired
    and the bytes sat in the bucket forever, under a tombstone saying
    LOCKED. Left due, the next sweep after expiry destroys it and writes
    the DELETED record."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)

    _purge(conn, _VersionedStore(seen=1, removed=0, locked=1),
           owner=owner, case_id=case_id)
    still_due = [d for d in RetentionService(conn).due(case_id=case_id)
                 if d.object_id == ev]
    assert still_due and not still_due[0].held, (
        "a refused exhibit dropped out of the sweep, so nothing will ever "
        "retry it once the lock expires")

    # The lock has expired; the store now lets the version go.
    result = _purge(conn, _VersionedStore(seen=1, removed=1, locked=0),
                    owner=owner, case_id=case_id)
    assert result.storage_deleted == 1
    assert _purged_at(conn, ev) is not None
    outcomes = [s["storage_outcome"]
                for s in RetentionService(conn).tombstones(case_id)]
    assert sorted(outcomes) == sorted([STORAGE_LOCKED, STORAGE_DELETED]), (
        "both attempts must leave their own record: the refusal and the "
        "destruction are different facts on different dates")


# ---------------------------------------------------------------------------
# Defect 2: a permissions failure is not a retention lock
# ---------------------------------------------------------------------------

def test_a_plain_access_denied_is_a_failure_not_a_retention_lock(conn):
    """What a read-only key, or a bucket policy denying s3:DeleteObject,
    produces. Recording it as LOCKED_UNTIL_RETENTION told the operator
    the bytes would go by themselves when a retention expired. They will
    not; nothing here is under retention."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    _evidence(conn, case_id, owner)
    store = _KeylessStore(_s3_error("AccessDenied", "Access Denied."))

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert result.storage_failed == 1
    assert result.storage_locked == 0, (
        "a permissions failure was recorded as a retention lock")
    assert _tombstone_outcome(conn, case_id) == STORAGE_FAILED


def test_a_worm_refusal_is_a_retention_lock(conn):
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    _evidence(conn, case_id, owner)
    store = _KeylessStore(_s3_error(
        "AccessDenied", "Object is WORM protected and cannot be overwritten"))

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert result.storage_locked == 1 and result.storage_failed == 0
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED


@pytest.mark.parametrize("exc, expected", [
    # What MinIO actually says for a COMPLIANCE-locked version, measured
    # against the live stack 2026-09-02 (not AccessDenied, as the evidence
    # module's docstring had it).
    (_s3_error("InvalidRequest",
               "Object is WORM protected and cannot be overwritten"),
     STORAGE_LOCKED),
    (_s3_error("RetentionPeriodNotMet", "x"), STORAGE_LOCKED),
    (_s3_error("MethodNotAllowed", "x"), STORAGE_LOCKED),
    (_s3_error("InvalidRequest", "Invalid Request"), STORAGE_FAILED),
    # "There is no lock configuration on this bucket" is the OPPOSITE of a
    # retention lock, and its message contains the words "Object Lock".
    (_s3_error("ObjectLockConfigurationNotFoundError",
               "Object Lock configuration does not exist for this bucket"),
     STORAGE_FAILED),
    # A storage key that happens to contain the word "retention" must not
    # turn a plain refusal into a lock: the classifier reads the MESSAGE,
    # not the whole `str(exc)`, which quotes the object name.
    (_s3_error("AccessDenied", "Access Denied.",
               object_name="case/retention-notes.pdf"), STORAGE_FAILED),
    # The message-only shapes the existing governance stubs raise.
    (RuntimeError("object is under a retention lock"), STORAGE_LOCKED),
    (RuntimeError("connection reset by peer"), STORAGE_FAILED),
], ids=["minio-worm-invalidrequest", "retention-period-not-met",
        "method-not-allowed", "bare-invalid-request", "no-lock-config",
        "retention-in-key-name", "message-only-lock", "transport"])
def test_refusal_classification(conn, exc, expected):
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    _evidence(conn, case_id, owner)

    result = _purge(conn, _KeylessStore(exc), owner=owner, case_id=case_id)

    assert _tombstone_outcome(conn, case_id) == expected
    if expected == STORAGE_LOCKED:
        assert (result.storage_locked, result.storage_failed) == (1, 0)
    else:
        assert (result.storage_locked, result.storage_failed) == (0, 1)


def test_the_out_of_schedule_path_reports_the_same_counts(conn):
    """The other caller of `_purge_evidence`, on the one path that writes
    an out-of-schedule tombstone. It reads the same counts; if the two
    callers ever diverge, this is the one a court sees."""
    from noctornal_api.approvals import ApprovalService

    owner = _user(conn)
    approver = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    svc_a = ApprovalService(conn)
    payload = {"case_id": str(case_id), "evidence_ids": [str(ev)],
               "authority": "test: out of schedule"}
    req = svc_a.request(operation="evidence.purge", case_id=case_id,
                        payload=payload, requested_by=owner,
                        justification="exhibit collected outside the warrant")
    svc_a.decide(req.id, decided_by=approver, approve=True)

    store = _VersionedStore(seen=2, removed=0, locked=2)
    result = RetentionService(conn, store).purge_out_of_schedule(
        actor_id=owner, authority="test: out of schedule",
        approval_request_id=req.id, case_id=case_id, evidence_ids=[ev])

    assert store.keyless_calls == []
    assert result.storage_locked == 2 and result.storage_deleted == 0
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED
    assert _purged_at(conn, ev) is None
