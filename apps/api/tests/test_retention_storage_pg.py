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

3. The fix for (1) then reported `storage_deleted` / `storage_locked` in
   OBJECT VERSIONS while `evidence_purged` stayed in exhibit rows, and two
   docstrings plus the governance router went on saying all three account
   for the batch. An exhibit with one version removed and one refused
   answered `evidence_purged: 1, storage_deleted: 1, storage_locked: 1`
   with its row unpurged and every byte readable -- "one object deleted"
   for an exhibit that is entirely intact. The counters are exhibit rows
   again; `_assert_counters_account_for_the_batch` binds the arithmetic so
   the docstrings cannot drift from it a second time, and the version
   detail lives in the warning that names its key.

4. `purge_out_of_schedule` took (1)'s "leave a refused row unmarked"
   behaviour together with `purge_due`'s justification for it -- "it stays
   due, and the next sweep finishes the job" -- which is false on that
   path: `due()` returns evidence only when `case.retention_until <= now`,
   and an out-of-schedule purge is for exhibits whose retention has NOT
   expired. A refused early destruction therefore returned
   `evidence_purged: 1, warnings: []`, left the bytes and the row alone,
   put the exhibit on no sweep at all, and spent the four-eyes approval.
   Every out-of-schedule test here used `_expired_case`, a case that is
   ALSO due on schedule, so none of them could see it; the new ones use
   `_live_case`.

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


def _live_case(conn, owner):
    """A case whose retention has NOT expired.

    This is the only kind of case `purge_out_of_schedule` exists for: the
    scheduled sweep already handles the expired ones. Every out-of-schedule
    test in this file used `_expired_case`, which is ALSO due on schedule,
    so none of them could see that a refused out-of-schedule row is never
    retried by anything -- `due()` gates evidence on
    `case.retention_until <= now`, and here it never is.
    """
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    return CaseService(conn).create(
        code=f"OP-RST-{uuid4().hex[:6]}", title="Out of schedule",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1),
        owner_user_id=owner, created_by=owner)


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


class _PerKeyStore:
    """Like `_VersionedStore`, but the answer depends on the KEY.

    `_VersionedStore` gives every key in a batch the same answer, and with
    a batch of one exhibit a per-ROW counter and a per-VERSION counter are
    numerically identical for most scripts. That is how the units of
    `storage_deleted` / `storage_locked` were switched from rows to object
    versions on 2026-09-02 with all sixteen tests in this file still
    green. A batch that mixes a released row with a refused one tells them
    apart.
    """

    def __init__(self, answers: dict[str, tuple[int, int, int]]):
        self._answers = answers
        self.versioned_calls: list[str] = []
        self.keyless_calls: list[str] = []

    def delete_all_versions(self, key: str) -> VersionedDeleteResult:
        self.versioned_calls.append(key)
        seen, removed, locked = self._answers[key]
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


def _key(conn, evidence_id) -> str:
    return conn.execute(
        "SELECT storage_key FROM core.evidence WHERE id = %s",
        (evidence_id,)).fetchone()[0]


def _assert_counters_account_for_the_batch(result):
    """The invariant `PurgeResult.evidence_purged` and the governance
    router both state in prose, asserted so it cannot drift again.

    `retention.PurgeResult.evidence_purged` says "`storage_deleted` is
    [the number of rows marked purged], and the two differ by exactly
    `storage_locked + storage_failed`", and
    `http/routers/governance.py::_purge_response` tells the operator "the
    three account for the batch". Both were false between two commits on
    2026-09-02, when `deleted`/`locked` became sums of object VERSIONS,
    and no test in this file read the arithmetic, so nothing caught it.
    """
    assert (result.storage_deleted + result.storage_locked
            + result.storage_failed) == result.evidence_purged, (
        f"the three storage counters ({result.storage_deleted} deleted, "
        f"{result.storage_locked} locked, {result.storage_failed} failed) "
        f"do not account for the {result.evidence_purged} exhibit(s) "
        f"attempted, so they are not all in the same unit")
    assert (result.evidence_purged - result.storage_deleted
            == result.storage_locked + result.storage_failed)


# ---------------------------------------------------------------------------
# Defect 1: the purge must use the versioned delete and map its COUNTS
# ---------------------------------------------------------------------------

def test_a_locked_answer_is_recorded_as_locked_and_the_exhibit_stays(conn):
    """Two versions, both refused. The tombstone says LOCKED_UNTIL_RETENTION,
    `storage_locked` is 1 -- the one EXHIBIT the store refused, in the unit
    `evidence_purged` and the tombstone's `object_count` use -- and the row
    is NOT marked purged: a row marked purged while its bytes are
    retrievable is precisely the false record this file exists to end,
    and an unmarked row stays due so the next sweep after the lock
    expires actually destroys it.

    That both versions were refused is not lost, it is in the warning that
    names the key. See
    `test_one_refusal_in_a_batch_of_three_counts_one_row_not_its_versions`
    for the reason a count of 1 here is not just the batch size: the
    original defect was `storage_locked = len(evidence_ids)`, and a batch
    of one cannot tell the two apart."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    key = _key(conn, ev)
    store = _VersionedStore(seen=2, removed=0, locked=2)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert store.keyless_calls == [], (
        "the purge used the keyless delete(), which inserts a marker and "
        "destroys nothing on a versioned bucket")
    assert len(store.versioned_calls) == 1
    assert result.storage_locked == 1
    assert result.storage_deleted == 0
    assert result.storage_failed == 0
    _assert_counters_account_for_the_batch(result)
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED
    assert _purged_at(conn, ev) is None, (
        "the exhibit was marked purged while every version of its object "
        "is still in the store")
    assert any("object store disagrees" in w for w in result.warnings)
    assert any("2 of 2 version(s)" in w and key in w
               for w in result.warnings), (
        "the version detail was dropped when the counters went back to "
        "rows; it belongs in the warning that names the key")


def test_a_missing_object_is_a_failure_with_a_warning_never_a_success(conn):
    """A row whose key has NO versions at all is a disagreement between the
    database and the store -- the exhibit was written (the row says so)
    and the store has nothing under that key. That is FAILED, named per
    key, never DELETED: nothing was destroyed, so nothing may be recorded
    as destroyed."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    key = _key(conn, ev)
    store = _VersionedStore(seen=0, removed=0, locked=0)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert result.storage_failed == 1
    assert result.storage_deleted == 0
    assert result.storage_locked == 0
    _assert_counters_account_for_the_batch(result)
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
    _assert_counters_account_for_the_batch(result)
    assert _tombstone_outcome(conn, case_id) == STORAGE_DELETED
    assert _purged_at(conn, ev) is not None


def test_a_partial_refusal_marks_nothing_purged(conn):
    """One version gone, one locked: bytes remain, so the row is not
    purged, the batch is LOCKED, and the exhibit counts as REFUSED, not as
    a deletion. The removed version is still reported -- in the warning
    naming the key, where it cannot be read as an exhibit destroyed.

    This asserted `(storage_deleted, storage_locked) == (1, 1)` until
    2026-09-02, which encoded the object-version unit into the suite: it
    is the response "1 exhibit attempted, 1 object deleted" for an exhibit
    that is entirely intact."""
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    key = _key(conn, ev)
    store = _VersionedStore(seen=2, removed=1, locked=1)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert (result.storage_deleted, result.storage_locked) == (0, 1)
    _assert_counters_account_for_the_batch(result)
    assert any("1 of 2 version(s)" in w and key in w and "1 removed" in w
               for w in result.warnings), result.warnings
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
    assert result.storage_locked == 1 and result.storage_deleted == 0
    _assert_counters_account_for_the_batch(result)
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED
    assert _purged_at(conn, ev) is None


# ---------------------------------------------------------------------------
# Defect 3: the counters are EXHIBIT ROWS, in the unit the router publishes
# ---------------------------------------------------------------------------

def test_a_partly_refused_exhibit_is_never_counted_as_deleted(conn):
    """One version removed, one refused: the exhibit is intact and still
    readable, so NOTHING may be reported as deleted for it.

    Between two commits on 2026-09-02 `storage_deleted` summed
    `versions_removed` across keys and did so BEFORE the locked check, so
    this exact case answered `evidence_purged: 1, storage_deleted: 1,
    storage_locked: 1` with zero rows marked purged -- an API response
    reading "1 exhibit attempted, 1 object deleted" for an exhibit whose
    bytes are all still in the bucket. That is the same misreport the
    versioned delete was wired in to end, restated in a different unit.

    Reachable in production: evidence keys are content-addressed per case
    (`f"{case_id}/{shahex}"`), so a re-acquisition after an earlier purge
    leaves an old locked version, a delete marker and the new version
    under one key.
    """
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    store = _VersionedStore(seen=2, removed=1, locked=1)

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert _purged_at(conn, ev) is None
    assert result.storage_deleted == 0, (
        "the response reported an object deleted for an exhibit that is "
        "entirely intact: a removed version of a key whose other version "
        "is locked destroys nothing")
    _assert_counters_account_for_the_batch(result)


def test_one_refusal_in_a_batch_of_three_counts_one_row_not_its_versions(conn):
    """The counters are the unit the router and the tombstone speak.

    A single-exhibit batch cannot tell a per-row counter from a per-version
    one, which is why all sixteen tests here stayed green when the units
    changed. Three exhibits, one of them refused across three versions:
    `storage_locked` must be 1 (the exhibit the store refused), not 3 (its
    versions) and not 3 (the batch size, which is the ORIGINAL defect this
    file was written for), and `storage_deleted` must be 2 (the rows marked
    purged), not 3 (the versions removed from them).
    """
    owner = _user(conn)
    case_id = _expired_case(conn, owner)
    gone_a = _evidence(conn, case_id, owner)
    gone_b = _evidence(conn, case_id, owner)
    refused = _evidence(conn, case_id, owner)
    store = _PerKeyStore({
        _key(conn, gone_a): (2, 2, 0),
        _key(conn, gone_b): (1, 1, 0),
        _key(conn, refused): (3, 0, 3),
    })

    result = _purge(conn, store, owner=owner, case_id=case_id)

    assert result.evidence_purged == 3
    assert result.storage_deleted == 2, (
        "storage_deleted counted object versions (3), not the exhibit rows "
        "the store confirmed gone (2)")
    assert result.storage_locked == 1, (
        "storage_locked counted object versions (3), not the one exhibit "
        "the store refused")
    assert result.storage_failed == 0
    _assert_counters_account_for_the_batch(result)
    assert _purged_at(conn, gone_a) is not None
    assert _purged_at(conn, gone_b) is not None
    assert _purged_at(conn, refused) is None
    assert _tombstone_outcome(conn, case_id) == STORAGE_LOCKED


# ---------------------------------------------------------------------------
# Defect 4: an out-of-schedule refusal has no next sweep to fall back on
# ---------------------------------------------------------------------------

def test_a_refused_out_of_schedule_purge_says_nothing_will_retry_it(conn):
    """Both halves of one contract, read in one test.

    `_purge_evidence` leaves a refused row unmarked and justifies it with
    "it stays due, and the sweep after the lock expires finishes the job".
    That justification is true only of `purge_due`. `due()` gates evidence
    on `case.retention_until <= now`, and `purge_out_of_schedule` exists
    precisely for exhibits whose retention has NOT expired -- so a refused
    out-of-schedule row is not due, will not become due, and nothing will
    ever retry it, while the four-eyes approval that authorised the
    destruction has been consumed inside the same transaction.

    Until 2026-09-02 that path copied `purge_due`'s counts but none of its
    warnings, so a court-ordered early destruction refused by a
    COMPLIANCE lock returned `evidence_purged: 1, warnings: []`, changed
    nothing at all, and burned the signature in silence.
    """
    from noctornal_api.approvals import ApprovalService

    owner = _user(conn)
    approver = _user(conn)
    case_id = _live_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    svc_a = ApprovalService(conn)
    payload = {"case_id": str(case_id), "evidence_ids": [str(ev)],
               "authority": "test: court-ordered early destruction"}
    req = svc_a.request(operation="evidence.purge", case_id=case_id,
                        payload=payload, requested_by=owner,
                        justification="destruction ordered before expiry")
    svc_a.decide(req.id, decided_by=approver, approve=True)

    store = _VersionedStore(seen=2, removed=0, locked=2)
    result = RetentionService(conn, store).purge_out_of_schedule(
        actor_id=owner, authority="test: court-ordered early destruction",
        approval_request_id=req.id, case_id=case_id, evidence_ids=[ev])

    assert result.storage_locked == 1 and result.storage_deleted == 0
    assert _purged_at(conn, ev) is None
    # The other half of the contract: this is the sweep that is supposed to
    # finish the job, and the exhibit is not in it.
    assert [d for d in RetentionService(conn).due(case_id=case_id)
            if d.object_id == ev] == [], (
        "the case retention has not expired, so `due()` cannot return this "
        "exhibit -- if it did, the scheduled sweep really would retry it "
        "and the warning below would be wrong")

    joined = " ".join(result.warnings)
    assert result.warnings, (
        "a refused out-of-schedule purge returned no warning at all: the "
        "caller is told an exhibit was purged, the bytes are still there, "
        "the row is unmarked, no sweep will retry it and the approval is "
        "spent")
    assert "NOT marked purged" in joined, joined
    assert "not due" in joined and "will not come back due" in joined, joined
    assert "approval" in joined and "CONSUMED" in joined, joined


def test_an_out_of_schedule_purge_that_succeeds_warns_about_nothing(conn):
    """The warning above must be a real signal, not a banner on every
    out-of-schedule purge. Nothing was refused here, so nothing is said."""
    from noctornal_api.approvals import ApprovalService

    owner = _user(conn)
    approver = _user(conn)
    case_id = _live_case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    svc_a = ApprovalService(conn)
    payload = {"case_id": str(case_id), "evidence_ids": [str(ev)],
               "authority": "test: out of schedule, clean"}
    req = svc_a.request(operation="evidence.purge", case_id=case_id,
                        payload=payload, requested_by=owner,
                        justification="destruction ordered before expiry")
    svc_a.decide(req.id, decided_by=approver, approve=True)

    result = RetentionService(conn, _VersionedStore(
        seen=1, removed=1, locked=0)).purge_out_of_schedule(
        actor_id=owner, authority="test: out of schedule, clean",
        approval_request_id=req.id, case_id=case_id, evidence_ids=[ev])

    assert result.storage_deleted == 1 and result.warnings == []
    assert _purged_at(conn, ev) is not None
    assert _tombstone_outcome(conn, case_id) == STORAGE_DELETED
