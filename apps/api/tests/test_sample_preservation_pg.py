"""F2, decided by the owner on 2026-09-22: a rejected sample is PRESERVED,
not destroyed, and getting it back out takes two people.

What these tests hold, and what each would catch:

- the default disposition preserves: the ciphertext leaves the samples
  bucket, lands in the object-locked preservation bucket under a legal
  hold on the exact version written, the data key is KEPT, and the row
  says where the copy went. Against the REAL dev MinIO, because a stub can
  prove the code maps what it is told and cannot prove the store holds;
- `destroy` is still exactly the old behaviour, and a legal hold still
  refuses it; `preserve` is not blocked by a hold, because it deletes
  nothing that is not first held elsewhere;
- a failed copy changes nothing, a missing working copy is not recorded
  as a preservation, and a disposition this build does not know refuses
  and names the variable;
- the schema refuses a preserved row that has lost its key, and refuses
  to let an authorisation be rewritten, deleted or granted to oneself;
- retrieval is refused without a live authorisation, is refused to the
  Security Officer who granted one to somebody else, and with a live
  authorisation returns the SAME encrypted archive a download produces,
  leaves the hold in place, and is written to the custody ledger and the
  audit chain. Refusals are audited too;
- over HTTP: the retrieval crosses to the sample origin on a ticket
  minted for it, and a download ticket cannot be minted for a preserved
  sample; the queue answers each state filter and the case filter; the
  detail records a look and names who acted.

Gated on DATABASE_URL and MINIO_ENDPOINT, like test_evidence_lock_live_pg.
Every object written to the preservation bucket is held; teardown lifts
THIS FILE's holds and deletes THIS FILE's versions, which the product can
never do (PreservationStorage has no method for either).
"""
from __future__ import annotations

import io
import os
import zipfile
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and MINIO),
    reason="DATABASE_URL and MINIO_ENDPOINT required; preservation is live-gated",
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-11"
API = "/api/v1"
APP = "https://app.example"
SAMPLES = "https://samples.example"
EMAIL_LIKE = "pres-%@noctornal.test"
SCOPE = "Counsel asked for the loader to compare against the new variant"
BASIS = "Production order 2026-114, paragraph 3"


@pytest.fixture(autouse=True)
def deployment(monkeypatch):
    """A split deployment with a declared policy, and the disposition
    UNSET so the default is what is exercised unless a test says
    otherwise."""
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN",
                "NOCTORNAL_BASE_URL", "NOCTORNAL_REJECTED_SAMPLE_DISPOSITION",
                "PRESERVE_BUCKET"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)


class _Written:
    """Every preserved version this file creates, so teardown can lift
    exactly these holds and no others."""

    def __init__(self):
        self.preserved: list[tuple[str, str, str | None]] = []
        self.working: list[str] = []


@pytest.fixture
def written():
    return _Written()


@pytest.fixture
def conn(written):
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    for row in c.execute(
            f"""SELECT preserved_bucket, preserved_key, preserved_version_id
                  FROM lab.sample WHERE id IN {ssub}
                   AND preserved_key IS NOT NULL""").fetchall():
        written.preserved.append((row[0], row[1], row[2]))
    for row in c.execute(
            f"SELECT storage_key FROM lab.sample WHERE id IN {ssub}").fetchall():
        written.working.append(row[0])
    with c.transaction():
        c.execute("ALTER TABLE lab.preservation_authorisation "
                  "DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.preservation_authorisation "
                  f"WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.preservation_authorisation "
                  "ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE user_id IN {sub}")
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()
    _sweep(written)


def _sweep(written: _Written) -> None:
    """Lift this file's holds and remove its objects. Hygiene, not an
    assertion: whatever the store says is swallowed."""
    from minio.error import S3Error

    from noctornal_api.samples import PreservationStorage, SampleStorage
    pres = PreservationStorage()
    for bucket, key, _version in set(written.preserved):
        try:
            versions = [v for v in pres._client.list_objects(
                bucket, prefix=key, include_version=True)
                if v.object_name == key]
        except S3Error:
            continue
        for v in versions:
            try:
                pres._client.disable_object_legal_hold(bucket, key,
                                                       version_id=v.version_id)
                pres._client.remove_object(bucket, key, version_id=v.version_id)
            except S3Error:
                pass
    work = SampleStorage()
    for key in set(written.working):
        try:
            work.delete(key)
        except S3Error:
            pass


# --- helpers ------------------------------------------------------------

def _user(conn, *, roles=(), clearance="RED", name="Preservation"):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"pres-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, name, PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email


def _session(conn, email) -> str:
    """A step-up-fresh session, minted directly as the download-ticket
    tests do: every verb here is step-up gated."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-PRES-{uuid4().hex[:6]}", title="Preservation",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _payload() -> bytes:
    return b"MZ\x90\x00not-really-malware-" + uuid4().bytes * 4


def _live_svc(conn):
    from noctornal_api.samples import (
        PreservationStorage,
        SampleService,
        SampleStorage,
    )
    return SampleService(conn, SampleStorage(), PreservationStorage())


def _submit(conn, who, data=None, **kw):
    from noctornal_api.samples import SampleService, SampleStorage
    return SampleService(conn, SampleStorage()).submit(
        data or _payload(), submitted_by=who, original_filename="loader.exe",
        source_note="dropped by the loader in the capture", **kw)


class MemoryStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


class MemoryPreservation:
    """For the tests about ORDER and REFUSAL, where a live bucket adds
    nothing but held objects to clean up."""

    bucket = "memory-preserved"

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.objects: dict[str, bytes] = {}

    def preserve(self, key, data):
        from noctornal_api.samples import PreservedObject, SampleError
        if self.fail:
            raise SampleError("the preservation store refused the copy "
                              "(InternalError: simulated)")
        self.objects[key] = data
        return PreservedObject(self.bucket, key, "v1", len(data))

    def latest_held(self, key):
        from noctornal_api.samples import PreservedObject
        data = self.objects.get(key)
        return None if data is None else PreservedObject(
            self.bucket, key, "v1", len(data))

    def get(self, key, *, version_id=None, bucket=None):
        return self.objects[key]


def _custody(conn, sample_id, action):
    return conn.execute(
        """SELECT actor_id, detail, archive_format FROM lab.sample_access
            WHERE sample_id = %s AND action = %s ORDER BY occurred_at""",
        (sample_id, action)).fetchall()


def _audit(conn, action, sample_id):
    return conn.execute(
        """SELECT actor_id, outcome, detail FROM audit.event
            WHERE action = %s AND object_id = %s ORDER BY seq""",
        (action, sample_id)).fetchall()


def _key_row(conn, sample_id):
    return conn.execute(
        """SELECT data_key_ciphertext, data_key_id, state, preserved_bucket,
                  preserved_key, preserved_version_id, preserved_at
             FROM lab.sample WHERE id = %s""", (sample_id,)).fetchone()


def _preserve(conn, who, written, **kw):
    """A sample submitted to the real samples bucket and rejected under
    the default disposition, into the real preservation bucket."""
    sample = _submit(conn, who, **kw)
    out = _live_svc(conn).reject(sample.id, actor_id=who,
                                 reason="prohibited content, held for counsel")
    written.preserved.append((out.preserved_bucket, out.preserved_key, None))
    return sample, out


# --- the default: preserve ------------------------------------------------

def test_reject_preserves_by_default(conn, written):
    """F2's whole promise, measured against the real store: the bytes
    moved, the hold is on, the key is kept, and the row says where."""
    from minio.error import S3Error

    from noctornal_api.samples import (
        REJECTED,
        PreservationStorage,
        SampleStorage,
        disposition_setting,
    )
    assert disposition_setting() == ("preserve", None), (
        "with the variable unset the default must be preserve")
    who, _ = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _submit(conn, who)
    working = SampleStorage()
    storage_key = f"samples/{sample.sha256[:2]}/{sample.sha256}"
    ciphertext = working.get(storage_key)
    before = _key_row(conn, sample.id)

    out = _live_svc(conn).reject(sample.id, actor_id=who,
                                 reason="prohibited content, held for counsel")
    written.preserved.append((out.preserved_bucket, out.preserved_key, None))

    assert out.state == REJECTED
    assert out.bytes_disposition == "preserved"
    after = _key_row(conn, sample.id)
    assert after[3] == "noctornal-preserved"
    assert after[4] == f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    assert after[5], "the held version is recorded"
    assert after[6] is not None
    # The key is KEPT, byte for byte.
    assert bytes(after[0]) == bytes(before[0]) and len(bytes(after[0])) > 0
    assert after[1] == before[1]

    with pytest.raises(S3Error):
        working._client.stat_object(working._bucket, storage_key)

    pres = PreservationStorage()
    assert pres.get(after[4], version_id=after[5]) == ciphertext, (
        "what was preserved must be exactly what was stored, still encrypted")
    assert pres.is_held(after[4], version_id=after[5])
    with pytest.raises(S3Error):
        # WORM: a held version cannot be removed, by this credential or any.
        pres._client.remove_object(pres.bucket, after[4], version_id=after[5])

    [(actor, detail, _fmt)] = _custody(conn, sample.id, "REJECTED")
    assert actor == who
    assert detail["disposition"] == "preserved"
    assert detail["preserved_bucket"] == "noctornal-preserved"
    assert detail["preserved_key"] == after[4]
    assert detail["bytes_purged"] is False
    assert _audit(conn, "SAMPLE_REJECTED_PRESERVED", sample.id)


def test_a_preserved_sample_is_not_downloadable_and_says_why(conn, written):
    from noctornal_api.samples import SampleError
    who, _ = _user(conn, roles=("MALWARE_ANALYST",))
    sample, _out = _preserve(conn, who, written)
    with pytest.raises(SampleError, match="preservation store"):
        _live_svc(conn).download(sample.id, actor_id=who,
                                 request_origin=SAMPLES, clearance="RED")


def test_a_legal_hold_does_not_block_preservation(conn, monkeypatch):
    """Preserving deletes nothing that is not first held elsewhere, so a
    hold does not refuse it, and the ledger says a hold was in force."""
    from noctornal_api.samples import SampleService
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s",
                 (sample.id,))
    out = svc.reject(sample.id, actor_id=who, reason="prohibited, preserved")
    assert out.bytes_disposition == "preserved"
    assert not store.objects and pres.objects
    [(_a, detail, _f)] = _custody(conn, sample.id, "REJECTED")
    assert detail["legal_hold"] is True


def test_a_failed_copy_changes_nothing(conn):
    """If the copy fails, nothing moves and nothing is recorded."""
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService
    who, _ = _user(conn)
    store = MemoryStore()
    svc = SampleService(conn, store, MemoryPreservation(fail=True))
    sample = svc.submit(_payload(), submitted_by=who)
    with pytest.raises(SampleError, match="Nothing has changed"):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert store.objects, "the working copy must still be there"
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    assert not _custody(conn, sample.id, "REJECTED")


def test_a_missing_working_copy_is_not_recorded_as_preserved(conn):
    """The demo seed writes no bytes. Saying "preserved" for a row whose
    object never existed would be a false record."""
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService
    who, _ = _user(conn)
    store = MemoryStore()
    svc = SampleService(conn, store, MemoryPreservation())
    sample = svc.submit(_payload(), submitted_by=who)
    store.objects.clear()
    with pytest.raises(SampleError, match="nothing to preserve"):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert _key_row(conn, sample.id)[2] == QUARANTINED


def test_no_preservation_store_refuses_rather_than_destroying(conn):
    from noctornal_api.samples import SampleError, SampleService
    who, _ = _user(conn)
    store = MemoryStore()
    svc = SampleService(conn, store)
    sample = svc.submit(_payload(), submitted_by=who)
    with pytest.raises(SampleError, match="preservation store is not configured"):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert store.objects


def test_an_unknown_disposition_refuses_and_names_the_variable(conn, monkeypatch):
    from noctornal_api.samples import (
        DISPOSITION_ENV,
        QUARANTINED,
        SampleError,
        SampleService,
    )
    monkeypatch.setenv(DISPOSITION_ENV, "shred")
    who, _ = _user(conn)
    store = MemoryStore()
    svc = SampleService(conn, store, MemoryPreservation())
    sample = svc.submit(_payload(), submitted_by=who)
    with pytest.raises(SampleError, match=DISPOSITION_ENV):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    assert store.objects


def test_a_rejection_waiting_on_another_copies_nothing(conn):
    """Verifier on F2, 2026-09-22: two rejections of one sample used to
    BOTH copy into the preservation bucket, and the loser left a held
    version that no row named and nothing can delete. The row is now
    locked before the copy, so the second waits, reads REJECTED, and
    copies nothing. Here the "first" is another connection that rejects
    the row and commits while this rejection is waiting on its lock."""
    import threading

    from noctornal_api.db import connect
    from noctornal_api.samples import SampleError, SampleService
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)

    first = connect()
    try:
        first.autocommit = False
        first.execute("UPDATE lab.sample SET state = 'REJECTED', "
                      "reject_reason = 'the other rejection' WHERE id = %s",
                      (sample.id,))
        timer = threading.Timer(0.5, first.commit)
        timer.start()
        with pytest.raises(SampleError, match="already rejected") as refused:
            svc.reject(sample.id, actor_id=who, reason="prohibited content")
        timer.join()
    finally:
        first.close()
    assert "Nothing was copied" in str(refused.value)
    assert not pres.objects, "the waiting rejection must not have copied"
    assert store.objects, "and must not have touched the working copy"
    assert not _custody(conn, sample.id, "REJECTED")


@pytest.mark.parametrize("path", ["preserve", "record_only", "destroy"])
def test_a_rejection_that_cannot_get_the_row_gives_up_cleanly(conn, monkeypatch,
                                                              path):
    """If the other change outlasts the wait, the rejection stops with a
    message a person can act on, before anything is copied.

    And that message is what the router's 409 carries: raised from the
    LockNotAvailable, `safe_detail` replaced it with "the request could not
    be completed (ref ...)" (final review verifier on U5, 2026-09-23)."""
    from noctornal_api import samples
    from noctornal_api.db import connect
    from noctornal_api.http.errors import safe_detail
    monkeypatch.setattr(samples, "REJECT_LOCK_TIMEOUT", "200ms")
    if path == "destroy":
        monkeypatch.setenv(samples.DISPOSITION_ENV, "destroy")
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = samples.SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)

    other = connect()
    try:
        with other.transaction():
            other.execute("SELECT 1 FROM lab.sample WHERE id = %s FOR UPDATE",
                          (sample.id,))
            with pytest.raises(samples.SampleError,
                               match="still in progress") as refused:
                svc.reject(sample.id, actor_id=who, reason="prohibited content",
                           purge_bytes=path != "record_only")
    finally:
        other.close()
    assert "nothing was copied" in str(refused.value)
    assert safe_detail(refused.value) == str(refused.value)
    assert not pres.objects and store.objects
    assert _key_row(conn, sample.id)[2] == samples.QUARANTINED


def test_a_failure_after_the_copy_names_the_held_copy(conn):
    """Once a held copy exists nothing in this product can delete it, so
    every failure after that point must say where it is. A working store
    that will not delete stands in for any such failure."""
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService

    class StuckStore(MemoryStore):
        def delete(self, key):
            raise OSError("simulated: the working store refused the delete")

    who, _ = _user(conn)
    store, pres = StuckStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    with pytest.raises(SampleError) as refused:
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    assert key in str(refused.value) and "version v1" in str(refused.value)
    # A delete that raised may still have removed the object, so the
    # refusal may not promise the working copy is there (U4, 2026-09-23).
    assert "did not confirm deleting" in str(refused.value)
    assert "still in place" not in str(refused.value)
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    assert not _custody(conn, sample.id, "REJECTED")


def _chain_lock_free() -> bool:
    """Whether the audit chain's advisory lock (0013's `audit.chain_hash`
    takes it for every append and holds it to COMMIT) is free, asked from a
    second connection."""
    from noctornal_api.db import connect
    other = connect()
    try:
        with other.transaction():
            return other.execute(
                "SELECT pg_try_advisory_xact_lock("
                "hashtextextended('audit.event.chain', 0))").fetchone()[0]
    finally:
        other.close()


def test_the_working_copy_delete_does_not_hold_the_audit_chain(conn):
    """Final review C7, 2026-09-23: the working-copy delete, a network
    call, ran after the audit append, so the chain's global advisory lock
    was held across it and a stalled store stalled every audited write in
    the deployment. The delete now runs before the append."""
    from noctornal_api.samples import SampleService
    seen: list[bool] = []

    class Probe(MemoryStore):
        def delete(self, key):
            seen.append(_chain_lock_free())
            super().delete(key)

    who, _ = _user(conn)
    store, pres = Probe(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    out = svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert out.bytes_disposition == "preserved"
    assert seen == [True], "the chain lock was held during the delete"
    assert _audit(conn, "SAMPLE_REJECTED_PRESERVED", sample.id), (
        "the audit row is still written, after the delete")


class _FakeLockedStore:
    """A stand-in for the preservation store's S3 client, for the failures
    a live MinIO will not produce on demand: a PUT whose answer is lost,
    and a read-back that fails or disagrees after the held PUT returned."""

    def __init__(self, *, put_error=None, stat_error=None, size_delta=0,
                 held=True):
        self.put_error = put_error
        self.stat_error = stat_error
        self.size_delta = size_delta
        self.held = held
        self.puts: list[int] = []

    def put_object(self, bucket, key, data, length, **_kw):
        from types import SimpleNamespace
        if self.put_error is not None:
            raise self.put_error
        self.puts.append(length)
        return SimpleNamespace(version_id=f"held-{len(self.puts)}")

    def stat_object(self, bucket, key, version_id=None):
        from types import SimpleNamespace
        if self.stat_error is not None:
            raise self.stat_error
        return SimpleNamespace(size=self.puts[-1] + self.size_delta,
                               version_id=version_id)

    def is_object_legal_hold_enabled(self, bucket, key, version_id=None):
        return self.held


@pytest.mark.parametrize("fault", ["read_back_raises", "size_disagrees",
                                   "hold_not_reported"])
def test_a_read_back_failure_after_the_held_put_names_the_copy(conn, fault):
    """Final review C8, 2026-09-23: once the held PUT returns, a held
    version EXISTS and nothing in this product can delete it. A read-back
    that raised (an S3 or transport error) answered a bare 500, and one that
    disagreed said "Nothing has changed"; neither named the version, and
    each retry wrote another. Now every such failure is a SampleError (the
    router's 409) naming bucket, key and version, and an audit row records
    it outside the rolled-back transaction."""
    from noctornal_api.samples import (
        QUARANTINED,
        PreservationStorage,
        SampleError,
        SampleService,
    )
    fake = {"read_back_raises": _FakeLockedStore(
                stat_error=TimeoutError("simulated: no answer to the HEAD")),
            "size_disagrees": _FakeLockedStore(size_delta=-1),
            "hold_not_reported": _FakeLockedStore(held=False)}[fault]
    pres = PreservationStorage()
    pres._client = fake
    who, _ = _user(conn)
    store = MemoryStore()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"

    with pytest.raises(SampleError) as refused:
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    text = str(refused.value)
    assert f"{pres.bucket}/{key}, version held-1" in text, text
    assert "Nothing has changed" not in text, text
    # The console offers "record the rejection only" on either phrase, and
    # that is the one way out that strands a held copy.
    assert "purge_bytes" not in text and "legal hold" not in text.lower(), text
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    assert store.objects, "the working copy was not deleted"
    [(actor, outcome, detail)] = _audit(
        conn, "SAMPLE_PRESERVATION_INCOMPLETE", sample.id)
    assert actor == who and outcome == "FAILED"
    assert detail["preserved_key"] == key
    assert detail["preserved_version_id"] == "held-1"
    assert detail["copy_confirmed"] is True
    assert detail["working_copy_gone"] is False


def test_a_held_put_that_was_never_answered_says_a_copy_may_exist(conn):
    """C8's sibling: the PUT went out and no answer came back, so a held
    version may exist and its version is unknown. A 500 said nothing."""
    from noctornal_api.samples import (
        QUARANTINED,
        PreservationStorage,
        SampleError,
        SampleService,
    )
    pres = PreservationStorage()
    pres._client = _FakeLockedStore(
        put_error=TimeoutError("simulated: the answer was lost"))
    who, _ = _user(conn)
    store = MemoryStore()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    with pytest.raises(SampleError, match="may exist") as refused:
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert f"{pres.bucket}/{key}" in str(refused.value)
    assert _key_row(conn, sample.id)[2] == QUARANTINED and store.objects
    [(_a, outcome, detail)] = _audit(
        conn, "SAMPLE_PRESERVATION_INCOMPLETE", sample.id)
    assert outcome == "FAILED" and detail["copy_confirmed"] is False
    assert detail["preserved_version_id"] is None


#: Raw PQ text of the kind a psycopg error carries, which the HTTP layer
#: must never return to a client.
_PQ_TEXT = "DETAIL:  Key (sample_id)=(pq-secret-value) is not present"


def _fail_the_audit_once(svc, action):
    """Make the first append of `action` fail as it fails in production,
    with a psycopg error: the append is an INSERT and only COMMIT follows
    it, so nothing else can fail after the working-copy delete. A
    RuntimeError stood in here until the final review's verifier found it
    hid the real defect: `safe_detail` discards the whole message of an
    error chained to a psycopg one (U4, 2026-09-23)."""
    import psycopg
    real = svc._audit
    state = {"failed": False}

    def audit(name, **kw):
        if name == action and not state["failed"]:
            state["failed"] = True
            raise psycopg.OperationalError(
                f"simulated: server closed the connection unexpectedly "
                f"{_PQ_TEXT}")
        return real(name, **kw)
    svc._audit = audit


def test_a_failure_after_the_delete_says_so_and_the_retry_adopts_the_copy(
        conn):
    """Final review U4, 2026-09-23. A failure after the working-copy delete
    was reported as "the working copy is still in place"; the retry then
    found nothing to read and pointed at a record-only rejection, which
    left the held copy named by no row, for good. Now the refusal says the
    held copy is the only copy, and the retry records THAT copy."""
    from noctornal_api.http.errors import safe_detail
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    _fail_the_audit_once(svc, "SAMPLE_REJECTED_PRESERVED")

    with pytest.raises(SampleError) as refused:
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    text = str(refused.value)
    assert "no longer in the samples store" in text, text
    assert "still in place" not in text, text
    assert "purge_bytes" not in text and "legal hold" not in text.lower()
    assert key in text and "version v1" in text
    assert not store.objects and pres.objects, "the delete had happened"
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    [(_a, _o, detail)] = _audit(conn, "SAMPLE_PRESERVATION_INCOMPLETE",
                                sample.id)
    assert detail["working_copy_gone"] is True
    # What the analyst is shown: the router answers 409 with
    # `safe_detail(exc)`, which returned "the request could not be completed
    # (ref ...)" for this refusal while it was chained to the psycopg error.
    # The database error is named by class and ref, never by its PQ text.
    shown = safe_detail(refused.value)
    assert shown == text, shown
    assert "OperationalError" in shown and f"ref {detail['log_ref']}" in shown
    assert "pq-secret-value" not in shown and "DETAIL" not in shown, shown
    assert "written to the audit log" in shown

    out = svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert out.bytes_disposition == "preserved"
    assert out.preserved_key == key
    [(_a, custody, _f)] = _custody(conn, sample.id, "REJECTED")
    assert custody["adopted_held_copy"] is True
    assert custody["preserved_version_id"] == "v1"
    assert _audit(conn, "SAMPLE_REJECTED_PRESERVED", sample.id)


def test_a_dropped_connection_after_the_delete_still_names_the_copy(conn):
    """The final review verifier's case, with a connection that really
    dies between the working-copy delete and COMMIT (U4, 2026-09-23). The
    audit row recording the failure cannot be written either, on the same
    dead connection, so the refusal is the only record of where the one
    remaining copy is, and it has to reach the analyst whole. A retry on a
    live connection then adopts that copy."""
    from noctornal_api.db import connect
    from noctornal_api.http.errors import safe_detail
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    doomed = connect()
    svc = SampleService(doomed, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    real = svc._audit

    def audit(name, **kw):
        if name == "SAMPLE_REJECTED_PRESERVED":
            doomed.close()
        return real(name, **kw)
    svc._audit = audit
    try:
        with pytest.raises(SampleError) as refused:
            svc.reject(sample.id, actor_id=who, reason="prohibited content")
    finally:
        doomed.close()
    shown = safe_detail(refused.value)
    assert f"{pres.bucket}/{key}, version v1" in shown, shown
    assert "no longer in the samples store" in shown, shown
    assert "could not be written to the audit log" in shown, shown
    assert "request could not be completed" not in shown, shown
    assert not store.objects and pres.objects
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    assert not _audit(conn, "SAMPLE_PRESERVATION_INCOMPLETE", sample.id)

    out = SampleService(conn, store, pres).reject(
        sample.id, actor_id=who, reason="prohibited content")
    assert out.bytes_disposition == "preserved" and out.preserved_key == key
    [(_a, custody, _f)] = _custody(conn, sample.id, "REJECTED")
    assert custody["adopted_held_copy"] is True


@pytest.mark.parametrize("fault", ["held_read_fails", "data_key_fails"])
def test_an_adoption_that_cannot_check_the_copy_refuses_cleanly(
        conn, monkeypatch, fault):
    """Adoption reads the held copy and opens it with the kept data key.
    Either failing raised raw and answered a bare 500, where a missing
    working object had always been a 409 (final review verifier on U4,
    2026-09-23). Now it is a refusal that names the held copy it found and
    records nothing."""
    from noctornal_api import samples
    from noctornal_api.http.errors import safe_detail

    class Unreadable(MemoryPreservation):
        def get(self, key, *, version_id=None, bucket=None):
            raise OSError("simulated: the preservation store did not answer")

    who, _ = _user(conn)
    store = MemoryStore()
    pres = Unreadable() if fault == "held_read_fails" else MemoryPreservation()
    svc = samples.SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    # An earlier attempt moved the real ciphertext and failed to record it.
    [ciphertext] = store.objects.values()
    pres.objects[key] = ciphertext
    store.objects.clear()
    if fault == "data_key_fails":
        def no_key(*_a, **_k):
            raise ValueError("simulated: the key ring has no such key")
        monkeypatch.setattr(samples.envelope, "decrypt", no_key)

    with pytest.raises(samples.SampleError) as refused:
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    text = str(refused.value)
    assert f"{pres.bucket}/{key} (version v1)" in text, text
    assert ("could not be read" if fault == "held_read_fails"
            else "data key could not be opened") in text, text
    assert "nothing has changed" in text and "purge_bytes" not in text
    assert safe_detail(refused.value) == text
    assert _key_row(conn, sample.id)[2] == samples.QUARANTINED
    assert not _custody(conn, sample.id, "REJECTED")


def test_the_retry_adopts_the_held_version_in_the_real_store(conn, written):
    """U4 against the real object-locked bucket: `latest_held` must find the
    version the failed attempt wrote (a HEAD and a hold read, which the
    preservation account's policy allows), and the retry must record THAT
    version, not write another."""
    from minio.error import S3Error

    from noctornal_api.samples import (
        PreservationStorage,
        SampleError,
        SampleStorage,
    )
    who, _ = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _submit(conn, who)
    svc = _live_svc(conn)
    _fail_the_audit_once(svc, "SAMPLE_REJECTED_PRESERVED")
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    written.preserved.append(("noctornal-preserved", key, None))
    with pytest.raises(SampleError, match="no longer in the samples store"):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    first = PreservationStorage().latest_held(key)
    assert first is not None and first.version_id

    out = svc.reject(sample.id, actor_id=who, reason="prohibited content")
    row = _key_row(conn, sample.id)
    assert out.bytes_disposition == "preserved"
    assert row[5] == first.version_id, "the retry must adopt, not rewrite"
    assert PreservationStorage().latest_held(key).version_id == first.version_id
    working = SampleStorage()
    storage_key = f"samples/{sample.sha256[:2]}/{sample.sha256}"
    with pytest.raises(S3Error):
        working._client.stat_object(working._bucket, storage_key)


def test_a_retry_never_adopts_a_held_copy_that_is_not_this_sample(conn):
    """The adoption proves the bytes: same size is not enough, the kept
    data key must open them to this sample's SHA-256."""
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    key = f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    pres.objects[key] = bytes(sample.byte_size)
    store.objects.clear()
    with pytest.raises(SampleError, match="is not this sample"):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert _key_row(conn, sample.id)[2] == QUARANTINED
    assert not _custody(conn, sample.id, "REJECTED")


def test_an_unreachable_working_store_is_not_read_as_a_missing_object(conn):
    """Only a store that says the object is ABSENT can lead to adoption or
    to the record-only suggestion; one that did not answer proves
    nothing."""
    from noctornal_api.samples import QUARANTINED, SampleError, SampleService

    class Down(MemoryStore):
        def get(self, key):
            raise OSError("simulated: connection refused")

    who, _ = _user(conn)
    store, pres = Down(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    with pytest.raises(SampleError, match="could not be read") as refused:
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert "purge_bytes" not in str(refused.value)
    assert _key_row(conn, sample.id)[2] == QUARANTINED and not pres.objects


@pytest.mark.parametrize("path", ["record_only", "destroy"])
def test_a_rejection_waiting_on_another_changes_nothing(conn, monkeypatch,
                                                         path):
    """Final review U5, 2026-09-23: only the preserving path locked the
    row, so a record-only (or destroy) rejection that started while
    another was in flight passed the unlocked pre-check, waited on its
    UPDATE, then overwrote the first one's reason and appended a second,
    contradictory REJECTED custody row. Destroy also deleted the bytes
    first. Every path now takes the row lock and reads REJECTED."""
    import threading

    from noctornal_api.db import connect
    from noctornal_api.samples import DISPOSITION_ENV, SampleError, SampleService
    if path == "destroy":
        monkeypatch.setenv(DISPOSITION_ENV, "destroy")
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)

    first = connect()
    try:
        first.autocommit = False
        first.execute("UPDATE lab.sample SET state = 'REJECTED', "
                      "reject_reason = 'the other rejection' WHERE id = %s",
                      (sample.id,))
        timer = threading.Timer(0.5, first.commit)
        timer.start()
        with pytest.raises(SampleError, match="already rejected"):
            svc.reject(sample.id, actor_id=who, reason="a second opinion",
                       purge_bytes=path == "destroy")
        timer.join()
    finally:
        first.close()
    reason = conn.execute("SELECT reject_reason FROM lab.sample WHERE id = %s",
                          (sample.id,)).fetchone()[0]
    assert reason == "the other rejection"
    assert not _custody(conn, sample.id, "REJECTED")
    assert store.objects, "nothing was destroyed"


def test_purge_bytes_false_records_and_disposes_of_nothing(conn):
    from noctornal_api.samples import REJECTED, SampleService
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    out = svc.reject(sample.id, actor_id=who, reason="out of scope",
                     purge_bytes=False)
    assert out.state == REJECTED and out.bytes_disposition == "kept"
    assert store.objects and not pres.objects
    assert len(bytes(_key_row(conn, sample.id)[0])) > 0


# --- destroy, as an operator's choice --------------------------------------

def test_destroy_mode_deletes_the_bytes_and_the_key(conn, monkeypatch):
    from noctornal_api.samples import DISPOSITION_ENV, SampleService
    monkeypatch.setenv(DISPOSITION_ENV, "destroy")
    who, _ = _user(conn)
    store, pres = MemoryStore(), MemoryPreservation()
    svc = SampleService(conn, store, pres)
    sample = svc.submit(_payload(), submitted_by=who)
    out = svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert out.bytes_disposition == "destroyed"
    assert not store.objects and not pres.objects
    row = _key_row(conn, sample.id)
    assert bytes(row[0]) == b"" and row[4] is None
    [(_a, detail, _f)] = _custody(conn, sample.id, "REJECTED")
    assert detail["disposition"] == "destroyed" and detail["bytes_purged"]


@pytest.mark.parametrize("where", ["sample", "case"])
def test_a_legal_hold_still_blocks_destroy(conn, monkeypatch, where):
    from noctornal_api.samples import (
        DISPOSITION_ENV,
        QUARANTINED,
        SampleError,
        SampleService,
    )
    monkeypatch.setenv(DISPOSITION_ENV, "destroy")
    who, _ = _user(conn)
    case_id = _case(conn, who)
    store = MemoryStore()
    svc = SampleService(conn, store)
    sample = svc.submit(_payload(), submitted_by=who, case_id=case_id)
    if where == "sample":
        conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s",
                     (sample.id,))
    else:
        conn.execute('UPDATE core."case" SET legal_hold = true, '
                     "legal_hold_reason = 'preservation order' WHERE id = %s",
                     (case_id,))
    with pytest.raises(SampleError, match="legal hold"):
        svc.reject(sample.id, actor_id=who, reason="prohibited content")
    assert store.objects
    assert _key_row(conn, sample.id)[2] == QUARANTINED


# --- the schema ------------------------------------------------------------

def test_the_database_refuses_a_preserved_row_without_its_key(conn):
    """Ciphertext with no key satisfies a preservation order in form and
    defeats it in substance, so 0063 makes it impossible, not just
    avoided."""
    import psycopg

    from noctornal_api.samples import SampleService
    who, _ = _user(conn)
    svc = SampleService(conn, MemoryStore(), MemoryPreservation())
    sample = svc.submit(_payload(), submitted_by=who)
    svc.reject(sample.id, actor_id=who, reason="prohibited, preserved")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE lab.sample SET data_key_ciphertext = '' "
                     "WHERE id = %s", (sample.id,))
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE lab.sample SET preserved_at = NULL WHERE id = %s",
                     (sample.id,))


def test_every_truncate_guarded_table_is_accounted_for(conn):
    """The accounting `test_app_role_privileges_pg.py` does, without the
    runtime role that file needs. That file runs only where
    `noctornal_app` exists (CI creates it; no developer database has it),
    so when 0063 first added a BEFORE TRUNCATE trigger that 0060 had never
    heard of, CI went red and every local run was green (verifier,
    2026-09-22). This reads only the catalog and the migrations, so it
    fails where the change is made."""
    import importlib.util
    from pathlib import Path

    versions = (Path(__file__).resolve().parents[3] / "db" / "migrations"
                / "versions")
    ledgers: set[str] = set()
    guarded: dict[str, tuple[str, ...]] = {}
    for path in sorted(versions.glob("[0-9][0-9][0-9][0-9]_*.py")):
        if path.name < "0060":
            continue
        spec = importlib.util.spec_from_file_location(f"m{path.stem[:4]}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        ledgers |= set(getattr(module, "LEDGERS", ()))
        guarded.update(getattr(module, "GUARDED_TABLES", {}))
    assert guarded.get("lab.preservation_authorisation") == (
        "SELECT", "INSERT", "UPDATE"), guarded
    found = {r[0] for r in conn.execute(
        """SELECT n.nspname || '.' || c.relname
             FROM pg_trigger t
             JOIN pg_class c ON c.oid = t.tgrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE NOT t.tgisinternal
              AND pg_get_triggerdef(t.oid) LIKE '%BEFORE TRUNCATE%'""")}
    assert found == ledgers | set(guarded), {
        "unaccounted for": sorted(found - ledgers - set(guarded)),
        "declared but not guarded": sorted((ledgers | set(guarded)) - found)}


def test_an_authorisation_is_two_people_and_cannot_be_rewritten(conn):
    import psycopg

    from noctornal_api.samples import SampleService
    officer, _ = _user(conn, roles=("SECURITY_OFFICER",))
    owner, _ = _user(conn, roles=("CASE_OWNER",))
    svc = SampleService(conn, MemoryStore(), MemoryPreservation())
    sample = svc.submit(_payload(), submitted_by=owner)
    svc.reject(sample.id, actor_id=owner, reason="prohibited, preserved")

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO lab.preservation_authorisation
                   (sample_id, granted_to, granted_by, scope_note, legal_basis,
                    expires_at)
               VALUES (%s, %s, %s, %s, %s, now() + interval '1 day')""",
            (sample.id, officer, officer, SCOPE, BASIS))
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO lab.preservation_authorisation
                   (sample_id, granted_to, granted_by, scope_note, legal_basis,
                    expires_at)
               VALUES (%s, %s, %s, %s, %s, now() + interval '31 days')""",
            (sample.id, owner, officer, SCOPE, BASIS))

    auth = svc.grant_preservation_authorisation(
        sample.id, granted_to=owner, granted_by=officer, scope_note=SCOPE,
        legal_basis=BASIS)
    for sql in ("UPDATE lab.preservation_authorisation SET scope_note = "
                "'widened to everything in the building' WHERE id = %s",
                "UPDATE lab.preservation_authorisation SET expires_at = "
                "expires_at + interval '1 day' WHERE id = %s",
                "DELETE FROM lab.preservation_authorisation WHERE id = %s"):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql, (auth,))
    svc.revoke_preservation_authorisation(auth, sample_id=sample.id,
                                          actor_id=officer)
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE lab.preservation_authorisation "
                     "SET revoked_at = NULL, revoked_by = NULL WHERE id = %s",
                     (auth,))


def test_a_grant_is_refused_to_oneself_and_to_someone_who_cannot_use_it(conn):
    from noctornal_api.samples import SampleError, SampleService
    officer, _ = _user(conn, roles=("SECURITY_OFFICER",))
    analyst, _ = _user(conn, roles=("MALWARE_ANALYST",))
    svc = SampleService(conn, MemoryStore(), MemoryPreservation())
    sample = svc.submit(_payload(), submitted_by=analyst)
    svc.reject(sample.id, actor_id=analyst, reason="prohibited, preserved")
    with pytest.raises(SampleError, match="two people"):
        svc.grant_preservation_authorisation(
            sample.id, granted_to=officer, granted_by=officer,
            scope_note=SCOPE, legal_basis=BASIS)
    with pytest.raises(SampleError, match="sample.preserved.retrieve"):
        svc.grant_preservation_authorisation(
            sample.id, granted_to=analyst, granted_by=officer,
            scope_note=SCOPE, legal_basis=BASIS)
    with pytest.raises(SampleError, match="blanket"):
        svc.grant_preservation_authorisation(
            sample.id, granted_to=analyst, granted_by=officer,
            scope_note="because", legal_basis=BASIS)


# --- retrieval ---------------------------------------------------------------

def _open_archive(blob: bytes) -> bytes:
    zf = zipfile.ZipFile(io.BytesIO(blob))
    info = zf.infolist()[0]
    assert info.flag_bits & 0x1, "the retrieval must be the ENCRYPTED archive"
    return zf.read(info.filename, pwd=b"infected")


def test_retrieval_is_refused_without_an_authorisation(conn, written):
    from noctornal_api.samples import AuthorisationRequired
    owner, _ = _user(conn, roles=("CASE_OWNER",))
    sample, _out = _preserve(conn, owner, written)
    with pytest.raises(AuthorisationRequired, match="live authorisation"):
        _live_svc(conn).retrieve_preserved(
            sample.id, actor_id=owner, request_origin=SAMPLES, clearance="RED")
    [(actor, outcome, detail)] = _audit(
        conn, "SAMPLE_PRESERVED_RETRIEVAL_REFUSED", sample.id)
    assert actor == owner and outcome == "DENIED"
    assert detail["reason"] == "no_live_authorisation"
    assert not _custody(conn, sample.id, "DOWNLOADED")


def test_retrieval_is_refused_to_the_authoriser_themselves(conn, written):
    """The Security Officer who granted a retrieval to the case owner
    holds no authorisation naming THEMSELVES, and cannot create one."""
    from noctornal_api.samples import AuthorisationRequired
    officer, _ = _user(conn, roles=("SECURITY_OFFICER",))
    owner, _ = _user(conn, roles=("CASE_OWNER",))
    sample, _out = _preserve(conn, owner, written)
    svc = _live_svc(conn)
    svc.grant_preservation_authorisation(
        sample.id, granted_to=owner, granted_by=officer, scope_note=SCOPE,
        legal_basis=BASIS)
    with pytest.raises(AuthorisationRequired):
        svc.retrieve_preserved(sample.id, actor_id=officer,
                               request_origin=SAMPLES, clearance="RED")
    refused = _audit(conn, "SAMPLE_PRESERVED_RETRIEVAL_REFUSED", sample.id)
    assert [r[0] for r in refused] == [officer]
    assert not _custody(conn, sample.id, "DOWNLOADED")


def test_a_live_authorisation_releases_the_encrypted_archive_and_is_audited(
        conn, written):
    from noctornal_api.samples import PreservationStorage
    officer, _ = _user(conn, roles=("SECURITY_OFFICER",))
    owner, _ = _user(conn, roles=("CASE_OWNER",))
    data = _payload()
    sample = _submit(conn, owner, data=data)
    out = _live_svc(conn).reject(sample.id, actor_id=owner,
                                 reason="prohibited content, held for counsel")
    written.preserved.append((out.preserved_bucket, out.preserved_key, None))
    svc = _live_svc(conn)
    auth = svc.grant_preservation_authorisation(
        sample.id, granted_to=owner, granted_by=officer, scope_note=SCOPE,
        legal_basis=BASIS)

    blob, digest = svc.retrieve_preserved(
        sample.id, actor_id=owner, request_origin=SAMPLES, clearance="RED")
    assert digest == sample.sha256
    assert _open_archive(blob) == data

    [(actor, detail, fmt)] = _custody(conn, sample.id, "DOWNLOADED")
    assert actor == owner and fmt == "ZIP_INFECTED"
    assert detail["source"] == "preservation_store"
    assert detail["authorisation_id"] == str(auth)
    [(actor, outcome, adetail)] = _audit(conn, "SAMPLE_PRESERVED_RETRIEVED",
                                         sample.id)
    assert actor == owner and outcome == "SUCCESS"
    assert adetail["authorisation_id"] == str(auth)
    assert conn.execute(
        "SELECT retrieval_count FROM lab.preservation_authorisation "
        "WHERE id = %s", (auth,)).fetchone()[0] == 1
    row = _key_row(conn, sample.id)
    assert PreservationStorage().is_held(row[4], version_id=row[5]), (
        "a retrieval must never release the legal hold")


def test_a_revoked_authorisation_releases_nothing(conn, written):
    from noctornal_api.samples import AuthorisationRequired
    officer, _ = _user(conn, roles=("SECURITY_OFFICER",))
    owner, _ = _user(conn, roles=("CASE_OWNER",))
    sample, _out = _preserve(conn, owner, written)
    svc = _live_svc(conn)
    auth = svc.grant_preservation_authorisation(
        sample.id, granted_to=owner, granted_by=officer, scope_note=SCOPE,
        legal_basis=BASIS)
    svc.revoke_preservation_authorisation(auth, sample_id=sample.id,
                                          actor_id=officer)
    with pytest.raises(AuthorisationRequired):
        svc.retrieve_preserved(sample.id, actor_id=owner,
                               request_origin=SAMPLES, clearance="RED")


def test_retrieval_is_refused_on_the_application_origin(conn, written):
    """Invariant 10 applies to a preserved sample exactly as to a live one."""
    from noctornal_api.samples import SampleError
    officer, _ = _user(conn, roles=("SECURITY_OFFICER",))
    owner, _ = _user(conn, roles=("CASE_OWNER",))
    sample, _out = _preserve(conn, owner, written)
    svc = _live_svc(conn)
    svc.grant_preservation_authorisation(
        sample.id, granted_to=owner, granted_by=officer, scope_note=SCOPE,
        legal_basis=BASIS)
    with pytest.raises(SampleError, match="sample origin"):
        svc.retrieve_preserved(sample.id, actor_id=owner, request_origin=APP,
                               clearance="RED")
    [(_a, _o, detail)] = _audit(conn, "SAMPLE_PRESERVED_RETRIEVAL_REFUSED",
                                sample.id)
    assert detail["reason"] == "origin_split"


# --- over HTTP ---------------------------------------------------------------

@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def test_a_retrieval_crosses_the_split_on_a_ticket_minted_for_it(
        conn, client, written, monkeypatch):
    officer, officer_email = _user(conn, roles=("SECURITY_OFFICER",))
    owner, owner_email = _user(conn, roles=("CASE_OWNER",))
    analyst, analyst_email = _user(conn, roles=("MALWARE_ANALYST",))
    data = _payload()
    sample = _submit(conn, analyst, data=data)

    # Rejected over HTTP: the default preserves.
    r = client.post(f"{API}/samples/{sample.id}/reject",
                    headers=_auth(_session(conn, analyst_email)),
                    json={"reason": "prohibited content, held for counsel"})
    assert r.status_code == 200, r.text
    assert r.json()["bytes_disposition"] == "preserved"
    row = _key_row(conn, sample.id)
    written.preserved.append((row[3], row[4], row[5]))

    owner_token = _session(conn, owner_email)
    officer_token = _session(conn, officer_email)
    retrieve = f"{API}/samples/{sample.id}/preserved/retrieval-ticket"

    # No authorisation: 451, the control working.
    r = client.post(retrieve, headers=_auth(owner_token))
    assert r.status_code == 451, r.text

    # The case owner cannot authorise, the officer cannot authorise
    # themselves, and the officer CAN authorise the owner.
    grant = f"{API}/samples/{sample.id}/preserved/authorisations"
    body = {"scope_note": SCOPE, "legal_basis": BASIS, "duration_days": 2}
    r = client.post(grant, headers=_auth(owner_token),
                    json={**body, "granted_to": owner_email})
    assert r.status_code == 403, r.text
    r = client.post(grant, headers=_auth(officer_token),
                    json={**body, "granted_to": officer_email})
    assert r.status_code == 400, r.text
    r = client.post(grant, headers=_auth(officer_token),
                    json={**body, "granted_to": owner_email})
    assert r.status_code == 201, r.text

    # The officer, holding no authorisation and not the retrieve verb, is
    # refused the ticket; a download ticket for a preserved sample is
    # refused to the analyst, and the owner cannot mint one at all.
    assert client.post(retrieve, headers=_auth(officer_token)).status_code == 403
    r = client.post(f"{API}/samples/{sample.id}/download-ticket",
                    headers=_auth(_session(conn, analyst_email)))
    assert r.status_code == 409 and "preservation store" in r.text, r.text
    r = client.post(f"{API}/samples/{sample.id}/download-ticket",
                    headers=_auth(owner_token))
    assert r.status_code == 403, r.text

    minted = client.post(retrieve, headers=_auth(owner_token))
    assert minted.status_code == 201, minted.text
    ticket = minted.json()
    assert ticket["download_url"] == f"{SAMPLES}{API}/samples/{sample.id}/download"

    # The second process.
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    served = client.post(f"{API}/samples/{sample.id}/download",
                         data={"ticket": ticket["ticket"]})
    assert served.status_code == 200, served.text
    assert served.headers["Content-Security-Policy"] == (
        "default-src 'none'; sandbox")
    assert _open_archive(served.content) == data
    [(actor, detail, _f)] = _custody(conn, sample.id, "DOWNLOADED")
    assert actor == owner and detail["via"] == "ticket"
    assert detail["source"] == "preservation_store"
    assert _audit(conn, "SAMPLE_RETRIEVAL_TICKET_ISSUED", sample.id)
    assert _audit(conn, "SAMPLE_PRESERVED_RETRIEVED", sample.id)


def test_the_officer_reaches_preserved_samples_without_reading_content(
        conn, client):
    """Final review U3, 2026-09-23: authorising a retrieval was offered only
    inside the Lab's sample card, under `sample.read`, which the Security
    Officer does not hold (Security Officers read no case content). So the
    only role allowed to authorise could never reach the form. The officer
    now has a list of their own, gated on `sample.preserved.authorise`,
    carrying identity and authorisations and none of the content."""
    from noctornal_api.samples import SampleService
    officer, officer_email = _user(conn, roles=("SECURITY_OFFICER",))
    amber, amber_email = _user(conn, roles=("SECURITY_OFFICER",),
                               clearance="AMBER")
    owner, owner_email = _user(conn, roles=("CASE_OWNER",))
    svc = SampleService(conn, MemoryStore(), MemoryPreservation())
    sample = svc.submit(_payload(), submitted_by=owner,
                        original_filename="invoice.pdf.exe",
                        source_note="from the informant's laptop")
    svc.reject(sample.id, actor_id=owner, reason="prohibited, preserved")
    red = svc.submit(_payload(), submitted_by=owner, classification="RED")
    svc.reject(red.id, actor_id=owner, reason="prohibited, preserved")
    officer_token = _auth(_session(conn, officer_email))

    # The premise: the Lab is closed to the officer, by design.
    assert client.get(f"{API}/samples", headers=officer_token).status_code == 403
    assert client.get(f"{API}/samples/{sample.id}",
                      headers=officer_token).status_code == 403

    r = client.get(f"{API}/samples/preserved", headers=officer_token)
    assert r.status_code == 200, r.text
    listed = {s["id"]: s for s in r.json()["samples"]}
    row = listed[str(sample.id)]
    assert row["sha256"] == sample.sha256
    assert row["preserved_key"] == f"preserved/{sample.sha256[:2]}/{sample.sha256}"
    assert row["authorisations"] == []
    for content in ("original_filename", "source_note", "reject_reason",
                    "analyses", "custody", "submitted_by"):
        assert content not in row, f"the officer's list carries {content}"
    assert "invoice.pdf.exe" not in r.text and "informant" not in r.text
    assert "prohibited, preserved" not in r.text

    # What the officer does from there.
    r = client.post(f"{API}/samples/{sample.id}/preserved/authorisations",
                    headers=officer_token,
                    json={"scope_note": SCOPE, "legal_basis": BASIS,
                          "granted_to": owner_email})
    assert r.status_code == 201, r.text
    row = next(s for s in client.get(
        f"{API}/samples/preserved", headers=officer_token).json()["samples"]
        if s["id"] == str(sample.id))
    [auth] = row["authorisations"]
    assert auth["live"] and auth["granted_to_email"] == owner_email

    # The labels still gate it, as they gate the authorise route.
    r = client.get(f"{API}/samples/preserved",
                   headers=_auth(_session(conn, amber_email)))
    assert r.status_code == 200, r.text
    ids = {s["id"] for s in r.json()["samples"]}
    assert str(sample.id) in ids and str(red.id) not in ids
    # And it is the officer's verb, not everybody's.
    r = client.get(f"{API}/samples/preserved",
                   headers=_auth(_session(conn, owner_email)))
    assert r.status_code == 403, r.text


def test_the_queue_answers_every_state_and_the_case_filter(conn, client):
    """ux13-lab:rejected-filter-always-empty and lab-not-case-scoped: the
    route took neither a state nor a case, so three filters were always
    empty and a case's Lab listed every case."""
    from noctornal_api.samples import SampleService
    owner, owner_email = _user(conn, roles=("CASE_OWNER",))
    case_a, case_b = _case(conn, owner), _case(conn, owner)
    svc = SampleService(conn, MemoryStore())
    live = svc.submit(_payload(), submitted_by=owner, case_id=case_a)
    gone = svc.submit(_payload(), submitted_by=owner, case_id=case_a)
    other = svc.submit(_payload(), submitted_by=owner, case_id=case_b)
    svc.reject(gone.id, actor_id=owner, reason="out of scope",
               purge_bytes=False)
    token = _auth(_session(conn, owner_email))

    def ids(**params):
        r = client.get(f"{API}/samples", params=params, headers=token)
        assert r.status_code == 200, r.text
        return {s["id"] for s in r.json()["samples"]}

    assert ids(state="REJECTED", case_id=str(case_a)) == {str(gone.id)}
    assert ids(case_id=str(case_a)) == {str(live.id)}, (
        "the working set excludes rejected work and other cases")
    assert str(other.id) in ids()
    assert ids(state="REPORTED", case_id=str(case_a)) == set()
    r = client.get(f"{API}/samples", params={"state": "DELETED"}, headers=token)
    assert r.status_code == 400 and "QUARANTINED" in r.text, r.text
    row = next(s for s in client.get(
        f"{API}/samples", params={"state": "REJECTED", "case_id": str(case_a)},
        headers=token).json()["samples"])
    assert row["reject_reason"] == "out of scope"
    assert row["bytes_disposition"] == "kept"
    assert row["submitted_by_name"] == "Preservation"


def test_the_detail_records_a_look_and_names_who_acted(conn, client):
    """ux13-lab:custody-ledger-hides-who-and-what: "every look is a row"
    and no look was; the ledger named nobody."""
    from noctornal_api.samples import SampleService
    owner, owner_email = _user(conn, roles=("CASE_OWNER",), name="Olive Owner")
    sample = SampleService(conn, MemoryStore()).submit(
        _payload(), submitted_by=owner, source_note="from the capture")
    token = _auth(_session(conn, owner_email))
    for _ in range(2):
        r = client.get(f"{API}/samples/{sample.id}", headers=token)
        assert r.status_code == 200, r.text
    views = [d for _a, d, _f in _custody(conn, sample.id, "VIEWED_META")
             if d.get("event") == "viewed"]
    assert len(views) == 1, "one look per person per window, not per render"
    body = r.json()
    assert body["sample"]["source_note"] == "from the capture"
    assert body["sample"]["submitted_by_name"] == "Olive Owner"
    events = {c["event"] for c in body["custody"]}
    assert {"submitted", "viewed"} <= events
    assert all(c["actor_name"] == "Olive Owner" for c in body["custody"])
