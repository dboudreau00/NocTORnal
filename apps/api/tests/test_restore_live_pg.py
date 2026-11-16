"""A restore into a fresh bucket set of the REAL dev MinIO (decision 240).

The in-process tests prove the logic against a store written for them. This proves it against the store the
product ships: a fresh evidence bucket and a fresh preservation bucket, each with object lock, an exhibit and
a preserved sample whose lodged version ids are ones this store never gave (as if from a lost store, so the
pinned read fails with NoSuchVersion), their bytes in a mirror directory, and the real tool. It checks what
only the store can say: the version it hands back, the COMPLIANCE lock it keeps and the legal hold it reads
back (a delete of the version is refused while either holds), a second run that finds the bytes in place and
writes nothing, and a doctored mirror file refused with nothing stored.

## Every exhibit written here is locked for LOCK_SECONDS, permanently

A COMPLIANCE retention cannot be shortened or lifted by any credential, so the locks are seconds, the buckets
are this run's own (`noctornal-r07-...`, never the production-shaped names) and the keys sit under one
prefix. The module's teardown waits for the locks to end, removes every version, then the buckets. Never
raise LOCK_SECONDS to something that outlives a working day. A preserved sample is held and not locked, so
the teardown lifts its hold (the one place a hold is lifted, as in `test_sample_preservation_pg.py`: the
product has no method for it) before it deletes the version.

Gated exactly like `test_evidence_lock_live_pg.py`: DATABASE_URL and MINIO_ENDPOINT, and a precondition that
FAILS, never skips, when a fresh bucket reports no object lock (a pass would be for the wrong reason).
Account prefix `rstl-`.
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import blake3
import pytest

import rls_support as s
from restore_support import write_mirror
from rolled_back import rolled_back

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = [pytest.mark.skipif(
    not (DATABASE_URL and MINIO and os.environ.get("NOCTORNAL_APP_DB_ROLE")),
    reason="DATABASE_URL, MINIO_ENDPOINT and NOCTORNAL_APP_DB_ROLE required; the live restore is gated")]

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "rstl-"
#: The version id a lost store gave: a well-formed one, as the real store's ids are, that this store never
#: issued, so a read of it is NoSuchVersion and not a malformed request.
LOST_VERSION = "7c0ff3a1-52d0-4b57-a0aa-0d6f8a4a9b11"
#: The shortest lock this file allows itself, long enough that every refusal below happens while it holds.
LOCK_SECONDS = 10
KEY_PREFIX = "_itest-restore/"
LOCK_OFF = "lock is off; a pass here would be for the wrong reason"


class _Live:
    """The fresh buckets and every object this module put in them, for the teardown."""

    def __init__(self, evidence_bucket: str, preserved_bucket: str) -> None:
        self.evidence_bucket = evidence_bucket
        self.preserved_bucket = preserved_bucket
        self.keys: list[str] = []
        self.held_keys: list[str] = []
        self.lock_ends: list[datetime] = []


def _fresh_bucket(store, name: str) -> None:
    store.make_bucket(name, object_lock=True)
    caps = store.bucket_capabilities(name)
    if caps.object_lock is not True or caps.versioning != "Enabled":
        pytest.fail(f"{LOCK_OFF}: bucket_capabilities({name!r}) reports object lock "
                    f"{caps.object_lock!r} and versioning {caps.versioning!r}")


@pytest.fixture(scope="module")
def live():
    from noctornal_api.evidence import EvidenceStorage
    from noctornal_api.samples import PreservationStorage
    suffix = uuid4().hex[:10]
    live = _Live(f"noctornal-r07-ev-{suffix}", f"noctornal-r07-pr-{suffix}")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("EVIDENCE_BUCKET", live.evidence_bucket)
        mp.setenv("PRESERVE_BUCKET", live.preserved_bucket)
        probe, held = EvidenceStorage(), PreservationStorage()
        try:
            _fresh_bucket(probe.store, live.evidence_bucket)
            _fresh_bucket(held.store, live.preserved_bucket)
            yield live
        finally:
            _remove(probe, held, live)


def _remove(storage, held, live: _Live) -> None:
    """Wait out the locks, then remove every version this module wrote and the buckets. A bucket the store
    will not remove fails the module's teardown and is named, so one is never left behind unseen."""
    from noctornal_api.objectstore.errors import StoreError
    if live.lock_ends:
        time.sleep(max(0.0, (max(live.lock_ends) - datetime.now(timezone.utc)).total_seconds()) + 2)
    left = []
    try:
        for key in {v.key for v in storage.store.list_versions(live.evidence_bucket, KEY_PREFIX)}:
            # A result that says a version is still locked is not a failure to raise: the lock's end is on
            # the store's clock, so wait a little and ask again.
            for _ in range(10):
                if storage.delete_all_versions(key).versions_locked == 0:
                    break
                time.sleep(2)
        storage.store.remove_bucket(live.evidence_bucket)
    except StoreError as exc:
        left.append(f"{live.evidence_bucket}: {exc.code}")
    try:
        # By exact key: a listing is one level deep and a preserved key has directories in it.
        for key in set(live.held_keys):
            for v in list(held.store.list_versions(live.preserved_bucket, key)):
                if v.key == key:
                    held.store.set_legal_hold(live.preserved_bucket, key, v.version_id, False)
                    held.store.delete_version(live.preserved_bucket, key, v.version_id)
        held.store.remove_bucket(live.preserved_bucket)
    except StoreError as exc:
        left.append(f"{live.preserved_bucket}: {exc.code}")
    if left:
        pytest.fail("the live restore test left a bucket: " + "; ".join(left))


def _lock(live: _Live):
    """The injected lock: seconds, and noted for the teardown."""
    def lock_until(_case, _recorded, _now):
        end = datetime.now(timezone.utc) + timedelta(seconds=LOCK_SECONDS)
        live.lock_ends.append(end)
        return end, "a live test's own few-second lock"
    return lock_until


def _exhibit(conn, live: _Live, mirror, *, data: bytes, mirrored: bytes | None = None):
    """An exhibit row as a lost store left it: a lodged version this store never gave, an ACQUIRED row
    whose lock ended long ago, and a mirror file."""
    from noctornal_api.evidence import EvidenceService
    boss = s.user(conn, "AMBER", prefix=PREFIX)
    case_id = s.case(conn, boss)
    key = f"{KEY_PREFIX}{uuid4().hex}"
    live.keys.append(key)
    ev = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3, storage_key, storage_bucket,
                storage_version_id, acquired_by, acquired_at, acquisition_method, retention_until)
           VALUES (%s, 'live restore', 'text/plain', %s, %s, %s, %s, 'the-lost-bucket',
                   %s, %s, now(), 'MANUAL_UPLOAD', %s) RETURNING id""",
        (case_id, len(data), hashlib.sha256(data).digest(), blake3.blake3(data).digest(), key,
         LOST_VERSION, boss,
         (datetime.now(timezone.utc) - timedelta(days=30)).date())).fetchone()[0]
    EvidenceService(conn, None)._custody(
        ev, "ACQUIRED", boss, hash_verified=True,
        detail={"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "lock_ends_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()})
    write_mirror(mirror, key, data if mirrored is None else mirrored)
    return ev, boss, case_id, key


def _versions(storage, key: str) -> list:
    return [v for v in storage.store.list_versions(storage.bucket, key)
            if v.key == key and not v.is_delete_marker]


def _sample(conn, live: _Live, mirror, *, plaintext: bytes, mirrored: bytes | None = None):
    """A rejected sample as a lost store left it: a preserved version this store never gave, the row a
    rejection writes, and a mirror file of its ciphertext."""
    from noctornal_api.samples import _xor_stream
    from noctornal_api.security import envelope
    boss = s.user(conn, "AMBER", prefix=PREFIX)
    case_id = s.case(conn, boss)
    data_key = os.urandom(32)
    blob, key_id = envelope.encrypt(data_key.hex())
    ciphertext = bytes(_xor_stream(plaintext, data_key))
    sha = hashlib.sha256(plaintext)
    key = f"preserved/{sha.hexdigest()[:2]}/{sha.hexdigest()}"
    live.held_keys.append(key)
    sid = conn.execute(
        """INSERT INTO lab.sample
               (case_id, sha256, sha1, md5, byte_size, storage_key, storage_bucket,
                data_key_ciphertext, data_key_id, submitted_by, state, reject_reason,
                preserved_bucket, preserved_key, preserved_version_id, preserved_at)
           VALUES (%s, %s, %s, %s, %s, %s, 'working-b', %s, %s, %s, 'REJECTED', 'live test',
                   %s, %s, %s, now()) RETURNING id""",
        (case_id, sha.digest(), hashlib.sha1(plaintext, usedforsecurity=False).digest(),
         hashlib.md5(plaintext, usedforsecurity=False).digest(), len(plaintext),
         f"w/{uuid4().hex}", blob, key_id, boss, live.preserved_bucket, key, LOST_VERSION)
    ).fetchone()[0]
    write_mirror(mirror, key, ciphertext if mirrored is None else mirrored)
    return sid, boss, case_id, key


def test_restore_into_a_fresh_locked_bucket_against_the_dev_minio(live, tmp_path):
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    from noctornal_api.objectstore.errors import StoreRefusal
    from noctornal_api.objectstore.types import COMPLIANCE
    from noctornal_api.restore import Restore
    storage = EvidenceStorage()
    assert storage.bucket == live.evidence_bucket
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    data = b"live restore " + uuid4().hex.encode()
    where = {"via": "live test", "host": "h", "os_user": "u"}
    with rolled_back() as conn:
        ev, boss, case_id, key = _exhibit(conn, live, mirror, data=data)
        svc = EvidenceService(conn, storage)

        def run(**kw):
            kw.setdefault("apply", True)
            if kw["apply"]:
                kw.update(actor_id=boss, authority="LIVE-TEST-1")
            return Restore(conn, evidence=storage, evidence_mirror=mirror, cases=[case_id],
                           where=where, lock_until=_lock(live), **kw).run()

        # The store holds nothing at the lodged version, so the exhibit reads as missing: the alarm.
        assert svc.verify_integrity(ev, boss) is False

        # A dry run reads and writes nothing, here or in the store.
        [dry] = run(apply=False).outcomes
        assert dry.code == "WOULD_RESTORE" and _versions(storage, key) == []

        [done] = run().outcomes
        assert done.code == "RESTORED" and done.detail["adopted"] is False
        [version] = _versions(storage, key)
        assert done.detail["new_version_id"] == version.version_id
        lodged = conn.execute("SELECT storage_version_id FROM core.evidence WHERE id = %s",
                              (ev,)).fetchone()[0]
        assert lodged == LOST_VERSION != version.version_id
        [(detail, actor, verified)] = [r for r in conn.execute(
            "SELECT detail, actor_id, hash_verified FROM core.evidence_custody "
            "WHERE evidence_id = %s AND action = 'RESTORED'", (ev,)).fetchall()]
        assert (actor, verified) == (boss, True)
        assert detail["new_version_id"] == version.version_id
        assert detail["old_version_id"] == lodged and detail["store_profile"] == "minio"
        assert detail["bucket"] == live.evidence_bucket and detail["lodged_bucket"] == "the-lost-bucket"

        # The reads follow the row to the version the store gave, and every digest still checks.
        assert svc.verify_integrity(ev, boss) is True
        assert svc.view(ev, boss) == data

        # The store keeps the lock the restore asked for: COMPLIANCE, and a delete of the version refused.
        held = storage.store.get_retention(storage.bucket, key, version.version_id)
        assert held.mode == COMPLIANCE
        assert abs((held.until - datetime.fromisoformat(detail["lock_ends_at"])).total_seconds()) < 2
        with pytest.raises(StoreRefusal):
            storage.store.delete_version(storage.bucket, key, version.version_id)
        assert len(_versions(storage, key)) == 1

        # A second run finds the bytes in place and writes nothing.
        custody_before = conn.execute("SELECT count(*) FROM core.evidence_custody").fetchone()[0]
        [again] = run().outcomes
        assert again.code == "ALREADY_PRESENT"
        assert len(_versions(storage, key)) == 1
        assert conn.execute("SELECT count(*) FROM core.evidence_custody").fetchone()[0] == custody_before


def test_a_doctored_mirror_file_is_refused_against_the_dev_minio_and_nothing_is_stored(live, tmp_path):
    from noctornal_api.evidence import EvidenceStorage
    from noctornal_api.restore import Restore
    storage = EvidenceStorage()
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    data = b"the real bytes " + uuid4().hex.encode()
    with rolled_back() as conn:
        ev, boss, case_id, key = _exhibit(conn, live, mirror, data=data,
                                          mirrored=b"D" * len(data))
        report = Restore(conn, apply=True, actor_id=boss, authority="LIVE-TEST-2", evidence=storage,
                         evidence_mirror=mirror, cases=[case_id], lock_until=_lock(live)).run()
        [refused] = report.outcomes
        assert (refused.code, refused.reason) == ("REFUSED", "hash_mismatch")
        assert _versions(storage, key) == []
        assert conn.execute("SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s "
                            "AND action = 'RESTORED'", (ev,)).fetchone()[0] == 0


def test_a_preserved_sample_restores_into_a_fresh_held_bucket_against_the_dev_minio(live, tmp_path):
    from noctornal_api.objectstore.errors import StoreRefusal
    from noctornal_api.restore import Restore
    from noctornal_api.samples import PreservationStorage, held_ciphertext_differs
    held = PreservationStorage()
    assert held.bucket == live.preserved_bucket
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    plaintext = b"MZ live sample " + uuid4().hex.encode()
    with rolled_back() as conn:
        sid, boss, case_id, key = _sample(conn, live, mirror, plaintext=plaintext)

        def run(**kw):
            kw.setdefault("apply", True)
            if kw["apply"]:
                kw.update(actor_id=boss, authority="LIVE-TEST-3")
            return Restore(conn, preserved=held, preserved_mirror=mirror, cases=[case_id],
                           where={"via": "live test", "host": "h", "os_user": "u"}, **kw).run()

        def stored():
            return [v for v in held.store.list_versions(held.bucket, key) if v.key == key]

        # The store holds nothing at the preserved version, so a retrieval would read nothing.
        assert stored() == []

        # A dry run reads and writes nothing, here or in the store.
        [dry] = run(apply=False).outcomes
        assert dry.code == "WOULD_RESTORE" and stored() == []

        [done] = run().outcomes
        assert done.code == "RESTORED" and done.detail["adopted"] is False
        [version] = stored()
        assert done.detail["new_version_id"] == version.version_id != LOST_VERSION
        assert conn.execute("SELECT preserved_version_id FROM lab.sample WHERE id = %s",
                            (sid,)).fetchone()[0] == LOST_VERSION
        assert conn.execute("SELECT lab.sample_current_preserved_version(%s)",
                            (sid,)).fetchone()[0] == version.version_id
        [(detail, actor)] = conn.execute(
            "SELECT detail, actor_id FROM lab.sample_access "
            "WHERE sample_id = %s AND action = 'RESTORED'", (sid,)).fetchall()
        assert actor == boss and detail["hold_confirmed"] is True and detail["verified"] is True
        assert detail["old_version_id"] == LOST_VERSION and detail["store_profile"] == "minio"

        # The store keeps the hold the put set, and the bytes it holds are the sample's.
        assert held.is_held(key, version_id=version.version_id) is True
        with pytest.raises(StoreRefusal):
            held.store.delete_version(held.bucket, key, version.version_id)
        assert held_ciphertext_differs(
            conn, sid, held.get(key, version_id=version.version_id)) is None

        # A second run finds the copy in place and writes nothing.
        before = conn.execute("SELECT count(*) FROM lab.sample_access").fetchone()[0]
        [again] = run().outcomes
        assert again.code == "ALREADY_PRESENT"
        assert len(stored()) == 1
        assert conn.execute("SELECT count(*) FROM lab.sample_access").fetchone()[0] == before


def test_a_doctored_preserved_file_is_refused_against_the_dev_minio_and_nothing_is_stored(
        live, tmp_path):
    from noctornal_api.restore import Restore
    from noctornal_api.samples import PreservationStorage
    held = PreservationStorage()
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    plaintext = b"MZ the real sample " + uuid4().hex.encode()
    with rolled_back() as conn:
        sid, boss, case_id, key = _sample(conn, live, mirror, plaintext=plaintext,
                                          mirrored=b"D" * len(plaintext))
        [refused] = Restore(conn, apply=True, actor_id=boss, authority="LIVE-TEST-4", preserved=held,
                            preserved_mirror=mirror, cases=[case_id]).run().outcomes
        assert (refused.code, refused.reason) == ("REFUSED", "hash_mismatch")
        assert [v for v in held.store.list_versions(held.bucket, key) if v.key == key] == []
        assert conn.execute("SELECT count(*) FROM lab.sample_access WHERE sample_id = %s "
                            "AND action = 'RESTORED'", (sid,)).fetchone()[0] == 0


def test_an_interrupted_restore_is_adopted_not_repeated_against_the_dev_minio(live, tmp_path):
    """The object was put and the record never written: the rerun finds the stored version by listing the
    key (a listing one level deep, which a key with directories in it tests) and records it instead of
    putting a second, which could never be removed."""
    from noctornal_api.evidence import EvidenceStorage
    from noctornal_api.restore import Restore
    from noctornal_api.samples import PreservationStorage
    storage, held = EvidenceStorage(), PreservationStorage()
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    data = b"interrupted " + uuid4().hex.encode()
    plaintext = b"MZ interrupted " + uuid4().hex.encode()
    with rolled_back() as conn:
        ev, boss, case_id, key = _exhibit(conn, live, mirror, data=data)
        sid, _boss, sample_case, held_key = _sample(conn, live, mirror, plaintext=plaintext)
        # What an interrupted run left behind: the exhibit's bytes under a lock, the sample's under a hold.
        end = datetime.now(timezone.utc) + timedelta(seconds=LOCK_SECONDS)
        live.lock_ends.append(end)
        left_behind = storage.store.put(storage.bucket, key, data, retain_until=end).version_id
        ciphertext = (mirror / held_key).read_bytes()
        left_held = held.preserve(held_key, ciphertext).version_id

        report = Restore(conn, apply=True, actor_id=boss, authority="LIVE-TEST-5", evidence=storage,
                         evidence_mirror=mirror, preserved=held, preserved_mirror=mirror,
                         cases=[case_id, sample_case], lock_until=_lock(live)).run()
        by_kind = {o.kind: o for o in report.outcomes}
        assert (by_kind["exhibit"].code, by_kind["exhibit"].detail["adopted"]) == ("RESTORED", True)
        assert (by_kind["sample"].code, by_kind["sample"].detail["adopted"]) == ("RESTORED", True)
        assert by_kind["exhibit"].detail["new_version_id"] == left_behind
        assert by_kind["sample"].detail["new_version_id"] == left_held
        assert [v.version_id for v in _versions(storage, key)] == [left_behind]
        assert len([v for v in held.store.list_versions(held.bucket, held_key)
                    if v.key == held_key]) == 1
