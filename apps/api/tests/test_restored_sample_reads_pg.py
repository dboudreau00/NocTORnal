"""A preserved sample restored into a new store is read from the version a restore named (0199).

The held ciphertext sits in a store that never held the sample, under a version id of that store's own. The
row still names the version it was preserved as, so a read of it finds nothing; once a RESTORED access row
names the new version the one path that decrypts a sample for use (`_verified_plaintext`, which the
preserved retrieval shares) reads it, opens it with the sample's data key and compares the SHA-256.

The rows are committed, because `_verified_plaintext` refuses to run inside a transaction (an alarm that
rolled back with its failure would vanish), and removed in teardown with the ledger's guard stood down by
name, as `test_sample_preservation_pg` does. Account prefix `rsr-`.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest
from psycopg.types.json import Json

import rls_support as s
from objectstore_helpers import FakeS3
from restore_support import preservation_storage

pytestmark = s.GATED

PREFIX = "rsr-"
PLAINTEXT = b"MZ the bytes of a rejected sample"


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    with c.transaction():
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN "
                  f"(SELECT id FROM lab.sample WHERE submitted_by IN {users})")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {users}")
    s.cleanup(c, PREFIX)
    c.close()


def _held_sample(owner, boss, case_id, fresh: FakeS3):
    """A preserved sample row naming a version the fresh store never gave, and its ciphertext put into the
    fresh store under the version it did give."""
    from noctornal_api.samples import _xor_stream
    from noctornal_api.security import envelope
    data_key = os.urandom(32)
    blob, key_id = envelope.encrypt(data_key.hex())
    key = f"preserved/{uuid4().hex}"
    new_version = fresh.put("held-b", key, bytes(_xor_stream(PLAINTEXT, data_key)),
                            legal_hold=True).version_id
    sample = owner.execute(
        """INSERT INTO lab.sample
               (case_id, sha256, byte_size, storage_key, storage_bucket, data_key_ciphertext,
                data_key_id, submitted_by, state, reject_reason, preserved_bucket, preserved_key,
                preserved_version_id, preserved_at)
           VALUES (%s, %s, %s, %s, 'b', %s, %s, %s, 'REJECTED', 'test', 'held-b', %s,
                   'version-of-the-lost-store', now())
           RETURNING id""",
        (case_id, hashlib.sha256(PLAINTEXT).digest(), len(PLAINTEXT), f"w/{uuid4().hex}", blob,
         key_id, boss, key)).fetchone()[0]
    return sample, new_version


def test_a_restored_preserved_sample_reads_from_the_version_a_restore_named(owner):
    from noctornal_api.samples import STORE_PRESERVATION, SampleService
    boss = s.user(owner, "AMBER", prefix=PREFIX)
    fresh = FakeS3()
    pres = preservation_storage(fresh, "held-b")
    sample, new_version = _held_sample(owner, boss, s.case(owner, boss), fresh)
    svc = SampleService(owner, None, pres)

    # The row's version is the lost store's: the new store holds nothing at it.
    from noctornal_api.objectstore.errors import ObjectMissing
    with pytest.raises(ObjectMissing):
        svc._verified_plaintext(sample, actor_id=boss, store=STORE_PRESERVATION)

    owner.execute(
        "INSERT INTO lab.sample_access (sample_id, actor_id, actor_kind, action, detail) "
        "VALUES (%s, %s, 'USER', 'RESTORED', %s)",
        (sample, boss, Json({"new_version_id": new_version, "old_version_id":
                             "version-of-the-lost-store", "verified": True,
                             "hold_confirmed": True})))
    assert bytes(svc._verified_plaintext(sample, actor_id=boss,
                                         store=STORE_PRESERVATION)) == PLAINTEXT
    assert owner.execute("SELECT preserved_version_id FROM lab.sample WHERE id = %s",
                         (sample,)).fetchone()[0] == "version-of-the-lost-store"
    assert owner.execute("SELECT lab.sample_current_preserved_version(%s)",
                         (sample,)).fetchone()[0] == new_version


def test_a_forged_restored_sample_pointer_still_fails_the_sha256(owner):
    """A row naming a held version of other bytes redirects the read to them and the read refuses them,
    recording the alarm: the pointer is not trusted, the bytes are checked."""
    from noctornal_api.samples import STORE_PRESERVATION, SampleIntegrityError, SampleService
    boss = s.user(owner, "AMBER", prefix=PREFIX)
    fresh = FakeS3()
    pres = preservation_storage(fresh, "held-b")
    sample, _real = _held_sample(owner, boss, s.case(owner, boss), fresh)
    # A later version of THIS sample's key, holding other bytes.
    key = owner.execute("SELECT preserved_key FROM lab.sample WHERE id = %s",
                        (sample,)).fetchone()[0]
    forged = fresh.put("held-b", key, b"not the sample at all", legal_hold=True).version_id
    owner.execute(
        "INSERT INTO lab.sample_access (sample_id, actor_id, actor_kind, action, detail) "
        "VALUES (%s, %s, 'USER', 'RESTORED', %s)",
        (sample, boss, Json({"new_version_id": forged, "verified": True,
                             "hold_confirmed": True})))
    with pytest.raises(SampleIntegrityError):
        SampleService(owner, None, pres)._verified_plaintext(
            sample, actor_id=boss, store=STORE_PRESERVATION)
    assert owner.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'SAMPLE_INTEGRITY_ALARM' "
        "AND object_id = %s", (sample,)).fetchone()[0] == 1
