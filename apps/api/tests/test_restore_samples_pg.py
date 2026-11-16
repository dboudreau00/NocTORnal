"""The restore of preserved samples into a preservation bucket that never held them (decision 240, 0199).

Each sample is preserved into one in-process store (the one that was lost) under a legal hold, a file of its
ciphertext is left in a mirror directory as `mc mirror` leaves one, and the restore runs against a second
store with the real triggers and ledgers. What each test would catch:

- ciphertext that does not open to the sample (size, SHA-256, SHA-1, MD5) reaches the store or the ledger;
- a copy is recorded that the store did not keep, did not hold or could not confirm;
- a copy is put twice, or into a bucket the row does not name;
- the tool places or lifts a hold on an object it did not put, deletes, or shortens anything;
- the plaintext leaves memory, or a key or a plaintext reaches a row, a log or the report.

Every row is made in a transaction that is rolled back. Account prefix `rsmp-`.
"""
from __future__ import annotations

import json
import logging
import os
from uuid import UUID, uuid4

import pytest

import rls_support as s
from objectstore_helpers import FakeS3
from restore_support import HELD, SampleWorld, foreign_version_ids
from rolled_back import rolled_back

pytestmark = s.GATED

PREFIX = "rsmp-"
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def world(tmp_path):
    (tmp_path / "mirror").mkdir()
    with rolled_back() as conn:
        boss = s.user(conn, "RED", prefix=PREFIX)
        yield SampleWorld(conn, boss, s.case(conn, boss), tmp_path / "mirror")


def _only(report):
    assert len(report.outcomes) == 1, [o.as_dict() for o in report.outcomes]
    return report.outcomes[0]


def _row_version(world, sample_id):
    return world.conn.execute("SELECT preserved_version_id FROM lab.sample WHERE id = %s",
                              (sample_id,)).fetchone()[0]


def _current(world, sample_id):
    return world.conn.execute("SELECT lab.sample_current_preserved_version(%s)",
                              (sample_id,)).fetchone()[0]


# ---------------------------------------------------------------------------
# What is restored, and how it is recorded
# ---------------------------------------------------------------------------

def test_a_preserved_sample_restores_under_a_hold_and_reads_back_held(world):
    from noctornal_api.samples import held_ciphertext_differs
    sm = world.preserve()
    outcome = _only(world.restore())
    assert outcome.code == "RESTORED" and outcome.detail["adopted"] is False
    [stored] = world.versions()
    assert outcome.detail["new_version_id"] == stored.version_id
    assert world.fresh.legal_hold_is_on(HELD, sm.key, stored.version_id) is True
    # The ciphertext in the new store is the sample's: it opens to its recorded digests.
    assert held_ciphertext_differs(world.conn, sm.id, world.fresh.get(
        HELD, sm.key, version_id=stored.version_id)) is None
    # One RESTORED access row, a USER row naming the account, and the retrieval resolves it.
    [(detail, actor, kind)] = world.restored_rows(sm.id)
    assert (actor, kind) == (world.boss, "USER")
    assert detail["new_version_id"] == stored.version_id and detail["old_version_id"] == sm.version
    assert detail["verified"] is True and detail["hold_confirmed"] is True
    assert detail["bucket"] == HELD and detail["adopted"] is False and detail["source"] == "mirror"
    assert detail["digests"] == ["sha256", "sha1", "md5"]
    assert detail["authority"] == "TICKET-2026-1114" and detail["via"] == "test"
    assert detail["store_profile"] == "s3" and detail["store_host"] == "fake-s3:0"
    assert _current(world, sm.id) == stored.version_id
    # The version it was preserved as stays on the row, and the sample row was not written.
    assert _row_version(world, sm.id) == sm.version != stored.version_id
    [(audit_outcome, audit_detail, audit_actor)] = world.audit("SAMPLE_PRESERVED_RESTORED", sm.id)
    assert (audit_outcome, audit_actor) == ("SUCCESS", world.boss)
    assert audit_detail["authority"] == "TICKET-2026-1114" and audit_detail["adopted"] is False


def test_the_run_is_recorded_once_with_counts_for_both_kinds(world):
    world.preserve()
    report = world.restore()
    [(_o, detail, _a)] = world.audit("RESTORE_RUN", UUID(report.run_id))
    assert detail["counts"]["restored"] == 1 and detail["preserved_mirror"] is True
    assert detail["evidence_mirror"] is False


def test_a_second_run_finds_the_restored_copy_in_place_and_writes_nothing(world):
    sm = world.preserve()
    world.restore()
    again = _only(world.restore())
    assert again.code == "ALREADY_PRESENT"
    assert len(world.versions()) == 1 and len(world.restored_rows(sm.id)) == 1


def test_a_copy_already_in_place_under_the_recorded_version_writes_nothing(world):
    """A store whose replication kept version ids: the row's own version is there, held and opening to the
    sample, so nothing is put and nothing is recorded."""
    sm = world.preserve()
    same = world.fresh.put(HELD, sm.key, sm.ciphertext, legal_hold=True).version_id
    world.conn.execute("UPDATE lab.sample SET preserved_version_id = %s WHERE id = %s",
                       (same, sm.id))
    assert _only(world.restore()).code == "ALREADY_PRESENT"
    assert len(world.versions()) == 1 and world.restored_rows(sm.id) == []


def test_a_copy_in_place_with_no_hold_is_refused_and_the_tool_places_no_hold(world):
    sm = world.preserve()
    same = world.fresh.put(HELD, sm.key, sm.ciphertext, legal_hold=False).version_id
    world.conn.execute("UPDATE lab.sample SET preserved_version_id = %s WHERE id = %s",
                       (same, sm.id))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "hold_missing")
    assert world.fresh.legal_hold_is_on(HELD, sm.key, same) is False
    assert world.restored_rows(sm.id) == []


def test_a_copy_in_place_that_does_not_open_to_the_sample_is_an_alarm_not_a_restore(world):
    sm = world.preserve()
    same = world.fresh.put(HELD, sm.key, b"x" * len(sm.ciphertext), legal_hold=True).version_id
    world.conn.execute("UPDATE lab.sample SET preserved_version_id = %s WHERE id = %s",
                       (same, sm.id))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "current_version_fails")
    assert outcome.detail["which"] == "sha256"
    assert len(world.versions()) == 1 and world.restored_rows(sm.id) == []


# ---------------------------------------------------------------------------
# What does not verify writes nothing
# ---------------------------------------------------------------------------

def test_a_preserved_sample_whose_ciphertext_does_not_open_to_its_sha256_is_refused(world):
    sm = world.preserve()
    doctored = bytearray(sm.ciphertext)
    doctored[0] ^= 0xFF
    (world.mirror / sm.key).write_bytes(bytes(doctored))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason, outcome.detail["which"]) == (
        "REFUSED", "hash_mismatch", "sha256")
    assert world.versions() == [] and world.restored_rows(sm.id) == []
    [(audit_outcome, detail, _a)] = world.audit("SAMPLE_PRESERVED_RESTORE_REFUSED", sm.id)
    assert audit_outcome == "DENIED" and detail["reason"] == "hash_mismatch"
    assert world.audit("SAMPLE_PRESERVED_RESTORED", sm.id) == []


def test_a_mirror_file_of_another_size_is_refused_without_being_opened(world):
    sm = world.preserve()
    (world.mirror / sm.key).write_bytes(sm.ciphertext + b"!")
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "size_mismatch")
    assert world.versions() == []


def test_a_sha1_or_md5_the_row_records_is_checked_too(world):
    """A ciphertext that opens to the right SHA-256 and a wrong SHA-1 is not this sample's."""
    sm = world.preserve()
    world.conn.execute("UPDATE lab.sample SET sha1 = %s WHERE id = %s", (b"\x01" * 20, sm.id))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason, outcome.detail["which"]) == (
        "REFUSED", "hash_mismatch", "sha1")
    world.conn.execute("UPDATE lab.sample SET sha1 = NULL, md5 = %s WHERE id = %s",
                       (b"\x02" * 16, sm.id))
    assert _only(world.restore()).detail["which"] == "md5"
    assert world.versions() == []


def test_a_sample_with_no_recorded_sha1_or_md5_is_proved_by_its_sha256_alone(world):
    sm = world.preserve(sha1=False, md5=False)
    outcome = _only(world.restore())
    assert outcome.code == "RESTORED"
    assert world.restored_rows(sm.id)[0][0]["digests"] == ["sha256"]


def test_a_missing_mirror_file_is_a_refusal_the_run_exits_one_on(world):
    sm = world.preserve(mirror=False)
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "mirror_missing")
    assert world.versions() == [] and world.restored_rows(sm.id) == []


def test_a_preserved_sample_restore_refuses_a_different_bucket(world):
    """A move of bucket is a separate decision: the row names `other-b`, the configured bucket is `held-b`."""
    sm = world.preserve(bucket="other-b")
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "bucket_differs")
    assert outcome.detail == {"lodged_bucket": "other-b", "configured_bucket": HELD}
    assert world.versions() == [] and world.restored_rows(sm.id) == []


def test_a_sample_whose_data_key_will_not_open_writes_nothing_and_says_where_to_look(world):
    sm = world.preserve()
    world.conn.execute("UPDATE lab.sample SET data_key_ciphertext = %s WHERE id = %s",
                       (b"not a sealed key", sm.id))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("FAILED", "data_key_unavailable")
    assert "key ring" in outcome.detail["note"]
    assert world.versions() == [] and world.restored_rows(sm.id) == []


def test_a_restricted_sample_is_refused_on_a_store_nobody_has_declared(world, monkeypatch):
    """Invariant 8 at a restore as at a rejection: a preservation store outside the deployment takes no RED
    sample until counsel's declaration is recorded."""
    from noctornal_api.objectstore.custody import COUNSEL_ENV
    sm = world.preserve(classification="RED")
    monkeypatch.setenv("PRESERVE_ENDPOINT", "objects.vendor.example:443")
    monkeypatch.delenv(COUNSEL_ENV, raising=False)
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "custody_undeclared")
    assert world.versions() == []
    monkeypatch.setenv(COUNSEL_ENV, "counsel's memo of 2026-11-15")
    assert _only(world.restore()).code == "RESTORED"
    assert len(world.restored_rows(sm.id)) == 1


# ---------------------------------------------------------------------------
# What the store does
# ---------------------------------------------------------------------------

class _Unverified(FakeS3):
    """A store that keeps the held copy and will not say so: the read-back of the hold answers no."""

    def __init__(self):
        super().__init__()
        self.say_no = True

    def legal_hold_is_on(self, bucket, key, version_id=None):
        return False if self.say_no else super().legal_hold_is_on(bucket, key, version_id)


def test_a_preservation_put_that_was_unverified_is_named_and_not_recorded(tmp_path):
    from restore_support import preservation_storage
    (tmp_path / "mirror").mkdir()
    fresh = _Unverified()
    with rolled_back() as conn:
        boss = s.user(conn, "RED", prefix=PREFIX)
        w = SampleWorld(conn, boss, s.case(conn, boss), tmp_path / "mirror", fresh=fresh)
        w.fresh_storage = preservation_storage(fresh, HELD)
        sm = w.preserve()
        outcome = _only(w.restore())
        assert (outcome.code, outcome.reason) == ("FAILED", "store_refused")
        [stored] = w.versions()
        assert outcome.detail["version_id"] == stored.version_id
        assert outcome.detail["bucket"] == HELD and outcome.detail["key"] == sm.key
        assert "does not report the hold" in outcome.detail["store_said"]
        assert w.restored_rows(sm.id) == [] and w.audit("SAMPLE_PRESERVED_RESTORED", sm.id) == []
        # The store tells the truth on the next run: it finds the held version, puts nothing, records it.
        fresh.say_no = False
        again = _only(w.restore())
        assert again.code == "RESTORED" and again.detail["adopted"] is True
        assert [v.version_id for v in w.versions()] == [stored.version_id]


def _after_the_put(world) -> list:
    """The version ids the restore's own put made, filled in as the put returns: what a test doctors is the
    store's answer to the restore's read-back, which comes after the put's own checks."""
    made_ids: list = []
    real = world.fresh_storage.preserve

    def preserve(key, data):
        made = real(key, data)
        made_ids.append(made.version_id)
        return made
    world.fresh_storage.preserve = preserve
    return made_ids


def test_a_held_copy_that_does_not_read_back_as_the_sample_is_named_and_nothing_records_it(world):
    sm = world.preserve()
    made_ids = _after_the_put(world)
    store = world.fresh
    real_get = store.get

    def get(bucket, key, *, version_id=None):
        data = real_get(bucket, key, version_id=version_id)
        return data[:-1] + bytes([data[-1] ^ 1]) if version_id in made_ids else data
    store.get = get
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("FAILED", "hash_mismatch"), outcome.as_dict()
    assert outcome.detail["version_id"] == made_ids[0]
    assert outcome.detail["bucket"] == HELD and outcome.detail["key"] == sm.key
    assert world.restored_rows(sm.id) == [] and world.audit("SAMPLE_PRESERVED_RESTORED", sm.id) == []
    store.get = real_get
    again = _only(world.restore())
    assert again.code == "RESTORED" and again.detail["adopted"] is True
    assert [v.version_id for v in world.versions()] == made_ids


def test_a_held_copy_the_store_no_longer_reports_held_is_named_and_nothing_records_it(world):
    sm = world.preserve()
    made_ids = _after_the_put(world)
    store = world.fresh
    real_hold = store.legal_hold_is_on
    store.legal_hold_is_on = lambda bucket, key, version_id=None: (
        False if version_id in made_ids else real_hold(bucket, key, version_id))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("FAILED", "hold_missing"), outcome.as_dict()
    assert outcome.detail["version_id"] == made_ids[0] and outcome.detail["key"] == sm.key
    assert world.restored_rows(sm.id) == [] and world.audit("SAMPLE_PRESERVED_RESTORED", sm.id) == []
    store.legal_hold_is_on = real_hold
    again = _only(world.restore())
    assert again.code == "RESTORED" and again.detail["adopted"] is True


def test_a_preservation_put_nobody_answered_is_named_and_not_recorded(world):
    sm = world.preserve()

    def silent(*_a, **_kw):
        raise TimeoutError("timed out")
    world.fresh.put = silent
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("FAILED", "store_refused")
    assert "one may exist" in outcome.detail["note"] and outcome.detail["key"] == sm.key
    assert world.restored_rows(sm.id) == []


def test_a_store_that_refuses_the_held_put_leaves_nothing_and_says_which_code(world):
    from noctornal_api.objectstore import errors
    sm = world.preserve()

    def refuse(*_a, **_kw):
        raise errors.refusal("AccessDenied", "Access Denied", status=403)
    world.fresh.put = refuse
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "store_refused")
    assert "AccessDenied" in outcome.detail["store_said"]
    assert world.versions() == [] and world.restored_rows(sm.id) == []


def test_a_store_that_gives_no_version_id_is_a_failure_that_names_the_object(world):
    sm = world.preserve()
    world.fresh.no_version_id = True
    outcome = _only(world.restore())
    assert outcome.code == "FAILED" and outcome.detail["bucket"] == HELD
    assert world.restored_rows(sm.id) == []


def test_a_sample_restore_is_resumable_and_adopts_a_held_version_it_finds(world, monkeypatch):
    """The held put succeeded and the database write failed: the object is held and no row names it. The
    rerun adopts it, which is the only way to converge: a second held version could never be removed."""
    import psycopg

    from noctornal_api.restore import EVENT_SAMPLE, Restore
    sm = world.preserve()
    real = Restore._audit
    calls = {"n": 0}

    def flaky(self, action, *a, **kw):
        if action == EVENT_SAMPLE and calls["n"] == 0:
            calls["n"] += 1
            raise psycopg.errors.InternalError_("the connection dropped")
        return real(self, action, *a, **kw)
    monkeypatch.setattr(Restore, "_audit", flaky)
    first = _only(world.restore())
    assert first.code == "FAILED" and first.detail["version_id"]
    assert world.restored_rows(sm.id) == []
    [stored] = world.versions()
    assert stored.version_id == first.detail["version_id"]
    second = _only(world.restore())
    assert second.code == "RESTORED" and second.detail["adopted"] is True
    assert [v.version_id for v in world.versions()] == [stored.version_id]
    assert world.restored_rows(sm.id)[0][0]["adopted"] is True


def test_a_held_version_of_other_bytes_is_not_adopted(world):
    sm = world.preserve()
    world.fresh.put(HELD, sm.key, b"y" * len(sm.ciphertext), legal_hold=True)
    outcome = _only(world.restore())
    assert outcome.code == "RESTORED" and outcome.detail["adopted"] is False
    assert len(world.versions()) == 2


def test_a_copy_that_is_not_held_is_not_adopted(world):
    sm = world.preserve()
    world.fresh.put(HELD, sm.key, sm.ciphertext, legal_hold=False)
    outcome = _only(world.restore())
    assert outcome.code == "RESTORED" and outcome.detail["adopted"] is False
    assert len(world.versions()) == 2


def test_a_store_that_will_not_list_versions_is_refused_in_words_unless_no_adopt_is_given(world):
    from noctornal_api.objectstore import errors
    sm = world.preserve()

    def refuse(*_a, **_kw):
        raise errors.refusal("AccessDenied", "Access Denied", status=403)
    world.fresh.list_versions = refuse
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "store_refused")
    assert "--no-adopt" in outcome.detail["note"]
    assert world.restored_rows(sm.id) == []
    assert _only(world.restore(adopt=False)).code == "RESTORED"


# ---------------------------------------------------------------------------
# Which samples, in which order
# ---------------------------------------------------------------------------

def test_a_dry_run_changes_nothing_anywhere(world):
    sm = world.preserve()
    ledger = world.count("SELECT count(*) FROM lab.sample_access")
    audit = world.count("SELECT count(*) FROM audit.event")
    outcome = _only(world.restore(apply=False))
    assert outcome.code == "WOULD_RESTORE" and outcome.detail["digests"] == ["sha256", "sha1", "md5"]
    assert world.versions() == []
    assert world.count("SELECT count(*) FROM lab.sample_access") == ledger
    assert world.count("SELECT count(*) FROM audit.event") == audit
    assert world.restored_rows(sm.id) == []


def test_an_unpinned_sample_is_listed_not_restored(world):
    sm = world.preserve(version=False)
    outcome = _only(world.restore())
    assert outcome.code == "UNPINNED" and world.versions() == []
    assert world.restored_rows(sm.id) == []


def test_the_case_filter_and_the_limit_choose_what_a_run_takes_up(world):
    mine = [world.preserve(b"mine-%d" % i) for i in range(3)]
    other_case = s.case(world.conn, world.boss)
    elsewhere = world.preserve(b"elsewhere", case_id=other_case)
    report = world.restore(limit=2)
    assert report.count("RESTORED") == 2
    assert str(elsewhere.id) not in {o.id for o in report.outcomes}
    third = world.restore()
    assert third.count("RESTORED") == 1 and third.count("ALREADY_PRESENT") == 2
    assert {str(m.id) for m in mine} == {o.id for o in third.outcomes}
    only_other = world.restore(cases=[other_case])
    assert only_other.count("RESTORED") == 1 and only_other.outcomes[0].id == str(elsewhere.id)


def test_a_limit_counts_the_samples_a_run_restores_so_batches_reach_every_one(world):
    """Samples already in place are scanned and not charged: three runs of two take all five."""
    kept = [world.preserve(b"batch-%d" % i) for i in range(5)]
    seen = []
    for expected_new in (2, 2, 1):
        report = world.restore(limit=2)
        assert report.count("RESTORED") == expected_new, [o.as_dict() for o in report.outcomes]
        seen.append(report.count("ALREADY_PRESENT"))
    assert seen == [0, 2, 4]
    assert world.restore(limit=2).count("RESTORED") == 0
    assert all(len(world.restored_rows(sm.id)) == 1 for sm in kept)


def test_a_sample_that_is_refused_does_not_use_the_limit_up(world):
    kept = [world.preserve(b"stall-%d" % i) for i in range(3)]
    world.preserve(b"no-mirror", mirror=False)
    for _ in range(4):
        world.restore(limit=1)
    assert sum(len(world.restored_rows(sm.id)) for sm in kept) == 3
    last = world.restore(limit=1)
    assert last.count("REFUSED") == 1 and last.count("RESTORED") == 0


def test_a_version_id_the_new_store_cannot_parse_is_nothing_there_and_the_sample_restores(world):
    """The same word MinIO gives an exhibit's id: InvalidArgument is nothing there, so the probe of the
    recorded version does not refuse a sample moved from another store."""
    sm = world.preserve()
    foreign_version_ids(world.fresh)
    outcome = _only(world.restore())
    assert outcome.code == "RESTORED", outcome.as_dict()
    [(detail, *_)] = world.restored_rows(sm.id)
    assert detail["old_version_id"] == sm.version
    assert detail["new_version_id"] == outcome.detail["new_version_id"] != sm.version
    assert world.fresh.legal_hold_is_on(HELD, sm.key, detail["new_version_id"]) is True


def test_a_sample_never_named_by_a_preserved_key_is_not_a_candidate(world):
    sm = world.preserve()
    world.conn.execute(
        """INSERT INTO lab.sample (case_id, sha256, byte_size, storage_key, storage_bucket,
                                   data_key_ciphertext, data_key_id, submitted_by)
           VALUES (%s, %s, 3, %s, 'b', %s, 'k', %s)""",
        (world.case_id, os.urandom(32), f"w/{uuid4().hex}", b"sealed", world.boss))
    assert [o.id for o in world.restore().outcomes] == [str(sm.id)]


# ---------------------------------------------------------------------------
# What the tool never does
# ---------------------------------------------------------------------------

class _Spy(FakeS3):
    """A store that records every call that could destroy or loosen anything, a legal hold included."""

    def __init__(self):
        super().__init__()
        self.destructive: list[str] = []

    def delete_version(self, *a, **kw):
        self.destructive.append("delete_version")
        return super().delete_version(*a, **kw)

    def delete_key(self, *a, **kw):
        self.destructive.append("delete_key")
        return super().delete_key(*a, **kw)

    def set_legal_hold(self, *a, **kw):
        self.destructive.append("set_legal_hold")
        return super().set_legal_hold(*a, **kw)

    def remove_bucket(self, *a, **kw):
        self.destructive.append("remove_bucket")
        return super().remove_bucket(*a, **kw)


def test_the_sample_restore_never_deletes_places_or_lifts_anything(tmp_path):
    from restore_support import preservation_storage
    (tmp_path / "mirror").mkdir()
    spy = _Spy()
    with rolled_back() as conn:
        boss = s.user(conn, "RED", prefix=PREFIX)
        w = SampleWorld(conn, boss, s.case(conn, boss), tmp_path / "mirror", fresh=spy)
        w.fresh_storage = preservation_storage(spy, HELD)
        w.preserve()
        w.preserve()
        w.preserve(mirror=False)
        w.restore()
        w.restore()
        w.restore(apply=False)
    assert spy.destructive == []


def test_the_plaintext_never_leaves_memory(world, tmp_path, caplog):
    """No file is written anywhere, and no log line, report or row carries the plaintext or the data key."""
    plaintext = b"MZ the plaintext of a rejected sample " + uuid4().hex.encode()
    sm = world.preserve(plaintext)
    before = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    with caplog.at_level(logging.DEBUG):
        report = world.restore()
        refused = world.restore(apply=False)
    after = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*"))
    assert before == after, "the restore wrote a file"
    haystack = "\n".join([
        caplog.text, json.dumps(report.as_dict()), json.dumps(refused.as_dict()),
        json.dumps([[str(c) for c in r] for r in world.restored_rows(sm.id)]),
        json.dumps([str(r) for r in world.audit("SAMPLE_PRESERVED_RESTORED", sm.id)]),
        json.dumps([str(r) for r in world.audit("RESTORE_RUN")])])
    assert plaintext.decode() not in haystack
    assert sm.data_key.hex() not in haystack and repr(sm.data_key) not in haystack
    assert sm.ciphertext.hex() not in haystack


def test_no_secret_reaches_a_row_or_the_report(world, monkeypatch):
    monkeypatch.setenv("PRESERVE_SECRET_KEY", "a-dev-placeholder-secret-value")
    monkeypatch.setenv("PRESERVE_ACCESS_KEY", "a-dev-placeholder-access-value")
    sm = world.preserve()
    report = world.restore()
    text = json.dumps(report.as_dict()) + json.dumps(
        [[str(c) for c in r] for r in world.restored_rows(sm.id)]) + json.dumps(
        [str(r) for r in world.audit("SAMPLE_PRESERVED_RESTORED", sm.id)])
    assert "placeholder" not in text


def test_the_sample_record_shows_a_restore_without_where_it_ran_or_under_what_authority(world):
    """The RESTORED row keeps the host, the account, the store and the authority for the audit; the ledger
    a reader of the sample record sees keeps the version ids and the bucket, and no more."""
    from noctornal_api.samples import SampleService
    sm = world.preserve()
    world.restore(where={"via": "test", "host": "prod-restore-host-01", "os_user": "root"})
    [(stored, *_)] = world.restored_rows(sm.id)
    for key in ("host", "os_user", "store_host", "store_profile", "authority", "run_id"):
        assert key in stored, key
    [row] = [c for c in SampleService(world.conn).custody(sm.id, clearance="RED")
             if c["action"] == "RESTORED"]
    shown = row["detail"]
    assert set(shown) <= set(SampleService._RESTORED_DETAIL_KEYS)
    assert shown["old_version_id"] == sm.version and shown["bucket"] == HELD
    assert shown["new_version_id"] == stored["new_version_id"]
    flat = json.dumps(row)
    for text in ("prod-restore-host-01", "root", "fake-s3", "TICKET-2026-1114", stored["run_id"]):
        assert text not in flat, text
    assert row["actor_id"] == str(world.boss)


# ---------------------------------------------------------------------------
# The proof, and the script
# ---------------------------------------------------------------------------

def test_the_proof_names_the_first_fact_that_differs(world):
    from noctornal_api.samples import held_ciphertext_differs
    sm = world.preserve()
    assert held_ciphertext_differs(world.conn, sm.id, sm.ciphertext) is None
    assert held_ciphertext_differs(world.conn, sm.id, sm.ciphertext[:-1]) == "size"
    assert held_ciphertext_differs(world.conn, sm.id, b"\x00" * len(sm.ciphertext)) == "sha256"


def test_the_proof_refuses_a_sample_that_does_not_exist(world):
    from noctornal_api.samples import SampleError, held_ciphertext_differs
    with pytest.raises(SampleError, match="no such sample"):
        held_ciphertext_differs(world.conn, uuid4(), b"x")


def test_the_script_restores_a_preserved_sample_and_reports_it(world, capsys, tmp_path):
    import importlib.util
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location(f"restore_script_{uuid4().hex[:6]}",
                                                  root / "scripts" / "restore_object_versions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    s.grant_global(world.conn, world.boss, "SYS_ADMIN")
    email = world.conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                               (world.boss,)).fetchone()[0]
    sm = world.preserve()
    world.preserve(mirror=False)
    report_file = tmp_path / "report.json"
    code = module.main(["--preserved-mirror", str(world.mirror), "--apply", "--actor", email,
                        "--authority", "TICKET-1234", "--report", str(report_file),
                        "--case", str(world.case_id)],
                       conn=world.conn, preserved=world.fresh_storage)
    assert code == 1, "one sample has no mirror file"
    out = capsys.readouterr().out
    assert "restored=1" in out and "refused=1" in out and "left: sample" in out
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert {o["kind"] for o in data["outcomes"]} == {"sample"}
    assert len(world.restored_rows(sm.id)) == 1
    # With neither mirror named there is nothing to restore.
    with pytest.raises(SystemExit) as done:
        module.main([], conn=world.conn)
    assert done.value.code == 2
