"""The restore of mirrored exhibits into a store that never held them (decision 240).

Each exhibit is lodged into one in-process store (the one that was lost) through the real ingest, a file of
its bytes is left in a mirror directory as `mc mirror` leaves one, and the restore runs against a second
store with the real service, the real triggers and the real ledgers. What each test would catch:

- bytes that do not verify (SHA-256, BLAKE3, size, the ACQUIRED row) reach the store or the ledger;
- the database is written for an object the store did not keep, or the object is written twice;
- a rerun after a failure puts a second locked version instead of adopting the first;
- a mirror path escapes its root;
- a dry run changes anything, or a real run happens without a named account and an authority;
- a lock is shorter than the exhibit had;
- the tool deletes, lifts or shortens anything.

Every row is made in a transaction that is rolled back. Account prefix `rstr-`.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest

import rls_support as s
from objectstore_helpers import FakeS3
from restore_support import World, foreign_version_ids, soon, write_mirror
from rolled_back import rolled_back

pytestmark = s.GATED

PREFIX = "rstr-"
ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "restore_object_versions.py"


@pytest.fixture
def world(tmp_path):
    (tmp_path / "mirror").mkdir()
    with rolled_back() as conn:
        boss = s.user(conn, "AMBER", prefix=PREFIX)
        yield World(conn, boss, s.case(conn, boss), tmp_path / "mirror")


def _script():
    spec = importlib.util.spec_from_file_location(f"restore_script_{uuid4().hex[:6]}", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tamper_row(conn, evidence_id, **columns):
    """An owner's edit of an anchor, with the guard stood down by name inside the rolled-back transaction."""
    conn.execute("ALTER TABLE core.evidence DISABLE TRIGGER evidence_anchors_fixed")
    try:
        for column, value in columns.items():
            conn.execute(f"UPDATE core.evidence SET {column} = %s WHERE id = %s", (value, evidence_id))
    finally:
        conn.execute("ALTER TABLE core.evidence ENABLE TRIGGER evidence_anchors_fixed")


def _only(report):
    assert len(report.outcomes) == 1, [o.as_dict() for o in report.outcomes]
    return report.outcomes[0]


# ---------------------------------------------------------------------------
# What does not verify writes nothing
# ---------------------------------------------------------------------------

def test_a_restore_refuses_a_mirror_file_whose_sha256_differs_and_writes_nothing(world):
    ex = world.lodge()
    write_mirror(world.mirror, ex.key, b"x" * len(ex.data))
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason, outcome.detail["which"]) == ("REFUSED", "hash_mismatch", "sha256")
    assert world.versions() == []
    assert world.restored_rows(ex.id) == []
    refused = world.audit("EVIDENCE_RESTORE_REFUSED", ex.id)
    assert [(r[0], r[1]["reason"]) for r in refused] == [("DENIED", "hash_mismatch")]


def test_a_restore_refuses_a_file_whose_blake3_differs_though_its_sha256_matches(world):
    ex = world.lodge()
    _tamper_row(world.conn, ex.id, blake3=os.urandom(32))
    outcome = _only(world.restore())
    assert (outcome.reason, outcome.detail["which"]) == ("hash_mismatch", "blake3")
    assert world.versions() == [] and world.restored_rows(ex.id) == []


def test_a_restore_refuses_a_file_of_another_size_without_reading_it(world):
    ex = world.lodge()
    write_mirror(world.mirror, ex.key, ex.data + b"more")
    outcome = _only(world.restore())
    assert (outcome.reason, outcome.detail) == ("size_mismatch", {
        "mirror_bytes": len(ex.data) + 4, "recorded_bytes": len(ex.data)})
    assert world.versions() == []


def test_a_restore_refuses_a_file_that_disagrees_with_the_acquired_custody_row(world):
    """Substituting the bytes and rewriting the row to match them is what the hash-chained ACQUIRED row
    exists to catch, and a restore is not a way round it."""
    import blake3
    import hashlib
    ex = world.lodge()
    doctored = b"d" * len(ex.data)
    write_mirror(world.mirror, ex.key, doctored)
    _tamper_row(world.conn, ex.id, sha256=hashlib.sha256(doctored).digest(),
                blake3=blake3.blake3(doctored).digest())
    outcome = _only(world.restore())
    assert (outcome.reason, outcome.detail["which"]) == (
        "anchor_mismatch", "the ACQUIRED custody row's digest")
    assert world.versions() == [] and world.restored_rows(ex.id) == []


def test_a_restore_refuses_an_exhibit_with_no_acquired_row_to_check_against(world):
    import blake3
    import hashlib
    data = b"a row somebody wrote by hand"
    key = f"{world.case_id}/{uuid4().hex}"
    ev = world.conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3, storage_key, storage_bucket,
                storage_version_id, acquired_by, acquired_at, acquisition_method)
           VALUES (%s, 'hand', 'text/plain', %s, %s, %s, %s, 'b', 'lost-version', %s, now(),
                   'MANUAL_UPLOAD') RETURNING id""",
        (world.case_id, len(data), hashlib.sha256(data).digest(), blake3.blake3(data).digest(),
         key, world.boss)).fetchone()[0]
    write_mirror(world.mirror, key, data)
    outcome = _only(world.restore())
    assert (outcome.reason, outcome.detail["which"]) == ("anchor_mismatch", "no ACQUIRED custody row")
    assert world.restored_rows(ev) == [] and world.versions() == []


def test_a_restore_updates_nothing_when_the_store_refuses_the_put(world):
    from noctornal_api.objectstore import errors
    ex = world.lodge()

    def refuse(*_a, **_kw):
        raise errors.refusal("AccessDenied", "Access Denied", status=403)
    world.fresh.put = refuse
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason, outcome.detail["store_code"]) == (
        "REFUSED", "store_refused", "AccessDenied")
    assert world.restored_rows(ex.id) == []
    assert world.count("SELECT count(*) FROM audit.event WHERE action = 'EVIDENCE_RESTORED' "
                       "AND object_id = %s", ex.id) == 0


def test_a_store_that_gives_no_version_id_is_a_failure_that_names_the_object(world):
    ex = world.lodge()
    world.fresh.no_version_id = True
    outcome = _only(world.restore())
    assert outcome.code == "FAILED" and outcome.detail["bucket"] == "evidence-b"
    assert world.restored_rows(ex.id) == []


# ---------------------------------------------------------------------------
# What does verify is recorded, and nothing else is rewritten
# ---------------------------------------------------------------------------

def test_a_restore_records_the_new_version_in_a_chained_custody_row_and_an_audit_row(world):
    from noctornal_api.audit_verify import verify_chain
    from noctornal_api.custody_verify import verify_custody_chain
    ex = world.lodge()
    report = world.restore()
    outcome = _only(report)
    assert outcome.code == "RESTORED"
    [new] = [v for v in world.versions()]
    assert outcome.detail["new_version_id"] == new.version_id != ex.version
    [(detail, actor, verified)] = world.restored_rows(ex.id)
    assert (actor, verified) == (world.boss, True)
    assert detail["new_version_id"] == new.version_id and detail["old_version_id"] == ex.version
    assert detail["adopted"] is False and detail["source"] == "mirror"
    assert detail["run_id"] == report.run_id and detail["authority"] == "TICKET-2026-1114"
    assert detail["sha256"] and detail["blake3"] and detail["byte_size"] == len(ex.data)
    assert detail["via"] == "test" and detail["bucket"] == "evidence-b"
    assert detail["store_profile"] == "s3" and detail["store_host"] == "fake-s3:0"
    [(outcome_word, audit_detail, audit_actor)] = world.audit("EVIDENCE_RESTORED", ex.id)
    assert (outcome_word, audit_actor) == ("SUCCESS", world.boss)
    assert audit_detail["run_id"] == report.run_id
    [(_o, run_detail, _a)] = world.audit("RESTORE_RUN", UUID(report.run_id))
    assert run_detail["counts"]["restored"] == 1 and run_detail["authority"] == "TICKET-2026-1114"
    assert verify_custody_chain(world.conn, evidence_id=ex.id).intact
    assert verify_chain(world.conn, limit=500).intact


def test_the_lodged_version_and_every_anchor_stay_on_the_row_after_a_restore(world):
    ex = world.lodge()
    cols = "storage_version_id, storage_key, storage_bucket, sha256, blake3, byte_size, case_id"
    before = world.conn.execute(f"SELECT {cols} FROM core.evidence WHERE id = %s", (ex.id,)).fetchone()
    world.restore()
    after = world.conn.execute(f"SELECT {cols} FROM core.evidence WHERE id = %s", (ex.id,)).fetchone()
    assert after == before and before[0] == ex.version


def test_the_day_a_restored_lock_ends_moves_forward_as_a_lock_extension_moves_it(world):
    ex = world.lodge(retain_until=datetime.now(timezone.utc) + timedelta(hours=2))
    far = datetime.now(timezone.utc) + timedelta(days=40)
    world.restore(lock_until=lambda *_a: (far, "a test's own lock"))
    day = world.conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                             (ex.id,)).fetchone()[0]
    assert day == far.date()


def test_a_restored_exhibit_verifies_and_reads_under_its_new_version(world):
    ex = world.lodge()
    world.restore()
    assert world.svc.verify_integrity(ex.id, world.boss) is True
    assert world.svc.view(ex.id, world.boss) == ex.data
    assert world.svc.export(ex.id, world.boss) == ex.data


def test_before_a_restore_the_new_store_raises_the_alarm_the_restore_removes(world):
    ex = world.lodge()
    assert world.svc.verify_integrity(ex.id, world.boss) is False
    world.restore()
    assert world.svc.verify_integrity(ex.id, world.boss) is True


def test_a_restore_that_finds_the_recorded_version_present_writes_nothing(world):
    """A replicated store kept the version ids: the exhibit reads as it did, and the restore adds neither an
    object nor a row."""
    ex = world.lodge()
    before = world.count("SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s", ex.id)
    outcome = _only(world.restore(evidence=world.lost_storage))
    assert outcome.code == "ALREADY_PRESENT"
    assert len(world.versions(world.lost)) == 1
    assert world.count("SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s",
                       ex.id) == before


def test_a_second_run_finds_the_restored_version_in_place_and_writes_nothing(world):
    ex = world.lodge()
    world.restore()
    again = _only(world.restore())
    assert again.code == "ALREADY_PRESENT"
    assert len(world.versions()) == 1 and len(world.restored_rows(ex.id)) == 1


def test_a_restore_is_resumable_and_adopts_a_verified_version_it_finds_instead_of_putting_a_second(
        world, monkeypatch):
    """The put succeeded and the database write failed: the object is locked and no row names it. The rerun
    adopts it, which is the only way to converge, because a second locked version could never be removed."""
    from noctornal_api.restore import EVENT_EXHIBIT, Restore
    ex = world.lodge()
    real = Restore._audit
    calls = {"n": 0}

    def flaky(self, action, *a, **kw):
        if action == EVENT_EXHIBIT and calls["n"] == 0:
            calls["n"] += 1
            raise psycopg.errors.InternalError_("the connection dropped")
        return real(self, action, *a, **kw)
    monkeypatch.setattr(Restore, "_audit", flaky)
    first = _only(world.restore())
    assert first.code == "FAILED" and first.detail["version_id"]
    assert world.restored_rows(ex.id) == []
    [stored] = world.versions()
    assert stored.version_id == first.detail["version_id"]
    second = _only(world.restore())
    assert second.code == "RESTORED" and second.detail["adopted"] is True
    assert [v.version_id for v in world.versions()] == [stored.version_id]
    [(detail, _a, _v)] = world.restored_rows(ex.id)
    assert detail["new_version_id"] == stored.version_id and detail["adopted"] is True


def test_a_no_adopt_run_puts_a_second_version_and_says_so_in_the_row(world):
    ex = world.lodge()
    world.fresh.put("evidence-b", ex.key, ex.data, retain_until=soon())
    outcome = _only(world.restore(adopt=False))
    assert outcome.code == "RESTORED" and outcome.detail["adopted"] is False
    assert len(world.versions()) == 2


def test_a_store_that_will_not_list_versions_is_refused_in_words_unless_no_adopt_is_given(world):
    from noctornal_api.objectstore import errors
    ex = world.lodge()

    def refuse(*_a, **_kw):
        raise errors.refusal("AccessDenied", "Access Denied", status=403)
    world.fresh.list_versions = refuse
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "store_refused")
    assert "--no-adopt" in outcome.detail["note"]
    assert world.restored_rows(ex.id) == []


def test_a_version_id_the_new_store_cannot_parse_is_nothing_there_and_the_restore_goes_on(world):
    """MinIO answers an id another store issued with InvalidArgument and not NoSuchVersion. Reading that as a
    refusal would refuse every exhibit of a move between stores, at the first probe."""
    ex = world.lodge()
    foreign_version_ids(world.fresh)
    outcome = _only(world.restore())
    assert outcome.code == "RESTORED", outcome.as_dict()
    [(detail, *_)] = world.restored_rows(ex.id)
    assert detail["old_version_id"] == ex.version
    assert detail["new_version_id"] == outcome.detail["new_version_id"] != ex.version
    assert len(world.versions()) == 1


def test_only_a_read_that_names_a_version_takes_invalid_argument_for_nothing_there():
    """An InvalidArgument on a read of the latest, and every other refusal, is still the store's answer."""
    from noctornal_api.objectstore import errors
    from noctornal_api.restore import Restore

    class Answers:
        def __init__(self, code, status=400):
            self.code, self.status = code, status

        def get(self, bucket, key, *, version_id=None):
            raise errors.refusal(self.code, "x", status=self.status)

    assert Restore._read_version(Answers("InvalidArgument"), "b", "k", "v-1") is None
    assert Restore._read_version(Answers("NoSuchVersion", 404), "b", "k", "v-1") is None
    for version, store in ((None, Answers("InvalidArgument")), ("v-1", Answers("AccessDenied", 403)),
                           ("v-1", Answers("InvalidArgument", 500))):
        with pytest.raises(errors.StoreRefusal):
            Restore._read_version(store, "b", "k", version)


def test_a_version_in_place_that_does_not_verify_is_an_alarm_not_a_restore(world):
    ex = world.lodge()
    world.lost.buckets["evidence-b"].objects[ex.key][0].data = b"z" * len(ex.data)
    outcome = _only(world.restore(evidence=world.lost_storage))
    assert (outcome.code, outcome.reason) == ("REFUSED", "current_version_fails")
    assert len(world.versions(world.lost)) == 1 and world.restored_rows(ex.id) == []


# ---------------------------------------------------------------------------
# Which exhibits, and in which order
# ---------------------------------------------------------------------------

def test_a_purged_exhibit_is_never_restored_and_is_reported(world):
    ex = world.lodge()
    world.conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (ex.id,))
    report = world.restore()
    outcome = _only(report)
    assert outcome.code == "PURGED" and outcome.detail == {"mirror_still_holds_bytes": True}
    assert any(str(ex.id) in w and "purged" in w for w in report.warnings)
    assert world.versions() == [] and world.restored_rows(ex.id) == []


def test_an_unpinned_exhibit_is_listed_not_restored(tmp_path):
    (tmp_path / "mirror").mkdir()
    with rolled_back() as conn:
        boss = s.user(conn, "AMBER", prefix=PREFIX)
        w = World(conn, boss, s.case(conn, boss), tmp_path / "mirror", lost=FakeS3(no_version_id=True))
        ex = w.lodge()
        assert ex.version is None
        outcome = _only(w.restore())
        assert outcome.code == "UNPINNED" and w.versions() == []


def test_the_case_filter_and_the_limit_choose_what_a_run_takes_up(world):
    mine = [world.lodge(b"mine-%d" % i) for i in range(3)]
    other_case = s.case(world.conn, world.boss)
    elsewhere = World(world.conn, world.boss, other_case, world.mirror, lost=world.lost,
                      fresh=world.fresh).lodge(b"elsewhere")
    report = world.restore(limit=2)
    assert report.count("RESTORED") == 2
    done = {o.id for o in report.outcomes}
    assert str(elsewhere.id) not in done
    third = world.restore()
    assert third.count("RESTORED") == 1 and third.count("ALREADY_PRESENT") == 2
    assert {str(m.id) for m in mine} == {o.id for o in third.outcomes}
    only_other = world.restore(cases=[other_case])
    assert only_other.count("RESTORED") == 1 and only_other.outcomes[0].id == str(elsewhere.id)


def test_a_limit_counts_the_exhibits_a_run_restores_so_batches_reach_every_one(world):
    """Objects already in place are scanned and not charged: three runs of two take all five."""
    lodged = [world.lodge(b"batch-%d" % i) for i in range(5)]
    seen = []
    for expected_new in (2, 2, 1):
        report = world.restore(limit=2)
        assert report.count("RESTORED") == expected_new, [o.as_dict() for o in report.outcomes]
        seen.append(report.count("ALREADY_PRESENT"))
    assert seen == [0, 2, 4]
    assert world.restore(limit=2).count("RESTORED") == 0
    assert world.count("SELECT count(DISTINCT evidence_id) FROM core.evidence_custody "
                       "WHERE action = 'RESTORED' AND evidence_id = ANY(%s)",
                       [e.id for e in lodged]) == 5


def test_a_dry_run_limit_names_the_same_exhibits_a_real_run_would_take(world):
    for i in range(3):
        world.lodge(b"dry-%d" % i)
    report = world.restore(apply=False, limit=2)
    assert report.count("WOULD_RESTORE") == 2 and len(report.outcomes) == 2


def test_an_exhibit_that_is_refused_does_not_use_the_limit_up(world):
    """One that cannot be restored is reported by every run and never stands between the batch and the rest."""
    lodged = [world.lodge(b"stall-%d" % i) for i in range(3)]
    (world.mirror.joinpath(*world.conn.execute(
        "SELECT storage_key FROM core.evidence WHERE id = %s", (lodged[0].id,)).fetchone()[0].split("/"))
     ).unlink()
    for _ in range(4):
        world.restore(limit=1)
    assert world.count("SELECT count(*) FROM core.evidence_custody WHERE action = 'RESTORED' "
                       "AND evidence_id = ANY(%s)", [e.id for e in lodged]) == 2
    last = world.restore(limit=1)
    assert last.count("REFUSED") == 1 and last.count("RESTORED") == 0


def test_a_restricted_exhibit_is_refused_on_a_store_nobody_has_declared(world, monkeypatch):
    """Invariant 8 at a restore as at the upload: a store outside the deployment takes no RED exhibit until
    counsel's declaration is recorded."""
    from noctornal_api.objectstore.custody import COUNSEL_ENV
    ex = world.lodge(classification="RED")
    monkeypatch.setenv("OBJECT_STORE_ENDPOINT", "objects.vendor.example:443")
    monkeypatch.delenv(COUNSEL_ENV, raising=False)
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "custody_undeclared")
    assert world.versions() == []
    monkeypatch.setenv(COUNSEL_ENV, "counsel's memo of 2026-11-15")
    assert _only(world.restore()).code == "RESTORED"
    assert len(world.restored_rows(ex.id)) == 1


# ---------------------------------------------------------------------------
# The mirror path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key", [
    "", "/etc/passwd", "../outside", "a/../../outside", "a/./b", "a//b", "a\\b", "a\x00b",
    "C:/Windows/win.ini", "..", "a/..", "./a"])
def test_a_mirror_path_cannot_leave_its_root(tmp_path, key):
    from noctornal_api.restore import PathRefused, locate
    (tmp_path / "mirror").mkdir()
    (tmp_path / "outside").write_bytes(b"secret")
    with pytest.raises(PathRefused):
        locate(tmp_path / "mirror", key)


def test_a_key_that_names_a_file_outside_the_mirror_is_refused_and_never_read(world, tmp_path):
    ex = world.lodge()
    secret = tmp_path / "secret"
    secret.write_bytes(ex.data)
    _tamper_row(world.conn, ex.id, storage_key="../secret")
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "path_refused")
    assert world.versions() == []


def _link(link: Path, target: Path) -> bool:
    """A real directory link where the host allows one: a symlink, or on Windows a junction."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, check=False)
        return done.returncode == 0
    return False


def test_a_link_on_the_path_is_refused(tmp_path):
    from noctornal_api.restore import PathRefused, locate
    root = tmp_path / "mirror"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "obj").write_bytes(b"outside the mirror")
    if _link(root / "linked", outside):
        with pytest.raises(PathRefused, match="link"):
            locate(root, "linked/obj")
    # The test of what counts as a link, whatever the host lets a test make.
    from noctornal_api.restore import _is_link
    assert _is_link(SimpleNamespace(st_mode=stat.S_IFLNK))
    assert _is_link(SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400))
    assert not _is_link(SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x20))


def test_a_missing_file_and_a_directory_in_a_file_s_place(tmp_path):
    from noctornal_api.restore import MirrorMissing, PathRefused, locate
    root = tmp_path / "mirror"
    (root / "case").mkdir(parents=True)
    with pytest.raises(MirrorMissing):
        locate(root, "case/none")
    with pytest.raises(MirrorMissing):
        locate(tmp_path / "no-such-root", "case/none")
    with pytest.raises(PathRefused, match="regular file"):
        locate(root, "case")
    (root / "file").write_bytes(b"x")
    with pytest.raises(PathRefused, match="directory"):
        locate(root, "file/inside")
    assert locate(root, "file")[1] == 1


def test_a_missing_mirror_file_is_a_refusal_the_run_exits_one_on(world):
    ex = world.lodge(mirror=False)
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("REFUSED", "mirror_missing")
    assert world.restored_rows(ex.id) == []


# ---------------------------------------------------------------------------
# The lock
# ---------------------------------------------------------------------------

def test_the_restore_lock_is_never_shorter_than_the_recorded_lock(world):
    from noctornal_api.objectstore.types import COMPLIANCE
    recorded = datetime.now(timezone.utc) + timedelta(days=5)
    ex = world.lodge(retain_until=recorded)
    world.restore()
    [(detail, *_)] = world.restored_rows(ex.id)
    ends = datetime.fromisoformat(detail["lock_ends_at"])
    assert ends >= recorded.replace(microsecond=0)
    assert "recorded lock, which had not ended" in detail["lock_reason"]
    [version] = world.versions()
    held = world.fresh.get_retention("evidence-b", ex.key, version.version_id)
    assert held.mode == COMPLIANCE and held.until >= recorded.replace(microsecond=0)


def test_a_recorded_lock_that_had_ended_is_replaced_by_a_fresh_default_period_and_says_so(world):
    ex = world.lodge(retain_until=datetime.now(timezone.utc) - timedelta(hours=1))
    world.restore()
    [(detail, *_)] = world.restored_rows(ex.id)
    assert "had already ended" in detail["lock_reason"]
    assert datetime.fromisoformat(detail["lock_ends_at"]) > datetime.now(timezone.utc) + timedelta(hours=20)


def test_a_lock_the_store_does_not_hold_is_not_recorded(world):
    """A store can accept a lock and not keep it (docs/17 F24): the row would say a guarantee that is not
    there, so the object is named in the report and nothing records it."""
    ex = world.lodge()
    real = world.fresh.get_retention

    def silent(bucket, key, version_id):
        return None
    world.fresh.get_retention = silent
    outcome = _only(world.restore())
    assert outcome.code == "FAILED" and outcome.detail["version_id"]
    assert world.restored_rows(ex.id) == []
    world.fresh.get_retention = real


def test_an_object_that_does_not_read_back_as_the_exhibit_is_named_and_nothing_records_it(world):
    """The read by the new version id comes before any database write: bytes the store hands back altered
    (same size, so only the digests can tell) leave the object named in the report and the ledger untouched,
    and a run that finds the store sound again adopts the object instead of putting a second."""
    ex = world.lodge()
    store, put_ids = world.fresh, []
    real_put, real_get = store.put, store.get

    def put(*args, **kwargs):
        result = real_put(*args, **kwargs)
        put_ids.append(result.version_id)
        return result

    def get(bucket, key, *, version_id=None):
        data = real_get(bucket, key, version_id=version_id)
        return data[:-1] + bytes([data[-1] ^ 1]) if version_id in put_ids else data
    store.put, store.get = put, get
    outcome = _only(world.restore())
    assert (outcome.code, outcome.reason) == ("FAILED", "hash_mismatch"), outcome.as_dict()
    assert outcome.detail["version_id"] == put_ids[0] and outcome.detail["bucket"] == "evidence-b"
    assert outcome.detail["key"] == world.conn.execute(
        "SELECT storage_key FROM core.evidence WHERE id = %s", (ex.id,)).fetchone()[0]
    assert world.restored_rows(ex.id) == []
    assert world.audit("EVIDENCE_RESTORED", ex.id) == []
    store.get = real_get
    again = _only(world.restore())
    assert again.code == "RESTORED" and again.detail["adopted"] is True
    assert len(world.versions()) == 1 and put_ids == [again.detail["new_version_id"]]


def test_an_exhibit_purged_while_the_restore_ran_is_named_with_its_orphan_and_nothing_records_it(world):
    ex = world.lodge()
    real, purged = world.fresh.get_retention, []

    def purge_then_answer(bucket, key, version_id):
        if not purged:
            world.conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (ex.id,))
            purged.append(version_id)
        return real(bucket, key, version_id)
    world.fresh.get_retention = purge_then_answer
    report = world.restore()
    outcome = _only(report)
    assert outcome.code == "PURGED" and outcome.detail["version_id"] == purged[0], outcome.as_dict()
    assert outcome.detail["bucket"] == "evidence-b" and outcome.detail["key"]
    assert any(str(ex.id) in w and purged[0] in w for w in report.warnings)
    assert world.restored_rows(ex.id) == []
    assert world.audit("EVIDENCE_RESTORED", ex.id) == []


# ---------------------------------------------------------------------------
# Dry run, accounts, and what the tool never does
# ---------------------------------------------------------------------------

def test_a_dry_run_changes_nothing_anywhere(world):
    ex = world.lodge()
    snap = lambda: (  # noqa: E731
        world.count("SELECT count(*) FROM core.evidence_custody"),
        world.count("SELECT count(*) FROM audit.event"),
        world.conn.execute("SELECT retention_until FROM core.evidence WHERE id = %s",
                           (ex.id,)).fetchone()[0],
        world.versions(), world.fresh.buckets["evidence-b"].objects.copy())
    before = snap()
    report = world.restore(apply=False)
    outcome = _only(report)
    assert outcome.code == "WOULD_RESTORE" and "lock_ends_at" in outcome.detail
    assert snap() == before
    assert "dry run" in report.counters()


def test_a_dry_run_says_what_it_would_refuse_and_records_nothing(world):
    world.lodge(mirror=False)
    before = world.count("SELECT count(*) FROM audit.event")
    outcome = _only(world.restore(apply=False))
    assert outcome.reason == "mirror_missing"
    assert world.count("SELECT count(*) FROM audit.event") == before


def test_a_real_restore_needs_a_named_account_and_an_authority(world):
    from noctornal_api.restore import Restore, RestoreRefused
    with pytest.raises(RestoreRefused, match="names the account"):
        Restore(world.conn, apply=True, authority="TICKET-1", evidence=world.fresh_storage,
                evidence_mirror=world.mirror)
    with pytest.raises(RestoreRefused, match="authority"):
        Restore(world.conn, apply=True, actor_id=world.boss, evidence=world.fresh_storage,
                evidence_mirror=world.mirror)


@pytest.mark.parametrize("value", [None, "", "  ", "yes", "replace-me", "ok", "tbd", "abc"])
def test_an_authority_that_is_not_a_reference_is_refused(value):
    from noctornal_api.restore import RestoreRefused, validate_authority
    with pytest.raises(RestoreRefused, match="reference an auditor can follow"):
        validate_authority(value)
    assert validate_authority(" INC-2026-0412 ") == "INC-2026-0412"


def test_a_restore_without_a_named_active_account_and_an_authority_refuses_with_exit_2(
        world, capsys):
    """Every refusal is exit 2 with nothing in the store, and not one of them says which addresses are
    accounts."""
    module = _script()
    s.grant_global(world.conn, world.boss, "SYS_ADMIN")
    email = world.conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                               (world.boss,)).fetchone()[0]
    plain = s.user(world.conn, "AMBER", prefix=PREFIX)
    plain_email = world.conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                                     (plain,)).fetchone()[0]
    gone = s.user(world.conn, "AMBER", prefix=PREFIX)
    s.grant_global(world.conn, gone, "SYS_ADMIN")
    world.conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (gone,))
    gone_email = world.conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                                    (gone,)).fetchone()[0]
    world.lodge()
    # The case is named: a run that names none takes up every exhibit in the database, and on a database
    # other suites have left exhibits in, which have no mirror file here, the last run would exit 1.
    base = ["--evidence-mirror", str(world.mirror), "--apply", "--case", str(world.case_id)]

    def run(*extra):
        return module.main([*base, *extra], conn=world.conn, evidence=world.fresh_storage)

    assert run("--actor", email) == 2                                          # no authority
    assert run("--actor", email, "--authority", "tbd") == 2                    # not a reference
    assert run("--authority", "TICKET-1234") == 2                              # no account
    assert run("--actor", "nobody@example.test", "--authority", "TICKET-1234") == 2
    assert run("--actor", plain_email, "--authority", "TICKET-1234") == 2      # no retention.manage
    assert run("--actor", gone_email, "--authority", "TICKET-1234") == 2       # inactive
    err = capsys.readouterr().err
    assert err.count("refused:") == 6
    assert "nobody@example.test" not in err and plain_email not in err
    assert world.versions() == [] and world.count(
        "SELECT count(*) FROM core.evidence_custody WHERE action = 'RESTORED'") == 0
    assert run("--actor", email, "--authority", "TICKET-1234") == 0
    assert len(world.versions()) == 1


def test_the_script_exits_one_while_something_is_left_and_writes_a_report(world, capsys, tmp_path):
    module = _script()
    world.lodge()
    world.lodge(mirror=False)
    report_file = tmp_path / "report.json"
    code = module.main(["--evidence-mirror", str(world.mirror), "--report", str(report_file),
                        "--case", str(world.case_id)], conn=world.conn, evidence=world.fresh_storage)
    assert code == 1
    out = capsys.readouterr().out
    assert "would_restore=1" in out and "refused=1" in out and "left: exhibit" in out
    assert "dry run: nothing was changed" in out
    data = json.loads(report_file.read_text(encoding="utf-8"))
    assert data["apply"] is False and data["counts"]["would_restore"] == 1
    assert {o["outcome"] for o in data["outcomes"]} == {"WOULD_RESTORE", "REFUSED"}
    if os.name == "posix":
        assert stat.S_IMODE(report_file.stat().st_mode) == 0o600
    # Never over a file that exists.
    assert module.main(["--evidence-mirror", str(world.mirror), "--report", str(report_file)],
                       conn=world.conn, evidence=world.fresh_storage) == 2


def test_a_restore_that_names_nothing_to_restore_is_a_usage_error(world, capsys):
    with pytest.raises(SystemExit) as done:
        _script().main([], conn=world.conn, evidence=world.fresh_storage)
    assert done.value.code == 2


def test_the_script_makes_the_refusal_every_job_makes_first(monkeypatch, capsys):
    from noctornal_api import config, db
    module = _script()

    def boom(*_a, **_kw):
        raise AssertionError("connected before the refusal")
    monkeypatch.setattr(db, "connect_system", boom)
    monkeypatch.setattr(os, "environ", {"NOCTORNAL_ENV": "production"})
    code = module.main(["--evidence-mirror", "/nowhere"], evidence=object())
    assert code == config.JOB_REFUSAL_EXIT
    assert capsys.readouterr().err.startswith("restore_object_versions: refusing to run:")


def test_two_restores_never_run_at_once(world):
    from noctornal_api.restore import RestoreRefused
    world.lodge()
    other = s.owner_conn()
    other.execute("SELECT pg_advisory_lock(hashtextextended('noctornal.restore_object_versions', 0))")
    try:
        with pytest.raises(RestoreRefused, match="another restore is running"):
            world.restore()
    finally:
        other.execute("SELECT pg_advisory_unlock(hashtextextended("
                      "'noctornal.restore_object_versions', 0))")
        other.close()
    assert world.versions() == []
    assert _only(world.restore()).code == "RESTORED", "the lock is released when a run ends"


class _Spy(FakeS3):
    """A store that records every call that could destroy or loosen anything."""

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

    def set_compliance_retention(self, bucket, key, version_id, until):
        held = self.get_retention(bucket, key, version_id)
        if held is not None and held.until is not None and until < held.until:
            self.destructive.append("shorten")
        return super().set_compliance_retention(bucket, key, version_id, until)


def test_the_restore_never_deletes_lifts_or_shortens_anything(tmp_path):
    from restore_support import evidence_storage
    (tmp_path / "mirror").mkdir()
    spy = _Spy()
    with rolled_back() as conn:
        boss = s.user(conn, "AMBER", prefix=PREFIX)
        w = World(conn, boss, s.case(conn, boss), tmp_path / "mirror", fresh=spy)
        w.fresh_storage = evidence_storage(spy)
        w.lodge()
        w.lodge()
        w.lodge(mirror=False)
        w.restore()
        w.restore()
        w.restore(apply=False)
    assert spy.destructive == []


def test_no_secret_reaches_a_row_or_the_report(world, monkeypatch):
    monkeypatch.setenv("OBJECT_STORE_SECRET_KEY", "a-dev-placeholder-secret-value")
    monkeypatch.setenv("OBJECT_STORE_ACCESS_KEY", "a-dev-placeholder-access-value")
    ex = world.lodge()
    report = world.restore()
    text = json.dumps(report.as_dict()) + json.dumps(
        [[str(c) for c in r] for r in world.restored_rows(ex.id)]) + json.dumps(
        [str(r) for r in world.audit("EVIDENCE_RESTORED", ex.id)])
    assert "placeholder" not in text
