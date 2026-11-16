"""An exhibit restored into a new store reads where it now lives, and every read still proves the bytes (0198).

The exhibit is lodged into one in-process store (the one that was lost) and its bytes are put into a second
store that never held it, under a version id of that store's own. Before a RESTORED custody row the read
asks the second store for the lodged version and reports the integrity alarm a missing object is; with the
row it asks for the version the row names. A row that names a version holding other bytes buys nothing:
the SHA-256, the BLAKE3 and the ACQUIRED anchor are checked on every read, so a forged pointer is an alarm.

Every row is made in a transaction that is rolled back. Account prefix `rrd-`.
"""
from __future__ import annotations

import pytest
from psycopg.types.json import Json

import rls_support as s
from objectstore_helpers import FakeS3
from restore_support import evidence_storage, soon
from rolled_back import rolled_back

pytestmark = s.GATED

PREFIX = "rrd-"
DATA = b"the exhibit's bytes, as lodged"


@pytest.fixture
def world():
    from noctornal_api.evidence import EvidenceService
    with rolled_back() as conn:
        boss = s.user(conn, "AMBER", prefix=PREFIX)
        case_id = s.case(conn, boss)
        lost = FakeS3()
        lost_svc = EvidenceService(conn, evidence_storage(lost))
        lodged = lost_svc.ingest(case_id=case_id, title="t", media_type="image/png", data=DATA,
                                 acquired_by=boss, acquisition_method="MANUAL_UPLOAD")
        key, version = conn.execute(
            "SELECT storage_key, storage_version_id FROM core.evidence WHERE id = %s",
            (lodged.evidence_id,)).fetchone()
        assert version, "the lodging store gave a version"
        fresh = FakeS3()
        fresh_storage = evidence_storage(fresh)
        yield {"conn": conn, "boss": boss, "ev": lodged.evidence_id, "key": key, "lodged": version,
               "lost": lost_svc, "fresh": fresh, "fresh_storage": fresh_storage,
               "svc": EvidenceService(conn, fresh_storage)}


def _put(world, data: bytes = DATA) -> str:
    return world["fresh"].put(world["fresh_storage"].bucket, world["key"], data,
                              retain_until=soon()).version_id


def _restored(world, version: str) -> None:
    world["conn"].execute(
        "INSERT INTO core.evidence_custody (evidence_id, action, actor_id, detail, hash_verified) "
        "VALUES (%s, 'RESTORED', %s, %s, true)",
        (world["ev"], world["boss"],
         Json({"new_version_id": version, "old_version_id": world["lodged"]})))


def _alarms(world) -> int:
    return world["conn"].execute(
        "SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s "
        "AND action = 'HASH_VERIFIED' AND hash_verified = false", (world["ev"],)).fetchone()[0]


def test_an_exhibit_not_restored_reads_the_version_it_was_lodged_as(world):
    conn = world["conn"]
    assert conn.execute("SELECT core.evidence_current_version(%s)",
                        (world["ev"],)).fetchone()[0] == world["lodged"]
    assert world["lost"].view(world["ev"], world["boss"]) == DATA
    assert world["lost"].verify_integrity(world["ev"], world["boss"]) is True


def test_an_exhibit_in_a_store_that_never_held_its_version_raises_an_alarm_until_restored(world):
    _put(world)
    assert world["svc"].verify_integrity(world["ev"], world["boss"]) is False
    assert _alarms(world) == 1


def test_a_restored_exhibit_verifies_and_reads_under_its_new_version(world):
    """`verify_integrity`, `view` and `export` each ask for the version the RESTORED row names."""
    new = _put(world)
    _restored(world, new)
    svc, ev, boss = world["svc"], world["ev"], world["boss"]
    assert svc.verify_integrity(ev, boss) is True
    assert svc.view(ev, boss) == DATA
    assert svc.export(ev, boss) == DATA
    assert _alarms(world) == 0
    actions = [e.action for e in svc.custody_log(ev)]
    assert actions.count("RESTORED") == 1 and {"VIEWED", "EXPORTED"} <= set(actions)


def test_the_lodged_version_stays_on_the_row_after_a_restore(world):
    new = _put(world)
    _restored(world, new)
    row = world["conn"].execute(
        "SELECT storage_version_id, storage_key FROM core.evidence WHERE id = %s",
        (world["ev"],)).fetchone()
    assert row == (world["lodged"], world["key"])
    assert world["conn"].execute("SELECT core.evidence_current_version(%s)",
                                 (world["ev"],)).fetchone()[0] == new != world["lodged"]


def test_a_forged_restored_pointer_still_fails_the_read_time_hashes(world):
    """A row naming a version that holds other bytes redirects the read to them, and the read refuses
    them: the pointer is not trusted, the bytes are checked."""
    from noctornal_api.evidence import IntegrityError
    forged = _put(world, b"bytes an attacker put on the key")
    _restored(world, forged)
    svc, ev, boss = world["svc"], world["ev"], world["boss"]
    assert svc.verify_integrity(ev, boss) is False
    with pytest.raises(IntegrityError):
        svc.view(ev, boss)
    assert _alarms(world) == 2
    detail = world["conn"].execute(
        "SELECT detail FROM core.evidence_custody WHERE evidence_id = %s "
        "AND action = 'HASH_VERIFIED' ORDER BY id DESC LIMIT 1", (ev,)).fetchone()[0]
    assert detail.get("sha256_ok") is False


def test_a_pointer_to_a_version_that_does_not_exist_is_an_alarm_not_a_server_error(world):
    _restored(world, "no-such-version")
    assert world["svc"].verify_integrity(world["ev"], world["boss"]) is False
    assert _alarms(world) == 1


def test_the_newest_restored_row_decides(world):
    first = _put(world)
    second = _put(world)
    _restored(world, "stale-version")
    _restored(world, first)
    _restored(world, second)
    assert world["conn"].execute("SELECT core.evidence_current_version(%s)",
                                 (world["ev"],)).fetchone()[0] == second
    assert world["svc"].verify_integrity(world["ev"], world["boss"]) is True
