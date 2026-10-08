"""Evidence ingest, identity and integrity (unit g44, 2026-10-03).

One test or more per review finding, each failing without its fix:

- rls-4 and evidence-ingest-dedup-oracle: the bytes of an exhibit the
  uploader may not see are lodged as a new exhibit with an object of its
  own, exactly as novel bytes are: no 500, no extra version on the hidden
  object, no custody row on it.
- evidence-reingest-after-purge-dropped: bytes whose exhibit was destroyed
  are stored again.
- http_ui-003 and evidence-orphan-locked-object: nothing the row would
  refuse puts a byte in the bucket, and a put whose row never commits is
  recorded.
- evidence-integrity-anchors-mutable: the hashes cannot be rewritten by any
  role, reads ask for the version that was lodged, a concealed object is an
  alarm, and the hash-chained ACQUIRED row is compared.
- http_ui-009: an .eml with a NUL in a parsed header is recorded.

Accounts `g44t-*`; the object store is `g44_support.VersionedStore`, so
nothing is written to the dev bucket.
"""
from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn


@pytest.fixture
def store(monkeypatch):
    st = g.VersionedStore()
    import noctornal_api.evidence as ev
    import noctornal_api.http.routers.evidence as evr
    monkeypatch.setattr(ev, "EvidenceStorage", lambda: st)
    monkeypatch.setattr(evr, "EvidenceStorage", lambda: st)
    return st


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


def _custody_count(c, evidence_id) -> int:
    return c.execute("SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s",
                     (evidence_id,)).fetchone()[0]


def _rows_for(c, case_id, data: bytes) -> list:
    import hashlib
    return c.execute(
        "SELECT id, storage_key, classification::text, purged_at IS NOT NULL "
        "FROM core.evidence WHERE case_id = %s AND sha256 = %s ORDER BY created_at",
        (case_id, hashlib.sha256(data).digest())).fetchall()


def _upload(client, headers, case_id, data, **form):
    form.setdefault("title", "g44 upload")
    form.setdefault("classification", "AMBER")
    return client.post(f"/api/v1/cases/{case_id}/evidence", headers=headers,
                       files={"file": ("f.bin", data, "application/octet-stream")},
                       data=form)


# --- rls-4, evidence-ingest-dedup-oracle ---------------------------------

def test_the_bytes_of_a_hidden_exhibit_are_lodged_as_a_new_exhibit(conn, store, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, analyst, "ANALYST")
    hidden, data = g.lodge(conn, store, case_id, boss, classification="RED")
    hidden_key = g.evidence_row(conn, hidden.evidence_id)[0]
    assert len(store.objects[hidden_key]) == 1
    before = _custody_count(conn, hidden.evidence_id)
    headers = g.token(conn, analyst)
    register = client.get(f"/api/v1/cases/{case_id}/evidence", headers=headers).json()
    assert register["total"] == 0, "the fixture's analyst must not see the RED exhibit"

    novel = _upload(client, headers, case_id, b"g44-novel-" + uuid4().hex.encode())
    probe = _upload(client, headers, case_id, data)

    assert novel.status_code == 201, novel.text
    assert probe.status_code == 201, probe.text
    # Indistinguishable from a novel upload: same status, same shape, and
    # `deduplicated` false, with an exhibit id that is the uploader's own.
    assert set(probe.json()) == set(novel.json())
    assert probe.json()["deduplicated"] is False
    assert probe.json()["evidence_id"] != str(hidden.evidence_id)
    # Nothing was put on the hidden exhibit's object and nothing was written
    # to its custody trail.
    assert len(store.objects[hidden_key]) == 1
    assert _custody_count(conn, hidden.evidence_id) == before
    rows = _rows_for(conn, case_id, data)
    assert len(rows) == 2
    assert {r[1] for r in rows} == {hidden_key, rows[1][1]} and rows[1][1] != hidden_key
    assert rows[1][2] == "AMBER"
    # Beside the hidden exhibit's key, never under it (2026-10-07: the
    # store does not list a key nested under another object, so the purge
    # could not destroy it; test_evidence_lock_live_pg measures that).
    from noctornal_api.evidence import own_key
    assert rows[1][1] == own_key(hidden_key, rows[1][0])
    assert not rows[1][1].startswith(hidden_key + "/")


def test_the_service_alone_never_writes_on_a_key_it_cannot_see(conn, store):
    """Without any ceiling given, on the request role: row security hides the
    RED exhibit, and the system read of its key still keeps the put off it."""
    boss = g.user(conn, "RED")
    analyst = g.user(conn, "AMBER")
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, analyst, "ANALYST")
    hidden, data = g.lodge(conn, store, case_id, boss, classification="RED")
    hidden_key = g.evidence_row(conn, hidden.evidence_id)[0]
    _, raw = s.session(conn, analyst)
    a = s.app_conn(raw)
    try:
        res = g.service(a, store).ingest(
            case_id=case_id, title="probe", media_type="text/plain", data=data,
            acquired_by=analyst, acquisition_method="MANUAL_UPLOAD",
            classification="AMBER")
    finally:
        a.close()
    assert res.deduplicated is False
    assert len(store.objects[hidden_key]) == 1
    assert store.puts.count(hidden_key) == 1


def test_an_exhibit_the_uploader_may_see_is_still_deduplicated(conn, store, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    analyst = g.user(conn, "AMBER", roles=("ANALYST",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, analyst, "ANALYST")
    headers = g.token(conn, analyst)
    data = b"g44-visible-" + uuid4().hex.encode()
    first = _upload(client, headers, case_id, data)
    again = _upload(client, headers, case_id, data)
    assert first.json()["deduplicated"] is False
    assert again.status_code == 201 and again.json()["deduplicated"] is True
    assert again.json()["evidence_id"] == first.json()["evidence_id"]
    assert len(_rows_for(conn, case_id, data)) == 1
    assert len(store.objects[g.evidence_row(conn, first.json()["evidence_id"])[0]]) == 1


def test_the_same_bytes_at_other_labels_are_an_exhibit_of_their_own(conn, store, client):
    """2026-10-07: the lookup ignored the labels the
    uploader asked for, so AMBER bytes and then the same bytes as RED came
    back 201 `deduplicated: true` with the AMBER exhibit, and the RED request
    was dropped without a word. 0141 allows one exhibit per labels."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    headers = g.token(conn, boss)
    data = b"labels-" + uuid4().hex.encode()
    amber = _upload(client, headers, case_id, data, classification="AMBER")
    red = _upload(client, headers, case_id, data, classification="RED")
    assert amber.status_code == 201 and red.status_code == 201, (amber.text, red.text)
    assert amber.json()["deduplicated"] is False
    assert red.json()["deduplicated"] is False
    assert red.json()["evidence_id"] != amber.json()["evidence_id"]
    assert g.evidence_row(conn, red.json()["evidence_id"])[2] == "RED"
    assert g.evidence_row(conn, amber.json()["evidence_id"])[2] == "AMBER"
    assert len(_rows_for(conn, case_id, data)) == 2
    # Each label set still deduplicates onto its own exhibit.
    again_amber = _upload(client, headers, case_id, data, classification="AMBER")
    again_red = _upload(client, headers, case_id, data, classification="RED")
    assert again_amber.json()["deduplicated"] is True
    assert again_amber.json()["evidence_id"] == amber.json()["evidence_id"]
    assert again_red.json()["deduplicated"] is True
    assert again_red.json()["evidence_id"] == red.json()["evidence_id"]
    assert len(_rows_for(conn, case_id, data)) == 2


def test_the_same_bytes_in_another_compartment_are_an_exhibit_of_their_own(conn, store):
    boss = g.user(conn, "RED", compartments=("LABELS-C3",))
    case_id = g.case(conn, boss)
    first, data = g.lodge(conn, store, case_id, boss, classification="AMBER",
                          reader_ceiling=("RED", frozenset({"LABELS-C3"})))
    second, _ = g.lodge(conn, store, case_id, boss, data=data,
                        classification="AMBER", compartments=["LABELS-C3"],
                        reader_ceiling=("RED", frozenset({"LABELS-C3"})))
    assert second.deduplicated is False
    assert second.evidence_id != first.evidence_id
    third, _ = g.lodge(conn, store, case_id, boss, data=data,
                       classification="AMBER", compartments=["LABELS-C3"],
                       reader_ceiling=("RED", frozenset({"LABELS-C3"})))
    assert third.deduplicated is True and third.evidence_id == second.evidence_id
    assert len(_rows_for(conn, case_id, data)) == 2


def test_a_reader_cleared_for_both_is_deduplicated_onto_the_older_one(conn, store):
    boss = g.user(conn, "RED")
    analyst = g.user(conn, "AMBER")
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, analyst, "ANALYST")
    hidden, data = g.lodge(conn, store, case_id, boss, classification="RED")
    g.lodge(conn, store, case_id, analyst, data=data, classification="AMBER",
            reader_ceiling=("AMBER", frozenset()))
    assert len(_rows_for(conn, case_id, data)) == 2
    res, _ = g.lodge(conn, store, case_id, boss, data=data, classification="RED",
                     reader_ceiling=("RED", frozenset()))
    assert res.deduplicated is True and res.evidence_id == hidden.evidence_id


def test_two_live_exhibits_of_the_same_bytes_at_the_same_labels_are_refused_by_the_database(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    first, data = g.lodge(conn, store, case_id, boss)
    row = conn.execute(
        """SELECT media_type, byte_size, sha256, blake3, acquired_by,
                  acquisition_method, classification, compartments
             FROM core.evidence WHERE id = %s""", (first.evidence_id,)).fetchone()
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO core.evidence
                       (case_id, title, media_type, byte_size, sha256, blake3,
                        storage_key, storage_bucket, acquired_by, acquired_at,
                        acquisition_method, classification, compartments)
                   VALUES (%s, 't', %s, %s, %s, %s, %s, 'b', %s, now(), %s, %s, %s)""",
                (case_id, row[0], row[1], row[2], row[3], f"{case_id}/other",
                 row[4], row[5], row[6], row[7]))


def test_two_exhibits_never_share_an_object(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    first, data = g.lodge(conn, store, case_id, boss, classification="RED")
    row = conn.execute("SELECT storage_key FROM core.evidence WHERE id = %s",
                       (first.evidence_id,)).fetchone()
    with pytest.raises(psycopg.errors.UniqueViolation):
        with conn.transaction():
            conn.execute(
                """INSERT INTO core.evidence
                       (case_id, title, media_type, byte_size, sha256, blake3,
                        storage_key, storage_bucket, acquired_by, acquired_at,
                        acquisition_method, classification)
                   SELECT case_id, 't', media_type, byte_size, sha256, blake3,
                          storage_key, storage_bucket, acquired_by, now(),
                          acquisition_method, 'AMBER'
                     FROM core.evidence WHERE id = %s""", (first.evidence_id,))
    assert row[0].startswith(str(case_id))


# --- evidence-reingest-after-purge-dropped -------------------------------

def test_bytes_whose_exhibit_was_destroyed_are_stored_again(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    first, data = g.lodge(conn, store, case_id, boss)
    key = g.evidence_row(conn, first.evidence_id)[0]
    store.delete_all_versions(key)
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s",
                 (first.evidence_id,))
    before = _custody_count(conn, first.evidence_id)

    again, _ = g.lodge(conn, store, case_id, boss, data=data)

    assert again.deduplicated is False
    assert again.evidence_id != first.evidence_id
    new_key = g.evidence_row(conn, again.evidence_id)[0]
    assert new_key != key and store.get(new_key) == data
    assert _custody_count(conn, first.evidence_id) == before, (
        "nothing is appended to the destroyed exhibit")
    live = [r for r in _rows_for(conn, case_id, data) if not r[3]]
    assert [r[0] for r in live] == [again.evidence_id]


# --- http_ui-003, evidence-orphan-locked-object --------------------------

@pytest.mark.parametrize("field", ["title", "description", "source_url", "authority_ref"])
def test_a_nul_in_a_text_field_is_refused_before_anything_is_stored(conn, store, field):
    from noctornal_api.evidence import EvidenceError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    kw = {"title": "t", field: "a\x00b"}
    with pytest.raises(EvidenceError, match="NUL"):
        g.lodge(conn, store, case_id, boss, **kw)
    assert store.puts == []


def test_an_exhibit_below_its_case_is_refused_before_anything_is_stored(conn, store, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)                    # AMBER
    data = b"g44-floor-" + uuid4().hex.encode()
    r = _upload(client, g.token(conn, boss), case_id, data, classification="GREEN")
    assert r.status_code == 400, r.text
    assert "below" in r.json()["detail"] and "AMBER" in r.json()["detail"]
    assert store.puts == [] and _rows_for(conn, case_id, data) == []


def test_a_nul_in_an_upload_is_a_400_and_stores_nothing(conn, store, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    data = b"g44-nul-" + uuid4().hex.encode()
    r = _upload(client, g.token(conn, boss), case_id, data, title="a\x00b")
    assert r.status_code == 400, r.text
    assert store.puts == [] and _rows_for(conn, case_id, data) == []


def test_the_row_is_written_before_the_object_and_commits_with_it(conn, store):
    """Row first, in the same transaction: at the moment of the put the
    exhibit's row is visible to the uploader's own connection and to nobody
    else, and a put that fails leaves no row."""
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    data = b"g44-order-" + uuid4().hex.encode()
    seen: dict = {}

    def at_put(_key):
        import hashlib
        digest = hashlib.sha256(data).digest()
        seen["mine"] = _rows_for(conn, case_id, data)
        other = s.owner_conn()
        try:
            seen["other"] = other.execute(
                "SELECT count(*) FROM core.evidence WHERE sha256 = %s",
                (digest,)).fetchone()[0]
        finally:
            other.close()

    store.on_put = at_put
    res, _ = g.lodge(conn, store, case_id, boss, data=data)
    assert len(seen["mine"]) == 1 and seen["other"] == 0
    assert len(_rows_for(conn, case_id, data)) == 1 and res.deduplicated is False


def test_a_failed_put_leaves_no_row(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    data = b"g44-putfail-" + uuid4().hex.encode()

    def boom(_key):
        raise ConnectionError("the object store went away")

    store.on_put = boom
    # A store that did not answer is `StoreUnavailable` since 2026-10-08 (the
    # HTTP layer's 503), with the store's own error kept as its cause; this
    # test pinned the raw ConnectionError escaping.
    from noctornal_api.evidence import StoreUnavailable
    with pytest.raises(StoreUnavailable) as raised:
        g.lodge(conn, store, case_id, boss, data=data)
    assert isinstance(raised.value.__cause__, ConnectionError)
    assert _rows_for(conn, case_id, data) == []


def test_a_put_whose_row_never_commits_is_recorded_as_an_orphan(conn, store):
    """The object landed and the read-back failed: the row rolls back and the
    audit log names the key, so a sweep can find what no row owns."""
    from noctornal_api.evidence import IntegrityError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    data = b"g44-orphan-" + uuid4().hex.encode()

    class Torn(g.VersionedStore):
        def get(self, key, version_id=None):
            return b"short"

    torn = Torn()
    with pytest.raises(IntegrityError):
        g.lodge(conn, torn, case_id, boss, data=data)
    assert _rows_for(conn, case_id, data) == []
    rows = g.audit_rows(conn, "EVIDENCE_OBJECT_ORPHANED", case_id=case_id)
    assert len(rows) == 1
    detail, outcome, _object_id, _case = rows[0]
    assert outcome == "FAILED" and detail["bucket"] == "g44-fake"
    assert detail["storage_key"] in torn.objects and detail["reason"] == "IntegrityError"


# --- evidence-integrity-anchors-mutable ----------------------------------

@pytest.mark.parametrize("column,value", [
    ("sha256", b"\x00" * 32), ("blake3", b"\x00" * 32), ("byte_size", 1),
    ("storage_key", "x/y"), ("storage_bucket", "other")])
def test_no_role_rewrites_an_exhibits_anchors(conn, store, column, value):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    res, _ = g.lodge(conn, store, case_id, boss)
    _, raw = s.session(conn, boss)
    a = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.CheckViolation, match="fixed when it is lodged"):
            with a.transaction():
                a.execute(f"UPDATE core.evidence SET {column} = %s WHERE id = %s",
                          (value, res.evidence_id))
    finally:
        a.close()
    # The schema owner is refused too: correcting a row means disabling the
    # guard by name, in a transaction that is itself on the record.
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(f"UPDATE core.evidence SET {column} = %s WHERE id = %s",
                         (value, res.evidence_id))


def test_an_exhibit_cannot_move_to_another_case(conn, store):
    boss = g.user(conn, "RED")
    one, two = g.case(conn, boss), g.case(conn, boss)
    res, _ = g.lodge(conn, store, one, boss)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute("UPDATE core.evidence SET case_id = %s WHERE id = %s",
                         (two, res.evidence_id))


def test_the_stored_version_is_set_once(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    res, _ = g.lodge(conn, store, case_id, boss)
    version = g.evidence_row(conn, res.evidence_id)[1]
    assert version and version == store.objects[g.evidence_row(conn, res.evidence_id)[0]][0][0]
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute("UPDATE core.evidence SET storage_version_id = 'x' WHERE id = %s",
                         (res.evidence_id,))


def test_what_retention_and_labels_need_stays_writable(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    res, _ = g.lodge(conn, store, case_id, boss)
    conn.execute(
        "UPDATE core.evidence SET title = 'renamed', legal_hold = true, "
        "legal_hold_reason = 'g44 hold', retention_until = retention_until + 1, "
        "classification = 'RED' WHERE id = %s", (res.evidence_id,))
    assert conn.execute("SELECT title, legal_hold FROM core.evidence WHERE id = %s",
                        (res.evidence_id,)).fetchone() == ("renamed", True)


def test_a_newer_version_on_the_key_is_never_served(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    res, data = g.lodge(conn, store, case_id, boss)
    key = g.evidence_row(conn, res.evidence_id)[0]
    store.replace(key, b"FORGED-" + data)
    assert store.get(key).startswith(b"FORGED-"), "the swap is the latest version"
    svc = g.service(conn, store)
    assert svc.view(res.evidence_id, boss) == data
    assert svc.verify_integrity(res.evidence_id, boss) is True


def test_a_concealed_object_is_an_alarm_and_not_a_500(conn, store):
    """A legacy row names no version, so its read asks for the latest, and a
    delete marker answers NoSuchKey: that is an INTEGRITY_ALARM, a failed
    HASH_VERIFIED and an IntegrityError, never an unrecorded 500."""
    from noctornal_api.evidence import IntegrityError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    legacy = g.VersionedStore(versioned=False)
    res, _ = g.lodge(conn, legacy, case_id, boss)
    assert g.evidence_row(conn, res.evidence_id)[1] is None
    legacy.conceal(g.evidence_row(conn, res.evidence_id)[0])
    svc = g.service(conn, legacy)

    assert svc.verify_integrity(res.evidence_id, boss) is False
    with pytest.raises(IntegrityError):
        svc.view(res.evidence_id, boss)

    alarms = g.audit_rows(conn, "EVIDENCE_INTEGRITY_ALARM", object_id=res.evidence_id)
    assert len(alarms) == 2 and all(a[0]["object_missing"] for a in alarms)
    checks = [e for e in svc.custody_log(res.evidence_id) if e.action == "HASH_VERIFIED"]
    assert [e.hash_verified for e in checks] == [False, False]


def test_a_concealed_key_does_not_hide_an_exhibit_whose_version_is_recorded(conn, store):
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    res, data = g.lodge(conn, store, case_id, boss)
    store.conceal(g.evidence_row(conn, res.evidence_id)[0])
    assert g.service(conn, store).view(res.evidence_id, boss) == data


def test_rewritten_hashes_fail_against_the_acquired_custody_row(conn, store):
    """The full attack of the review: the object replaced and the row's
    hashes rewritten to match. Reads and verify compared the object with the
    row only, so both stayed green; the hash-chained ACQUIRED row still
    holds the original digest and is now compared."""
    import hashlib

    from noctornal_api.evidence import IntegrityError, _blake3d
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    legacy = g.VersionedStore(versioned=False)
    res, _ = g.lodge(conn, legacy, case_id, boss)
    key = g.evidence_row(conn, res.evidence_id)[0]
    forged = b"FORGED-" + uuid4().hex.encode()
    legacy.replace(key, forged)
    with conn.transaction():
        conn.execute("ALTER TABLE core.evidence DISABLE TRIGGER evidence_anchors_fixed")
        conn.execute("UPDATE core.evidence SET sha256 = %s, blake3 = %s WHERE id = %s",
                     (hashlib.sha256(forged).digest(), _blake3d(forged), res.evidence_id))
        conn.execute("ALTER TABLE core.evidence ENABLE TRIGGER evidence_anchors_fixed")
    svc = g.service(conn, legacy)
    assert svc.verify_integrity(res.evidence_id, boss) is False
    with pytest.raises(IntegrityError):
        svc.view(res.evidence_id, boss)
    alarm = g.audit_rows(conn, "EVIDENCE_INTEGRITY_ALARM", object_id=res.evidence_id)
    assert alarm and alarm[0][0]["acquired_anchor_ok"] is False


def test_blake3_is_checked_on_every_read(conn, store):
    from noctornal_api.evidence import IntegrityError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    legacy = g.VersionedStore(versioned=False)
    res, _ = g.lodge(conn, legacy, case_id, boss)
    with conn.transaction():
        conn.execute("ALTER TABLE core.evidence DISABLE TRIGGER evidence_anchors_fixed")
        conn.execute("UPDATE core.evidence SET blake3 = %s WHERE id = %s",
                     (b"\x01" * 32, res.evidence_id))
        conn.execute("ALTER TABLE core.evidence ENABLE TRIGGER evidence_anchors_fixed")
    with pytest.raises(IntegrityError):
        g.service(conn, legacy).view(res.evidence_id, boss)
    alarm = g.audit_rows(conn, "EVIDENCE_INTEGRITY_ALARM", object_id=res.evidence_id)
    assert alarm and alarm[0][0]["blake3_ok"] is False


# --- verify-destroyed-exhibit ------------------------------------------
#
# `a missing object is an integrity alarm` also fired for an exhibit retention
# destroyed on purpose: a verify or a content read of it wrote a failed
# HASH_VERIFIED custody row, an EVIDENCE_INTEGRITY_ALARM audit row and an
# URGENT notification, for any evidence.read holder, as often as they liked.

def _destroyed_exhibit(conn, store):
    """(boss, case id, exhibit id) of an exhibit the retention sweep destroyed:
    its row says purged and the store has nothing under its key."""
    from noctornal_api.retention import RetentionService
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    res, _ = g.lodge(conn, store, case_id, boss)
    g.age_case(conn, case_id, g.expired())
    out = RetentionService(conn, store).purge_due(
        actor_id=boss, authority="g44 retention schedule 2026-10", case_id=case_id)
    assert out.evidence_purged == 1 and store.deleted
    return boss, case_id, res.evidence_id


def _alarm_state(conn, evidence_id):
    """(alarm audit rows, failed custody checks, all custody rows)."""
    return (len(g.audit_rows(conn, "EVIDENCE_INTEGRITY_ALARM", object_id=evidence_id)),
            conn.execute("SELECT count(*) FROM core.evidence_custody WHERE "
                         "evidence_id = %s AND hash_verified = false",
                         (evidence_id,)).fetchone()[0],
            _custody_count(conn, evidence_id))


def test_a_destroyed_exhibit_is_refused_plainly_and_alarms_nothing(conn, store):
    from noctornal_api.evidence import PURGED_DETAIL, ExhibitUnavailable
    boss, _case_id, evidence_id = _destroyed_exhibit(conn, store)
    before = _alarm_state(conn, evidence_id)
    svc = g.service(conn, store)
    for read in (svc.verify_integrity, svc.view, svc.export):
        with pytest.raises(ExhibitUnavailable) as caught:
            read(evidence_id, boss)
        assert str(caught.value) == PURGED_DETAIL
    assert _alarm_state(conn, evidence_id) == before
    assert before[0] == 0 and before[1] == 0


def test_over_http_a_live_exhibit_whose_object_is_gone_is_still_an_alarm(conn, store, client):
    """The question 'is retention doing this?' is asked on a system
    connection, so this runs it as the request role does in production."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    res, _ = g.lodge(conn, store, case_id, boss)
    store.delete_all_versions(g.evidence_row(conn, res.evidence_id)[0])
    headers = g.token(conn, boss)
    base = f"/api/v1/cases/{case_id}/evidence/{res.evidence_id}"

    verify = client.post(f"{base}/verify", headers=headers)
    content = client.get(f"{base}/content", headers=headers)

    assert verify.status_code == 200 and verify.json() == {"ok": False}, verify.text
    assert content.status_code == 409 and content.json()["title"] == "Integrity check failed"
    alarms = g.audit_rows(conn, "EVIDENCE_INTEGRITY_ALARM", object_id=res.evidence_id)
    assert len(alarms) == 2 and all(a[0]["object_missing"] for a in alarms)


def test_verify_and_content_of_a_destroyed_exhibit_are_a_409_that_records_nothing(
        conn, store, client):
    from noctornal_api.evidence import PURGED_DETAIL
    boss, case_id, evidence_id = _destroyed_exhibit(conn, store)
    before = _alarm_state(conn, evidence_id)
    headers = g.token(conn, boss)
    base = f"/api/v1/cases/{case_id}/evidence/{evidence_id}"
    for _ in range(2):
        verify = client.post(f"{base}/verify", headers=headers)
        content = client.get(f"{base}/content", headers=headers)
        for answer in (verify, content):
            assert answer.status_code == 409, answer.text
            assert answer.json()["title"] == "Exhibit unavailable"
            assert answer.json()["detail"] == PURGED_DETAIL
    assert _alarm_state(conn, evidence_id) == before


def test_an_exhibit_a_purge_is_destroying_now_is_not_called_tampered_with(conn, store):
    """The purge deletes the object and holds the row until it commits. A
    read in that window finds the object gone and the row still live, and
    used to alarm. It now gets the plain answer and writes nothing; once the
    purge commits it gets the destroyed one."""
    from noctornal_api.evidence import (
        BEING_DESTROYED_DETAIL,
        PURGED_DETAIL,
        ExhibitUnavailable,
    )
    from noctornal_api.retention import RetentionService
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    res, _ = g.lodge(conn, store, case_id, boss)
    evidence_id = res.evidence_id
    g.age_case(conn, case_id, g.expired())
    before = _alarm_state(conn, evidence_id)
    seen: dict = {}
    original = store.delete_all_versions

    def delete_then_probe(key):
        result = original(key)
        # The object is gone and the purge's transaction has not committed:
        # the row is locked, and a second connection reads it as live.
        other = s.owner_conn()
        try:
            # A regression must fail here, not wait on the purge for ever:
            # without the guard a read writes a custody row, whose foreign
            # key waits on the row the purge holds, and the purge waits on us.
            other.execute("SET lock_timeout = '2s'")
            seen["row"] = other.execute(
                "SELECT purged_at IS NULL FROM core.evidence WHERE id = %s",
                (evidence_id,)).fetchone()[0]
            for name in ("verify_integrity", "view"):
                try:
                    getattr(g.service(other, store), name)(evidence_id, boss)
                except ExhibitUnavailable as exc:
                    seen[name] = str(exc)
        finally:
            other.close()
        return result

    store.delete_all_versions = delete_then_probe
    out = RetentionService(conn, store).purge_due(
        actor_id=boss, authority="g44 retention schedule 2026-10", case_id=case_id)

    assert out.evidence_purged == 1
    assert seen["row"] is True, "the fixture must read the exhibit as live mid-purge"
    assert seen["verify_integrity"] == BEING_DESTROYED_DETAIL
    assert seen["view"] == BEING_DESTROYED_DETAIL
    # The reads wrote nothing; the purge itself ends the trail with its
    # DESTROYED row (2026-10-07).
    after = (before[0], before[1], before[2] + 1)
    assert _alarm_state(conn, evidence_id) == after
    assert conn.execute(
        "SELECT action FROM core.evidence_custody WHERE evidence_id = %s "
        "ORDER BY id DESC LIMIT 1", (evidence_id,)).fetchone()[0] == "DESTROYED"
    with pytest.raises(ExhibitUnavailable) as caught:
        g.service(conn, store).verify_integrity(evidence_id, boss)
    assert str(caught.value) == PURGED_DETAIL
    assert _alarm_state(conn, evidence_id) == after


def test_a_live_exhibit_whose_object_is_gone_is_still_an_alarm(conn, store):
    """The refusal is for retention's doing only: nobody holds the row and
    nothing is purged, so a missing object is concealment and is raised."""
    from noctornal_api.evidence import IntegrityError
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    res, _ = g.lodge(conn, store, case_id, boss)
    key = g.evidence_row(conn, res.evidence_id)[0]
    store.delete_all_versions(key)
    svc = g.service(conn, store)
    assert svc.verify_integrity(res.evidence_id, boss) is False
    with pytest.raises(IntegrityError):
        svc.view(res.evidence_id, boss)
    alarms = g.audit_rows(conn, "EVIDENCE_INTEGRITY_ALARM", object_id=res.evidence_id)
    assert len(alarms) == 2 and all(a[0]["object_missing"] for a in alarms)


# --- unique-after-put ---------------------------------------------------

@pytest.mark.parametrize("error", [
    psycopg.errors.UniqueViolation, psycopg.errors.OperationalError, RuntimeError])
def test_every_failure_after_the_put_is_recorded_as_an_orphan(conn, store, monkeypatch, error):
    """The custody append fails after the object is stored under its lock. A
    unique violation used to leave the first handler by re-raising and never
    reached the sibling that records the orphan."""
    from noctornal_api.evidence import EvidenceService
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    data = b"g44-after-put-" + uuid4().hex.encode()

    def refuse(self, *_a, **_k):
        raise error("g44 injected failure after the put")

    monkeypatch.setattr(EvidenceService, "_custody", refuse)
    with pytest.raises(error):
        g.lodge(conn, store, case_id, boss, data=data)
    assert _rows_for(conn, case_id, data) == []
    assert len(store.puts) == 1
    rows = g.audit_rows(conn, "EVIDENCE_OBJECT_ORPHANED", case_id=case_id)
    assert len(rows) == 1
    assert rows[0][0]["storage_key"] == store.puts[0]
    assert rows[0][0]["reason"] == error.__name__


# --- http_ui-009 ----------------------------------------------------------

def _eml(subject_line: str, tag: str,
         from_line: str = "From: a@evil.example") -> bytes:
    crlf = chr(13) + chr(10)
    lines = [
        "Received: from evil.example (evil.example [203.0.113.7]) by "
        "mx.victim.example; Mon, 1 Jan 2026 00:00:00 +0000",
        from_line, "To: cfo@victim.example", subject_line,
        f"Message-ID: <{tag}@evil.example>", "", f"body {tag}", ""]
    return crlf.join(lines).encode()


@pytest.mark.parametrize("subject,from_line", [
    ("Subject: wi\x00re", "From: a@evil.example"),
    ("Subject: =?utf-8?b?d2kAcmU=?=", "From: a@evil.example"),
    ("Subject: wire", "From: =?utf-8?b?QQBC?= <a@evil.example>")])
def test_an_eml_with_a_nul_header_is_recorded_and_says_so(conn, store, client,
                                                          subject, from_line):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    headers = g.token(conn, boss)
    raw = _eml(subject, f"g44-{uuid4().hex[:8]}", from_line)
    url = f"/api/v1/cases/{case_id}/deception/emails"
    files = {"file": ("m.eml", raw, "message/rfc822")}

    first = client.post(url, headers=headers, files=files, data={"classification": "AMBER"})
    retry = client.post(url, headers=headers, files=files, data={"classification": "AMBER"})

    assert first.status_code == 201, first.text
    assert any(gap["step"] == "nul_characters" for gap in first.json()["parse_gaps"])
    assert conn.execute(
        "SELECT count(*) FROM deception.email_message WHERE case_id = %s",
        (case_id,)).fetchone()[0] >= 1
    # A retry deduplicates onto the lodged exhibit and is not a 500 either.
    assert retry.status_code < 500, retry.text


def test_parse_eml_returns_no_nul_anywhere():
    from dataclasses import fields, is_dataclass

    from noctornal_api.deception import parse_eml
    parsed = parse_eml(_eml("Subject: a\x00b", "g44-walk"))

    def walk(value, where):
        if isinstance(value, str):
            assert "\x00" not in value, where
        elif isinstance(value, (list, tuple, set, frozenset)):
            for i, v in enumerate(value):
                walk(v, f"{where}[{i}]")
        elif isinstance(value, dict):
            for k, v in value.items():
                walk(k, f"{where}.key")
                walk(v, f"{where}.{k}")
        elif is_dataclass(value):
            for f in fields(value):
                walk(getattr(value, f.name), f"{where}.{f.name}")

    walk(parsed, "parsed")
    assert parsed.subject and chr(0xFFFD) in parsed.subject
