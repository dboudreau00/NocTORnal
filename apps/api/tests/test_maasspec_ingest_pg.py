"""A MaaSSpec spectrum through the ingest parser, with and without NOCTORNAL_MAASSPEC.

Switch off (the default), a spectrum is any other JSON object: it is categorised from the key and the
structure as it always was. Switch on, a valid spectrum is filed as an IOC_FEED record in quarantine and an
invalid one is a dead letter whose error text names a path and no value from the document. Nothing else is
written either way.

The last group records what a repeated analysis does today, which the mapper does not change.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ingest tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

DATA = Path(__file__).parent / "data"
SPECTRUM = json.loads((DATA / "maasspec_fixture.spectrum.json").read_text(encoding="utf-8"))
SENTINEL = "SENTINEL-do-not-echo-7731"
SWITCH = "NOCTORNAL_MAASSPEC"


def compact(document) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class MemoryStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'maas-%@noctornal.test')"
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'maas-%@noctornal.test'")
    c.close()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def svc(conn, store):
    from noctornal_api.ingest import IngestService
    return IngestService(conn, store)


@pytest.fixture
def switch_off(monkeypatch):
    monkeypatch.delenv(SWITCH, raising=False)


@pytest.fixture
def switch_on(monkeypatch):
    monkeypatch.setenv(SWITCH, "on")


def _key(conn, svc, **kw):
    from noctornal_api.stores import PgUserStore
    owner = PgUserStore(conn).create_user(
        f"maas-{uuid4().hex[:8]}@noctornal.test", "Maas", "x" * 20)
    issued = svc.issue_key(name="spectra", owner_user_id=owner, **kw)
    return svc.authenticate(issued.secret)


def _ingest(svc, key, raw, **kw):
    batch = svc.accept(key, raw, **kw)
    return batch, svc.parse_batch(batch.batch_id, raw=raw)


def _records(conn, batch_id):
    return conn.execute(
        """SELECT id, category, category_confidence, category_source, case_id, payload,
                  duplicate_of
             FROM ingest.record WHERE batch_id = %s ORDER BY id""",
        (batch_id,)).fetchall()


def _dead(conn, batch_id):
    return conn.execute(
        "SELECT error_class, error_detail FROM ingest.dead_letter WHERE batch_id = %s "
        "ORDER BY id", (batch_id,)).fetchall()


# --- switch off: nothing changes ---------------------------------------------------------------------------

@pytest.mark.parametrize("setting", [None, "", "off", "true", "1"])
def test_a_spectrum_is_categorised_as_before_when_the_switch_is_not_on(
        conn, svc, monkeypatch, setting):
    from noctornal_api.ingest import categorise
    if setting is None:
        monkeypatch.delenv(SWITCH, raising=False)
    else:
        monkeypatch.setenv(SWITCH, setting)
    key = _key(conn, svc, declared_category="PASTE")
    expected = categorise(SPECTRUM, declared="PASTE")
    assert expected == ("PASTE", 0.5, "DECLARED")

    batch, result = _ingest(svc, key, compact(SPECTRUM))

    assert result.records == 1 and result.dead == 0
    (row,) = _records(conn, batch.batch_id)
    assert (row[1], float(row[2]), row[3]) == expected
    assert row[5] == SPECTRUM


def test_an_invalid_spectrum_is_stored_like_any_object_when_the_switch_is_off(
        conn, svc, switch_off):
    bad = copy.deepcopy(SPECTRUM)
    bad["findings"][0]["confidence"] = 1.5
    bad[SENTINEL] = True
    batch, result = _ingest(svc, _key(conn, svc), compact(bad))
    assert result.records == 1 and result.dead == 0
    assert not _dead(conn, batch.batch_id)


# --- switch on: a valid spectrum -----------------------------------------------------------------------------

def test_a_valid_spectrum_is_an_ioc_feed_record_in_quarantine(conn, svc, switch_on):
    key = _key(conn, svc, declared_category="PASTE")
    batch, result = _ingest(svc, key, compact(SPECTRUM))

    assert result.records == 1 and result.dead == 0
    (row,) = _records(conn, batch.batch_id)
    assert row[1] == "IOC_FEED"
    assert float(row[2]) == 1.0
    assert row[3] == "STRUCTURE"
    assert row[4] is None, "in quarantine: attached to no case"
    assert row[5] == SPECTRUM, "the body is stored as received"
    assert row[6] is None
    assert svc.triage_state(row[0]) == "NEW"
    assert not _dead(conn, batch.batch_id)


def test_the_label_comes_from_the_key_never_from_the_document(conn, svc, switch_on):
    key = _key(conn, svc)
    document = copy.deepcopy(SPECTRUM)
    document["metadata"] = {"classification": "CLEAR", "compartments": ["NOT-THIS"]}
    batch, _ = _ingest(svc, key, compact(document))
    row = conn.execute(
        "SELECT classification::text, compartments FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()
    assert row[0] == "AMBER"
    assert row[1] == []


def test_a_spectrum_mapping_writes_no_graph_element_or_proposal(conn, svc, switch_on):
    counts = ("SELECT (SELECT count(*) FROM core.node), (SELECT count(*) FROM core.edge), "
              "(SELECT count(*) FROM core.assertion)")
    before = conn.execute(counts).fetchone()
    _ingest(svc, _key(conn, svc), compact(SPECTRUM))
    assert conn.execute(counts).fetchone() == before


def test_a_batch_of_spectra_is_one_record_each(conn, svc, switch_on):
    second = copy.deepcopy(SPECTRUM)
    second["analysis_id"] = str(uuid4())
    raw = compact(SPECTRUM) + b"\n" + compact(second)
    batch, result = _ingest(svc, _key(conn, svc), raw)
    assert result.records == 2 and result.dead == 0
    assert {r[1] for r in _records(conn, batch.batch_id)} == {"IOC_FEED"}


def test_an_array_of_spectra_is_expanded_and_each_is_checked(conn, svc, switch_on):
    bad = copy.deepcopy(SPECTRUM)
    bad["input"]["sha256"] = "nope"
    raw = json.dumps([SPECTRUM, bad]).encode("utf-8")
    batch, result = _ingest(svc, _key(conn, svc), raw)
    assert result.records == 1 and result.dead == 1
    assert len(_records(conn, batch.batch_id)) == 1


def test_a_body_that_is_not_a_spectrum_is_categorised_as_before(conn, svc, switch_on):
    from noctornal_api.ingest import categorise
    key = _key(conn, svc, declared_category="PASTE")
    plain = {"indicator": "198.51.100.7", "type": "ipv4"}
    batch, result = _ingest(svc, key, compact(plain))
    assert result.records == 1
    (row,) = _records(conn, batch.batch_id)
    assert (row[1], float(row[2]), row[3]) == categorise(plain, declared="PASTE")


# --- switch on: an invalid spectrum --------------------------------------------------------------------------

def _corruptions():
    wrong_type = copy.deepcopy(SPECTRUM)
    wrong_type["summary"]["c2_count"] = SENTINEL
    unknown_key = copy.deepcopy(SPECTRUM)
    unknown_key["findings"][0][SENTINEL] = SENTINEL
    bad_enum = copy.deepcopy(SPECTRUM)
    bad_enum["findings"][0]["type"] = SENTINEL
    bad_hash = copy.deepcopy(SPECTRUM)
    bad_hash["input"]["sha256"] = SENTINEL
    bad_version = copy.deepcopy(SPECTRUM)
    bad_version["maasspec_version"] = SENTINEL
    deep = copy.deepcopy(SPECTRUM)
    node = {"leaf": SENTINEL}
    for _ in range(40):
        node = {SENTINEL: node}
    deep["metadata"] = node
    return {"wrong type": wrong_type, "unknown key": unknown_key, "bad enum": bad_enum,
            "bad sha256": bad_hash, "bad version": bad_version, "deep nesting": deep}


@pytest.mark.parametrize("label", sorted(_corruptions()))
def test_an_invalid_spectrum_is_a_dead_letter_that_names_no_value(
        conn, svc, switch_on, label):
    document = _corruptions()[label]
    batch, result = _ingest(svc, _key(conn, svc), compact(document))

    assert result.records == 0 and result.dead == 1
    assert not _records(conn, batch.batch_id)
    ((error_class, detail),) = _dead(conn, batch.batch_id)
    assert error_class == "SpectrumRefused"
    assert detail.startswith("maasspec: ")
    assert SENTINEL not in detail
    state = conn.execute("SELECT state FROM ingest.batch WHERE id = %s",
                         (batch.batch_id,)).fetchone()[0]
    assert state == "FAILED"


def test_an_oversize_spectrum_is_a_dead_letter(conn, svc, switch_on):
    from noctornal_api import maasspec
    big = copy.deepcopy(SPECTRUM)
    big["metadata"] = {"pad": "x" * (maasspec.MAX_SPECTRUM_BYTES + 1)}
    batch, result = _ingest(svc, _key(conn, svc), compact(big))
    assert result.records == 0 and result.dead == 1
    ((error_class, detail),) = _dead(conn, batch.batch_id)
    assert error_class == "SpectrumRefused"
    assert "larger" in detail


def test_one_bad_spectrum_does_not_take_a_good_one_with_it(conn, svc, switch_on):
    bad = copy.deepcopy(SPECTRUM)
    bad["analysis_id"] = SENTINEL
    raw = compact(SPECTRUM) + b"\n" + compact(bad)
    batch, result = _ingest(svc, _key(conn, svc), raw)
    assert (result.records, result.dead) == (1, 1)
    assert [r[1] for r in _records(conn, batch.batch_id)] == ["IOC_FEED"]
    assert SENTINEL not in _dead(conn, batch.batch_id)[0][1]


# --- a repeated analysis, as it behaves today -------------------------------------------------------------------

def test_a_repeat_with_the_same_idempotency_key_and_body_is_one_batch(conn, svc, store, switch_on):
    key = _key(conn, svc)
    raw = compact(SPECTRUM)
    analysis = SPECTRUM["analysis_id"]
    first = svc.accept(key, raw, idempotency_key=analysis)
    second = svc.accept(key, raw, idempotency_key=analysis)

    assert first.duplicate is False
    assert second.duplicate is True
    assert second.batch_id == first.batch_id
    assert list(store.objects.values()) == [raw]
    svc.parse_batch(first.batch_id, raw=raw)
    assert len(_records(conn, first.batch_id)) == 1


def test_a_repeat_with_the_same_idempotency_key_and_another_body_is_dropped(
        conn, svc, store, switch_on):
    key = _key(conn, svc)
    first_raw = compact(SPECTRUM)
    changed = copy.deepcopy(SPECTRUM)
    changed["findings"] = []
    second_raw = compact(changed)
    analysis = SPECTRUM["analysis_id"]

    first = svc.accept(key, first_raw, idempotency_key=analysis)
    second = svc.accept(key, second_raw, idempotency_key=analysis)

    assert second.duplicate is True
    assert second.batch_id == first.batch_id
    assert list(store.objects.values()) == [first_raw], "the second body is not kept anywhere"
    assert svc.raw_for(first.batch_id) == first_raw


def test_the_same_idempotency_key_on_another_api_key_is_its_own_batch(conn, svc, switch_on):
    raw = compact(SPECTRUM)
    analysis = SPECTRUM["analysis_id"]
    first = svc.accept(_key(conn, svc), raw, idempotency_key=analysis)
    second = svc.accept(_key(conn, svc), raw, idempotency_key=analysis)
    assert second.duplicate is False
    assert second.batch_id != first.batch_id


def test_the_same_body_without_an_idempotency_key_is_a_second_batch_and_a_flagged_copy(
        conn, svc, switch_on):
    key = _key(conn, svc)
    raw = compact(SPECTRUM)
    first, _ = _ingest(svc, key, raw)
    second, result = _ingest(svc, key, raw)

    assert second.duplicate is False
    assert second.batch_id != first.batch_id
    assert result.records == 1 and result.duplicates == 1
    original = _records(conn, first.batch_id)[0]
    copy_row = _records(conn, second.batch_id)[0]
    assert copy_row[6] == original[0], "stored, and linked to the first by content"
    assert original[6] is None


def test_the_same_idempotency_key_after_24_hours_is_still_a_duplicate(
        conn, svc, switch_on):
    key = _key(conn, svc)
    raw = compact(SPECTRUM)
    analysis = SPECTRUM["analysis_id"]
    first = svc.accept(key, raw, idempotency_key=analysis)
    conn.execute("UPDATE ingest.batch SET received_at = now() - interval '25 hours' "
                 "WHERE id = %s", (first.batch_id,))
    again = svc.accept(key, raw, idempotency_key=analysis)
    assert again.duplicate is True
    assert again.batch_id == first.batch_id
