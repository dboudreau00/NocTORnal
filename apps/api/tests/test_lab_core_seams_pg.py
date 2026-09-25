"""The seams every Lab step builds on (F11, 2026-09-24; docs/00 decision 70).

One row shape by name, one label gate with one exclusions list, one path
that decrypts and verifies with an alarm that survives, a custody model
that names a person or says nobody asked, one writer for machine findings,
derived gaps, and one proposal entry point. Screening (F13) and the
sandbox (F14) fill these by adding lines; these tests fail if a reader
bypasses the gate or a seam changes shape.

Email prefix `lcs-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    declare_policy,
    left_behind,
    make_case,
    make_user,
    pe_image,
    teardown,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set")

PREFIX = "lcs-"


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    declare_policy(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    assert left_behind(c, PREFIX)["users"] == 0
    c.close()


@pytest.fixture
def store():
    return MemoryStore()


def _submit(conn, store, who, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(pe_image() + uuid4().bytes,
                                             submitted_by=who, **kw)


class HeldStore:
    """A preservation store double: one held object."""

    def __init__(self, data: bytes):
        self.data = data

    def get(self, key, *, version_id=None, bucket=None):
        return self.data


def _preserve(conn, sample_id):
    """Mark a sample rejected and preserved, as a completed preserving
    rejection leaves it, without a preservation store."""
    conn.execute(
        """UPDATE lab.sample SET state = 'REJECTED', reject_reason = 'held',
                  preserved_bucket = 'preserve', preserved_key = 'preserved/x',
                  preserved_version_id = 'v1', preserved_at = now()
            WHERE id = %s""", (sample_id,))


# --- the one gate ----------------------------------------------------------------

def test_every_lab_reader_goes_through_the_one_gate(conn, store, monkeypatch):
    """An exclusion that holds everything back empties every Lab reader,
    the system readers included, and leaves the officer's list alone.

    Each reader is first shown to FIND the samples without the exclusion,
    so an empty answer under it proves the gate rather than an empty
    query: until 2026-09-24 the similarity check asked for a hash no
    sample had, which passed with or without the exclusion, and this test
    had no retrohunt at all."""
    from noctornal_api import lab_similarity, lab_triage, samples
    from noctornal_api.samples import SampleService
    from noctornal_api.yara_rules import RulesetService, parse_bundle
    who = make_user(conn, PREFIX)
    officer = make_user(conn, PREFIX)
    # GREEN, so a GREEN reader's retrohunt below sees these two samples
    # and none of the estate's (which is AMBER and above).
    s = _submit(conn, store, who, classification="GREEN")
    other = _submit(conn, store, who, classification="GREEN")
    held = _submit(conn, store, who)
    _preserve(conn, held.id)
    imphash = uuid4().hex
    conn.execute("UPDATE lab.sample SET imphash = %s WHERE id = ANY(%s)",
                 (imphash, [s.id, other.id]))
    # An active rule set version, for the retrohunt. Nothing is compiled
    # or scanned here, so the engine is not needed.
    rulesets = RulesetService(conn)
    set_id = rulesets.create(key=f"lcs-{uuid4().hex[:8]}", display_name="Gate",
                             description=None, classification="GREEN",
                             compartments=(), actor_id=who)["id"]
    version = rulesets.add_version(
        set_id, parse_bundle("g.yar", b"rule g { condition: false }\n"),
        licence="MIT", licence_review_required=False,
        provenance={"via": "upload"}, note=None, uploaded_by=who, key=None)
    conn.execute("INSERT INTO lab.yara_activation (ruleset_id, version_id, "
                 "activated_by) VALUES (%s, %s, %s)",
                 (set_id, version["id"], officer))

    def similar_ids():
        out = lab_similarity.similar(
            conn, hashes={"imphash": imphash}, by="imphash",
            thresholds=lab_similarity.Thresholds(), clearance="RED",
            compartments=frozenset())
        return {r["sample"]["id"] for r in out["results"]}

    def hunt():
        return lab_triage.retrohunt(
            conn, version["id"], ruleset_id=set_id, number=1, actor_id=who,
            clearance="GREEN", compartments=frozenset())

    svc = SampleService(conn, store)
    assert svc.visible(s.id, clearance="RED")
    assert similar_ids() == {str(s.id), str(other.id)}
    real = samples.LAB_EXCLUSIONS
    monkeypatch.setattr(samples, "LAB_EXCLUSIONS", ("false",))
    assert svc.queue(clearance="RED", states=samples.QUEUE_STATES) == []
    assert svc.visible(s.id, clearance="RED") is None
    with pytest.raises(samples.SampleError, match="no such sample"):
        svc._downloadable(s.id, clearance="RED")
    with pytest.raises(samples.SampleError, match="no such sample"):
        svc._retrievable(held.id, actor_id=who, clearance="RED",
                         compartments=frozenset(), stage="mint")
    assert similar_ids() == set()
    counts = hunt()
    assert counts["queued"] == counts["merged"] == 0
    assert not any(counts["skipped"].values())
    assert lab_triage.enqueue(conn, other.id, trigger="ON_DEMAND",
                              requested_by=who).run_id is None
    claimed, skipped = lab_triage.claim(conn, lab_triage.settings_or_default(),
                                        run_id=conn.execute(
                                            "SELECT id FROM lab.static_run "
                                            "WHERE sample_id = %s", (s.id,)
                                        ).fetchone()[0])
    assert claimed is None and skipped == 1
    listed = svc.preserved_for_authorisation(clearance="RED")
    assert str(held.id) in {x["id"] for x in listed}
    # And the retrohunt finds both once the exclusion is lifted (s's run
    # was ended by the claim above; other's submission run is still
    # queued, so one is queued anew and one merges).
    monkeypatch.setattr(samples, "LAB_EXCLUSIONS", real)
    counts = hunt()
    assert counts["queued"] + counts["merged"] == 2, counts


def test_the_gate_renderings_carry_the_exclusions():
    from noctornal_api import samples
    assert samples.LABEL_GATE_SQL == samples.lab_gate()
    assert samples.LABEL_PREDICATE_SQL == samples.lab_gate(exclusions=False)
    assert "%(gate_clearance)s" in samples.lab_gate()
    assert "x.classification" in samples.lab_gate(s="x", c="k")


def test_gate_params_refuses_a_missing_clearance():
    from noctornal_api.samples import SampleError, gate_params
    with pytest.raises(SampleError, match="needs the caller's clearance"):
        gate_params(None, frozenset())
    assert gate_params("AMBER", {"B", "A"}) == {
        "gate_clearance": "AMBER", "gate_compartments": ["A", "B"]}


# --- the row shape ---------------------------------------------------------------

def test_record_decodes_by_name(conn, store):
    from dataclasses import fields

    from noctornal_api import samples
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    names = {f.name for f in fields(samples.Sample)}
    assert names == {f for _c, f in samples.SAMPLE_FIELDS} | {"key_destroyed"}
    reordered = tuple(reversed(samples.SAMPLE_FIELDS))
    cols = ", ".join(c for c, _f in reordered)
    row = conn.execute(
        f"SELECT {cols}, octet_length(data_key_ciphertext) = 0 FROM lab.sample "
        f"WHERE id = %s", (s.id,)).fetchone()
    got = samples._record(row, tuple(f for _c, f in reordered) + ("key_destroyed",))
    assert got == samples.SampleService(conn).get(s.id)


def test_xor_stream_chunked_is_byte_identical():
    from noctornal_api.samples import _xor_stream

    def old(data, key):
        stream = bytearray()
        counter = 0
        while len(stream) < len(data):
            stream.extend(hashlib.sha256(key + counter.to_bytes(8, "big")).digest())
            counter += 1
        return bytes(b ^ s for b, s in zip(data, stream[:len(data)], strict=True))

    key = os.urandom(32)
    for n in (0, 1, 31, 32, 33, (1 << 20) + 7):
        data = os.urandom(n)
        assert bytes(_xor_stream(data, key)) == old(data, key), n


# --- one verified-plaintext path -------------------------------------------------

def test_verified_plaintext_refuses_inside_a_transaction(conn, store):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    before = conn.execute("SELECT count(*) FROM lab.sample_access").fetchone()[0]
    with pytest.raises(RuntimeError, match="outside a transaction"):
        with conn.transaction():
            SampleService(conn, store)._verified_plaintext(s.id, actor_id=who)
    assert conn.execute("SELECT count(*) FROM lab.sample_access").fetchone()[0] == before


def test_integrity_alarm_survives_the_raise_for_both_stores(conn, store):
    from noctornal_api.samples import (STORE_PRESERVATION, SampleIntegrityError,
                                       SampleService)
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    key = next(k for k in store.objects if s.sha256 in k)
    good = store.objects[key]
    store.objects[key] = b"x" + good
    with pytest.raises(SampleIntegrityError, match="^sample integrity check failed"):
        SampleService(conn, store)._verified_plaintext(s.id, actor_id=who)
    held = _submit(conn, store, who)
    held_key = next(k for k in store.objects if held.sha256 in k)
    _preserve(conn, held.id)
    svc = SampleService(conn, store, HeldStore(b"y" + store.objects[held_key]))
    with pytest.raises(SampleIntegrityError,
                       match="^preserved sample integrity check failed"):
        svc._verified_plaintext(held.id, actor_id=None, store=STORE_PRESERVATION)
    rows = conn.execute(
        """SELECT sample_id, actor_kind, detail->>'store' FROM lab.sample_access
            WHERE sample_id IN (%s, %s)
              AND detail->>'event' = 'integrity_check_failed'
            ORDER BY id""", (s.id, held.id)).fetchall()
    assert rows == [(s.id, "USER", "working"),
                    (held.id, "SYSTEM", "preservation")]
    audits = conn.execute(
        """SELECT actor_kind, outcome FROM audit.event
            WHERE action = 'SAMPLE_INTEGRITY_ALARM' AND object_id IN (%s, %s)
            ORDER BY seq""", (s.id, held.id)).fetchall()
    assert audits == [("USER", "DENIED"), ("SYSTEM", "DENIED")]


def test_verified_plaintext_refuses_a_sample_above_the_maximum_before_reading(conn):
    from noctornal_api.samples import SampleError, SampleService

    class Unread(MemoryStore):
        def get(self, key):
            raise AssertionError("the store was read")

    who = make_user(conn, PREFIX)
    store = MemoryStore()
    s = _submit(conn, store, who)
    with pytest.raises(SampleError, match="nothing was read"):
        SampleService(conn, Unread())._verified_plaintext(
            s.id, actor_id=who, max_bytes=10)


# --- custody ---------------------------------------------------------------------

def test_system_custody_names_nobody_and_only_for_machine_actions(conn, store):
    from psycopg.errors import CheckViolation
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    for action in ("DOWNLOADED", "SHARED", "DETONATED", "ASSIGNED"):
        with pytest.raises(CheckViolation):
            conn.execute("""INSERT INTO lab.sample_access (sample_id, actor_id,
                            actor_kind, action) VALUES (%s, NULL, 'SYSTEM', %s)""",
                         (s.id, action))
    with pytest.raises(CheckViolation):
        conn.execute("""INSERT INTO lab.sample_access (sample_id, actor_id,
                        actor_kind, action) VALUES (%s, NULL, 'USER', 'SCANNED')""",
                     (s.id,))
    with pytest.raises(CheckViolation):
        conn.execute("""INSERT INTO lab.sample_access (sample_id, actor_id,
                        actor_kind, action) VALUES (%s, %s, 'SYSTEM', 'SCANNED')""",
                     (s.id, who))
    for action in ("SCANNED", "VIEWED_META", "REJECTED", "ANALYSED"):
        conn.execute("""INSERT INTO lab.sample_access (sample_id, actor_id,
                        actor_kind, action) VALUES (%s, NULL, 'SYSTEM', %s)""",
                     (s.id, action))


def test_custody_returns_null_actor_and_kind_for_system_rows(conn, store):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    svc = SampleService(conn)
    svc._access(s.id, None, "SCANNED", {"event": "static_triage"})
    rows = svc.custody(s.id)
    system = [r for r in rows if r["action"] == "SCANNED"]
    assert system and system[0]["actor_id"] is None
    assert system[0]["actor_kind"] == "SYSTEM"
    person = [r for r in rows if r["event"] == "submitted"][0]
    assert person["actor_kind"] == "USER" and person["actor_id"] == str(who)


# --- machine analyses ------------------------------------------------------------

def test_machine_analysis_writes_no_custody_no_state_and_no_graph(conn, store):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    conn.execute("UPDATE lab.static_run SET status = 'RUNNING', started_at = now() "
                 "WHERE sample_id = %s", (s.id,))
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s",
                       (s.id,)).fetchone()[0]

    def counts():
        return conn.execute(
            """SELECT (SELECT count(*) FROM lab.sample_access WHERE sample_id = %s),
                      (SELECT state FROM lab.sample WHERE id = %s),
                      (SELECT count(*) FROM core.node),
                      (SELECT count(*) FROM core.edge),
                      (SELECT count(*) FROM core.assertion),
                      (SELECT count(*) FROM collect.proposal)""",
            (s.id, s.id)).fetchone()

    before = counts()
    with conn.transaction():
        SampleService(conn).record_machine_analysis(
            s.id, kind="STATIC", tool="t", tool_version="1", findings={},
            run_id=run)
    assert counts() == before
    conn.execute("UPDATE lab.static_run SET status = 'DONE', finished_at = now() "
                 "WHERE id = %s", (run,))


def test_machine_analysis_is_refused_for_rejected_and_read_only_samples(conn, store):
    from noctornal_api.samples import (SampleCaseReadOnly, SampleError,
                                       SampleService)
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    SampleService(conn, store).reject(s.id, actor_id=who, reason="no",
                                      purge_bytes=False)
    with pytest.raises(SampleError, match="rejected"):
        SampleService(conn).record_machine_analysis(
            s.id, kind="STATIC", tool="t", tool_version="1", findings={})
    case = make_case(conn, who)
    t = _submit(conn, store, who, case_id=case)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 "WHERE id = %s", (case,))
    with pytest.raises(SampleCaseReadOnly):
        SampleService(conn).record_machine_analysis(
            t.id, kind="STATIC", tool="t", tool_version="1", findings={})
    with pytest.raises(SampleError, match="unknown machine analysis kind"):
        SampleService(conn).record_machine_analysis(
            s.id, kind="MANUAL_RE", tool="t", tool_version="1", findings={})


def test_analyses_name_what_produced_a_machine_row():
    from noctornal_api.samples import MACHINE_PRODUCERS, PROPOSAL_ORIGINS
    assert MACHINE_PRODUCERS == {"STATIC": "NocTORnal static triage",
                                 "YARA": "YARA scan",
                                 # F14 fills the sandbox's seam.
                                 "SANDBOX": "CAPEv2 sandbox"}
    assert PROPOSAL_ORIGINS[("analyst", None)] == "lab/analysis"
    assert PROPOSAL_ORIGINS[("machine", "STATIC")] == "lab/static-triage"
    assert PROPOSAL_ORIGINS[("machine", "SANDBOX")] == "lab/sandbox"


# --- gaps -------------------------------------------------------------------------

def test_the_screening_gap_is_derived_not_stored(conn, store):
    from noctornal_api.http.routers.samples import _named
    from noctornal_api.samples import (DERIVED_GAP_STEPS, GAP_STATUSES,
                                       SampleService)
    who = make_user(conn, PREFIX)
    s = _submit(conn, store, who)
    stored = [g["step"] for g in s.triage_gaps]
    assert "prohibited_content_screening" not in stored
    assert all(g["status"] in GAP_STATUSES for g in s.triage_gaps)
    svc = SampleService(conn)
    row = _named(svc, [svc.get(s.id)])[0]
    derived = [g for g in row["triage_gaps"] if g["step"] in DERIVED_GAP_STEPS]
    # F13 owns the body; with no list loaded the sentence says
    # nothing was compared (the demo estate and this suite load none).
    assert derived == [{"step": "prohibited_content_screening",
                        "status": "unavailable",
                        "reason": "no prohibited-content hash list is loaded; "
                                  "nothing was compared"}]
    # A legacy row that still stores the entry shows it once, derived.
    from psycopg.types.json import Json
    conn.execute("UPDATE lab.sample SET triage_gaps = triage_gaps || %s::jsonb "
                 "WHERE id = %s",
                 (Json([{"step": "prohibited_content_screening",
                         "reason": "old words"}]), s.id))
    row = _named(svc, [svc.get(s.id)])[0]
    again = [g for g in row["triage_gaps"]
             if g["step"] == "prohibited_content_screening"]
    assert len(again) == 1 and again[0]["reason"] != "old words"


# --- the proposal entry point ----------------------------------------------------

def test_propose_entry_uses_the_origin_and_a_system_actor_when_none(conn, store):
    from noctornal_api.samples import SampleService
    who = make_user(conn, PREFIX)
    case = make_case(conn, who)
    s = _submit(conn, store, who, case_id=case)
    svc = SampleService(conn)
    conn.execute("UPDATE lab.static_run SET status = 'RUNNING', started_at = now() "
                 "WHERE sample_id = %s", (s.id,))
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s",
                       (s.id,)).fetchone()[0]
    with conn.transaction():
        svc.record_machine_analysis(
            s.id, kind="STATIC", tool="noctornal static triage",
            tool_version="pefile 2024.8.26", findings={}, run_id=run,
            extracted_selectors=[{"selector_type": "IMPHASH",
                                  "value": "b" * 32, "why": "computed"}])
    conn.execute("UPDATE lab.static_run SET status = 'DONE', finished_at = now() "
                 "WHERE id = %s", (run,))
    found = next(a for a in svc.analyses(s.id) if a["origin"] == "machine")
    out = svc._propose_entry(svc.get(s.id), found, 0, actor_id=None,
                             origin="lab/static-triage")
    assert out == {"sent": True, "label": "b" * 32}
    assert conn.execute("SELECT origin FROM collect.proposal WHERE case_id = %s",
                        (case,)).fetchone()[0] == "lab/static-triage"
    actor = conn.execute(
        """SELECT actor_kind, actor_id FROM audit.event
            WHERE action = 'SAMPLE_SELECTOR_PROPOSED' AND object_id = %s
            ORDER BY seq DESC LIMIT 1""", (s.id,)).fetchone()
    assert actor == ("SYSTEM", None)
