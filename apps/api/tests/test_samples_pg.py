"""Phase 8 -- sample handling. The tests that matter are the refusals.

Invariant 10: samples never render, never execute; the binary is only ever
an encrypted archive download from a separate origin. Most of this file
asserts that the system says NO -- to ingest before a policy is declared,
to serving bytes from the app origin, to a second copy of the same binary,
to a family attribution with no confidence, and to a public detonation with
nobody's name on it.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; sample handling is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

# A benign stand-in with a PE magic. Nothing in this suite is real malware,
# and nothing here executes anything -- which is also the product's rule.
FAKE_PE = b"MZ\x90\x00" + b"this is not a real executable" * 20


@pytest.fixture(autouse=True)
def declared_policy(monkeypatch):
    """Most tests need ingest to work, so the declaration is made here --
    once, visibly, rather than by a default that would let the refusal rot."""
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'lab-%@noctornal.test')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.detonation WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'lab-%@noctornal.test'")
    c.close()


class MemoryStore:
    """Stands in for the sample bucket. Keeps live malware out of the test
    fixtures and lets the quarantine path be proved without one."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


#: `download()` refuses without a clearance (docs/17 F18). These tests are
#: about the origin split, the tamper check and the state machine, so they
#: pass a cleared caller and let the dedicated gate tests in
#: `test_samples_hardening_pg.py` cover the label check itself.
CLEARED = dict(clearance="RED")

def _user(conn, clearance="RED"):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"lab-{uuid4().hex[:8]}@noctornal.test", "RE", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-LAB-{uuid4().hex[:6]}", title="Lab",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def svc(conn, store):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store)


def _unique(seed: str) -> bytes:
    return FAKE_PE + seed.encode()


# --- the block that was lifted, and the refusal that replaced it --------

def test_ingest_is_refused_until_a_policy_is_declared(conn, store, monkeypatch):
    """decision 36 blocked this phase because a store of attacker-supplied
    binaries will eventually receive material whose possession alone is an
    offence. The operator lifted the block; the refusal that replaced it is
    that nothing ingests until somebody has DECLARED a policy exists and
    named the person material is escalated to.

    A declaration, not a verification. The software cannot check that the
    referenced policy exists or that anyone has read it -- what it can do is
    stop ingest being a one-click accident and put the operator's own
    reference in the audit trail, so "nobody knew" is not available later.
    """
    from noctornal_api.samples import PolicyNotDeclared, SampleService

    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", raising=False)
    alice = _user(conn)
    with pytest.raises(PolicyNotDeclared, match="prohibited-content policy"):
        SampleService(conn, store).submit(FAKE_PE, submitted_by=alice)


def test_a_designated_person_is_required_too(conn, store, monkeypatch):
    """docs/11: the response to prohibited material is a documented
    procedure with a named person, not a product feature."""
    from noctornal_api.samples import PolicyNotDeclared, SampleService

    monkeypatch.delenv("NOCTORNAL_DESIGNATED_PERSON", raising=False)
    alice = _user(conn)
    with pytest.raises(PolicyNotDeclared):
        SampleService(conn, store).submit(FAKE_PE, submitted_by=alice)


def test_the_policy_reference_is_not_a_boolean(monkeypatch):
    """"true" is what somebody types to make an error go away. A reference
    is something they have to actually possess."""
    from noctornal_api.samples import policy_declared

    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "  ")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "someone")
    assert policy_declared()[0] is False


# --- quarantine ---------------------------------------------------------

def test_a_sample_lands_in_quarantine_never_in_the_queue(conn, svc):
    """docs/11: nothing is visible to the RE queue until automated triage
    has run."""
    from noctornal_api.samples import QUARANTINED
    alice = _user(conn)
    s = svc.submit(FAKE_PE, submitted_by=alice, original_filename="invoice.pdf.exe")
    assert s.state == QUARANTINED


def test_the_object_key_is_the_hash_never_the_filename(conn, svc, store):
    """Original filenames are attacker-controlled and are themselves a
    payload vector: a traversal, a right-to-left override, a 4KB name."""
    alice = _user(conn)
    # The override is BUILT, never written as a literal: a U+202E in this
    # file would make the source read differently from how it executes,
    # which is exactly what scripts/check_source_hygiene.py refuses (and
    # did refuse, when this test was first written).
    rtl_override = chr(0x202E)
    hostile = "../../../etc/cron.d/pwn" + rtl_override + "gnp.exe"
    s = svc.submit(FAKE_PE, submitted_by=alice, original_filename=hostile)
    key = next(iter(store.objects))
    assert s.sha256 in key
    assert ".." not in key and rtl_override not in key
    # Kept for the record, though, because what the attacker called it is
    # itself evidence.
    row = conn.execute(
        "SELECT original_filename FROM lab.sample WHERE id = %s", (s.id,)
    ).fetchone()
    assert row[0] == hostile


def test_nothing_is_stored_as_an_executable(conn, svc, store):
    """Encrypted at rest under a per-sample key. Besides containment, this
    is what stops your own EDR quarantining the evidence -- docs/11 calls
    that a routine and embarrassing failure."""
    alice = _user(conn)
    svc.submit(FAKE_PE, submitted_by=alice)
    stored = next(iter(store.objects.values()))
    assert not stored.startswith(b"MZ"), "the PE magic must not survive at rest"
    assert stored != FAKE_PE


def test_the_same_binary_is_not_stored_twice(conn, svc):
    """Two analysts finding the same binary is a finding about the actors,
    not a reason for two copies of live malware.

    The refusal names the hash only for a caller who could have seen the
    existing row anyway. `submit()` without `visible_to_clearance` says
    nothing, and that default is the point: uploading a hash you suspect
    and reading the error back is a cheap probe for "is anybody else
    working this intrusion", which in a compartmented case is the answer
    the access gate exists to withhold (docs/17 F19).
    """
    from noctornal_api.samples import SampleError
    alice = _user(conn)
    svc.submit(FAKE_PE, submitted_by=alice)

    # Cleared: the useful message, so the analyst can go and link it.
    with pytest.raises(SampleError, match="already held"):
        svc.submit(FAKE_PE, submitted_by=alice, visible_to_clearance="RED")

    # Not cleared, and — the default — a caller who did not say. Both get a
    # refusal that discloses nothing, and neither stores a second copy.
    for kwargs in ({}, {"visible_to_clearance": "CLEAR"}):
        with pytest.raises(SampleError, match="not accepted") as raised:
            svc.submit(FAKE_PE, submitted_by=alice, **kwargs)
        assert "already held" not in str(raised.value)
        assert hashlib.sha256(FAKE_PE).hexdigest()[:16] not in str(raised.value)
    assert conn.execute(
        "SELECT count(*) FROM lab.sample WHERE sha256 = %s",
        (hashlib.sha256(FAKE_PE).digest(),)).fetchone()[0] == 1


def test_an_oversized_submission_is_refused(conn, svc, monkeypatch):
    from noctornal_api import samples
    from noctornal_api.samples import SampleError
    monkeypatch.setattr(samples, "MAX_SAMPLE_BYTES", 16)
    alice = _user(conn)
    with pytest.raises(SampleError, match="exceeds"):
        svc.submit(FAKE_PE, submitted_by=alice)


def test_an_empty_submission_is_refused(conn, svc):
    from noctornal_api.samples import SampleError
    alice = _user(conn)
    with pytest.raises(SampleError):
        svc.submit(b"", submitted_by=alice)


# --- static triage ------------------------------------------------------

def test_file_typing_is_by_structure_not_extension():
    """`invoice.pdf.exe` is the oldest trick there is. The extension is
    part of the attacker's message."""
    from noctornal_api.samples import file_type_of
    assert file_type_of(b"MZ\x90\x00rest") == "PE/MZ"
    assert file_type_of(b"\x7fELF\x02") == "ELF"
    assert file_type_of(b"%PDF-1.7") == "PDF"
    assert file_type_of(b"PK\x03\x04") == "ZIP or OOXML"
    assert file_type_of(b"nothing recognisable") == "unknown"


def test_entropy_separates_packed_from_plain():
    """Above ~7.2 bits/byte means packed, encrypted or compressed. A triage
    signal, not a verdict."""
    from noctornal_api.samples import shannon_entropy
    assert shannon_entropy(b"A" * 4096) < 0.1
    assert shannon_entropy(os.urandom(4096)) > 7.5
    assert shannon_entropy(b"") == 0.0


def test_what_triage_could_not_do_is_RECORDED_not_silently_null(conn, svc):
    """A NULL imphash reads as "this sample has no imports". A recorded gap
    reads as "nobody looked", which is the true statement."""
    alice = _user(conn)
    s = svc.submit(FAKE_PE, submitted_by=alice)
    steps = {g["step"] for g in s.triage_gaps}
    assert {"imphash", "ssdeep", "tlsh", "yara"} <= steps
    assert all(g.get("reason") for g in s.triage_gaps), (
        "a gap without a reason is as useless as a silent NULL")


def test_the_hashes_that_ARE_computed_are_right(conn, svc):
    import hashlib
    alice = _user(conn)
    s = svc.submit(FAKE_PE, submitted_by=alice)
    assert s.sha256 == hashlib.sha256(FAKE_PE).hexdigest()
    assert s.sha1 == hashlib.sha1(FAKE_PE).hexdigest()
    assert s.md5 == hashlib.md5(FAKE_PE).hexdigest()


# --- invariant 10: the origin split -------------------------------------

def test_download_is_refused_when_no_separate_origin_is_configured(
        conn, svc, monkeypatch):
    """Invariant 10 as a runtime check, not a deployment note. An origin
    split that is only ever written down does not survive the first hurried
    deploy -- and serving hostile bytes from the app origin means an escape
    runs with the analyst's session on the case file."""
    from noctornal_api.samples import SampleError
    monkeypatch.delenv("NOCTORNAL_SAMPLE_ORIGIN", raising=False)
    alice = _user(conn)
    s = svc.submit(_unique("origin"), submitted_by=alice)
    with pytest.raises(SampleError, match="not a deployment suggestion"):
        svc.download(s.id, actor_id=alice, request_origin="https://app.example", **CLEARED)


def test_download_is_refused_from_the_application_origin(conn, svc, monkeypatch):
    from noctornal_api.samples import SampleError
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice = _user(conn)
    s = svc.submit(_unique("appOrigin"), submitted_by=alice)
    with pytest.raises(SampleError, match="never from the application origin"):
        svc.download(s.id, actor_id=alice, request_origin="https://app.example", **CLEARED)


def test_download_from_the_sample_origin_returns_an_archive(conn, svc, monkeypatch):
    import zipfile

    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice = _user(conn)
    payload = _unique("good")
    s = svc.submit(payload, submitted_by=alice)
    blob, digest = svc.download(s.id, actor_id=alice,
                                request_origin="https://samples.example", **CLEARED)
    assert zipfile.is_zipfile(__import__("io").BytesIO(blob))
    with zipfile.ZipFile(__import__("io").BytesIO(blob)) as zf:
        assert zf.namelist() == [digest + ".bin"]
        # Named for its hash, not its original name: the archive is the last
        # place the attacker's filename should reappear.
        assert b"NO confidentiality" in zf.comment


def test_the_archive_says_what_the_password_is_worth():
    """The commonest mistake with the `infected` convention is treating it
    as confidentiality. The password is public and ZipCrypto is broken."""
    from noctornal_api.samples import archive
    import zipfile

    blob = archive(b"payload", "deadbeef")
    with zipfile.ZipFile(__import__("io").BytesIO(blob)) as zf:
        comment = zf.comment.decode()
    assert "PUBLIC" in comment and "NO confidentiality" in comment


def test_a_tampered_sample_is_never_served(conn, svc, store, monkeypatch):
    """Same discipline as the evidence read path: re-verify on EVERY read
    and fail closed. A sample whose bytes changed is a storage fault or a
    tamper, and neither is a thing to hand to an analyst."""
    from noctornal_api.samples import SampleError
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice = _user(conn)
    s = svc.submit(_unique("tamper"), submitted_by=alice)
    key = next(iter(store.objects))
    store.objects[key] = b"something else entirely"
    with pytest.raises(SampleError, match="integrity check failed"):
        svc.download(s.id, actor_id=alice, request_origin="https://samples.example", **CLEARED)


# --- the REJECTED path --------------------------------------------------

def test_rejection_keeps_the_record_and_destroys_the_content(conn, svc, store,
                                                             monkeypatch):
    """docs/11 requires a REJECTED path that records THAT something was
    rejected and why, without retaining the content. The asymmetry is the
    point: an auditor asking "did anything prohibited come through here"
    needs an answer, and the answer cannot be the material."""
    from noctornal_api.samples import REJECTED
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice = _user(conn)
    s = svc.submit(_unique("reject"), submitted_by=alice)
    assert store.objects

    rejected = svc.reject(s.id, actor_id=alice,
                          reason="prohibited content, escalated to the DP")
    assert rejected.state == REJECTED
    assert "escalated" in rejected.reject_reason
    assert not store.objects, "the bytes must not survive"


def test_a_rejected_sample_can_never_be_downloaded(conn, svc, monkeypatch):
    from noctornal_api.samples import SampleError
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice = _user(conn)
    s = svc.submit(_unique("gone"), submitted_by=alice)
    svc.reject(s.id, actor_id=alice, reason="prohibited")
    with pytest.raises(SampleError):
        svc.download(s.id, actor_id=alice,
                     request_origin="https://samples.example", **CLEARED)


def test_rejection_destroys_the_data_key_too(conn, svc):
    """Even if the object survives a bucket-lifecycle race, nothing can
    decrypt it."""
    alice = _user(conn)
    s = svc.submit(_unique("key"), submitted_by=alice)
    svc.reject(s.id, actor_id=alice, reason="prohibited")
    row = conn.execute(
        "SELECT data_key_ciphertext FROM lab.sample WHERE id = %s", (s.id,)
    ).fetchone()
    assert bytes(row[0]) == b""


def test_a_rejection_has_to_say_why(conn, svc):
    from noctornal_api.samples import SampleError
    alice = _user(conn)
    s = svc.submit(_unique("why"), submitted_by=alice)
    with pytest.raises(SampleError, match="say why"):
        svc.reject(s.id, actor_id=alice, reason="   ")


def test_the_database_refuses_a_rejected_row_with_no_reason(conn, svc):
    import psycopg
    alice = _user(conn)
    s = svc.submit(_unique("dbreason"), submitted_by=alice)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE lab.sample SET state = 'REJECTED' WHERE id = %s",
                     (s.id,))


# --- analysis and the graph -------------------------------------------

def test_a_family_attribution_without_a_confidence_is_refused(conn, svc):
    """A family attribution is an ASSESSMENT. One without a confidence is a
    fact wearing an assessment's clothes, and invariant 1 exists to stop
    exactly that reaching the graph."""
    from noctornal_api.samples import SampleError
    alice = _user(conn)
    s = svc.submit(_unique("family"), submitted_by=alice)
    with pytest.raises(SampleError, match="assessment, not a fact"):
        svc.record_analysis(s.id, analyst_id=alice, kind="MANUAL_RE",
                            family_assessment="Qakbot")


def test_a_family_attribution_with_a_confidence_is_recorded(conn, svc):
    alice = _user(conn)
    s = svc.submit(_unique("fam2"), submitted_by=alice)
    svc.record_analysis(s.id, analyst_id=alice, kind="MANUAL_RE",
                        family_assessment="Qakbot", confidence="MODERATE",
                        extracted_selectors=[{"type": "DOMAIN", "value": "c2.test"}])
    got = svc.analyses(s.id)
    assert got[0]["family_assessment"] == "Qakbot"
    assert got[0]["confidence"] == "MODERATE"
    assert got[0]["extracted_selectors"][0]["value"] == "c2.test"


def test_the_database_refuses_that_too(conn, svc):
    """The service gives the readable error; the constraint is the
    guarantee."""
    import psycopg
    alice = _user(conn)
    s = svc.submit(_unique("dbfam"), submitted_by=alice)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO lab.sample_analysis
                   (sample_id, kind, family_assessment)
               VALUES (%s, 'MANUAL_RE', 'Qakbot')""", (s.id,))


def test_analysis_moves_an_assigned_sample_into_analysis(conn, svc):
    from noctornal_api.samples import IN_ANALYSIS
    alice, re_analyst = _user(conn), _user(conn)
    s = svc.submit(_unique("flow"), submitted_by=alice)
    svc.assign(s.id, analyst_id=re_analyst, actor_id=alice)
    svc.record_analysis(s.id, analyst_id=re_analyst, kind="STATIC")
    assert svc.get(s.id).state == IN_ANALYSIS


def test_a_reported_sample_cannot_be_reassigned(conn, svc):
    from noctornal_api.samples import SampleError
    alice, re_analyst = _user(conn), _user(conn)
    s = svc.submit(_unique("reassign"), submitted_by=alice)
    conn.execute("UPDATE lab.sample SET state = 'REPORTED' WHERE id = %s", (s.id,))
    with pytest.raises(SampleError, match="quarantined or triaged"):
        svc.assign(s.id, analyst_id=re_analyst, actor_id=alice)


# --- detonation is an overt act ----------------------------------------

def test_a_public_detonation_needs_a_named_authoriser(conn, svc):
    """Operators watch public sandboxes for their own samples and treat a
    submission as a signal they have been noticed. That can end an
    operation that took months, so it cannot be a side effect of clicking
    Analyse."""
    from noctornal_api.samples import SampleError
    alice = _user(conn)
    s = svc.submit(_unique("boom"), submitted_by=alice)
    with pytest.raises(SampleError, match="named authoriser"):
        svc.request_detonation(s.id, requested_by=alice, target="ANY_RUN",
                               exposure_level="PUBLIC")


def test_a_private_detonation_does_not(conn, svc):
    alice = _user(conn)
    s = svc.submit(_unique("private"), submitted_by=alice)
    det = svc.request_detonation(s.id, requested_by=alice,
                                 target="PRIVATE_CAPE", exposure_level="NONE")
    assert det is not None


def test_the_database_refuses_an_unauthorised_exposure(conn, svc):
    import psycopg
    alice = _user(conn)
    s = svc.submit(_unique("dbboom"), submitted_by=alice)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO lab.detonation
                   (sample_id, target, exposure_level, requested_by)
               VALUES (%s, 'ANY_RUN', 'PUBLIC', %s)""", (s.id, alice))


def test_nothing_is_actually_submitted_anywhere(conn, svc):
    """docs/11: do not build a sandbox, integrate with one. What exists is
    the authorisation RECORD; there is no submission."""
    alice = _user(conn)
    s = svc.submit(_unique("norun"), submitted_by=alice)
    det_id = svc.request_detonation(s.id, requested_by=alice,
                                    target="PRIVATE_CAPE", exposure_level="NONE")
    row = conn.execute(
        "SELECT submitted_at, external_ref, report FROM lab.detonation "
        "WHERE id = %s", (det_id,)).fetchone()
    assert row[0] is None and row[1] is None and row[2] is None


# --- custody ------------------------------------------------------------

def test_every_touch_is_in_the_custody_ledger(conn, svc, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice, re_analyst = _user(conn), _user(conn)
    s = svc.submit(_unique("custody"), submitted_by=alice)
    svc.assign(s.id, analyst_id=re_analyst, actor_id=alice)
    svc.download(s.id, actor_id=re_analyst,
                 request_origin="https://samples.example", **CLEARED)
    actions = [row["action"] for row in svc.custody(s.id)]
    assert "DOWNLOADED" in actions and "ASSIGNED" in actions


def test_a_download_records_the_wrapper_it_left_in(conn, svc, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    alice = _user(conn)
    s = svc.submit(_unique("wrapper"), submitted_by=alice)
    svc.download(s.id, actor_id=alice, request_origin="https://samples.example", **CLEARED)
    row = next(r for r in svc.custody(s.id) if r["action"] == "DOWNLOADED")
    assert row["archive_format"] == "ZIP_INFECTED"


def test_the_custody_ledger_is_append_only(conn, svc):
    """"Who took a copy of a live binary" is not a question anybody may
    quietly re-answer."""
    import psycopg
    alice = _user(conn)
    s = svc.submit(_unique("append"), submitted_by=alice)
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE lab.sample_access SET action = 'VIEWED_META' "
                     "WHERE sample_id = %s", (s.id,))
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("DELETE FROM lab.sample_access WHERE sample_id = %s", (s.id,))


# --- the queue is labelled, like everything else ------------------------

def test_the_queue_is_filtered_by_the_callers_own_clearance(conn, svc):
    """A sample can be classified above its case, so a case-level gate
    alone would leak its existence."""
    alice = _user(conn)
    svc.submit(_unique("green"), submitted_by=alice, classification="GREEN")
    svc.submit(_unique("red"), submitted_by=alice, classification="RED")
    assert len(svc.queue(clearance="RED")) >= 2
    visible = svc.queue(clearance="GREEN")
    assert all(s.classification == "GREEN" for s in visible)


def test_a_compartmented_sample_is_invisible_without_the_compartment(conn, svc):
    alice = _user(conn)
    svc.submit(_unique("comp"), submitted_by=alice,
               compartments=frozenset({"OPERATION-X"}))
    assert not [s for s in svc.queue(clearance="RED")
                if "OPERATION-X" in s.compartments]
    assert [s for s in svc.queue(clearance="RED",
                                 compartments=frozenset({"OPERATION-X"}))
            if "OPERATION-X" in s.compartments]


# --- the role boundary --------------------------------------------------

def test_the_malware_analyst_role_grants_no_case_access(conn):
    """docs/11: the RE channel is a role, not a folder. Being trusted with
    hostile binaries is a different trust to being trusted with the case
    file, and conflating them is how a lab handoff becomes an
    access-control hole."""
    granted = {r[0] for r in conn.execute(
        "SELECT permission_key FROM iam.role_permission "
        "WHERE role_key = 'MALWARE_ANALYST'").fetchall()}
    assert "sample.download" in granted
    assert "case.read" not in granted
    assert "evidence.read" not in granted
    assert not any(p.startswith("graph.") for p in granted)


def test_case_roles_can_see_a_sample_but_not_download_it(conn):
    for role in ("CASE_OWNER", "ANALYST", "REVIEWER"):
        granted = {r[0] for r in conn.execute(
            "SELECT permission_key FROM iam.role_permission "
            "WHERE role_key = %s", (role,)).fetchall()}
        assert "sample.read" in granted
        assert "sample.download" not in granted, (
            f"{role} must not be able to take a copy of a live binary")


def test_downloading_a_sample_is_a_step_up_permission(conn):
    """The one action in the system that puts working malware on somebody's
    disk."""
    row = conn.execute(
        "SELECT requires_step_up FROM iam.permission WHERE key = %s",
        ("sample.download",)).fetchone()
    assert row[0] is True
