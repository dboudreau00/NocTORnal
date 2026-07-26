"""The Phase 8 criticals from the first adversarial pass, 2026-07-26.

Phase 8 had never been reviewed. Six hostile lenses, then a refutation
round, produced nine CRITICAL findings under 1108 passing tests — with two
distinct root causes:

  1. **`download()` applied no label check of any kind.** Not the sample's
     classification, not its compartments, not its case's. `queue()`
     filters and `detail()` 404s, so the same caller was told the sample
     did not exist and handed its bytes one request later — on the one
     path in the system that puts working malware on somebody's disk.

  2. **The "encrypted archive" was a plain ZIP.** Python's `zipfile`
     cannot write encrypted entries (`setpassword` is decrypt-only), so
     `ARCHIVE_PASSWORD` was defined, exported and referenced by nothing.
     The entry carried flag bits 0x0000 and opened with no prompt, while
     the archive comment and a response header both told the analyst a
     password protected it.

Both are fixed. These tests are the reason they cannot come back.

Env-gated on DATABASE_URL for the ones that need it; the archive tests are
pure and always run.
"""
from __future__ import annotations

import io
import os
import zipfile
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

from noctornal_api.samples import (  # noqa: E402
    ARCHIVE_PASSWORD,
    SampleError,
    SampleService,
    archive,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")


# ---------------------------------------------------------------------------
# The archive. Pure — no database, no gate.
# ---------------------------------------------------------------------------

def _open(blob: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(blob))


PAYLOAD = b"MZ\x90\x00" + b"LIVE-MALWARE-BODY-HERE" * 200


def test_the_archive_entry_is_actually_encrypted():
    """Flag bit 0. The old one carried 0x0000 while claiming otherwise."""
    info = _open(archive(PAYLOAD, "ab" * 32)).infolist()[0]
    assert info.flag_bits & 0x1, "the encryption bit must be set"
    # Bit 3 (data descriptor) must NOT be set: with it, the password check
    # byte comes from the mod-time rather than the CRC and readers
    # disagree about which.
    assert not info.flag_bits & 0x8, "no data descriptor"
    assert info.compress_type == zipfile.ZIP_DEFLATED


def test_the_archive_cannot_be_opened_without_the_password():
    """The interlock. A live binary must not come out of a file manager on
    a double-click."""
    zf = _open(archive(PAYLOAD, "ab" * 32))
    with pytest.raises(RuntimeError, match="password required"):
        zf.read(zf.namelist()[0])


def test_a_wrong_password_is_refused():
    """The 12-byte header's last byte is the high byte of the CRC, which is
    how a reader recognises a wrong password. Getting that field wrong
    produces an archive that 'works' and silently yields garbage."""
    zf = _open(archive(PAYLOAD, "ab" * 32))
    zf.setpassword(b"not-the-password")
    with pytest.raises(RuntimeError, match="[Bb]ad password"):
        zf.read(zf.namelist()[0])


def test_the_right_password_returns_the_exact_bytes():
    """Round-tripped through Python's OWN decryptor, which is the
    strongest available check that this is the real format rather than a
    plausible-looking one: the reader is somebody else's code and does not
    know what the writer intended."""
    zf = _open(archive(PAYLOAD, "ab" * 32))
    zf.setpassword(ARCHIVE_PASSWORD)
    assert zf.read(zf.namelist()[0]) == PAYLOAD
    # testzip() verifies the CRC over the DECRYPTED stream.
    assert zf.testzip() is None


def test_the_entry_is_named_for_its_hash_not_its_filename():
    """The original name is attacker-controlled and the archive is the
    last place it should reappear."""
    digest = "cd" * 32
    assert _open(archive(PAYLOAD, digest)).namelist() == [f"{digest}.bin"]


def test_the_comment_still_says_the_password_is_not_confidentiality():
    """The commonest mistake with this convention is treating it as
    protection. Now that the encryption is real, that warning matters
    MORE, not less — ZipCrypto is broken and the password is printed in a
    response header."""
    comment = _open(archive(PAYLOAD, "ab" * 32)).comment.decode()
    assert "NO confidentiality" in comment
    assert "infected" in comment


# ---------------------------------------------------------------------------
# The download gate. Needs a database.
# ---------------------------------------------------------------------------

pg = pytest.mark.skipif(not DATABASE_URL,
                        reason="DATABASE_URL not set; sample gate tests gated")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


class _MemStore:
    """Storage is injected precisely so the quarantine path is provable
    without a bucket full of live malware."""

    bucket = "noctornal-samples"

    def __init__(self):
        self.objects = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


@pytest.fixture
def policy(monkeypatch):
    """Sample ingest refuses until a policy is DECLARED. That refusal is
    the whole reason this phase was blocked, so the fixture declares one
    rather than the code skipping the check."""
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "TEST-POLICY-1")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "test designated person")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")


def _submit(conn, store, *, classification="AMBER", compartments=frozenset(),
            case_id=None):
    from noctornal_api.stores import PgUserStore
    who = PgUserStore(conn).create_user(
        f"shp-{uuid4().hex[:8]}@noctornal.test", "Shp", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (who,))
    sample = SampleService(conn, store).submit(
        # Unique per call. `submit()` deduplicates on content — two
        # analysts finding the same binary is a finding about the actors,
        # not a reason for two copies of live malware — so a fixed payload
        # makes the second test in a run fail on the first one's row.
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=who, case_id=case_id,
        original_filename="x.bin", classification=classification,
        compartments=compartments)
    return sample.id, who


def _cleanup(conn, sample_id, *user_ids, case_id=None):
    """Remove what can be removed, and leave what must not be.

    `lab.sample_access` is APPEND-ONLY — a trigger raises on DELETE, and
    docs/11 wants exactly that: a custody ledger you can prune is not one.
    So a test that downloads a sample cannot delete the sample (the ledger
    references it), nor the actor (the ledger names them). The rows stay,
    and that is the system working rather than a leak.

    Third instance of this shape today: `core.purge_tombstone` does the
    same for a destruction, and `audit.event` for everything. Append-only
    records outlive their subject BY DESIGN, and any teardown that assumes
    otherwise fails on a foreign key pointing at a table the test never
    touched.
    """
    held = conn.execute(
        "SELECT count(*) FROM lab.sample_access WHERE sample_id = %s",
        (sample_id,)).fetchone()[0]
    if not held:
        conn.execute("DELETE FROM lab.sample WHERE id = %s", (sample_id,))
    if case_id and not held:
        conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s",
                     (case_id,))
        conn.execute('DELETE FROM core."case" WHERE id = %s', (case_id,))
    if not held:
        for user_id in user_ids:
            conn.execute("DELETE FROM iam.app_user WHERE id = %s", (user_id,))


@pg
def test_download_refuses_to_guess_at_a_clearance(conn):
    """Defaulting would make every caller that forgets silently maximally
    privileged — which is exactly how this path came to have no label
    check at all. `SampleService.queue` still defaults `clearance="RED"`,
    which is the same failure waiting to happen; download does not."""
    svc = SampleService(conn)
    with pytest.raises(SampleError, match="needs the caller's clearance"):
        svc.download(uuid4(), actor_id=uuid4(), request_origin="https://x",
                     clearance=None)


@pg
def test_an_over_classified_sample_does_not_exist_to_the_downloader(
        conn, policy):
    """The critical, in one test.

    `detail()` 404s an over-classified sample and `download()` used to
    hand the same caller its bytes one request later. The answer is now
    the same on both paths, and it is "no such sample" rather than a
    refusal — a status code must not be an existence oracle for a
    compartmented case.
    """
    store = _MemStore()
    sample_id, who = _submit(conn, store, classification="RED",
                             compartments=frozenset({"OP-KESTREL"}))
    try:
        svc = SampleService(conn, store)
        # Below the classification.
        with pytest.raises(SampleError, match="no such sample"):
            svc.download(sample_id, actor_id=who,
                         request_origin="https://samples.example",
                         clearance="GREEN", compartments=frozenset())
        # Cleared, but not read into the compartment.
        with pytest.raises(SampleError, match="no such sample"):
            svc.download(sample_id, actor_id=who,
                         request_origin="https://samples.example",
                         clearance="RED", compartments=frozenset())
        # And the caller who IS cleared still gets the bytes — closing the
        # hole by refusing everybody would be its own defect.
        blob, digest = svc.download(
            sample_id, actor_id=who,
            request_origin="https://samples.example",
            clearance="RED", compartments=frozenset({"OP-KESTREL"}))
        assert blob and digest
    finally:
        _cleanup(conn, sample_id, who)


@pg
def test_a_case_raises_a_samples_effective_labels(conn, policy):
    """`lab.sample` has no `enforce_tlp_floor` trigger — unlike node, edge
    and evidence — and the router's `classification` defaults to AMBER. So
    a sample submitted into a RED case sits at AMBER with nothing to catch
    it, and the case's labels have to be composed at read time or they are
    never applied at all.
    """
    from datetime import date

    from noctornal_api.cases import CaseService
    from noctornal_api.stores import PgUserStore
    owner = PgUserStore(conn).create_user(
        f"shp-{uuid4().hex[:8]}@noctornal.test", "Shp", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (owner,))
    case_id = CaseService(conn).create(
        code=f"OP-SHP-{uuid4().hex[:6]}", title="Shp",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification="RED")
    store = _MemStore()
    sample_id, who = _submit(conn, store, classification="AMBER",
                             case_id=case_id)
    try:
        svc = SampleService(conn, store)
        # AMBER clearance passes the SAMPLE's own label and must still be
        # refused, because the case is RED.
        with pytest.raises(SampleError, match="no such sample"):
            svc.download(sample_id, actor_id=owner,
                         request_origin="https://samples.example",
                         clearance="AMBER", compartments=frozenset())
        blob, _digest = svc.download(
            sample_id, actor_id=owner,
            request_origin="https://samples.example",
            clearance="RED", compartments=frozenset())
        assert blob
    finally:
        _cleanup(conn, sample_id, who, owner, case_id=case_id)
