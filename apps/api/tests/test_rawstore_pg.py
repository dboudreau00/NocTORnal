"""Raw-before-parse, which was aspirational until now.

docs/12: "`accept()` writes the raw bytes and returns 202 before anything
is parsed. When the parser is wrong -- and it will be -- you re-parse from
the original rather than asking a partner to resend three months of feed."

`IngestService` took a `storage` argument, every construction in the router
passed `None`, and `accept()` skipped the write **silently**. The batch row
recorded a `raw_key` pointing at nothing. Found while writing down the
dead-letter redactor's claim that the verbatim bytes remain in the batch's
raw object, and then checking whether that was true. It was not.

Env-gated on DATABASE_URL. Uses the in-memory store rather than MinIO: the
behaviour under test is the refusal, the round trip and the digest check,
none of which need a network service.
"""
from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; rawstore tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

from noctornal_api.ingest import IngestError, IngestService  # noqa: E402
from noctornal_api.rawstore import (  # noqa: E402
    InMemoryRawStorage,
    MissingObject,
    raw_key,
)

EMAIL_LIKE = "raw-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f" WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    return PgUserStore(conn).create_user(
        f"raw-{uuid4().hex[:8]}@noctornal.test", "Raw", "x" * 20)


def _key(svc, owner):
    return svc.authenticate(
        svc.issue_key(name="raw feed", owner_user_id=owner).secret)


PAYLOAD = json.dumps({"indicator": "1.2.3.4", "type": "ipv4"}).encode()


def test_accept_refuses_rather_than_acknowledging_and_dropping(conn):
    """The defect. A 202 with no stored bytes tells the partner their
    submission was accepted, leaves `parse` with nothing to read, and the
    loss is discovered months later by somebody trying to re-parse.

    docs/12's "raw before parse, always" is not satisfied by recording that
    we meant to.
    """
    owner = _user(conn)
    svc = IngestService(conn)          # no storage
    key = _key(svc, owner)
    with pytest.raises(IngestError, match="acknowledged and dropped"):
        svc.accept(key, PAYLOAD)
    assert conn.execute(
        "SELECT count(*) FROM ingest.batch WHERE api_key_id = %s",
        (key["id"],)).fetchone()[0] == 0, (
        "a refused accept must not leave a batch row behind")


def test_the_bytes_come_back_exactly(conn):
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    key = _key(svc, owner)
    batch = svc.accept(key, PAYLOAD)
    assert svc.raw_for(batch.batch_id) == PAYLOAD


def test_the_key_is_content_addressed_so_a_resend_costs_nothing(conn):
    """A partner replaying the same batch overwrites itself rather than
    accumulating copies."""
    owner = _user(conn)
    storage = InMemoryRawStorage()
    svc = IngestService(conn, storage)
    key = _key(svc, owner)
    svc.accept(key, PAYLOAD)
    svc.accept(key, PAYLOAD)
    assert storage.get(raw_key(PAYLOAD)) == PAYLOAD


def test_a_swapped_object_is_refused_not_parsed(conn):
    """Re-parsing something that is not what arrived attributes records to
    a submission that never happened."""
    owner = _user(conn)
    storage = InMemoryRawStorage()
    svc = IngestService(conn, storage)
    key = _key(svc, owner)
    batch = svc.accept(key, PAYLOAD)
    stored_key = conn.execute(
        "SELECT raw_key FROM ingest.batch WHERE id = %s",
        (batch.batch_id,)).fetchone()[0]
    storage.put(stored_key, b'{"indicator": "9.9.9.9", "type": "ipv4"}')
    with pytest.raises(IngestError, match="does not match the digest"):
        svc.raw_for(batch.batch_id)


def test_a_batch_with_no_object_says_so_rather_than_parsing_nothing(conn):
    """An empty payload parses to zero records and marks the batch PARSED,
    silently losing it -- invariant 12 failing on the path built to catch
    loss. This is the state of every batch accepted before storage was
    wired, so the error names the only repair: ask the partner to resend.
    """
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    key = _key(svc, owner)
    batch = svc.accept(key, PAYLOAD)
    conn.execute("UPDATE ingest.batch SET raw_key = %s WHERE id = %s",
                 ("ingest/00/never-stored", batch.batch_id))
    with pytest.raises(MissingObject, match="has to resend"):
        svc.raw_for(batch.batch_id)


def test_the_raw_store_is_not_the_evidence_store():
    """Three differences, and each one matters -- see the module docstring.

    The one with teeth is object lock: `EvidenceStorage` writes with
    COMPLIANCE-mode retention, which not even root can delete before the
    deadline. On a stealer-log feed with a 90-day category clock that would
    make an over-retained credential dump undeletable by anybody, including
    in response to a deletion order (decision 50).
    """
    import inspect

    from noctornal_api.evidence import EvidenceStorage
    from noctornal_api.rawstore import RawBatchStorage
    raw_put = inspect.signature(RawBatchStorage.put).parameters
    ev_put = inspect.signature(EvidenceStorage.put).parameters
    assert "retain_until" in ev_put, "the exhibit store locks objects"
    assert "retain_until" not in raw_put, (
        "a raw batch must NOT be written under an object lock that would "
        "refuse a lawful deletion")
    assert "retention" not in inspect.getsource(RawBatchStorage.put)
