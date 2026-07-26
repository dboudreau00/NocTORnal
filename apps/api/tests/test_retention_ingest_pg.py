"""The ingest retention clock, which until 2026-07-25 nothing read.

docs/17 F17(a). `ingest.record.retain_until` has carried a clock since
migration 0033 and `ingest.dead_letter.retain_until` since 0040.
`RetentionService.due()` queried `core.evidence` and `collect.document`
and nothing else, so both clocks ticked and nothing ever expired.

That is worse than it sounds. The 90-day dead-letter default was chosen
*because* unassessed third-party victim data deserves the shortest rule —
and a clock nobody reads delivers the longest possible rule instead. The
labels and the gating shipped; the expiry did not.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; retention tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

from noctornal_api.ingest import IngestService  # noqa: E402
from noctornal_api.rawstore import InMemoryRawStorage  # noqa: E402
from noctornal_api.retention import RetentionService  # noqa: E402

EMAIL_LIKE = "rti-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {bsub})")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f" WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        # A case that was PURGED cannot be deleted, and that is correct
        # rather than inconvenient: `core.purge_tombstone` has a foreign key
        # to the case and an append-only trigger, so the record of a
        # destruction outlives everything it refers to. Deleting the case
        # would make "we destroyed 40 records from that feed on this date"
        # unanswerable, which is the one question a tombstone exists for.
        #
        # So teardown removes only the cases nothing was destroyed in, and
        # leaves the rest. Any future test that purges will hit this too.
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f'AND id NOT IN (SELECT case_id FROM core.purge_tombstone '
                  f'                WHERE case_id IS NOT NULL)')
        # Same reasoning for the actor: `purge_tombstone.purged_by` names
        # who destroyed the material, and a destruction whose actor can be
        # deleted is an unattributed one.
        c.execute(
            f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}' "
            f'AND id NOT IN (SELECT owner_user_id FROM core."case") '
            f"AND id NOT IN (SELECT purged_by FROM core.purge_tombstone)")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"rti-{uuid4().hex[:8]}@noctornal.test", "Rti", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED', "
                 "compartments = %s WHERE id = %s", (["STEALER-2026"], uid))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-RTI-{uuid4().hex[:6]}", title="Rti",
        legal_basis="production order", retention_until=date(2029, 1, 1),
        review_due=date(2028, 1, 1), owner_user_id=owner, created_by=owner)


def _expired_record(conn, svc, owner, case_id=None):
    key = svc.authenticate(svc.issue_key(
        name="rti feed", owner_user_id=owner,
        declared_category="STEALER_LOG",
        forced_compartment="STEALER-2026").secret)
    raw = json.dumps({"passwords": [], "cookies": [], "autofill": [],
                      "machine_id": uuid4().hex}).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    conn.execute(
        "UPDATE ingest.record SET retain_until = %s WHERE id = %s",
        (datetime.now(timezone.utc) - timedelta(days=1), record_id))
    return record_id


def test_an_expired_ingest_record_is_actually_due(conn):
    """The whole finding. It carried a clock and nothing read it."""
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    case_id = _case(conn, owner)
    record_id = _expired_record(conn, svc, owner, case_id)

    due = RetentionService(conn).due(case_id=case_id)
    mine = [d for d in due if d.object_id == record_id]
    assert mine, "an expired ingest record must appear in the sweep"
    assert mine[0].object_type == "ingest_record"


def test_purging_a_record_destroys_its_credentials_too(conn):
    """Destroying the payload and leaving the credential it named would be
    the worst possible half-measure: the context goes and the secret
    stays."""
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    case_id = _case(conn, owner)
    record_id = _expired_record(conn, svc, owner, case_id)
    svc.store_credential(record_id, kind="PASSWORD", value="hunter2",
                         service_domain="bank.example")

    result = RetentionService(conn).purge_due(
        actor_id=owner, authority="scheduled retention run",
        case_id=case_id)
    assert result.records_purged == 1
    row = conn.execute(
        "SELECT purged_at, payload FROM ingest.record WHERE id = %s",
        (record_id,)).fetchone()
    assert row[0] is not None
    assert row[1] == {}, "the payload goes; the row stays"
    assert conn.execute(
        "SELECT count(*) FROM ingest.victim_credential WHERE record_id = %s",
        (record_id,)).fetchone()[0] == 0


def test_a_case_legal_hold_reaches_ingest_records(conn):
    """A hold that stopped at the schema boundary would be a hold with a
    gap in it — and the ingest side is the material most likely to be the
    subject of one."""
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    case_id = _case(conn, owner)
    record_id = _expired_record(conn, svc, owner, case_id)
    conn.execute(
        'UPDATE core."case" SET legal_hold = true, '
        "legal_hold_reason = 'production order 2026-0009' WHERE id = %s",
        (case_id,))

    svc_r = RetentionService(conn)
    due = [d for d in svc_r.due(case_id=case_id) if d.object_id == record_id]
    assert due and due[0].held is True

    result = svc_r.purge_due(actor_id=owner, authority="scheduled run",
                             case_id=case_id)
    assert result.records_purged == 0
    assert result.held_back >= 1
    assert conn.execute(
        "SELECT purged_at FROM ingest.record WHERE id = %s",
        (record_id,)).fetchone()[0] is None


def test_an_expired_dead_letter_can_be_purged_even_if_it_predates_0040(conn):
    """Migration 0040's `CHECK (redacted) NOT VALID` is re-evaluated on
    every UPDATE, so a pre-redactor row would otherwise be the ONE thing a
    purge cannot destroy — the unredacted victim credentials becoming the
    only permanent rows in the table. The purge sets `redacted = true` in
    the same statement that replaces the fragment."""
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    key = svc.authenticate(svc.issue_key(
        name="rti broken feed", owner_user_id=owner).secret)
    raw = b"{not json at all"
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    dead_id = conn.execute(
        "SELECT id FROM ingest.dead_letter WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    conn.execute(
        "UPDATE ingest.dead_letter SET retain_until = %s WHERE id = %s",
        (datetime.now(timezone.utc) - timedelta(days=1), dead_id))
    # Putting the row back into the pre-redactor state needs the constraint
    # off, because `NOT VALID` does not exempt UPDATES — which is the whole
    # finding this test exists for. Dropping and restoring it around the
    # setup is the only way to construct a grandfathered row at all, and
    # the fact that it is the only way is the point.
    conn.execute("ALTER TABLE ingest.dead_letter "
                 "DROP CONSTRAINT dead_letter_new_rows_are_redacted")
    try:
        conn.execute("UPDATE ingest.dead_letter SET redacted = false "
                     "WHERE id = %s", (dead_id,))
    finally:
        conn.execute("ALTER TABLE ingest.dead_letter ADD CONSTRAINT "
                     "dead_letter_new_rows_are_redacted "
                     "CHECK (redacted) NOT VALID")

    result = RetentionService(conn).purge_due(
        actor_id=owner, authority="scheduled retention run")
    assert result.dead_letters_purged >= 1
    row = conn.execute(
        "SELECT purged_at, raw_fragment, redacted FROM ingest.dead_letter "
        "WHERE id = %s", (dead_id,)).fetchone()
    assert row[0] is not None
    assert row[1] == "[purged on retention]"
    assert row[2] is True


def test_a_dead_letter_is_not_swept_by_a_case_scoped_purge(conn):
    """Dead letters have no case, so no case hold can reach them. Including
    them in every case's sweep would mean the first case-scoped purge of
    the week destroys the whole deployment's queue."""
    owner = _user(conn)
    svc = IngestService(conn, InMemoryRawStorage())
    case_id = _case(conn, owner)
    key = svc.authenticate(svc.issue_key(
        name="rti broken feed", owner_user_id=owner).secret)
    raw = b"{not json at all"
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    conn.execute(
        "UPDATE ingest.dead_letter SET retain_until = %s WHERE batch_id = %s",
        (datetime.now(timezone.utc) - timedelta(days=1), batch.batch_id))

    result = RetentionService(conn).purge_due(
        actor_id=owner, authority="scheduled run", case_id=case_id)
    assert result.dead_letters_purged == 0
