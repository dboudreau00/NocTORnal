"""Evidence: WORM ingest, hashing, chain of custody, linking (docs/09
Phase 1). Env-gated on DATABASE_URL and MINIO_ENDPOINT — needs the compose
stack (Postgres + MinIO with the object-locked evidence bucket) up.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and MINIO),
    reason="DATABASE_URL and MINIO_ENDPOINT required; evidence test is gated",
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    # Evidence + custody are WORM/append-only by design, so cleanup must
    # briefly disable the custody trigger (the test role owns the table).
    # audit.event rows carry no case FK and are meant to persist — left in.
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ev-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    with c.transaction():
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ev-%@noctornal.test'")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
    c.close()


@pytest.fixture
def case(conn):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash)
           VALUES (%s, 'Ev', 'x') RETURNING id""",
        (f"ev-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Evidence IT', 'AMBER', %s, 'dev', '2027-01-01', '2026-12-01')""",
        (case_id, f"OP-EV-{uuid4().hex[:6]}", uid),
    )
    return case_id, uid


@pytest.fixture
def svc(conn):
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    return EvidenceService(conn, EvidenceStorage())


def _ingest(svc, case_id, uid, data=b"exhibit-bytes", title="screenshot.png"):
    return svc.ingest(case_id=case_id, title=title, media_type="image/png",
                      data=data, acquired_by=uid, acquisition_method="MANUAL_UPLOAD")


def test_ingest_hashes_and_stores_and_records_custody(conn, case, svc):
    import hashlib
    case_id, uid = case
    data = b"the-original-bytes-" + uuid4().hex.encode()
    res = _ingest(svc, case_id, uid, data)
    assert res.sha256_hex == hashlib.sha256(data).hexdigest()
    assert res.deduplicated is False
    # evidence row carries the hash and is worm-flagged
    row = conn.execute(
        "SELECT sha256, is_worm_locked, byte_size FROM core.evidence WHERE id=%s",
        (res.evidence_id,),
    ).fetchone()
    assert bytes(row[0]).hex() == res.sha256_hex and row[1] is True and row[2] == len(data)
    # custody has an ACQUIRED entry
    log = svc.custody_log(res.evidence_id)
    assert [e.action for e in log] == ["ACQUIRED"]


def test_view_returns_original_bytes_and_logs_access(conn, case, svc):
    case_id, uid = case
    data = b"view-me-" + uuid4().hex.encode()
    res = _ingest(svc, case_id, uid, data)
    got = svc.view(res.evidence_id, uid)
    assert got == data                       # round-trips through WORM store
    assert "VIEWED" in [e.action for e in svc.custody_log(res.evidence_id)]


def test_integrity_verification_passes_for_untampered(conn, case, svc):
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"integrity-" + uuid4().hex.encode())
    assert svc.verify_integrity(res.evidence_id, uid) is True
    log = svc.custody_log(res.evidence_id)
    hv = [e for e in log if e.action == "HASH_VERIFIED"]
    assert hv and hv[-1].hash_verified is True


def test_integrity_verification_detects_hash_mismatch(conn, case, svc):
    """If the stored hash no longer matches the bytes, verification fails
    and records hash_verified=false — the tamper alarm."""
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"will-corrupt-" + uuid4().hex.encode())
    conn.execute("UPDATE core.evidence SET sha256 = %s WHERE id = %s",
                 (b"\x00" * 32, res.evidence_id))
    assert svc.verify_integrity(res.evidence_id, uid) is False
    hv = [e for e in svc.custody_log(res.evidence_id) if e.action == "HASH_VERIFIED"]
    assert hv[-1].hash_verified is False


def test_dual_hash_blake3_stored_and_checked(conn, case, svc):
    import blake3
    case_id, uid = case
    data = b"dual-hash-" + uuid4().hex.encode()
    res = _ingest(svc, case_id, uid, data)
    stored = conn.execute(
        "SELECT blake3 FROM core.evidence WHERE id = %s", (res.evidence_id,)
    ).fetchone()[0]
    assert bytes(stored) == blake3.blake3(data).digest()


def test_read_path_detects_object_tampering(conn, case, svc):
    """The real gap the review found: a swapped object VERSION must not be
    served with a clean custody entry. view() recomputes and fails closed."""
    from noctornal_api.evidence import IntegrityError
    case_id, uid = case
    import io
    data = b"pristine-" + uuid4().hex.encode()
    res = _ingest(svc, case_id, uid, data)
    key = conn.execute(
        "SELECT storage_key FROM core.evidence WHERE id = %s", (res.evidence_id,)
    ).fetchone()[0]
    # Swap the object's latest version with different bytes (object lock
    # protects old versions from deletion, not the key from new versions).
    tampered = b"TAMPERED-" + uuid4().hex.encode()
    svc._s._client.put_object(svc._s.bucket, key, io.BytesIO(tampered),
                              length=len(tampered))
    with pytest.raises(IntegrityError):
        svc.view(res.evidence_id, uid)
    # The read raised an integrity alarm in the custody ledger.
    hv = [e for e in svc.custody_log(res.evidence_id) if e.action == "HASH_VERIFIED"]
    assert hv and hv[-1].hash_verified is False


def test_export_refuses_red_classification(conn, case, svc):
    """Invariant 8: RED evidence may not cross the boundary via export."""
    case_id, uid = case
    conn.execute("UPDATE core.\"case\" SET classification='RED' WHERE id=%s", (case_id,))
    res = svc.ingest(case_id=case_id, title="secret", media_type="text/plain",
                     data=b"red-" + uuid4().hex.encode(), acquired_by=uid,
                     acquisition_method="MANUAL_UPLOAD", classification="RED")
    with pytest.raises(Exception, match="invariant 8"):
        svc.export(res.evidence_id, uid)


def test_custody_occurred_at_is_server_pinned(conn, case, svc):
    """A back-dated custody INSERT is overridden to now() by the trigger."""
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"pin-" + uuid4().hex.encode())
    conn.execute(
        """INSERT INTO core.evidence_custody (evidence_id, action, actor_id, occurred_at)
           VALUES (%s, 'VIEWED', %s, '2001-01-01T00:00:00Z')""",
        (res.evidence_id, uid),
    )
    earliest = conn.execute(
        "SELECT min(occurred_at) FROM core.evidence_custody WHERE evidence_id=%s",
        (res.evidence_id,),
    ).fetchone()[0]
    assert earliest.year >= 2026  # the 2001 back-date did not take


def test_custody_actor_must_exist(conn, case, svc):
    """A custody entry cannot name a non-existent actor (FK)."""
    import psycopg
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"fk-" + uuid4().hex.encode())
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with conn.transaction():
            conn.execute(
                "INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
                "VALUES (%s, 'VIEWED', %s)", (res.evidence_id, uuid4()),
            )


def test_custody_is_hash_chained(conn, case, svc):
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"chain-" + uuid4().hex.encode())
    svc.view(res.evidence_id, uid)
    rows = conn.execute(
        "SELECT prev_hash, row_hash FROM core.evidence_custody "
        "WHERE evidence_id=%s ORDER BY id", (res.evidence_id,)
    ).fetchall()
    assert all(r[1] is not None for r in rows)  # every row is hashed
    # the VIEWED row commits to the ACQUIRED row's hash
    assert bytes(rows[1][0]) == bytes(rows[0][1])


def test_dedup_still_records_custody(conn, case, svc):
    case_id, uid = case
    data = b"dedup-custody-" + uuid4().hex.encode()
    a = _ingest(svc, case_id, uid, data)
    svc.ingest(case_id=case_id, title="again", media_type="image/png", data=data,
               acquired_by=uid, acquisition_method="COLLECTOR")
    actions = [e.action for e in svc.custody_log(a.evidence_id)]
    assert actions.count("ACQUIRED") == 2  # re-acquisition left a trail


def test_dedup_same_bytes_same_case(conn, case, svc):
    case_id, uid = case
    data = b"identical-" + uuid4().hex.encode()
    a = _ingest(svc, case_id, uid, data)
    b = _ingest(svc, case_id, uid, data)
    assert b.deduplicated is True and b.evidence_id == a.evidence_id
    assert conn.execute(
        "SELECT count(*) FROM core.evidence WHERE sha256 = %s AND case_id = %s",
        (bytes.fromhex(a.sha256_hex), case_id),
    ).fetchone()[0] == 1


def test_custody_ledger_is_append_only(conn, case, svc):
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"append-only-" + uuid4().hex.encode())
    import psycopg
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        with conn.transaction():
            conn.execute("UPDATE core.evidence_custody SET action='FORGED' "
                         "WHERE evidence_id=%s", (res.evidence_id,))
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        with conn.transaction():
            conn.execute("DELETE FROM core.evidence_custody WHERE evidence_id=%s",
                         (res.evidence_id,))


def test_actions_reach_the_audit_chain(conn, case, svc):
    case_id, uid = case
    res = _ingest(svc, case_id, uid, b"audited-" + uuid4().hex.encode())
    svc.view(res.evidence_id, uid)
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s ORDER BY seq",
        (res.evidence_id,),
    ).fetchall()]
    assert "EVIDENCE_ACQUIRED" in actions and "EVIDENCE_VIEWED" in actions


def test_link_evidence_to_node_and_edge(conn, case, svc):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid = case
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    n1 = g.create_node(case_id=case_id, node_type="IDENTITY", label="a", created_by=uid, assertion=a)
    n2 = g.create_node(case_id=case_id, node_type="GROUP", label="b", created_by=uid, assertion=a)
    edge = g.create_edge(case_id=case_id, edge_type="MEMBER_OF", src_node_id=n1,
                         dst_node_id=n2, created_by=uid, assertion=a)
    res = _ingest(svc, case_id, uid, b"linked-" + uuid4().hex.encode())
    svc.link_to_node(evidence_id=res.evidence_id, node_id=n1, created_by=uid,
                     relevance="depicts the persona")
    svc.link_to_edge(evidence_id=res.evidence_id, edge_id=edge, created_by=uid)
    assert conn.execute(
        "SELECT count(*) FROM core.evidence_link WHERE evidence_id = %s",
        (res.evidence_id,),
    ).fetchone()[0] == 2
