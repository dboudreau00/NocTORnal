"""The custody log names a person (README screenshot review, 2026-09-23).

The Evidence pane's custody log is the answer to "who touched this
exhibit, and when", and it answered the first half with an eight-hex id:
"ACQUIRED 2026-09-23 15:28 UTC, actor fcfd6f27". `custody_log` now joins
the account and returns its display name beside the id, which stays.

Everything is created inside a transaction that is rolled back, the idiom
`test_custody_verify_pg.py` uses for the same ledger: custody rows cannot
be deleted (the triggers block it), so nothing is committed and no
teardown is needed. Inserted directly rather than through
`EvidenceService.ingest`, so no MinIO is involved.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="needs a migrated database")


@pytest.fixture()
def conn():
    import psycopg

    from noctornal_api.db import dsn

    c = psycopg.connect(dsn())
    try:
        yield c
    finally:
        c.rollback()
        c.close()


def _exhibit(conn, display_name: str):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, %s, 'x', 'RED') RETURNING id""",
        (f"can-{uuid4().hex[:8]}@noctornal.test", display_name),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Custody names IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-CAN-{uuid4().hex[:6]}", uid),
    )
    evidence_id = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'names.eml', 'message/rfc822', 1024, %s, %s, %s,
                   'test-bucket', 'AMBER', 'MANUAL_UPLOAD', now(), %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"can/{uuid4().hex}", uid),
    ).fetchone()[0]
    return evidence_id, uid, case_id


def test_the_custody_log_names_the_actor(conn):
    from noctornal_api.evidence import EvidenceService

    evidence_id, uid, _ = _exhibit(conn, "Demo Analyst")
    svc = EvidenceService(conn, storage=None)
    svc._custody(evidence_id, "ACQUIRED", uid, hash_verified=True)
    svc._custody(evidence_id, "VIEWED", uid)

    log = svc.custody_log(evidence_id)
    assert [e.action for e in log] == ["ACQUIRED", "VIEWED"]
    assert {e.actor_name for e in log} == {"Demo Analyst"}, (
        "the log must say who, not only which id")
    assert {e.actor_id for e in log} == {uid}, "the id stays beside the name"


def test_the_custody_route_passes_the_name_through(conn):
    """The route builds `CustodyOut` field by field, so a name the service
    returns and the route drops would never reach the console. Called as
    the route, through its own gate: an analyst assigned to the case reads
    the log and gets the name."""
    from datetime import datetime, timezone

    from noctornal_api.evidence import EvidenceService
    from noctornal_api.http.deps import CurrentUser
    from noctornal_api.http.routers import evidence as route

    evidence_id, uid, case_id = _exhibit(conn, "Second Analyst")
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, 'ANALYST')",
                 (uid,))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, uid, uid))
    EvidenceService(conn, storage=None)._custody(evidence_id, "VIEWED", uid)

    user = CurrentUser(user_id=uid, session_id=uuid4(),
                       session_mfa_at=datetime.now(timezone.utc))
    out = route.custody(case_id, evidence_id, user=user, conn=conn)
    assert [(o.action, o.actor_id, o.actor_name) for o in out] == [
        ("VIEWED", str(uid), "Second Analyst")]
    assert out[0].model_dump()["actor_name"] == "Second Analyst"
