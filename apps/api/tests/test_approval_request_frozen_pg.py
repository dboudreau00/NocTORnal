"""An approval request is fixed once raised, decided once, spent once (F9,
2026-09-24; migration approval_request_frozen).

`core.approval_request` carried CHECK constraints only, so nothing in the
database stopped a writer rewriting what a decided request asked for, who
decided it, or putting a spent approval back. The two-person policy reads
these rows from a trigger, and a trigger that trusts a row anybody could
rewrite checks nothing. Each test below writes the row directly, the way
something going around the service would, and expects the database to
refuse.

Email prefix `arf-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from datetime import date
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Json

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; approvals are gated")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


class _RollBack(Exception):
    pass


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'arf-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'arf-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"arf-{uuid4().hex[:8]}@noctornal.test", "Frozen", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-ARF-{uuid4().hex[:6]}", title="Frozen approvals",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _payload():
    return {"source_node_id": str(uuid4()), "target_node_id": str(uuid4()),
            "reason": "same fingerprint", "basis_selector_id": None}


def _request(conn):
    from noctornal_api.approvals import ApprovalService
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = ApprovalService(conn).request(
        operation="node.merge", case_id=case_id, payload=payload,
        justification="two handles, one fingerprint", requested_by=alice)
    return req, alice, bob, case_id, payload


def _approved(conn):
    from noctornal_api.approvals import ApprovalService
    req, alice, bob, case_id, payload = _request(conn)
    ApprovalService(conn).decide(req.id, decided_by=bob, approve=True)
    return req, alice, bob, case_id, payload


def _refused(conn, sql, params, match):
    with pytest.raises(psycopg.errors.RaiseException, match=match):
        conn.execute(sql, params)


def test_a_request_is_created_pending_and_undecided(conn):
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    insert = """INSERT INTO core.approval_request
                    (case_id, operation, payload, payload_hash, justification,
                     requested_by, expires_at, state, decided_by, decided_at,
                     consumed_at, result_ref)
                VALUES (%s, 'node.merge', %s, %s, 'j', %s,
                        now() + interval '1 hour', %s, %s, %s, %s, %s)"""
    digest = hashlib.sha256(b"x").digest()
    for state, decided_by, decided, consumed, result in (
            ("APPROVED", bob, True, False, None),
            ("PENDING", None, False, True, None),
            ("PENDING", None, False, False, uuid4())):
        with pytest.raises(psycopg.errors.RaiseException,
                           match="created pending and undecided"):
            conn.execute(insert, (
                case_id, Json(_payload()), digest, alice, state, decided_by,
                "2026-01-01" if decided else None,
                "2026-01-01" if consumed else None, result))


def test_what_was_asked_for_cannot_be_rewritten(conn):
    pending, *_ = _request(conn)
    approved, alice, bob, case_id, _ = _approved(conn)
    other = _case(conn, alice)
    for row in (pending, approved):
        for column, value in (
                ("payload", Json(_payload())),
                ("payload_hash", hashlib.sha256(b"other").digest()),
                ("operation", "evidence.purge"),
                ("case_id", other),
                ("requested_by", bob),
                ("justification", "something else entirely")):
            _refused(conn,
                     f"UPDATE core.approval_request SET {column} = %s WHERE id = %s",
                     (value, row.id), "fixed when it is raised")


def test_a_decision_is_made_once(conn):
    approved, alice, bob, _, _ = _approved(conn)
    carol = _user(conn)
    _refused(conn, "UPDATE core.approval_request SET state = 'REJECTED' "
             "WHERE id = %s", (approved.id,), "never back")
    _refused(conn, "UPDATE core.approval_request SET decided_by = %s "
             "WHERE id = %s", (carol, approved.id), "made once")
    _refused(conn, "UPDATE core.approval_request SET decision_note = 'later' "
             "WHERE id = %s", (approved.id,), "made once")
    from noctornal_api.approvals import ApprovalService
    rejected, *_ = _request(conn)
    ApprovalService(conn).decide(rejected.id, decided_by=bob, approve=False)
    _refused(conn, "UPDATE core.approval_request SET state = 'APPROVED' "
             "WHERE id = %s", (rejected.id,), "never back")


def test_a_back_dated_decision_is_refused(conn):
    """The ledger measures the countersigner's window back from
    `decided_at`, so it must be the database's clock (2026-09-24)."""
    req, alice, bob, _, _ = _request(conn)
    _refused(conn, """UPDATE core.approval_request
                         SET state = 'APPROVED', decided_by = %s,
                             decided_at = now() - interval '8 days'
                       WHERE id = %s""", (bob, req.id), "time it is made")
    conn.execute("""UPDATE core.approval_request
                       SET state = 'APPROVED', decided_by = %s, decided_at = now()
                     WHERE id = %s""", (bob, req.id))


def test_a_spent_approval_stays_spent(conn):
    from noctornal_api.approvals import ApprovalService
    approved, alice, _, case_id, payload = _approved(conn)
    ApprovalService(conn).consume(approved.id, actor_id=alice,
                                  operation="node.merge", case_id=case_id,
                                  payload=payload)
    _refused(conn, "UPDATE core.approval_request SET state = 'APPROVED', "
             "consumed_at = NULL WHERE id = %s", (approved.id,), "never back")
    _refused(conn, "UPDATE core.approval_request SET consumed_at = now() - "
             "interval '1 hour' WHERE id = %s", (approved.id,), "spent once")
    fresh, alice2, _, case2, payload2 = _approved(conn)
    _refused(conn, """UPDATE core.approval_request
                         SET state = 'CONSUMED',
                             consumed_at = now() - interval '1 hour'
                       WHERE id = %s""", (fresh.id,), "time it is used")


def test_expiry_only_moves_earlier(conn):
    req, *_ = _request(conn)
    _refused(conn, "UPDATE core.approval_request SET expires_at = expires_at "
             "+ interval '1 day' WHERE id = %s", (req.id,), "never gains time")
    _refused(conn, "UPDATE core.approval_request SET requested_at = "
             "requested_at + interval '1 minute' WHERE id = %s", (req.id,),
             "never gains time")
    # Earlier is allowed: the expiry tests in test_approvals_pg rely on it.
    conn.execute("""UPDATE core.approval_request
                       SET requested_at = now() - interval '2 hours',
                           expires_at = now() - interval '1 hour'
                     WHERE id = %s""", (req.id,))


def test_the_result_is_recorded_once_after_consumption(conn):
    from noctornal_api.approvals import ApprovalService
    approved, alice, _, case_id, payload = _approved(conn)
    _refused(conn, "UPDATE core.approval_request SET result_ref = %s "
             "WHERE id = %s", (uuid4(), approved.id), "recorded once")
    svc = ApprovalService(conn)
    svc.consume(approved.id, actor_id=alice, operation="node.merge",
                case_id=case_id, payload=payload)
    first = uuid4()
    svc.attach_result(approved.id, first)
    _refused(conn, "UPDATE core.approval_request SET result_ref = %s "
             "WHERE id = %s", (uuid4(), approved.id), "recorded once")
    # The service's own second attempt is logged, never raised: the
    # operation it follows has already happened.
    svc.attach_result(approved.id, uuid4())
    assert svc.get(approved.id).result_ref == first


def test_the_service_lifecycle_still_works(conn):
    from noctornal_api.approvals import ApprovalService
    svc = ApprovalService(conn)
    approved, alice, bob, case_id, payload = _approved(conn)
    assert approved.state == "PENDING"
    done = svc.consume(approved.id, actor_id=alice, operation="node.merge",
                       case_id=case_id, payload=payload)
    assert done.state == "CONSUMED"
    svc.attach_result(approved.id, uuid4())
    withdrawn, *_ = _request(conn)
    assert svc.withdraw(withdrawn.id, actor_id=withdrawn.requested_by).state \
        == "WITHDRAWN"
    decided = svc.get(approved.id)
    assert decided.decided_by == bob and decided.decided_at is not None


def _migration(conn):
    path = next(VERSIONS.glob("*_approval_request_frozen.py"))
    spec = importlib.util.spec_from_file_location("m_arf", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def test_the_migration_round_trips(conn):
    m = _migration(conn)
    req, *_ = _request(conn)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        # With the guard gone the rewrite goes through, which is what the
        # guard is for.
        conn.execute("UPDATE core.approval_request SET justification = 'x' "
                     "WHERE id = %s", (req.id,))
        m.upgrade()
        with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
            conn.execute("UPDATE core.approval_request SET justification = 'y' "
                         "WHERE id = %s", (req.id,))
        raise _RollBack
