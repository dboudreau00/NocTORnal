"""Case CRUD: mandatory governance, atomic owner grant, validated status
lifecycle, audited mutations (docs/09 Phase 1). Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; case test is gated"
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'cs-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'cs-%@noctornal.test'")
    c.close()


@pytest.fixture
def users(conn):
    def mk(name, clearance="AMBER"):
        return conn.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
               VALUES (%s, %s, 'x', %s) RETURNING id""",
            (f"cs-{uuid4().hex[:8]}@noctornal.test", name, clearance),
        ).fetchone()[0]
    return mk


@pytest.fixture
def svc(conn):
    from noctornal_api.cases import CaseService
    return CaseService(conn)


def _create(svc, owner, code=None):
    return svc.create(
        code=code or f"OP-CS-{uuid4().hex[:6]}", title="Operation Kestrel",
        legal_basis="production order 2026-0042", retention_until=date(2028, 1, 1),
        review_due=date(2027, 6, 1), owner_user_id=owner, created_by=owner,
    )


def test_create_grants_owner_case_access(conn, svc, users):
    owner = users("Owner")
    case_id = _create(svc, owner)
    # the owner has a CASE_OWNER assignment in the same transaction
    role = conn.execute(
        "SELECT role_key FROM iam.case_assignment WHERE case_id=%s AND user_id=%s",
        (case_id, owner),
    ).fetchone()
    assert role[0] == "CASE_OWNER"
    assert svc.get(case_id).status == "DRAFT"


def test_create_is_audited(conn, svc, users):
    owner = users("Owner")
    case_id = _create(svc, owner)
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id=%s ORDER BY seq", (case_id,)
    ).fetchall()]
    assert "CASE_CREATED" in actions


def test_owner_can_act_via_the_access_gate(conn, svc, users):
    """End-to-end: after create, the five-part gate lets the owner create
    an edge on their own case (verb + relationship both satisfied)."""
    from noctornal_api.security.access import evaluate
    from noctornal_api.stores import PgAccessResolver
    owner = users("Owner")
    case_id = _create(svc, owner)
    ctx = PgAccessResolver(conn).resolve(
        user_id=owner, case_id=case_id, permission_key="graph.edge.create",
        object_classification="AMBER", object_compartments=frozenset(),
        mfa_satisfied_at=None,
    )
    assert evaluate(ctx).allowed


def test_under_cleared_owner_rejected(svc, users):
    """An owner cleared below the case classification is refused at
    creation (they could never see their own case)."""
    from noctornal_api.cases import CaseError
    green_owner = users("Owner", clearance="GREEN")
    with pytest.raises(CaseError, match="clearance"):
        svc.create(code=f"OP-CS-{uuid4().hex[:6]}", title="x", legal_basis="ok",
                   retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
                   owner_user_id=green_owner, created_by=green_owner,
                   classification="AMBER")


def test_missing_legal_basis_rejected(svc, users):
    from noctornal_api.cases import CaseError
    owner = users("Owner")
    with pytest.raises(CaseError, match="lawful basis"):
        svc.create(code=f"OP-CS-{uuid4().hex[:6]}", title="x", legal_basis="  ",
                   retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
                   owner_user_id=owner, created_by=owner)


def test_review_after_retention_rejected(svc, users):
    from noctornal_api.cases import CaseError
    owner = users("Owner")
    with pytest.raises(CaseError, match="review_due"):
        svc.create(code=f"OP-CS-{uuid4().hex[:6]}", title="x", legal_basis="ok",
                   retention_until=date(2027, 1, 1), review_due=date(2028, 1, 1),
                   owner_user_id=owner, created_by=owner)


def test_duplicate_code_rejected(svc, users):
    from noctornal_api.cases import CaseError
    owner = users("Owner")
    code = f"OP-CS-{uuid4().hex[:6]}"
    _create(svc, owner, code=code)
    with pytest.raises(CaseError, match="already in use"):
        _create(svc, owner, code=code)


def test_status_lifecycle_valid_path(conn, svc, users):
    owner = users("Owner")
    case_id = _create(svc, owner)
    svc.transition_status(case_id, "ACTIVE", actor_id=owner)
    svc.transition_status(case_id, "DORMANT", actor_id=owner)
    svc.transition_status(case_id, "ACTIVE", actor_id=owner)
    svc.transition_status(case_id, "CLOSED", actor_id=owner)
    row = svc.get(case_id)
    assert row.status == "CLOSED" and row.closed_at is not None


def test_illegal_status_transition_rejected(svc, users):
    from noctornal_api.cases import CaseError
    owner = users("Owner")
    case_id = _create(svc, owner)  # DRAFT
    with pytest.raises(CaseError, match="illegal status transition"):
        svc.transition_status(case_id, "PURGED", actor_id=owner)  # DRAFT -> PURGED


def test_assign_and_revoke_user(conn, svc, users):
    owner, analyst = users("Owner"), users("Analyst")
    case_id = _create(svc, owner)
    svc.assign_user(case_id, analyst, "ANALYST", granted_by=owner)
    assert conn.execute(
        "SELECT role_key FROM iam.case_assignment WHERE case_id=%s AND user_id=%s",
        (case_id, analyst),
    ).fetchone()[0] == "ANALYST"
    svc.revoke_user(case_id, analyst, revoked_by=owner)
    assert conn.execute(
        "SELECT count(*) FROM iam.case_assignment WHERE case_id=%s AND user_id=%s",
        (case_id, analyst),
    ).fetchone()[0] == 0


def test_cannot_revoke_owner(svc, users):
    from noctornal_api.cases import CaseError
    owner = users("Owner")
    case_id = _create(svc, owner)
    with pytest.raises(CaseError, match="owner"):
        svc.revoke_user(case_id, owner, revoked_by=owner)


def test_list_for_user(svc, users):
    owner, analyst = users("Owner"), users("Analyst")
    c1 = _create(svc, owner)
    c2 = _create(svc, owner)
    svc.assign_user(c1, analyst, "ANALYST", granted_by=owner)
    mine = {c.id for c in svc.list_for_user(analyst)}
    assert mine == {c1} and c2 not in mine


def test_metadata_update_is_audited(conn, svc, users):
    owner = users("Owner")
    case_id = _create(svc, owner)
    svc.update_metadata(case_id, updated_by=owner, title="Renamed Op",
                        authority_ref="warrant 99")
    assert svc.get(case_id).title == "Renamed Op"
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id=%s", (case_id,)
    ).fetchall()]
    assert "CASE_UPDATED" in actions
