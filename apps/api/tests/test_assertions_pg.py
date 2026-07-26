"""Invariant 1 — nothing is a fact (CONVENTIONS.md / docs/01).

The load-bearing tests are the two named test_invariant_1_*: a graph
element committed WITHOUT a supporting assertion must be rejected by the
database, by any path. These prove the deferred constraint trigger, so the
guarantee does not depend on every caller remembering to add an assertion.

Env-gated on DATABASE_URL (DB-level enforcement); skips otherwise.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; assertion-layer test is gated"
)

NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    # One transaction: the invariant-1 assertion trigger is deferred, so
    # deleting assertions and their nodes together lets the commit-time
    # check see the final state (both gone) rather than firing mid-cleanup.
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'a1-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'a1-%@noctornal.test'")
    c.close()


@pytest.fixture
def case(conn):
    """A user + case to hang graph elements on. Returns (case_id, user_id)."""
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash)
           VALUES (%s, 'A1', 'x') RETURNING id""",
        (f"a1-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Assertion IT', 'AMBER', %s, 'dev', '2027-01-01', '2026-12-01')""",
        (case_id, f"OP-A1-{uuid4().hex[:6]}", uid),
    )
    return case_id, uid


def _obs(uid: UUID):
    from noctornal_api.graph import AssertionInput
    return AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                          reliability="B", credibility="2")


# --- THE invariant-1 tests ---------------------------------------------

def test_invariant_1_node_write_requires_assertion(conn, case):
    """A node committed with no assertion is rejected at commit — this is
    invariant 1 enforced in the database, not just in the service."""
    case_id, uid = case
    with pytest.raises(psycopg.errors.CheckViolation, match="invariant 1"):
        with conn.transaction():
            conn.execute(
                """INSERT INTO core.node (case_id, node_type, label, created_by)
                   VALUES (%s, 'IDENTITY', 'orphan_persona', %s)""",
                (case_id, uid),
            )
    # And nothing was committed.
    assert conn.execute(
        "SELECT count(*) FROM core.node WHERE label = 'orphan_persona'"
    ).fetchone()[0] == 0


def test_invariant_1_edge_write_requires_assertion(conn, case):
    """An edge committed with no assertion is rejected at commit."""
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    svc = GraphWriteService(conn)
    a = svc.create_node(case_id=case_id, node_type="IDENTITY", label="a",
                        created_by=uid, assertion=_obs(uid))
    b = svc.create_node(case_id=case_id, node_type="GROUP", label="b",
                        created_by=uid, assertion=_obs(uid))
    with pytest.raises(psycopg.errors.CheckViolation, match="invariant 1"):
        with conn.transaction():
            conn.execute(
                """INSERT INTO core.edge (case_id, edge_type, src_node_id,
                       dst_node_id, created_by)
                   VALUES (%s, 'MEMBER_OF', %s, %s, %s)""",
                (case_id, a, b, uid),
            )
    assert conn.execute(
        "SELECT count(*) FROM core.edge WHERE src_node_id = %s", (a,)
    ).fetchone()[0] == 0


def test_invariant_1_deleting_last_assertion_rejected(conn, case):
    """Steady-state: once an element has its assertion, a later delete of
    that last assertion is rejected — the guarantee is not just at
    creation. (Closes the post-hoc-delete bypass.)"""
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    node_id = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label="sourced", created_by=uid,
        assertion=_obs(uid),
    )
    with pytest.raises(psycopg.errors.CheckViolation, match="last assertion for node"):
        with conn.transaction():
            conn.execute("DELETE FROM core.assertion WHERE node_id = %s", (node_id,))
    # The assertion survived the rejected delete.
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0] == 1


def test_invariant_1_set_constraints_immediate_bypass_closed(conn, case):
    """The SET CONSTRAINTS ALL IMMEDIATE timing game — fire the insert
    trigger early while the assertion exists, then delete it before commit
    — is closed by the symmetric assertion trigger."""
    case_id, uid = case
    node_id = uuid4()
    with pytest.raises(psycopg.errors.CheckViolation, match="invariant 1"):
        with conn.transaction():
            conn.execute(
                """INSERT INTO core.node (id, case_id, node_type, label, created_by)
                   VALUES (%s, %s, 'IDENTITY', 'sneaky', %s)""",
                (node_id, case_id, uid),
            )
            aid = conn.execute(
                """INSERT INTO core.assertion (case_id, node_id, basis, created_by)
                   VALUES (%s, %s, 'DIRECT_OBSERVATION', %s) RETURNING id""",
                (case_id, node_id, uid),
            ).fetchone()[0]
            conn.execute("SET CONSTRAINTS ALL IMMEDIATE")  # fire node trigger now
            conn.execute("DELETE FROM core.assertion WHERE id = %s", (aid,))
    assert conn.execute(
        "SELECT count(*) FROM core.node WHERE id = %s", (node_id,)
    ).fetchone()[0] == 0


# --- the sanctioned write path succeeds and is atomic ------------------

def test_create_node_with_assertion_succeeds(conn, case):
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    node_id = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label="bassterlord",
        created_by=uid, assertion=_obs(uid),
    )
    row = conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0]
    assert row == 1


def test_create_edge_with_assertion_and_default_sign(conn, case):
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    svc = GraphWriteService(conn)
    a = svc.create_node(case_id=case_id, node_type="IDENTITY", label="ripper",
                        created_by=uid, assertion=_obs(uid))
    b = svc.create_node(case_id=case_id, node_type="IDENTITY", label="victim",
                        created_by=uid, assertion=_obs(uid))
    # ACCUSED_SCAM has default_sign -1; created without an explicit sign.
    edge_id = svc.create_edge(
        case_id=case_id, edge_type="ACCUSED_SCAM", src_node_id=a, dst_node_id=b,
        created_by=uid, assertion=_obs(uid),
    )
    sign = conn.execute(
        "SELECT sign FROM core.edge WHERE id = %s", (edge_id,)
    ).fetchone()[0]
    assert sign == -1  # negative tie taken from the ontology
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE edge_id = %s", (edge_id,)
    ).fetchone()[0] == 1


def test_inference_without_rationale_rolls_back_whole_tx(conn, case):
    """A bad assertion (inference basis, no rationale) fails the CHECK and
    must take the node with it — no orphan node, atomicity holds."""
    from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
    case_id, uid = case
    bad = AssertionInput(basis="ANALYST_INFERENCE", created_by=uid, rationale=None)
    with pytest.raises(GraphWriteError):
        GraphWriteService(conn).create_node(
            case_id=case_id, node_type="IDENTITY", label="should_not_persist",
            created_by=uid, assertion=bad,
        )
    assert conn.execute(
        "SELECT count(*) FROM core.node WHERE label = 'should_not_persist'"
    ).fetchone()[0] == 0


def test_inference_with_rationale_succeeds(conn, case):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid = case
    a = AssertionInput(basis="ANALYST_INFERENCE", created_by=uid,
                       rationale="shared PGP key across both personas")
    node_id = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="PERSON", label="assessed", created_by=uid,
        assertion=a,
    )
    assert node_id is not None


def test_disagreement_two_assertions_on_one_node(conn, case):
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    svc = GraphWriteService(conn)
    node_id = svc.create_node(case_id=case_id, node_type="IDENTITY", label="x",
                              created_by=uid, assertion=_obs(uid))
    svc.add_assertion(case_id=case_id, node_id=node_id, assertion=_obs(uid))
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0] == 2


def test_retract_assertion_does_not_delete_node(conn, case):
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    svc = GraphWriteService(conn)
    node_id = svc.create_node(case_id=case_id, node_type="IDENTITY", label="y",
                              created_by=uid, assertion=_obs(uid))
    aid = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0]
    svc.retract_assertion(aid, retracted_by=uid, reason="source burned", at=NOW)
    retracted = conn.execute(
        "SELECT retracted_at FROM core.assertion WHERE id = %s", (aid,)
    ).fetchone()[0]
    assert retracted is not None
    # The node row still exists (retraction is projection-level, invariant 5).
    assert conn.execute(
        "SELECT count(*) FROM core.node WHERE id = %s", (node_id,)
    ).fetchone()[0] == 1


def test_retract_last_assertion_is_allowed(conn, case):
    """Retraction is row-preserving, so retracting even the SOLE assertion
    is allowed — the element dissolves from the live projection but its row
    and history survive (docs/01 retraction propagation). Trigger 2 must
    not block this."""
    from noctornal_api.graph import GraphWriteService
    case_id, uid = case
    svc = GraphWriteService(conn)
    node_id = svc.create_node(case_id=case_id, node_type="IDENTITY", label="z",
                              created_by=uid, assertion=_obs(uid))
    aid = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0]
    svc.retract_assertion(aid, retracted_by=uid, reason="source burned", at=NOW)
    # row still present (retracted), node still present, no live assertion.
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s "
        "AND retracted_at IS NULL", (node_id,)
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0] == 1


def test_retract_unknown_assertion_raises(conn, case):
    from noctornal_api.graph import GraphWriteError, GraphWriteService
    with pytest.raises(GraphWriteError, match="not found or already retracted"):
        GraphWriteService(conn).retract_assertion(
            uuid4(), retracted_by=case[1], reason="typo", at=NOW
        )


def test_ontology_still_enforced_on_service_writes(conn, case):
    """The write service does not bypass endpoint validation: an illegal
    edge is rejected and rolls back (no orphan, no assertion)."""
    from noctornal_api.graph import GraphWriteError, GraphWriteService
    case_id, uid = case
    svc = GraphWriteService(conn)
    grp = svc.create_node(case_id=case_id, node_type="GROUP", label="crew",
                          created_by=uid, assertion=_obs(uid))
    idn = svc.create_node(case_id=case_id, node_type="IDENTITY", label="member",
                          created_by=uid, assertion=_obs(uid))
    # VOUCHED_FOR is IDENTITY->IDENTITY; GROUP source is illegal.
    with pytest.raises(GraphWriteError):
        svc.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                        src_node_id=grp, dst_node_id=idn, created_by=uid,
                        assertion=_obs(uid))
