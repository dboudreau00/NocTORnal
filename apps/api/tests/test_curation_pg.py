"""Tags, node sets, and full-text search (docs/09 Phase 1).
Env-gated on DATABASE_URL (and MINIO for evidence search)."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; curation test is gated"
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'cur-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    with c.transaction():
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.tag_assignment WHERE evidence_id IN {esub} "
                  f"OR node_id IN (SELECT id FROM core.node WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.tag WHERE case_id IN {csub}")
        # Global tags (case_id IS NULL) are outside the case-scoped sweep,
        # so remove the ones this suite creates by their test namespace.
        c.execute("DELETE FROM core.tag WHERE case_id IS NULL AND namespace LIKE 'test-%'")
        c.execute(f"DELETE FROM core.node_set_member WHERE set_id IN "
                  f"(SELECT id FROM core.node_set WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.node_set WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'cur-%@noctornal.test'")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
    c.close()


@pytest.fixture
def case(conn):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'Cur', 'x', 'RED') RETURNING id""",
        (f"cur-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Curation IT', 'AMBER', %s, 'dev', '2027-01-01', '2026-12-01')""",
        (case_id, f"OP-CUR-{uuid4().hex[:6]}", uid),
    )
    return case_id, uid


def _node(conn, case_id, uid, label, node_type="IDENTITY"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type=node_type, label=label, created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
    )


# --- tags ---------------------------------------------------------------

def test_create_and_assign_tag_to_node(conn, case):
    from noctornal_api.curation import TagService
    case_id, uid = case
    svc = TagService(conn)
    tag = svc.create_tag(namespace="ttp", name="phishing", case_id=case_id,
                         external_id="T1566")
    node = _node(conn, case_id, uid, "actor")
    svc.assign(tag, assigned_by=uid, node_id=node)
    assert ("ttp", "phishing") in svc.tags_on_node(node)


def test_duplicate_tag_rejected(conn, case):
    from noctornal_api.curation import CurationError, TagService
    case_id, _ = case
    svc = TagService(conn)
    svc.create_tag(namespace="role", name="broker", case_id=case_id)
    with pytest.raises(CurationError, match="already exists"):
        svc.create_tag(namespace="role", name="broker", case_id=case_id)


def test_global_and_case_tag_coexist(conn, case):
    """A global taxonomy entry and a case entry with the same name coexist
    (two separate partial unique indexes)."""
    from noctornal_api.curation import TagService
    case_id, _ = case
    svc = TagService(conn)
    # Unique per run: a GLOBAL tag has no case_id, so the fixture's
    # case-scoped cleanup cannot remove it — the name must not collide with
    # a previous run, and the teardown deletes the 'test-%' namespace.
    ns = f"test-{uuid4().hex[:8]}"
    g = svc.create_tag(namespace=ns, name="T1566", case_id=None)
    c = svc.create_tag(namespace=ns, name="T1566", case_id=case_id)
    assert g != c


def test_tag_assign_requires_one_target(conn, case):
    from noctornal_api.curation import CurationError, TagService
    case_id, uid = case
    svc = TagService(conn)
    tag = svc.create_tag(namespace="x", name="y", case_id=case_id)
    with pytest.raises(CurationError, match="exactly one"):
        svc.assign(tag, assigned_by=uid)  # no target


# --- node sets ----------------------------------------------------------

def test_node_set_membership(conn, case):
    from noctornal_api.curation import NodeSetService
    case_id, uid = case
    svc = NodeSetService(conn)
    s = svc.create_set(case_id=case_id, name="watchlist", created_by=uid, is_pinned=True)
    n1 = _node(conn, case_id, uid, "one")
    n2 = _node(conn, case_id, uid, "two")
    svc.add_member(s, n1, note="prime suspect")
    svc.add_member(s, n2)
    assert set(svc.members(s)) == {n1, n2}
    svc.remove_member(s, n2)
    assert svc.members(s) == [n1]


# --- search -------------------------------------------------------------

def test_node_full_text_search(conn, case):
    from noctornal_api.curation import SearchService
    case_id, uid = case
    _node(conn, case_id, uid, "bassterlord the broker")
    _node(conn, case_id, uid, "unrelated persona")
    hits = SearchService(conn).search_nodes(
        case_id=case_id, query="broker", clearance="RED", compartments=frozenset())
    labels = [h.label for h in hits]
    assert "bassterlord the broker" in labels
    assert "unrelated persona" not in labels


def test_soft_deleted_nodes_excluded_from_search(conn, case):
    from noctornal_api.curation import SearchService
    case_id, uid = case
    n = _node(conn, case_id, uid, "ghost broker")
    conn.execute("UPDATE core.node SET deleted_at = now() WHERE id = %s", (n,))
    hits = SearchService(conn).search_nodes(
        case_id=case_id, query="ghost", clearance="RED", compartments=frozenset())
    assert n not in [h.id for h in hits]


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required for evidence search")
def test_evidence_full_text_search(conn, case):
    from noctornal_api.curation import SearchService
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    case_id, uid = case
    ev = EvidenceService(conn, EvidenceStorage())
    ev.ingest(case_id=case_id, title="ransom note transcript", media_type="text/plain",
              data=b"content-" + uuid4().hex.encode(), acquired_by=uid,
              acquisition_method="MANUAL_UPLOAD", description="LockBit negotiation")
    hits = SearchService(conn).search_evidence(
        case_id=case_id, query="ransom", clearance="RED", compartments=frozenset())
    assert any("ransom" in h.label for h in hits)
