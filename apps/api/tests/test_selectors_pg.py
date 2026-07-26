"""Selector storage: per-type normalisation, exact-match lookup, and the
observation/candidate helpers (docs/09 Phase 1). Env-gated on DATABASE_URL.

The load-bearing property is normaliser parity: what the store writes as
norm_value is EXACTLY what noctornal_ontology.normalise produces, so the
DB join key and the ontology definition can never diverge.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; selector test is gated"
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'sel-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'sel-%@noctornal.test'")
    c.close()


@pytest.fixture
def case(conn):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash)
           VALUES (%s, 'Sel', 'x') RETURNING id""",
        (f"sel-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Selector IT', 'AMBER', %s, 'dev', '2027-01-01', '2026-12-01')""",
        (case_id, f"OP-SEL-{uuid4().hex[:6]}", uid),
    )
    return case_id, uid


def _node(conn, case_id, uid, label, node_type="IDENTITY"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type=node_type, label=label, created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
    )


def test_record_normalises_via_ontology(conn, case):
    from noctornal_api.selectors import SelectorStore
    from noctornal_ontology import normalise
    case_id, _ = case
    row = SelectorStore(conn).record(
        case_id=case_id, selector_type="TELEGRAM_USER", raw_value="@DarkVendor",
    )
    assert row.norm_value == normalise("TELEGRAM_USER", "@DarkVendor") == "darkvendor"


def test_same_normalised_value_upserts_and_counts(conn, case):
    from noctornal_api.selectors import SelectorStore
    case_id, _ = case
    store = SelectorStore(conn)
    r1 = store.record(case_id=case_id, selector_type="TELEGRAM_USER", raw_value="@Foo")
    r2 = store.record(case_id=case_id, selector_type="TELEGRAM_USER", raw_value="foo")
    assert r1.id == r2.id                 # '@Foo' and 'foo' normalise the same
    assert r2.observation_cnt == 2
    assert conn.execute(
        "SELECT count(*) FROM core.selector WHERE case_id = %s", (case_id,)
    ).fetchone()[0] == 1


def test_find_normalises_query(conn, case):
    from noctornal_api.selectors import SelectorStore
    case_id, _ = case
    store = SelectorStore(conn)
    store.record(case_id=case_id, selector_type="TOX_PK",
                 raw_value="56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE51855")
    # queried in lowercase → normaliser upper-cases → still matches
    found = store.find(case_id=case_id, selector_type="TOX_PK",
                       raw_value="56a1ade4b65b86bcd51cc73e2cd4e542179f47959fe3e0e21b4b0acdade51855")
    assert found is not None
    assert store.find(case_id=case_id, selector_type="TOX_PK", raw_value="dead") is None


def test_unknown_selector_type_raises(conn, case):
    from noctornal_api.selectors import SelectorError, SelectorStore
    case_id, _ = case
    with pytest.raises(SelectorError):
        SelectorStore(conn).record(case_id=case_id, selector_type="NOPE", raw_value="x")


def test_strong_selector_reattribution_is_a_merge_lead(conn, case):
    """Attributing a strong selector already owned by another node raises
    a conflict (the merge lead) instead of silently repointing (docs/01)."""
    from noctornal_api.selectors import SelectorOwnerConflict, SelectorStore
    case_id, uid = case
    store = SelectorStore(conn)
    n1 = _node(conn, case_id, uid, "persona_one")
    n2 = _node(conn, case_id, uid, "persona_two")
    fpr = "39D3 4C99 8672 8B1A 0AEB 1F2C A41F 9DC7 6F08 6F5B"
    row = store.record(case_id=case_id, selector_type="PGP_FPR", raw_value=fpr, node_id=n1)
    with pytest.raises(SelectorOwnerConflict) as exc:
        store.link_to_node(row.id, n2)
    assert exc.value.existing_owner == n1
    # A deliberate repoint is still possible.
    store.link_to_node(row.id, n2, force=True)
    assert store.find(case_id=case_id, selector_type="PGP_FPR",
                      raw_value=fpr).node_id == n2


def test_weak_selector_reattribution_is_silent(conn, case):
    """A shared nickname (HANDLE is weak) is not evidence — repointing it
    does not raise the merge conflict (the admin/support reuse trap)."""
    from noctornal_api.selectors import SelectorStore
    case_id, uid = case
    store = SelectorStore(conn)
    n1 = _node(conn, case_id, uid, "one")
    n2 = _node(conn, case_id, uid, "two")
    row = store.record(case_id=case_id, selector_type="HANDLE", raw_value="admin", node_id=n1)
    store.link_to_node(row.id, n2)  # no conflict for a weak selector
    assert store.find(case_id=case_id, selector_type="HANDLE",
                      raw_value="admin").node_id == n2


def test_pivot_only_over_allowed_cases(conn, case):
    """Cross-case pivot must never return a match in a case the caller was
    not cleared for — it only searches the allowed set."""
    from noctornal_api.selectors import SelectorStore
    case_a, uid = case
    # A second case owned by the same test user (cleaned up by the fixture).
    case_b = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'B', 'AMBER', %s, 'dev', '2027-01-01', '2026-12-01')""",
        (case_b, f"OP-SEL-{uuid4().hex[:6]}", uid),
    )
    store = SelectorStore(conn)
    addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    store.record(case_id=case_a, selector_type="BTC_ADDR", raw_value=addr)
    store.record(case_id=case_b, selector_type="BTC_ADDR", raw_value=addr)

    both = store.pivots(selector_type="BTC_ADDR", raw_value=addr,
                        allowed_case_ids=[case_a, case_b])
    assert {r.case_id for r in both} == {case_a, case_b}
    # Not cleared for case_b → it is invisible.
    only_a = store.pivots(selector_type="BTC_ADDR", raw_value=addr,
                         allowed_case_ids=[case_a])
    assert {r.case_id for r in only_a} == {case_a}
    assert store.pivots(selector_type="BTC_ADDR", raw_value=addr,
                       allowed_case_ids=[]) == []


def test_link_to_node_fills_owner(conn, case):
    from noctornal_api.selectors import SelectorStore
    case_id, uid = case
    store = SelectorStore(conn)
    node_id = _node(conn, case_id, uid, "owner")
    row = store.record(case_id=case_id, selector_type="JABBER", raw_value="x@dark.im")
    assert row.node_id is None
    store.link_to_node(row.id, node_id)
    assert store.find(case_id=case_id, selector_type="JABBER",
                      raw_value="x@dark.im").node_id == node_id
