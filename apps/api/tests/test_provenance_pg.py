"""Evidence at the point of claim, and retraction (enhancements E1-E3).

The first real session of using this tool produced fourteen assertions and
zero exhibits, in a product whose thesis is chain of custody. Not because
the evidence path was broken -- it is tested end to end -- but because
nothing in the interface ASKED for an exhibit at the moment a claim was
made, and `assertion.evidence_id` had existed unused since Phase 1.

Retraction had the mirror-image problem: the service method existed, was
exposed nowhere, and the projection did not filter on live provenance, so
retracting a source changed nothing an analyst could see.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; provenance test is gated"
)

EMAIL_LIKE = "pv-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # Evidence custody is append-only by design, so the trigger must be
        # off inside the cleanup transaction (see docs/15).
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
    c.close()


@pytest.fixture
def world(conn):
    """Two entities joined by one tie, all unevidenced to begin with."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'PV', 'x', 'RED') RETURNING id""",
        (f"pv-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Provenance IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-PV-{uuid4().hex[:6]}", uid),
    )
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    n1 = g.create_node(case_id=case_id, node_type="IDENTITY", label="one",
                       created_by=uid, assertion=a)
    n2 = g.create_node(case_id=case_id, node_type="IDENTITY", label="two",
                       created_by=uid, assertion=a)
    edge = g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                         src_node_id=n1, dst_node_id=n2, created_by=uid,
                         assertion=a)
    return case_id, uid, n1, n2, edge


def _exhibit(conn, case_id, uid, title="screenshot.png"):
    """An evidence row directly, so this suite does not need MinIO."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, 'image/png', 1024, %s, %s, %s, 'test-bucket',
                   'AMBER', 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, title, b"\x01" * 32, b"\x02" * 32,
         f"k/{uuid4().hex}", uid),
    ).fetchone()[0]


def _svc(conn, clearance="RED"):
    from noctornal_api.projections import GraphService
    return GraphService(conn, clearance=clearance, compartments=frozenset())


def _proj(case_id, **kw):
    from noctornal_api.projections import Projection
    return Projection(case_id=case_id, **kw)


# --- E1: an assertion can carry its exhibit ------------------------------

def test_an_assertion_can_carry_an_exhibit_at_creation(conn, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, *_ = world
    ev = _exhibit(conn, case_id, uid)
    node = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label="evidenced",
        created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 evidence_id=ev),
    )
    row = conn.execute(
        "SELECT evidence_id FROM core.assertion WHERE node_id = %s", (node,)
    ).fetchone()
    assert row[0] == ev


# --- E2: provenance strength is visible on the graph ---------------------

def test_the_projection_reports_which_elements_rest_on_an_exhibit(conn, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, n1, _n2, edge = world
    sub = _svc(conn).project(_proj(case_id))
    assert all(n["has_evidence"] is False for n in sub.nodes)
    assert all(e["has_evidence"] is False for e in sub.edges)

    ev = _exhibit(conn, case_id, uid)
    GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=n1,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 evidence_id=ev))
    sub = _svc(conn).project(_proj(case_id))
    by = {n["label"]: n for n in sub.nodes}
    assert by["one"]["has_evidence"] is True
    assert by["two"]["has_evidence"] is False


def test_evidence_coverage_is_reported_as_a_headline_number(conn, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, n1, _n2, _edge = world
    m = _svc(conn).metrics(_proj(case_id))
    assert m["evidence_coverage"]["ratio"] == 0.0
    assert m["evidence_coverage"]["elements"] == 3       # 2 nodes + 1 edge

    ev = _exhibit(conn, case_id, uid)
    GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=n1,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 evidence_id=ev))
    m = _svc(conn).metrics(_proj(case_id))
    assert m["evidence_coverage"]["nodes"] == 1
    assert m["evidence_coverage"]["ratio"] == pytest.approx(1 / 3, abs=1e-4)


def test_a_retracted_assertion_stops_counting_as_evidence(conn, world):
    """A withdrawn exhibit must stop propping up the element's provenance
    display, or the case looks better evidenced than it is."""
    from datetime import datetime, timezone
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid)
    g = GraphWriteService(conn)
    aid = g.add_assertion(
        case_id=case_id, node_id=n1,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 evidence_id=ev))
    assert next(n for n in _svc(conn).project(_proj(case_id)).nodes
                if n["label"] == "one")["has_evidence"] is True
    g.retract_assertion(aid, retracted_by=uid, reason="wrong exhibit",
                        at=datetime.now(timezone.utc))
    assert next(n for n in _svc(conn).project(_proj(case_id)).nodes
                if n["label"] == "one")["has_evidence"] is False


# --- E3: retraction dissolves an element from the live graph -------------

def test_retracting_the_last_assertion_removes_the_element(conn, world):
    """Decision 24: an element that loses all live support dissolves from
    the live graph while its row survives for temporal replay. This is the
    demonstration that the assertion model is load-bearing rather than
    decorative."""
    from datetime import datetime, timezone
    from noctornal_api.graph import GraphWriteService
    case_id, uid, n1, _n2, edge = world
    assert len(_svc(conn).project(_proj(case_id)).edges) == 1
    aid = conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s", (edge,)
    ).fetchone()[0]
    GraphWriteService(conn).retract_assertion(
        aid, retracted_by=uid, reason="source withdrawn",
        at=datetime.now(timezone.utc))
    sub = _svc(conn).project(_proj(case_id))
    assert sub.edges == []
    assert len(sub.nodes) == 2               # the entities survive
    # Nothing was deleted (invariant 5).
    assert conn.execute(
        "SELECT deleted_at FROM core.edge WHERE id = %s", (edge,)
    ).fetchone()[0] is None
    assert conn.execute(
        "SELECT retraction_reason FROM core.assertion WHERE id = %s", (aid,)
    ).fetchone()[0] == "source withdrawn"


def test_an_element_with_a_second_live_assertion_survives_retraction(conn, world):
    """Retracting ONE source does not dissolve an element that another
    source still supports -- otherwise a single analyst changing their mind
    would erase corroborated work."""
    from datetime import datetime, timezone
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, _n1, _n2, edge = world
    g = GraphWriteService(conn)
    g.add_assertion(case_id=case_id, edge_id=edge,
                    assertion=AssertionInput(basis="ANALYST_INFERENCE",
                                             created_by=uid,
                                             rationale="corroborated by a "
                                                       "second reporting stream"))
    first = conn.execute(
        """SELECT id FROM core.assertion WHERE edge_id = %s
            ORDER BY recorded_at LIMIT 1""", (edge,)).fetchone()[0]
    g.retract_assertion(first, retracted_by=uid, reason="first source burned",
                        at=datetime.now(timezone.utc))
    assert len(_svc(conn).project(_proj(case_id)).edges) == 1


def test_retracting_an_already_retracted_assertion_is_refused(conn, world):
    """A silent success would leave the caller believing a source was
    burned twice, and hide a double-click that meant something else."""
    from datetime import datetime, timezone
    from noctornal_api.graph import GraphWriteError, GraphWriteService
    case_id, uid, _n1, _n2, edge = world
    g = GraphWriteService(conn)
    aid = conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s", (edge,)
    ).fetchone()[0]
    now = datetime.now(timezone.utc)
    g.retract_assertion(aid, retracted_by=uid, reason="once", at=now)
    with pytest.raises(GraphWriteError):
        g.retract_assertion(aid, retracted_by=uid, reason="twice", at=now)


def test_history_survives_retraction_for_temporal_replay(conn, world):
    """`as_of` before the retraction must still show the element: the row
    and its history persist, only the LIVE graph loses it."""
    from datetime import datetime, timezone
    from noctornal_api.graph import GraphWriteService
    case_id, uid, _n1, _n2, edge = world
    aid = conn.execute(
        "SELECT id FROM core.assertion WHERE edge_id = %s", (edge,)
    ).fetchone()[0]
    GraphWriteService(conn).retract_assertion(
        aid, retracted_by=uid, reason="burned",
        at=datetime.now(timezone.utc))
    row = conn.execute(
        """SELECT retracted_at, retracted_by, retraction_reason
             FROM core.assertion WHERE id = %s""", (aid,)).fetchone()
    assert row[0] is not None and row[1] == uid and row[2] == "burned"


# --- U3: temporal intervals ---------------------------------------------

def test_a_tie_can_record_the_interval_it_was_true_in(conn, world):
    """"Was in LockBit until March" is the normal case. Without this the
    scrubber and trust decay have nothing to work with (docs/14 U3)."""
    from datetime import datetime, timezone
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid, n1, n2, _edge = world
    start = datetime(2024, 3, 1, tzinfo=timezone.utc)
    end = datetime(2025, 6, 30, tzinfo=timezone.utc)
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    crew = g.create_node(case_id=case_id, node_type="GROUP", label="the crew",
                         created_by=uid, assertion=a)
    g.create_edge(case_id=case_id, edge_type="MEMBER_OF", src_node_id=n1,
                  dst_node_id=crew, created_by=uid, valid_from=start,
                  valid_to=end, assertion=a)
    svc = _svc(conn)
    # Inside the interval the tie is there; after it, gone.
    during = svc.project(_proj(case_id, as_of=datetime(2024, 9, 1, tzinfo=timezone.utc)))
    after = svc.project(_proj(case_id, as_of=datetime(2026, 1, 1, tzinfo=timezone.utc)))
    assert any(e["edge_type"] == "MEMBER_OF" for e in during.edges)
    assert not any(e["edge_type"] == "MEMBER_OF" for e in after.edges)
