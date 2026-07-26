"""Reversible entity merge (docs/01 "Entity resolution", Phase 6).

docs/01: "Merging is the operation most likely to quietly corrupt a case."
So the tests are mostly about the corruption paths: a merge that cannot be
undone, a merge that crosses the persona/person boundary, a merge that
strands an edge, and a merge that happens twice.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; merge test is gated"
)

EMAIL_LIKE = "mg-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"""DELETE FROM core.node_merge_edge WHERE merge_id IN
                      (SELECT id FROM core.node_merge WHERE case_id IN {csub})""")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def world(conn):
    """Two personas that will turn out to be one actor, each with a tie to
    a third party, plus a tie BETWEEN them (the awkward case)."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'MG', 'x', 'RED') RETURNING id""",
        (f"mg-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Merge IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-MG-{uuid4().hex[:6]}", uid),
    )
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    ids = {k: g.create_node(case_id=case_id, node_type="IDENTITY", label=k,
                            created_by=uid, assertion=a)
           for k in ("alpha", "alpha_alt", "witness")}
    edges = {
        "a_w": g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                             src_node_id=ids["alpha"], dst_node_id=ids["witness"],
                             created_by=uid, assertion=a),
        "alt_w": g.create_edge(case_id=case_id, edge_type="COMMUNICATES_WITH",
                               src_node_id=ids["alpha_alt"],
                               dst_node_id=ids["witness"],
                               created_by=uid, assertion=a),
        "between": g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                                 src_node_id=ids["alpha_alt"],
                                 dst_node_id=ids["alpha"],
                                 created_by=uid, assertion=a),
    }
    return case_id, uid, ids, edges


def _svc(conn):
    from noctornal_api.merges import MergeService
    return MergeService(conn)


def _edge(conn, edge_id):
    return conn.execute(
        "SELECT src_node_id, dst_node_id, deleted_at FROM core.edge WHERE id = %s",
        (edge_id,)).fetchone()


def _visible(conn, case_id):
    from noctornal_api.projections import GraphService, Projection
    svc = GraphService(conn, clearance="RED", compartments=frozenset())
    return svc.project(Projection(case_id=case_id, preset="all"))


# --- the merge -----------------------------------------------------------

def test_a_merge_repoints_edges_and_hides_the_losing_node(conn, world):
    case_id, uid, ids, edges = world
    rec = _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                           target_node_id=ids["alpha"], merged_by=uid,
                           reason="same PGP fingerprint on both handles")
    assert rec.is_live and rec.edges_repointed == 2
    # The tie alpha_alt -> witness now runs from alpha.
    src, dst, deleted = _edge(conn, edges["alt_w"])
    assert src == ids["alpha"] and dst == ids["witness"] and deleted is None
    # The losing node still exists, with a redirect.
    row = conn.execute(
        "SELECT merged_into_id, merged_by FROM core.node WHERE id = %s",
        (ids["alpha_alt"],)).fetchone()
    assert row[0] == ids["alpha"] and row[1] == uid
    # And it is gone from the live graph.
    sub = _visible(conn, case_id)
    assert ids["alpha_alt"] not in sub.node_ids()
    assert ids["alpha"] in sub.node_ids()


def test_a_tie_between_the_merged_pair_does_not_become_a_self_loop(conn, world):
    """It would violate core.edge's own check constraint, and an actor
    vouching for themselves means nothing anyway."""
    case_id, uid, ids, edges = world
    _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                     target_node_id=ids["alpha"], merged_by=uid,
                     reason="same fingerprint")
    _src, _dst, deleted = _edge(conn, edges["between"])
    assert deleted is not None
    assert all(e["src_node_id"] != e["dst_node_id"]
               for e in _visible(conn, case_id).edges)


def test_the_merged_actor_keeps_both_sets_of_ties(conn, world):
    """The point of merging: one actor with the union of what both handles
    were seen doing."""
    case_id, uid, ids, _edges = world
    _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                     target_node_id=ids["alpha"], merged_by=uid,
                     reason="same fingerprint")
    types = {e["edge_type"] for e in _visible(conn, case_id).edges
             if e["src_node_id"] == ids["alpha"]}
    assert types == {"VOUCHED_FOR", "COMMUNICATES_WITH"}


# --- the reversal --------------------------------------------------------

def test_a_merge_can_be_undone_exactly(conn, world):
    """Reversal is a RESTORE, not a re-derivation. Working out where an
    edge "should" go after the fact is guesswork, and guesswork is what
    made the merge wrong in the first place."""
    case_id, uid, ids, edges = world
    before = {k: _edge(conn, v)[:2] for k, v in edges.items()}
    svc = _svc(conn)
    rec = svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                    target_node_id=ids["alpha"], merged_by=uid,
                    reason="same fingerprint")
    undone = svc.unmerge(rec.id, reversed_by=uid,
                         reason="the fingerprint was on a shared paste")
    assert not undone.is_live
    after = {k: _edge(conn, v)[:2] for k, v in edges.items()}
    assert after == before
    # The between-tie is live again.
    assert _edge(conn, edges["between"])[2] is None
    # And the node is back in the graph.
    assert ids["alpha_alt"] in _visible(conn, case_id).node_ids()
    assert conn.execute(
        "SELECT merged_into_id FROM core.node WHERE id = %s",
        (ids["alpha_alt"],)).fetchone()[0] is None


def test_a_reversed_merge_stays_in_the_history(conn, world):
    """A reversed merge that vanished would hide the fact that somebody
    once believed these were the same actor."""
    case_id, uid, ids, _edges = world
    svc = _svc(conn)
    rec = svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                    target_node_id=ids["alpha"], merged_by=uid,
                    reason="same fingerprint")
    svc.unmerge(rec.id, reversed_by=uid, reason="coincidence")
    history = svc.history(case_id)
    assert len(history) == 1
    assert history[0].reversal_reason == "coincidence"
    assert history[0].reason == "same fingerprint"


def test_a_merge_cannot_be_reversed_twice(conn, world):
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    svc = _svc(conn)
    rec = svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                    target_node_id=ids["alpha"], merged_by=uid, reason="x")
    svc.unmerge(rec.id, reversed_by=uid, reason="y")
    with pytest.raises(MergeError, match="already been reversed"):
        svc.unmerge(rec.id, reversed_by=uid, reason="z")


def test_a_node_can_be_merged_again_after_a_reversal(conn, world):
    """The unique index is on LIVE merges only, so a corrected call is not
    blocked by a withdrawn one."""
    case_id, uid, ids, _edges = world
    svc = _svc(conn)
    first = svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                      target_node_id=ids["alpha"], merged_by=uid, reason="x")
    svc.unmerge(first.id, reversed_by=uid, reason="wrong target")
    second = svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                       target_node_id=ids["witness"], merged_by=uid,
                       reason="right target this time")
    assert second.is_live
    assert len(svc.history(case_id)) == 2


# --- the corruption paths ------------------------------------------------

def test_a_persona_cannot_be_merged_into_a_person(conn, world):
    """Invariant 2. Saying a handle IS a human is an attribution carrying a
    confidence, not an assertion that the two records always described the
    same thing."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    person = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="PERSON", label="assessed human",
        created_by=uid,
        assertion=AssertionInput(basis="ANALYST_INFERENCE", created_by=uid,
                                 rationale="assessed from several sources"))
    with pytest.raises(MergeError, match="ATTRIBUTED_TO"):
        _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha"],
                         target_node_id=person, merged_by=uid,
                         reason="looks like the same guy")


def test_types_must_match(conn, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    wallet = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="WALLET", label="bc1qexample",
        created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid))
    with pytest.raises(MergeError, match="cannot merge"):
        _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha"],
                         target_node_id=wallet, merged_by=uid, reason="x")


def test_a_merge_must_say_why(conn, world):
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    with pytest.raises(MergeError, match="must say why"):
        _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                         target_node_id=ids["alpha"], merged_by=uid, reason="  ")


def test_a_node_cannot_be_merged_into_itself(conn, world):
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    with pytest.raises(MergeError, match="into itself"):
        _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha"],
                         target_node_id=ids["alpha"], merged_by=uid, reason="x")


def test_an_already_merged_node_cannot_be_merged_again(conn, world):
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    svc = _svc(conn)
    svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
              target_node_id=ids["alpha"], merged_by=uid, reason="x")
    with pytest.raises(MergeError, match="already merged away"):
        svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                  target_node_id=ids["witness"], merged_by=uid, reason="y")


def test_cannot_merge_into_a_node_that_is_itself_merged_away(conn, world):
    """It would build a redirect chain nothing resolves, and since the
    projection drops merged nodes the result is an actor that vanished."""
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    svc = _svc(conn)
    svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
              target_node_id=ids["alpha"], merged_by=uid, reason="x")
    with pytest.raises(MergeError, match="merge into the surviving node"):
        svc.merge(case_id=case_id, source_node_id=ids["witness"],
                  target_node_id=ids["alpha_alt"], merged_by=uid, reason="y")


def test_a_node_from_another_case_cannot_be_merged_in(conn, world):
    from noctornal_api.merges import MergeError
    case_id, uid, ids, _edges = world
    with pytest.raises(MergeError, match="not in this case"):
        _svc(conn).merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                         target_node_id=uuid4(), merged_by=uid, reason="x")


def test_both_the_merge_and_its_reversal_are_audited(conn, world):
    case_id, uid, ids, _edges = world
    svc = _svc(conn)
    rec = svc.merge(case_id=case_id, source_node_id=ids["alpha_alt"],
                    target_node_id=ids["alpha"], merged_by=uid, reason="x")
    svc.unmerge(rec.id, reversed_by=uid, reason="y")
    actions = [r[0] for r in conn.execute(
        """SELECT action FROM audit.event
            WHERE case_id = %s AND object_type = 'node_merge'
            ORDER BY seq""", (case_id,)).fetchall()]
    assert actions == ["NODE_MERGED", "NODE_UNMERGED"]
