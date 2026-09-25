"""L3 against Postgres (2026-09-24): the accepted-ties scope over a real
case, written through GraphWriteService, with review states set the way
tie review and legacy rows leave them (SUPERSEDED included, by UPDATE, as
test_tie_review_pg does: nothing in the database stops it on a tie).

Also the shared world and helpers of this group's Postgres files
(test_one_mode_pg, test_concor_pg import them), so one teardown covers
every account, case, projection and run they make. Email prefix `rs-`,
unique to these files. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; review scope test is gated")

EMAIL_LIKE = "rs-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    psub = f"(SELECT id FROM analytics.projection WHERE case_id IN {csub})"
    rsub = f"(SELECT id FROM analytics.metric_run WHERE projection_id IN {psub})"
    with c.transaction():
        c.execute(f"DELETE FROM analytics.node_metric WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.community_assignment WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.metric_run WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


class World:
    """A case, its owner, and helpers to add nodes and ties to it."""

    def __init__(self, conn):
        from noctornal_api.graph import AssertionInput, GraphWriteService
        self.conn = conn
        self.uid = conn.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
               VALUES (%s, 'RS', 'x', 'RED') RETURNING id""",
            (f"rs-{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
        self.case_id = uuid4()
        conn.execute(
            """INSERT INTO core."case" (id, code, title, classification,
                   owner_user_id, legal_basis, retention_until, review_due)
               VALUES (%s, %s, 'Analysis options IT', 'AMBER', %s, 'dev',
                       '2028-01-01', '2027-01-01')""",
            (self.case_id, f"OP-RS-{uuid4().hex[:6]}", self.uid))
        self.g = GraphWriteService(conn)
        self.a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=self.uid)
        self.ids: dict = {}
        self.edges: dict = {}

    def node(self, label, node_type="IDENTITY", **kw):
        self.ids[label] = self.g.create_node(case_id=self.case_id, node_type=node_type,
                                             label=label, created_by=self.uid,
                                             assertion=self.a, **kw)
        return self.ids[label]

    def tie(self, src, etype, dst, *, review=None, key=None, **kw):
        eid = self.g.create_edge(case_id=self.case_id, edge_type=etype,
                                 src_node_id=self.ids[src], dst_node_id=self.ids[dst],
                                 created_by=self.uid, assertion=self.a, **kw)
        if review:
            self.conn.execute("UPDATE core.edge SET review = %s::core.review_state "
                              "WHERE id = %s", (review, eid))
        self.edges[key or f"{src}-{etype}-{dst}"] = eid
        return eid

    def svc(self, clearance="RED"):
        from noctornal_api.analytics_runs import AnalyticsRunService
        return AnalyticsRunService(self.conn, clearance=clearance,
                                   compartments=frozenset(), actor_id=self.uid)

    def graph(self, clearance="RED"):
        from noctornal_api.projections import GraphService
        return GraphService(self.conn, clearance=clearance, compartments=frozenset())

    def proj(self, **kw):
        from noctornal_api.projections import Projection
        return Projection(case_id=self.case_id, **kw)


def params(**kw):
    from noctornal_api.analytics import AnalyticsParams
    return AnalyticsParams(**kw)


@pytest.fixture
def world(conn):
    """Five personas; one accepted vouch and one of every other state."""
    w = World(conn)
    for label in ("a", "b", "c", "d", "e"):
        w.node(label)
    w.tie("a", "VOUCHED_FOR", "b")
    w.tie("b", "VOUCHED_FOR", "c", review="PROPOSED")
    w.tie("c", "VOUCHED_FOR", "d", review="DISPUTED")
    w.tie("d", "VOUCHED_FOR", "e", review="REJECTED")
    w.tie("e", "VOUCHED_FOR", "a", review="SUPERSEDED")
    return w


def test_the_accepted_scope_keeps_accepted_ties_and_counts_every_other_state(world):
    sub = world.graph().project(world.proj(review_scope="accepted"))
    assert [e["id"] for e in sub.edges] == [world.edges["a-VOUCHED_FOR-b"]]
    assert sub.review_left_out == {"ties": {"proposed": 1, "disputed": 1, "rejected": 1,
                                            "superseded": 1, "other": 0}}
    default = world.graph().project(world.proj())
    assert len(default.edges) == 5 and default.review_left_out is None


def test_the_accepted_scope_keeps_every_node(world):
    sub = world.graph().project(world.proj(review_scope="accepted"))
    assert {n["label"] for n in sub.nodes} == {"a", "b", "c", "d", "e"}


def test_the_counts_are_taken_after_the_confidence_floor(world):
    """Over ties the caller already sees: a tie below the floor is not
    counted as left out by review."""
    world.tie("a", "VOUCHED_FOR", "c", review="PROPOSED")     # LOW, like every tie here
    sub = world.graph().project(world.proj(review_scope="accepted",
                                           min_confidence="HIGH"))
    assert sub.edges == []
    assert sum(sub.review_left_out["ties"].values()) == 0


def test_withheld_applies_the_review_scope(conn, world):
    """A RED proposal is withheld from an AMBER reader under "all", and is
    not in anybody's accepted view, so it is not withheld under it."""
    conn.execute('UPDATE core."case" SET withheld_disclosure = \'COUNT\' WHERE id = %s',
                 (world.case_id,))
    world.tie("a", "VOUCHED_FOR", "d", review="PROPOSED", classification="RED")
    amber = world.graph(clearance="AMBER")
    assert amber.withheld(world.proj()).edges == 1
    assert amber.withheld(world.proj(review_scope="accepted")).edges == 0
    world.tie("b", "VOUCHED_FOR", "e", classification="RED")      # accepted
    assert amber.withheld(world.proj(review_scope="accepted")).edges == 1


def test_an_accepted_only_run_is_its_own_projection_and_cache_entry(world):
    svc = world.svc()
    plain = svc.suite(world.proj(), params())
    accepted = svc.suite(world.proj(review_scope="accepted"), params())
    assert plain.run_id != accepted.run_id
    assert accepted.payload["review_scope"]["left_out"]["ties"]["superseded"] == 1
    assert accepted.payload["edge_count"] == 1
    # Reviewing the proposal changes the counts and so the key: not current.
    world.conn.execute("UPDATE core.edge SET review = 'ACCEPTED' WHERE id = %s",
                       (world.edges["b-VOUCHED_FOR-c"],))
    again = svc.latest(world.proj(review_scope="accepted"), params())
    assert again.run_id == accepted.run_id and again.current is False
