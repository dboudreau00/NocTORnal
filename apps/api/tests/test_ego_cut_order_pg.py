"""An ego network cut by the row cap keeps the oldest entities and says which cap cut it (review
INTEGRITY, AREA-06).

The ego network is built a step at a time. One step reads at most `_STEP_ROWS_PER_NODE` ties for each
entity of the bound, and `_reach` applied that limit with no order, so a hub with more ties than that
kept whichever rows the plan met first, while the answer called what it kept the nearest entities and
the entity bound's own cut (the older before the newer) sorted only what the step had already
returned. What is held here:

- a step that is cut keeps the entities that were recorded first, the same order the entity bound keeps
  them in, wherever the rows lie in the table;
- `cut_by` names the bound that cut the network, the row cap and the entity bound each, both when both
  cut it, and nothing when nothing did;
- the route answers it beside `truncated`.

The caps are lowered for the test, as `test_ego_path_from_the_centre_pg.py` lowers the entity bound: the
rows are inserted newest entity first, so a limit with no order keeps the newest. Everything is created
inside one transaction that is rolled back. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs a migrated database")


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


def _case(conn):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'Ego cut', 'x', 'RED') RETURNING id""",
        (f"egocut-{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, 'CASE_OWNER')",
                 (uid,))
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification, owner_user_id,
               legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Ego cut', 'AMBER', %s, 'dev', '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-EGOCUT-{uuid4().hex[:6]}", uid))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'CASE_OWNER', %s)""", (case_id, uid, uid))
    return case_id, uid


def _star(conn, neighbours: int, ties_each: int = 1):
    """A centre tied to `neighbours` entities, `ties_each` ties to each (told apart by the date they
    start, which the live-tie key allows). Returns the case, its owner, the centre and the neighbours
    oldest first. The rows go in newest entity first."""
    case_id, uid = _case(conn)
    base = datetime.now(timezone.utc) - timedelta(days=30)
    centre = uuid4()
    oldest_first = [uuid4() for _ in range(neighbours)]
    conn.execute(
        """INSERT INTO core.node (id, case_id, node_type, label, created_by, created_at)
           VALUES (%s, %s, 'IDENTITY', 'centre', %s, %s)""",
        (centre, case_id, uid, base - timedelta(days=1)))
    for k in reversed(range(neighbours)):
        conn.execute(
            """INSERT INTO core.node (id, case_id, node_type, label, created_by, created_at)
               VALUES (%s, %s, 'IDENTITY', %s, %s, %s)""",
            (oldest_first[k], case_id, f"n{k}", uid, base + timedelta(seconds=k)))
        for t in range(ties_each):
            conn.execute(
                """INSERT INTO core.edge (case_id, edge_type, src_node_id, dst_node_id, created_by,
                                          valid_from)
                   VALUES (%s, 'COMMUNICATES_WITH', %s, %s, %s, %s)""",
                (case_id, centre, oldest_first[k], uid, base + timedelta(days=t)))
    conn.execute(
        """INSERT INTO core.assertion (case_id, node_id, basis, created_by)
           SELECT case_id, id, 'DIRECT_OBSERVATION', created_by
             FROM core.node WHERE case_id = %s""", (case_id,))
    conn.execute(
        """INSERT INTO core.assertion (case_id, edge_id, basis, created_by)
           SELECT case_id, id, 'DIRECT_OBSERVATION', created_by
             FROM core.edge WHERE case_id = %s""", (case_id,))
    for table in ("core.node", "core.edge", "core.assertion"):
        conn.execute(f"ANALYZE {table}")
    return case_id, uid, centre, oldest_first


def _ego(conn, case_id, centre, depth=1):
    from noctornal_api.projections import GraphService, Projection
    return GraphService(conn, clearance="RED", compartments=frozenset()).ego(
        Projection(case_id=case_id), centre, depth)


def _lower_caps(monkeypatch, *, nodes: int, rows_per_node: int):
    from noctornal_api import projections

    monkeypatch.setattr(projections, "NEIGHBOURHOOD_MAX_NODES", nodes)
    monkeypatch.setattr(projections, "_STEP_ROWS_PER_NODE", rows_per_node)


def test_a_step_cut_by_the_row_cap_keeps_the_oldest_entities(conn, monkeypatch):
    """Twelve neighbours, six rows a step, room for five: with no order the step kept the first six
    rows it met, the newest, and the bound kept the oldest five of those."""
    case_id, _uid, centre, oldest_first = _star(conn, 12)
    _lower_caps(monkeypatch, nodes=6, rows_per_node=1)
    ego = _ego(conn, case_id, centre)
    assert ego.node_ids() == {centre, *oldest_first[:5]}, \
        "the oldest five entities of the twelve, and not the oldest five of the first six rows read"
    assert ego.truncated is True
    assert ego.cut_by == ["row_cap", "node_cap"], "both bounds cut this network, and it says so"


def test_the_row_cap_alone_cuts_at_a_tie_and_says_it_was_the_row_cap(conn, monkeypatch):
    """Forty neighbours, three ties to each, a hundred rows a step: the entities fit the bound, the
    ties do not, and the step keeps what the first hundred rows in age order reach."""
    case_id, _uid, centre, oldest_first = _star(conn, 40, ties_each=3)
    _lower_caps(monkeypatch, nodes=100, rows_per_node=1)
    ego = _ego(conn, case_id, centre)
    assert ego.node_ids() == {centre, *oldest_first[:34]}, \
        "33 whole entities (99 rows) and the first row of the 34th"
    assert ego.truncated is True
    assert ego.cut_by == ["row_cap"], "the entity bound did not cut this one"
    nodes = ego.node_ids()
    assert all(e["src_node_id"] in nodes and e["dst_node_id"] in nodes for e in ego.edges)


def test_the_entity_bound_alone_keeps_the_older_and_says_it_was_the_entity_bound(conn, monkeypatch):
    case_id, _uid, centre, oldest_first = _star(conn, 12)
    _lower_caps(monkeypatch, nodes=6, rows_per_node=20)
    ego = _ego(conn, case_id, centre)
    assert ego.node_ids() == {centre, *oldest_first[:5]}
    assert ego.truncated is True and ego.cut_by == ["node_cap"]


def test_a_network_nothing_cut_says_nothing_cut_it(conn):
    case_id, _uid, centre, oldest_first = _star(conn, 12)
    ego = _ego(conn, case_id, centre)
    assert ego.node_ids() == {centre, *oldest_first}
    assert ego.truncated is False and ego.cut_by == []


def test_the_ego_route_answers_which_bound_cut_the_network(conn, monkeypatch):
    from noctornal_api.http.deps import CurrentUser
    from noctornal_api.http.routers import graphview

    case_id, uid, centre, oldest_first = _star(conn, 40, ties_each=3)
    user = CurrentUser(user_id=uid, session_id=uuid4(), session_mfa_at=None)

    def ask():
        return graphview.ego(case_id, centre, depth=1, preset="all", include_inferred=False,
                             min_confidence="LOW", as_of=None, user=user, conn=conn)

    whole = ask()
    assert whole["truncated"] is False and whole["cut_by"] == []
    _lower_caps(monkeypatch, nodes=100, rows_per_node=1)
    cut = ask()
    assert cut["truncated"] is True and cut["cut_by"] == ["row_cap"]
    assert {n["id"] for n in cut["nodes"]} == {str(n) for n in {centre, *oldest_first[:34]}}
