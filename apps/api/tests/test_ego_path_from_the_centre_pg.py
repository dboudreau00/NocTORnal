"""docs/17, "ego and path past 5,000 entities" (Beta 1.1).

The ego and path views used to take the projection of the FIRST 5,000
entities of a case by creation time and search inside it, so on a case of
101,000 entities 88 of 100 ego requests answered 404 for an entity that was
there, and a path between two entities past the first 5,000 could not be
asked at all. They are built from the centre outward now: the ego network
gathers the neighbours of the neighbours level by level, the path search
grows from both ends until they meet, and each stops at
`projections.NEIGHBOURHOOD_MAX_NODES` and says so.

What these hold:

- the answer is what the old one was where the old one could answer: the same
  entities and ties as a search of the whole projection, under every
  projection parameter and every reader (a differential test against the old
  algorithm run over `project()`);
- the entities past the first 5,000 are reachable;
- a hidden, dissolved or merged entity is never passed through;
- a search that was cut off says so and never reports "not connected".

Everything is created inside one transaction that is rolled back. Env-gated
on DATABASE_URL.
"""
from __future__ import annotations

import os
from collections import defaultdict
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
           VALUES (%s, 'Ego', 'x', 'RED') RETURNING id""",
        (f"ego-{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, 'CASE_OWNER')",
                 (uid,))
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification, owner_user_id,
               legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Ego IT', 'AMBER', %s, 'dev', '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-EGO-{uuid4().hex[:6]}", uid))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'CASE_OWNER', %s)""", (case_id, uid, uid))
    return case_id, uid


def _svc(conn, clearance="RED", compartments=frozenset()):
    from noctornal_api.projections import GraphService
    return GraphService(conn, clearance=clearance, compartments=compartments)


def _proj(case_id, **kw):
    from noctornal_api.projections import Projection
    return Projection(case_id=case_id, **kw)


# --- a small case with every kind of obstacle ------------------------------------

@pytest.fixture()
def world(conn):
    """Ten entities and the ties between them, with a RED entity bridging
    two AMBER ones, an entity whose only claim is retracted, ties of every
    type, confidence, review state and inference, and a tie with a validity
    window:

        a - b - c - d - e - f          (a chain of COMMUNICATES_WITH)
        a - g (VOUCHED_FOR, ACCEPTED, HIGH)
        g - h (PAID)
        c - r - s                       (r is RED: s is reached only through it)
        a - x                           (x has no live claim left)
        b - d (inferred)
        e - j (valid only last year)
    """
    from noctornal_api.graph import AssertionInput, GraphWriteService
    case_id, uid = _case(conn)
    g = GraphWriteService(conn)
    claim = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    now = datetime.now(timezone.utc)
    ids = {k: g.create_node(case_id=case_id, node_type="IDENTITY", label=k,
                            created_by=uid, assertion=claim,
                            classification="RED" if k == "r" else "AMBER")
           for k in "abcdefghjrsx"}

    def tie(kind, s, d, *, confidence="LOW", **kw):
        return g.create_edge(
            case_id=case_id, edge_type=kind, src_node_id=ids[s], dst_node_id=ids[d],
            created_by=uid,
            assertion=kw.pop("assertion", AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=uid, confidence=confidence)),
            **kw)

    ties = {
        "ab": tie("COMMUNICATES_WITH", "a", "b"),
        "bc": tie("COMMUNICATES_WITH", "b", "c", confidence="MODERATE"),
        "cd": tie("COMMUNICATES_WITH", "c", "d"), "de": tie("COMMUNICATES_WITH", "d", "e"),
        "ef": tie("COMMUNICATES_WITH", "e", "f"),
        "ag": tie("VOUCHED_FOR", "a", "g", confidence="HIGH", review="ACCEPTED"),
        "gh": tie("PAID", "g", "h"),
        "cr": tie("COMMUNICATES_WITH", "c", "r"), "rs": tie("COMMUNICATES_WITH", "r", "s"),
        "ax": tie("COMMUNICATES_WITH", "a", "x"),
        "bd": tie("COMMUNICATES_WITH", "b", "d", is_inferred=True,
                  inference_method="CO_OCCURRENCE",
                  assertion=AssertionInput(basis="AUTOMATED_INFERENCE", created_by=uid,
                                           rationale="timing correlation only")),
        "ej": tie("COMMUNICATES_WITH", "e", "j", valid_from=now - timedelta(days=400),
                  valid_to=now - timedelta(days=300)),
    }
    # x loses its only live claim: it dissolves from the live graph.
    conn.execute("ALTER TABLE core.assertion DISABLE TRIGGER USER")
    conn.execute("UPDATE core.assertion SET retracted_at = now(), retracted_by = %s, "
                 "retraction_reason = 'test' WHERE node_id = %s", (uid, ids["x"]))
    conn.execute("ALTER TABLE core.assertion ENABLE TRIGGER USER")
    return case_id, uid, ids, ties


# --- the old algorithm, as the reference ---------------------------------------------

def _adjacency(sub):
    adjacency = defaultdict(set)
    for e in sub.edges:
        adjacency[e["src_node_id"]].add(e["dst_node_id"])
        adjacency[e["dst_node_id"]].add(e["src_node_id"])
    return adjacency


def _reference_ego(svc, p, centre, depth):
    """What `ego` answered before: a search of `project(limit=5000)`."""
    full = svc.project(p, limit=5000)
    if centre not in full.node_ids():
        return None
    adjacency = _adjacency(full)
    seen, frontier = {centre}, {centre}
    for _ in range(depth):
        nxt = set()
        for n in frontier:
            nxt |= adjacency[n] - seen
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    return ({n["id"] for n in full.nodes if n["id"] in seen},
            {e["id"] for e in full.edges
             if e["src_node_id"] in seen and e["dst_node_id"] in seen})


def _reference_hops(svc, p, src, dst):
    full = svc.project(p, limit=5000)
    if src not in full.node_ids() or dst not in full.node_ids():
        return None
    adjacency = _adjacency(full)
    dist, queue = {src: 0}, [src]
    while queue:
        cur = queue.pop(0)
        for nb in adjacency[cur]:
            if nb not in dist:
                dist[nb] = dist[cur] + 1
                queue.append(nb)
    return dist.get(dst)


PROJECTIONS = [
    {}, {"preset": "trust"}, {"preset": "financial"}, {"preset": "communication"},
    {"include_inferred": True}, {"min_confidence": "MODERATE"},
    {"min_confidence": "HIGH", "include_inferred": True},
    {"review_scope": "accepted"},
]


@pytest.mark.parametrize("clearance", ["RED", "AMBER"])
@pytest.mark.parametrize("params", PROJECTIONS, ids=lambda p: ",".join(
    f"{k}={v}" for k, v in p.items()) or "default")
def test_the_ego_network_is_what_a_search_of_the_whole_projection_gave(
        conn, world, params, clearance):
    case_id, _uid, ids, _ties = world
    svc = _svc(conn, clearance)
    p = _proj(case_id, **params)
    for centre in ids.values():
        for depth in (1, 2, 3, 4):
            expected = _reference_ego(svc, p, centre, depth)
            if expected is None:
                from noctornal_api.projections import ProjectionError
                with pytest.raises(ProjectionError):
                    svc.ego(p, centre, depth)
                continue
            got = svc.ego(p, centre, depth)
            assert (got.node_ids(), {e["id"] for e in got.edges}) == expected, (
                params, clearance, centre, depth)
            assert got.projection["ego"] == str(centre) and got.projection["depth"] == depth
            assert got.truncated is False


@pytest.mark.parametrize("clearance", ["RED", "AMBER"])
@pytest.mark.parametrize("params", PROJECTIONS, ids=lambda p: ",".join(
    f"{k}={v}" for k, v in p.items()) or "default")
def test_the_path_is_as_short_as_a_search_of_the_whole_projection_found(
        conn, world, params, clearance):
    case_id, _uid, ids, _ties = world
    svc = _svc(conn, clearance)
    p = _proj(case_id, **params)
    everything = list(ids.values())
    for src in everything:
        for dst in everything:
            expected = _reference_hops(svc, p, src, dst)
            if expected is None and (src not in svc.project(p).node_ids()
                                     or dst not in svc.project(p).node_ids()):
                from noctornal_api.projections import ProjectionError
                with pytest.raises(ProjectionError):
                    svc.shortest_path(p, src, dst)
                continue
            found = svc.shortest_path(p, src, dst)
            if expected is None:
                assert found == [], (params, clearance, src, dst)
                continue
            assert len(found) - 1 == expected, (params, clearance, src, dst, found)
            assert found[0] == src and found[-1] == dst
            joined = _adjacency(svc.project(p))
            assert all(b in joined[a] for a, b in zip(found, found[1:], strict=False)), found


def test_a_hidden_entity_is_never_passed_through(conn, world):
    """r is RED and the only way from c to s: an AMBER reader gets neither
    r nor s, and no path through r."""
    case_id, _uid, ids, _ties = world
    amber = _svc(conn, "AMBER")
    p = _proj(case_id)
    around = amber.ego(p, ids["c"], 4)
    assert ids["r"] not in around.node_ids() and ids["s"] not in around.node_ids()
    assert amber.shortest_path(p, ids["a"], ids["f"])
    from noctornal_api.projections import ProjectionError
    with pytest.raises(ProjectionError):
        amber.ego(p, ids["r"], 1)
    with pytest.raises(ProjectionError):
        amber.shortest_path(p, ids["a"], ids["r"])
    # s is AMBER and drawn, and the only way to it is through r, which is not.
    assert ids["s"] in amber.project(p).node_ids()
    assert amber.shortest_path(p, ids["a"], ids["s"]) == []
    red = _svc(conn, "RED")
    assert ids["s"] in red.ego(p, ids["c"], 2).node_ids()
    assert red.shortest_path(p, ids["a"], ids["s"])[-2] == ids["r"]


def test_a_dissolved_entity_is_neither_a_centre_nor_a_step(conn, world):
    from noctornal_api.projections import ProjectionError
    case_id, _uid, ids, _ties = world
    svc = _svc(conn)
    p = _proj(case_id)
    with pytest.raises(ProjectionError):
        svc.ego(p, ids["x"], 1)
    assert ids["x"] not in svc.ego(p, ids["a"], 2).node_ids()


def test_a_centre_in_another_case_is_not_found(conn, world):
    from noctornal_api.projections import ProjectionError
    case_id, _uid, _ids, _ties = world
    other_case, uid = _case(conn)
    from noctornal_api.graph import AssertionInput, GraphWriteService
    stranger = GraphWriteService(conn).create_node(
        case_id=other_case, node_type="IDENTITY", label="elsewhere", created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid))
    with pytest.raises(ProjectionError):
        _svc(conn).ego(_proj(case_id), stranger, 1)


def test_the_as_of_window_is_honoured_while_growing(conn, world):
    """The tie e-j was valid from 400 to 300 days ago: with no `as_of` the
    window is not asked, as of last year it holds, as of now it does not."""
    case_id, _uid, ids, _ties = world
    svc = _svc(conn)
    now = datetime.now(timezone.utc)
    last_year = now - timedelta(days=350)
    assert ids["j"] in svc.ego(_proj(case_id), ids["e"], 1).node_ids()
    assert ids["j"] in svc.ego(_proj(case_id, as_of=last_year), ids["e"], 1).node_ids()
    assert ids["j"] not in svc.ego(_proj(case_id, as_of=now), ids["e"], 1).node_ids()
    for as_of in (last_year, now):
        p = _proj(case_id, as_of=as_of)
        expected = _reference_ego(svc, p, ids["e"], 2)
        got = svc.ego(p, ids["e"], 2)
        assert (got.node_ids(), {e["id"] for e in got.edges}) == expected


# --- past the first 5,000 -----------------------------------------------------------

def _big_case(conn, *, old=5000, new=100):
    """`old` entities in a star around the first (spokes 2..old), then `new`
    created later: a centre tied to 49 of them and to the second spoke.

    Returns the case, the hub, the second spoke, the centre and the 49."""
    case_id, uid = _case(conn)
    base = datetime.now(timezone.utc) - timedelta(days=30)
    total = old + new
    conn.execute(
        """INSERT INTO core.node (id, case_id, node_type, label, created_by, created_at)
           SELECT gen_random_uuid(), %s, 'IDENTITY', 'n' || g, %s,
                  %s::timestamptz + g * interval '1 second'
             FROM generate_series(1, %s) g""", (case_id, uid, base, total))
    order = [r[0] for r in conn.execute(
        "SELECT id FROM core.node WHERE case_id = %s ORDER BY created_at", (case_id,))]
    hub, second, centre = order[0], order[1], order[old + 49]
    newcomers = order[old:old + 49]
    pairs = [(hub, n) for n in order[1:old]] + [(centre, n) for n in newcomers]
    pairs.append((centre, second))
    conn.execute(
        """INSERT INTO core.edge (case_id, edge_type, src_node_id, dst_node_id, created_by)
           SELECT %s, 'COMMUNICATES_WITH', s, d, %s
             FROM unnest(%s::uuid[], %s::uuid[]) AS t(s, d)""",
        (case_id, uid, [s for s, _ in pairs], [d for _, d in pairs]))
    conn.execute(
        """INSERT INTO core.assertion (case_id, node_id, basis, created_by)
           SELECT case_id, id, 'DIRECT_OBSERVATION', created_by
             FROM core.node WHERE case_id = %s""", (case_id,))
    conn.execute(
        """INSERT INTO core.assertion (case_id, edge_id, basis, created_by)
           SELECT case_id, id, 'DIRECT_OBSERVATION', created_by
             FROM core.edge WHERE case_id = %s""", (case_id,))
    # A bulk load is planned on the statistics of the table before it: analyze
    # as autovacuum would, or the planner scans per row what it should look up
    # (a minute for one step, measured). Rolled back with the rest.
    for table in ("core.node", "core.edge", "core.assertion"):
        conn.execute(f"ANALYZE {table}")
    return case_id, hub, second, centre, set(newcomers), order


def test_an_entity_past_the_first_5000_has_an_ego_network(conn):
    case_id, hub, second, centre, newcomers, order = _big_case(conn)
    svc = _svc(conn)
    p = _proj(case_id)
    assert centre not in svc.project(p, limit=5000).node_ids(), \
        "the fixture must put the centre past the first 5,000 entities"
    ego = svc.ego(p, centre, 1)
    assert ego.node_ids() == {centre, second} | newcomers
    assert len(ego.edges) == 50 and ego.truncated is False
    deeper = svc.ego(p, centre, 2)
    assert hub in deeper.node_ids() and len(deeper.edges) == 51


def test_a_path_between_entities_past_the_first_5000_is_found(conn):
    case_id, hub, second, centre, newcomers, order = _big_case(conn)
    svc = _svc(conn)
    spoke = order[3000]
    found = svc.shortest_path(_proj(case_id), centre, spoke)
    assert found == [centre, second, hub, spoke]
    # both ends past the first 5,000
    found = svc.shortest_path(_proj(case_id), next(iter(newcomers)), second)
    assert len(found) == 3 and found[0] in newcomers and found[1] == centre
    assert svc.shortest_path(_proj(case_id), centre, centre) == [centre]


def test_the_ego_routes_answer_for_an_entity_past_the_first_5000(conn):
    from noctornal_api.http.deps import CurrentUser
    from noctornal_api.http.routers import graphview

    case_id, hub, second, centre, newcomers, order = _big_case(conn)
    uid = conn.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                       (case_id,)).fetchone()[0]
    user = CurrentUser(user_id=uid, session_id=uuid4(), session_mfa_at=None)
    out = graphview.ego(case_id, centre, depth=1, preset="all", include_inferred=False,
                        min_confidence="LOW", as_of=None, user=user, conn=conn)
    assert {n["id"] for n in out["nodes"]} == {str(n) for n in {centre, second} | newcomers}
    assert out["truncated"] is False
    way = graphview.path(case_id, src=centre, dst=order[3000], preset="all",
                         include_inferred=False, min_confidence="LOW", user=user, conn=conn)
    assert way["connected"] is True and way["hops"] == 3 and way["path"][0] == str(centre)


# --- the bounds -----------------------------------------------------------------------

def test_an_ego_network_stops_at_the_bound_and_says_so(conn, monkeypatch):
    from noctornal_api import projections

    case_id, hub, second, centre, newcomers, order = _big_case(conn, old=200, new=100)
    monkeypatch.setattr(projections, "NEIGHBOURHOOD_MAX_NODES", 60)
    svc = _svc(conn)
    p = _proj(case_id)
    whole = svc.ego(p, centre, 1)
    assert len(whole.nodes) == 51 and whole.truncated is False
    cut = svc.ego(p, centre, 3)
    assert cut.truncated is True and len(cut.nodes) == 60
    assert centre in cut.node_ids() and newcomers <= cut.node_ids(), \
        "the nearer entities are kept before the farther ones"
    assert {e["src_node_id"] for e in cut.edges} | {e["dst_node_id"] for e in cut.edges} \
        <= cut.node_ids()


def test_a_search_that_hit_its_bound_never_says_not_connected(conn, monkeypatch):
    from noctornal_api import projections

    case_id, hub, second, centre, newcomers, order = _big_case(conn, old=300, new=100)
    monkeypatch.setattr(projections, "NEIGHBOURHOOD_MAX_NODES", 20)
    svc = _svc(conn)
    p = _proj(case_id)
    with pytest.raises(projections.PathSearchLimit):
        svc.shortest_path(p, centre, order[250])
    # Two ends that meet inside the bound are still joined.
    assert svc.shortest_path(p, centre, second) == [centre, second]


def test_two_components_are_not_connected_when_the_search_could_finish(conn, world):
    """Under the trust preset a's only tie is the vouch for g: f is in the
    projection and no path reaches it, and the search finishes to say so."""
    case_id, _uid, ids, _ties = world
    svc = _svc(conn)
    trust = _proj(case_id, preset="trust")
    assert svc.shortest_path(trust, ids["a"], ids["f"]) == []
    assert svc.shortest_path(trust, ids["a"], ids["g"]) == [ids["a"], ids["g"]]


def test_the_path_route_answers_a_cut_off_search_with_a_problem(conn, monkeypatch):
    from noctornal_api import projections
    from noctornal_api.http.deps import CurrentUser
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers import graphview

    case_id, hub, second, centre, newcomers, order = _big_case(conn, old=300, new=100)
    monkeypatch.setattr(projections, "NEIGHBOURHOOD_MAX_NODES", 20)
    uid = conn.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                       (case_id,)).fetchone()[0]
    user = CurrentUser(user_id=uid, session_id=uuid4(), session_mfa_at=None)
    with pytest.raises(Problem) as refused:
        graphview.path(case_id, src=centre, dst=order[250], preset="all",
                       include_inferred=False, min_confidence="LOW", user=user, conn=conn)
    assert refused.value.status == 422
    assert "cannot say they are not connected" in refused.value.detail


def test_a_one_mode_projection_is_still_searched_where_it_is_made(conn, world):
    """Derived ties exist only after `project()` has made them, so ego and
    path over a projection with venue families keep searching its result."""
    from noctornal_api.affiliation import OneModeParams

    case_id, _uid, ids, _ties = world
    svc = _svc(conn)
    p = _proj(case_id, one_mode=OneModeParams(families=("forum",)))
    around = svc.ego(p, ids["a"], 2)
    assert ids["a"] in around.node_ids()
    assert around.projection["ego"] == str(ids["a"])
    assert svc.shortest_path(p, ids["a"], ids["a"]) == [ids["a"]]
