"""Row-level security on stored analysis runs and layouts (S1, 2026-09-25).

0120 puts projections, runs, per-entity scores and the saved canvas under
policy. Run as the request role, bound by a real session's proof:

- a run is visible only at a visibility within the reader's ceiling for
  its case, so a run computed over a RED analyst's view never reaches an
  AMBER one, and a grant on the case raises it there;
- a score on an entity the reader cannot see is hidden with the entity;
- the saved canvas no longer hands a hidden entity's id and position to
  every reader of the case (it did in owner mode: GET /graph/layout read
  every position in the case);
- nothing calls a row-security helper per row.

Gated like the other row-security tests. Account prefix `rlsana-`.
"""
from __future__ import annotations

import json
from uuid import UUID

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsana-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {cases}")
    s.cleanup(c, PREFIX)
    c.close()


def _projection(conn, case_id: UUID, actor: UUID, name: str) -> UUID:
    return conn.execute(
        """INSERT INTO analytics.projection (case_id, name, edge_types, created_by)
           VALUES (%s, %s, '{}', %s) RETURNING id""",
        (case_id, name, actor)).fetchone()[0]


def _registered(conn, *keys: str) -> None:
    """Every compartment a raw write carries is registered first (0059)."""
    s.register(conn, *keys)


def _run(conn, projection: UUID, visibility: str) -> UUID:
    _registered(conn)
    return conn.execute(
        """INSERT INTO analytics.metric_run
               (projection_id, algorithm, params, is_approximate, status, result,
                visibility_clearance, visibility_compartments)
           VALUES (%s, 'suite', '{}', false, 'COMPLETE', '{}', %s, '{}')
           RETURNING id""", (projection, visibility)).fetchone()[0]


def _score(conn, run: UUID, node: UUID) -> None:
    conn.execute("""INSERT INTO analytics.node_metric (metric_run_id, node_id, metric, value)
                    VALUES (%s, %s, 'degree', 1.0)""", (run, node))


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def test_a_run_is_visible_only_at_a_visibility_the_reader_may_hold(owner):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    mine, other = s.case(owner, boss), s.case(owner, boss)
    s.assign(owner, mine, analyst)
    here = _projection(owner, mine, boss, "all")
    there = _projection(owner, other, boss, "all")
    amber_run, red_run = _run(owner, here, "AMBER"), _run(owner, here, "RED")
    elsewhere = _run(owner, there, "AMBER")
    visible_node = s.node(owner, mine, boss, "seen")
    hidden_node = s.node(owner, mine, boss, "unseen", "RED")
    _score(owner, amber_run, visible_node)
    _score(owner, amber_run, hidden_node)
    _, raw = s.session(owner, analyst)
    runs = "SELECT id FROM analytics.metric_run WHERE id = ANY(%s)"
    wanted = ([amber_run, red_run, elsewhere],)

    app = s.app_conn(raw)
    try:
        assert _ids(app, "SELECT id FROM analytics.projection WHERE id = ANY(%s)",
                    ([here, there],)) == {here}
        assert _ids(app, runs, wanted) == {amber_run}
        assert _ids(app, "SELECT node_id FROM analytics.node_metric "
                         "WHERE metric_run_id = %s", (amber_run,)) == {visible_node}
        s.break_glass(owner, analyst, "RED", mine)
        assert _ids(app, runs, wanted) == {amber_run, red_run}, (
            "a grant on this case raises this case's runs")
        assert s.per_row_definer_calls(
            app, "SELECT id FROM analytics.metric_run WHERE projection_id = %s",
            (here,)) == []
    finally:
        app.close()


def test_the_saved_canvas_no_longer_names_an_entity_its_reader_cannot_see(owner):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    seen = s.node(owner, case_id, boss, "seen")
    unseen = s.node(owner, case_id, boss, "unseen", "RED")
    layout = _projection(owner, case_id, boss, "__layout__")
    for node in (seen, unseen):
        owner.execute("""INSERT INTO analytics.layout_position
                             (projection_id, node_id, x, y, is_pinned)
                         VALUES (%s, %s, 1, 2, false)""", (layout, node))
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    _, raw = s.session(owner, analyst)
    r = TestClient(app).get(f"/api/v1/cases/{case_id}/graph/layout",
                            headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 200, r.text
    assert {UUID(p["node_id"]) for p in r.json()} == {seen}
    assert str(unseen) not in json.dumps(r.json())
