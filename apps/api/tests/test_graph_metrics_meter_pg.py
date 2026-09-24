"""The sociogram's metrics call has its own meter.

ux03 metrics-rate-limit-degrades-view (2026-09-23). `/graph/metrics` was
metered under `analytics.suite`, 30 per five minutes with a burst of 10 per
analyst, and the console calls it with every projection it draws: case
open, each preset or confidence change, Include inferred, Reload, and every
pause of a timeline scrub. About ten control changes spent the budget; Node
size then disabled itself, every node changed size, the "0% evidenced"
headline vanished, and the Analysis pane's Run was refused too, because it
was the same meter.

The two costs are not the same. The suite runs igraph centralities over the
projection; these four local counts cost about what drawing the projection
costs. So they are metered like the projection, on `graph.metrics`, and
spending one budget leaves the other whole. Env-gated on DATABASE_URL like
the HTTP e2e suite whose helpers this borrows.
"""
from __future__ import annotations

import pytest
import test_http_e2e as e2e
from test_http_e2e import (
    DATABASE_URL,
    _auth,
    _create_case,
    _limited,
    _make_user,
    _seed_small_graph,
    _session,
    _tiny,
)

# The e2e suite's own fixtures, so its teardown of e2e-% accounts, cases
# and projections covers what these tests create.
conn = e2e.conn
client = e2e.client

pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; HTTP e2e is gated")


def test_graph_metrics_is_not_metered_as_the_analytics_suite():
    from noctornal_api.ratelimit import LIMITS
    metrics, suite = LIMITS["graph.metrics"], LIMITS["analytics.suite"]
    # A realistic burst: a case open plus a morning of control changes.
    assert metrics.effective_burst >= 30
    assert metrics.quota / metrics.per_seconds > suite.quota / suite.per_seconds
    # Still per analyst, and still closed when the meter cannot be read.
    assert metrics.scope == suite.scope
    assert metrics.on_backend_failure == suite.on_backend_failure


def _setup(conn, client):
    _, email, _secret = _make_user(conn, clearance="RED",
                                   global_roles=("CASE_OWNER",))
    token = _session(conn, email)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    return token, case_id


def test_spending_the_metrics_budget_leaves_the_analysis_run_alone(conn, client):
    _limited(client.app, **{
        "graph.metrics": _tiny("graph.metrics", quota=2, per_seconds=300, burst=2)})
    token, case_id = _setup(conn, client)
    codes = [client.get(f"/api/v1/cases/{case_id}/graph/metrics",
                        headers=_auth(token)).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429], codes
    refused = client.get(f"/api/v1/cases/{case_id}/graph/metrics",
                         headers=_auth(token))
    # The console waits this out and retries by itself.
    assert int(refused.headers["Retry-After"]) >= 1
    assert "graph.metrics" in refused.json()["detail"]
    r = client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token))
    assert r.status_code == 200, r.text


def test_spending_the_analysis_budget_leaves_the_sociogram_metrics_alone(conn, client):
    _limited(client.app, **{
        "analytics.suite": _tiny("analytics.suite", quota=2, per_seconds=300, burst=2)})
    token, case_id = _setup(conn, client)
    for _ in range(3):
        client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token))
    assert client.get(f"/api/v1/cases/{case_id}/analytics",
                      headers=_auth(token)).status_code == 429
    r = client.get(f"/api/v1/cases/{case_id}/graph/metrics", headers=_auth(token))
    assert r.status_code == 200, r.text
    # And it advertises its own meter, not the one that was spent.
    from noctornal_api.ratelimit import LIMITS
    assert r.headers["RateLimit-Limit"] == str(LIMITS["graph.metrics"].quota)
