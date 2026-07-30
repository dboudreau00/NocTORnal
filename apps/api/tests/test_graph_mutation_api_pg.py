"""Corrections and retirements over HTTP: `PATCH`/`DELETE` on nodes and
edges, with the five-part gate in front of them.

These four endpoints are the first callers of `graph.node.update`,
`graph.node.delete`, `graph.edge.update` and `graph.edge.delete` — verbs
that were seeded in 0017/0053 and never checked, because until now a
mistyped node label was permanent. A first caller is exactly when the
refusals need writing down.

**The tests that carry this file are the ones that assert what does NOT
happen**, and they are in that order deliberately:

- an element id from ANOTHER case is a 404 — not a 403, not a 200 — and
  the element it names is left untouched, INCLUDING its edges. Retiring a
  node cascades to every tie it carries, so a cross-case retirement is not
  one wrong row, it is a subgraph;
- the 404 for another case's element is byte-identical to the 404 for an
  id that does not exist, so neither endpoint is an existence oracle;
- a caller who lacks the verb, and a caller who lacks the CLEARANCE for
  the element (as opposed to the case), are both refused — the CR7 rule:
  a RED node can live in an AMBER case;
- a soft delete sets `deleted_at` and the row, its assertions and its
  history all survive. `DELETE` reads as destruction and this is not that;
- nothing is silently accepted: an empty correction is refused rather
  than leaving an assertion behind claiming a change that did not happen
  (invariant 12), and the count of edges retired alongside a node comes
  back in the body rather than being discovered later.

Two invariants get their own named tests here because these are the
endpoints that could break them: **invariant 1** (a correction carries its
own assertion — "we corrected this" is a claim about the world) and
**invariant 5** (the overwritten label/weight reach `audit.event`, because
the correction destructively UPDATEs the only column that held them).

**The email prefix is `gmut-` and must stay unique.** Every fixture in
this suite cleans up on an email pattern, so two files sharing a prefix
delete each other's rows — which surfaces as a foreign-key error in
whichever file tears down second, pointing at a table neither test
touched.

Not in scope here: curation (tags / node sets) has its own router and its
own suite; this file is the graph-mutation router only.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from datetime import date, datetime, timezone
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; graph-mutation API is gated"
)

PASSWORD = "correct-horse-battery-staple"

# Set at import, exactly as the other _pg HTTP suites do. Skipping instead
# would be worse than useless: CI fails the run if ANY test skips, and
# these are the tests that prove the refusals.
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'gmut-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # ONE transaction, and assertions/edges/nodes go together: the
    # invariant-1 trigger is DEFERRED, so it sees the final state (all
    # gone) rather than firing mid-sweep on a node whose last assertion has
    # just been removed. Order otherwise follows the foreign keys —
    # assertion → edge → node → case_assignment → case → session/role →
    # user. `audit.event` is deliberately untouched: it is append-only
    # (invariant 6) and carries no FK to app_user.
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        # One test points a node at another via merged_into_id (a self-FK);
        # both rows go in this single statement, so the reference is
        # satisfied at statement end.
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'gmut-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    """A TestClient whose rate limiter this test alone owns.

    The default limiter is Redis-backed when REDIS_URL is set, and Redis is
    shared, persistent and blind to test boundaries — one test would spend
    the next one's budget and the suite would pass or fail by ordering. A
    flaky security test is a deleted security test.
    """
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- fixtures over HTTP -------------------------------------------------

def _make_user(conn, *, clearance="AMBER", global_roles=(), compartments=()):
    """A user with TOTP enrolled, returning (user_id, email, totp_secret)."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"gmut-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "GMut", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s WHERE id = %s",
        (clearance, list(compartments), uid),
    )
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _owner(conn, client, clearance="AMBER"):
    """A CASE_OWNER, signed in. Case creation grants them CASE_OWNER on the
    case in the same transaction, which is what puts the graph-write verbs
    in reach — role permissions come from the CASE ASSIGNMENT, not from the
    global role."""
    uid, email, secret = _make_user(conn, clearance=clearance,
                                    global_roles=("CASE_OWNER",))
    return uid, _login(client, email, secret)


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-GMUT-{uuid4().hex[:6]}", "title": "Operation Mutation",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _new_node(client, token, case_id, label, **kw) -> str:
    body = {"node_type": "IDENTITY", "label": label}
    body.update(kw)
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _new_edge(client, token, case_id, src, dst, edge_type="VOUCHED_FOR",
              **kw) -> str:
    body = {"edge_type": edge_type, "src_node_id": src, "dst_node_id": dst}
    body.update(kw)
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _patch(client, token, case_id, kind, oid, body):
    return client.patch(f"/api/v1/cases/{case_id}/graph/{kind}/{oid}",
                        headers=_auth(token), json=body)


def _retire(client, token, case_id, kind, oid, reason="duplicate of another entity"):
    """`httpx.delete()` accepts no body and these endpoints REQUIRE one —
    the reason is the thing a reviewer reads six months later — so the
    request has to be built the long way round."""
    return client.request("DELETE",
                          f"/api/v1/cases/{case_id}/graph/{kind}/{oid}",
                          headers=_auth(token), json={"reason": reason})


# --- what the database says ---------------------------------------------

def _node_row(conn, node_id):
    return conn.execute(
        "SELECT label, attrs, deleted_at, deleted_by, merged_into_id "
        "  FROM core.node WHERE id = %s", (node_id,)).fetchone()


def _edge_row(conn, edge_id):
    return conn.execute(
        "SELECT weight, confidence, attrs, sign, deleted_at, deleted_by "
        "  FROM core.edge WHERE id = %s", (edge_id,)).fetchone()


def _assertion_count(conn, column, oid) -> int:
    assert column in ("node_id", "edge_id")     # literal, never test input
    return conn.execute(
        f"SELECT count(*) FROM core.assertion WHERE {column} = %s", (oid,)
    ).fetchone()[0]


def _audit(conn, action, object_id):
    """The most recent audit row for one action on one object, or None."""
    row = conn.execute(
        "SELECT detail FROM audit.event WHERE action = %s AND object_id = %s "
        "ORDER BY seq DESC LIMIT 1", (action, object_id)).fetchone()
    return row[0] if row else None


# =======================================================================
# SAME-CASE VERIFICATION — the defect class this repo has had before
# =======================================================================

def test_a_node_from_another_case_is_404_not_403_and_not_200(conn, client):
    """The path's case_id is the one the gate authorised, so an element
    from a different case must not be reachable through it — even by a
    caller who owns BOTH cases, which is the case that catches a check
    written as "may this user touch this node?" instead of "is this node in
    THIS case?".

    404 rather than 403 so the status code cannot be used to confirm that a
    guessed id exists somewhere in the deployment.
    """
    _, token = _owner(conn, client)
    case_a = _create_case(client, token)
    case_b = _create_case(client, token)
    node_b = _new_node(client, token, case_b, "lives in b")

    r = _patch(client, token, case_a, "nodes", node_b, {"label": "hijacked"})
    assert r.status_code == 404, r.text
    assert r.headers["content-type"].startswith("application/problem+json")

    # ...and nothing happened to it.
    label, _attrs, deleted_at, _by, _merged = _node_row(conn, node_b)
    assert label == "lives in b"
    assert deleted_at is None
    assert _assertion_count(conn, "node_id", node_b) == 1, (
        "the refused correction must not leave an assertion behind")


def test_an_edge_from_another_case_is_404_not_403_and_not_200(conn, client):
    _, token = _owner(conn, client)
    case_a = _create_case(client, token)
    case_b = _create_case(client, token)
    src = _new_node(client, token, case_b, "src")
    dst = _new_node(client, token, case_b, "dst")
    edge_b = _new_edge(client, token, case_b, src, dst)

    r = _patch(client, token, case_a, "edges", edge_b, {"weight": 99})
    assert r.status_code == 404, r.text

    weight, _conf, _attrs, _sign, deleted_at, _by = _edge_row(conn, edge_b)
    assert float(weight) == 1.0
    assert deleted_at is None


def test_retiring_through_the_wrong_case_leaves_the_node_and_its_edges_live(
        conn, client):
    """The damage a cross-case retirement would do is not one row.
    `soft_delete_node` retires every live edge touching the node in the
    same transaction, so a missing same-case check would let a caller
    dissolve a subgraph in a case they were never assigned to."""
    _, token = _owner(conn, client)
    case_a = _create_case(client, token)
    case_b = _create_case(client, token)
    hub = _new_node(client, token, case_b, "hub")
    other = _new_node(client, token, case_b, "other")
    tie = _new_edge(client, token, case_b, hub, other)

    r = _retire(client, token, case_a, "nodes", hub)
    assert r.status_code == 404, r.text

    assert _node_row(conn, hub)[2] is None, "the node must still be live"
    assert _edge_row(conn, tie)[4] is None, "its tie must still be live"


def test_the_404_is_the_same_for_another_case_and_for_a_nonexistent_id(
        conn, client):
    """No existence oracle: the response for a REAL id in another case and
    the response for an id that exists nowhere must be indistinguishable,
    body included."""
    _, token = _owner(conn, client)
    case_a = _create_case(client, token)
    case_b = _create_case(client, token)
    node_b = _new_node(client, token, case_b, "real, elsewhere")
    src = _new_node(client, token, case_b, "s")
    edge_b = _new_edge(client, token, case_b, node_b, src)

    real = _patch(client, token, case_a, "nodes", node_b, {"label": "x"})
    fake = _patch(client, token, case_a, "nodes", uuid4(), {"label": "x"})
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()

    real = _retire(client, token, case_a, "edges", edge_b)
    fake = _retire(client, token, case_a, "edges", uuid4())
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()


# =======================================================================
# THE GATE
# =======================================================================

def test_a_read_only_assignee_can_neither_correct_nor_retire(conn, client):
    """READ_ONLY holds `case.read` and `evidence.read` and none of the four
    graph-write verbs. All four endpoints must refuse, and the elements
    must be exactly as they were."""
    from noctornal_api.cases import CaseService
    owner_id, owner_token = _owner(conn, client)
    case_id = _create_case(client, owner_token)
    a = _new_node(client, owner_token, case_id, "alpha")
    b = _new_node(client, owner_token, case_id, "bravo")
    tie = _new_edge(client, owner_token, case_id, a, b)

    reader_id, reader_email, reader_secret = _make_user(conn)
    CaseService(conn).assign_user(case_id, reader_id, "READ_ONLY",
                                  granted_by=owner_id)
    reader = _login(client, reader_email, reader_secret)

    # It can read the case — so this is the VERB failing, not the
    # relationship.
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(reader)).status_code == 200

    assert _patch(client, reader, case_id, "nodes", a,
                  {"label": "nope"}).status_code == 403
    assert _patch(client, reader, case_id, "edges", tie,
                  {"weight": 7}).status_code == 403
    assert _retire(client, reader, case_id, "nodes", a).status_code == 403
    assert _retire(client, reader, case_id, "edges", tie).status_code == 403

    assert _node_row(conn, a)[0] == "alpha"
    assert _node_row(conn, a)[2] is None
    assert float(_edge_row(conn, tie)[0]) == 1.0
    assert _edge_row(conn, tie)[4] is None


def test_a_refused_correction_is_audited(conn, client):
    """A denial that leaves no trace is a denial nobody can review. The
    audit row names the permission and which of the five checks failed —
    server-side only; the client is told neither."""
    from noctornal_api.cases import CaseService
    from noctornal_api.security.access import CHECK_ROLE
    owner_id, owner_token = _owner(conn, client)
    case_id = _create_case(client, owner_token)
    a = _new_node(client, owner_token, case_id, "alpha")

    reader_id, reader_email, reader_secret = _make_user(conn)
    CaseService(conn).assign_user(case_id, reader_id, "READ_ONLY",
                                  granted_by=owner_id)
    reader = _login(client, reader_email, reader_secret)
    r = _patch(client, reader, case_id, "nodes", a, {"label": "nope"})
    assert r.status_code == 403
    assert CHECK_ROLE not in r.text, "the failed check is audited, never disclosed"

    row = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'AUTHZ_DENIED' "
        "AND actor_id = %s ORDER BY seq DESC LIMIT 1", (reader_id,)).fetchone()
    assert row is not None
    assert row[0]["permission"] == "graph.node.update"
    assert CHECK_ROLE in row[0]["failed_checks"]


def test_a_stranger_to_the_case_gets_404_not_403(conn, client):
    """A caller with no relationship to the case must not learn it exists.
    `authorize_object` turns a failed assignment check into the same 404 a
    nonexistent case gives."""
    _, owner_token = _owner(conn, client)
    case_id = _create_case(client, owner_token)
    a = _new_node(client, owner_token, case_id, "alpha")

    _, out_email, out_secret = _make_user(conn)
    outsider = _login(client, out_email, out_secret)

    real = _patch(client, outsider, case_id, "nodes", a, {"label": "x"})
    fake = _patch(client, outsider, str(uuid4()), "nodes", a, {"label": "x"})
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()
    assert _node_row(conn, a)[0] == "alpha"


def test_an_under_cleared_caller_cannot_correct_or_retire_a_red_element(
        conn, client):
    """CR7: an element is protected by BOTH its own labels and its case's.
    A RED node inside an AMBER case is not rewritable — nor retirable — by
    an AMBER analyst who is otherwise fully entitled on the case and merely
    happens to know the node's id.

    Retirement is the one that matters most: it dissolves the node and
    every tie it carries from every analyst's graph, so it must not be
    reachable by a caller who could not see what they are destroying.
    """
    from noctornal_api.cases import CaseService
    owner_id, owner_token = _owner(conn, client, clearance="RED")
    case_id = _create_case(client, owner_token)              # AMBER case
    red = _new_node(client, owner_token, case_id, "informant truename",
                    classification="RED")

    amber_id, amber_email, amber_secret = _make_user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber_id, "ANALYST",
                                  granted_by=owner_id)
    amber = _login(client, amber_email, amber_secret)

    # The ANALYST role does grant the verb, and the case is AMBER, so the
    # case-level `require(...)` passes. Only the element's own label stops
    # this.
    assert _patch(client, amber, case_id, "nodes", red,
                  {"label": "rewritten"}).status_code == 403
    assert _retire(client, amber, case_id, "nodes", red).status_code == 403

    assert _node_row(conn, red)[0] == "informant truename"
    assert _node_row(conn, red)[2] is None


def test_these_routes_need_authentication(client):
    """No `conn` fixture: a tokenless request must 401 without ever opening
    a database connection (`session_token` is declared before `get_conn`),
    so an unauthenticated flood costs no connections."""
    case_id, oid = str(uuid4()), str(uuid4())
    for kind in ("nodes", "edges"):
        path = f"/api/v1/cases/{case_id}/graph/{kind}/{oid}"
        assert client.patch(path, json={"label": "x"}).status_code == 401, path
        assert client.request("DELETE", path,
                              json={"reason": "x"}).status_code == 401, path


# =======================================================================
# SOFT DELETE — nothing is destroyed
# =======================================================================

def test_retiring_a_node_sets_deleted_at_and_destroys_nothing(conn, client):
    """The row survives, its assertions survive, and the act is attributed.
    Clearing the column would bring the node back."""
    uid, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "wrong entity")
    assert _assertion_count(conn, "node_id", a) == 1

    r = _retire(client, token, case_id, "nodes", a, reason="duplicate of bravo")
    assert r.status_code == 200, r.text
    body = r.json()
    # 200 with a body, not 204: a bare 204 on a verb named DELETE reads as
    # destruction, and a client that only checks the status code would
    # never learn otherwise.
    assert body["soft_deleted"] is True
    assert body["destroyed"] is False
    assert body["edges_retired"] == 0

    label, _attrs, deleted_at, deleted_by, _merged = _node_row(conn, a)
    assert deleted_at is not None, "deleted_at must be set"
    assert deleted_by == uid, "the retirement must be attributed"
    assert label == "wrong entity", "the row is not blanked"
    assert _assertion_count(conn, "node_id", a) == 1, (
        "the assertions behind a retired node survive it")
    assert _audit(conn, "NODE_SOFT_DELETED", a)["reason"] == "duplicate of bravo"


def test_retiring_an_edge_sets_deleted_at_and_destroys_nothing(conn, client):
    uid, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)

    r = _retire(client, token, case_id, "edges", tie, reason="misread the post")
    assert r.status_code == 200, r.text
    assert r.json()["soft_deleted"] is True and r.json()["destroyed"] is False

    weight, _conf, _attrs, _sign, deleted_at, deleted_by = _edge_row(conn, tie)
    assert deleted_at is not None
    assert deleted_by == uid, (
        "core.edge.deleted_by exists so that 'who removed this tie?' has an "
        "answer — dropping one tie can dissolve a broker")
    assert _assertion_count(conn, "edge_id", tie) == 1
    # Both endpoints are untouched: retiring a tie is not retiring a person.
    assert _node_row(conn, a)[2] is None and _node_row(conn, b)[2] is None


def test_retiring_a_node_retires_its_incident_edges_and_says_how_many(
        conn, client):
    """A live edge against a retired node is invisible on the canvas (the
    projection constrains edges to the visible node set) and still counted
    by anything reading `core.edge` directly. It goes in the same
    transaction — and the count comes back, because retiring one actor can
    remove six ties and an analyst must not have to discover that later
    (invariant 12)."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    hub = _new_node(client, token, case_id, "hub")
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    out = _new_edge(client, token, case_id, hub, a)     # hub is the source
    inc = _new_edge(client, token, case_id, b, hub)     # hub is the target
    unrelated = _new_edge(client, token, case_id, a, b)  # touches neither end

    r = _retire(client, token, case_id, "nodes", hub, reason="never existed")
    assert r.status_code == 200, r.text
    assert r.json()["edges_retired"] == 2, (
        "both directions count: incidence is not the same as being the source")
    assert "2 incident edge(s)" in r.json()["note"]

    assert _edge_row(conn, out)[4] is not None
    assert _edge_row(conn, inc)[4] is not None
    assert _edge_row(conn, unrelated)[4] is None, (
        "a tie that does not touch the retired node is not collateral")

    # Not destroyed — all three edge rows still exist.
    assert conn.execute(
        "SELECT count(*) FROM core.edge WHERE id IN (%s, %s, %s)",
        (out, inc, unrelated)).fetchone()[0] == 3
    assert _audit(conn, "NODE_SOFT_DELETED", hub)["edges_retired"] == 2


def test_a_retired_node_leaves_the_live_graph_and_as_of_views_of_the_past(
        conn, client):
    """The difference from `valid_to`, made concrete. `valid_to` says "this
    stopped being true in March" and an as-of query into February must
    still show it. A retirement says "this should never have been in the
    case file", so `projections.py` applies `deleted_at IS NULL`
    REGARDLESS of as_of. Reaching for the wrong one either rewrites history
    or fails to remove a mistake."""
    from noctornal_api.projections import GraphService, Projection
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    hub = _new_node(client, token, case_id, "hub")
    a = _new_node(client, token, case_id, "alpha")
    tie = _new_edge(client, token, case_id, hub, a)
    hub_uuid, a_uuid, tie_uuid = UUID(hub), UUID(a), UUID(tie)

    before = datetime.now(timezone.utc)
    svc = GraphService(conn, clearance="RED", compartments=frozenset())
    live = svc.project(Projection(case_id=UUID(case_id)))
    assert hub_uuid in live.node_ids()
    assert tie_uuid in {e["id"] for e in live.edges}

    assert _retire(client, token, case_id, "nodes", hub).status_code == 200

    now = svc.project(Projection(case_id=UUID(case_id)))
    assert hub_uuid not in now.node_ids()
    assert a_uuid in now.node_ids(), "the surviving node is untouched"
    assert tie_uuid not in {e["id"] for e in now.edges}

    past = svc.project(Projection(case_id=UUID(case_id), as_of=before))
    assert hub_uuid not in past.node_ids(), (
        "a retirement is not temporal validity: it removes the element from "
        "as-of views of the past too")


def test_a_second_retirement_is_a_409_not_a_silent_success(conn, client):
    """"Already retired" is a fact about an element the caller has just
    been cleared for, so saying it discloses nothing new — and a silent
    200 would let a script believe it had retired something twice."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    assert _retire(client, token, case_id, "nodes", a).status_code == 200

    again = _retire(client, token, case_id, "nodes", a)
    assert again.status_code == 409, again.text
    assert "retired" in again.text


def test_a_retired_element_cannot_be_corrected(conn, client):
    """Editing something already out of the case file writes an assertion
    nobody will ever see rendered."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)
    assert _retire(client, token, case_id, "edges", tie).status_code == 200

    r = _patch(client, token, case_id, "edges", tie, {"weight": 5})
    assert r.status_code == 409, r.text
    assert float(_edge_row(conn, tie)[0]) == 1.0
    assert _assertion_count(conn, "edge_id", tie) == 1, (
        "a refused correction leaves no assertion")


def test_a_retirement_needs_a_written_reason(conn, client):
    """Retiring a node dissolves every tie it carries, and the one thing a
    reviewer cannot reconstruct six months later is what the analyst was
    thinking. `reason` is required and may not be empty."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    path = f"/api/v1/cases/{case_id}/graph/nodes/{a}"

    assert client.request("DELETE", path, headers=_auth(token),
                          json={}).status_code == 422
    assert client.request("DELETE", path, headers=_auth(token),
                          json={"reason": ""}).status_code == 422
    assert _node_row(conn, a)[2] is None, "neither refusal retired anything"


def test_a_merged_node_cannot_be_retired(conn, client):
    """Invariant 3 requires merges to be reversible. `unmerge` restores the
    loser's edges and clears the redirect — it does NOT clear `deleted_at`,
    so retiring a merged-away node would leave the reversal restoring live
    edges onto a deleted endpoint: a merge that reports itself reversed
    while being irreversible in effect."""
    uid, token = _owner(conn, client)
    case_id = _create_case(client, token)
    loser = _new_node(client, token, case_id, "loser")
    winner = _new_node(client, token, case_id, "winner")
    conn.execute(
        "UPDATE core.node SET merged_into_id = %s, merged_at = now(), "
        "merged_by = %s WHERE id = %s", (winner, uid, loser))

    r = _retire(client, token, case_id, "nodes", loser)
    assert r.status_code == 409, r.text
    assert "reverse the merge" in r.text
    assert _node_row(conn, loser)[2] is None


def test_a_correction_to_a_merged_node_says_it_will_not_appear(conn, client):
    """The edit is allowed — unmerging restores the node with whatever
    label it now carries — but a 200 the analyst reads as "done" and then
    cannot find on the canvas is a silent drop (invariant 12)."""
    uid, token = _owner(conn, client)
    case_id = _create_case(client, token)
    loser = _new_node(client, token, case_id, "loser")
    winner = _new_node(client, token, case_id, "winner")
    conn.execute(
        "UPDATE core.node SET merged_into_id = %s, merged_at = now(), "
        "merged_by = %s WHERE id = %s", (winner, uid, loser))

    r = _patch(client, token, case_id, "nodes", loser, {"label": "corrected"})
    assert r.status_code == 200, r.text
    assert r.json()["merged_into_id"] == winner
    assert "merged into another" in r.json()["note"]
    assert _node_row(conn, loser)[0] == "corrected"


# =======================================================================
# CORRECTIONS — invariants 1 and 5
# =======================================================================

def test_invariant_1_a_correction_carries_its_own_assertion(conn, client):
    """"We corrected this" is a claim about the world and needs a basis
    like any other. The original assertion stays, so the SEQUENCE of
    assertions is the audit of what this element has been called."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "basterlord")
    assert _assertion_count(conn, "node_id", a) == 1

    r = _patch(client, token, case_id, "nodes", a,
               {"label": "bassterlord",
                "assertion": {"basis": "DIRECT_OBSERVATION",
                              "reliability": "B", "credibility": "2"}})
    assert r.status_code == 200, r.text
    assert r.json()["updated"] == ["label"]
    assert _assertion_count(conn, "node_id", a) == 2

    # A single changed field names itself, and the claim carries the new
    # value — which is the only place the NEW value is recoverable from
    # once someone corrects it again.
    # `recorded_at`, not `created_at`: core.assertion distinguishes when we
    # WROTE the claim down from `observed_at`, when the thing was seen. The
    # column this originally ordered by does not exist on this table.
    claim = conn.execute(
        "SELECT claim_path, claim_value FROM core.assertion "
        " WHERE node_id = %s ORDER BY recorded_at DESC LIMIT 1", (a,)).fetchone()
    assert claim[0] == "label"
    assert claim[1] == {"label": "bassterlord"}
    assert _node_row(conn, a)[0] == "bassterlord"


def test_invariant_5_the_overwritten_label_reaches_the_audit_log(conn, client):
    """`update_node` does a destructive UPDATE on the one column that held
    the old label. The new value is recoverable from the assertion; the old
    one is recoverable from nowhere else, so for this column the audit row
    IS the superseded history."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "typo", attrs={"role": "broker"})

    assert _patch(client, token, case_id, "nodes", a,
                  {"label": "fixed"}).status_code == 200
    detail = _audit(conn, "NODE_UPDATED", a)
    assert detail is not None, "the correction must be audited"
    assert detail["fields"] == ["label"]
    assert detail["previous"] == {"label": "typo"}


def test_the_previous_edge_weight_is_recorded_without_rounding(conn, client):
    """`weight` is numeric(14,4). Rounding it to a float to get it into the
    audit row would corrupt the very value the row exists to preserve —
    CONVENTIONS: weights are numeric, never float."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)
    # `CreateEdgeBody` carries no weight (every edge is created at 1.0), so
    # the interesting scale is set directly — the point of this test is the
    # AUDIT round-trip, not how the value got there.
    conn.execute("UPDATE core.edge SET weight = 3.1416 WHERE id = %s", (tie,))
    before = _edge_row(conn, tie)[0]

    assert _patch(client, token, case_id, "edges", tie,
                  {"weight": 1.5}).status_code == 200
    detail = _audit(conn, "EDGE_UPDATED", tie)
    assert detail["previous"]["weight"] == str(before)
    assert str(before) == "3.1416", "the stored scale is preserved as text"
    assert float(_edge_row(conn, tie)[0]) == 1.5


def test_an_empty_correction_is_refused_and_leaves_no_assertion(conn, client):
    """Invariant 12. Accepting it silently would leave an assertion behind
    claiming a correction that never happened, and an audit row saying the
    same."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")

    r = _patch(client, token, case_id, "nodes", a, {})
    assert r.status_code == 400, r.text
    assert _assertion_count(conn, "node_id", a) == 1
    assert _audit(conn, "NODE_UPDATED", a) is None

    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)
    assert _patch(client, token, case_id, "edges", tie, {}).status_code == 400
    assert _assertion_count(conn, "edge_id", tie) == 1
    assert _audit(conn, "EDGE_UPDATED", tie) is None


def test_attrs_is_whole_object_replacement_not_a_merge(conn, client):
    """The service's semantics (`COALESCE(%s, attrs)`), pinned here because
    the alternative reading — "PATCH merges" — is the one a caller assumes
    from the verb, and assuming it silently deletes attributes."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha",
                  attrs={"role": "broker", "country": "RU"})

    assert _patch(client, token, case_id, "nodes", a,
                  {"attrs": {"role": "broker"}}).status_code == 200
    assert _node_row(conn, a)[1] == {"role": "broker"}, (
        "country is gone: attrs is replaced wholesale, not merged")

    # Omitting the field entirely leaves attributes untouched...
    assert _patch(client, token, case_id, "nodes", a,
                  {"label": "alpha prime"}).status_code == 200
    assert _node_row(conn, a)[1] == {"role": "broker"}
    # ...and an explicit empty object clears them.
    assert _patch(client, token, case_id, "nodes", a,
                  {"attrs": {}}).status_code == 200
    assert _node_row(conn, a)[1] == {}


def test_sign_is_not_reachable_through_the_correction_verb(conn, client):
    """Flipping a vouch into an accusation is a different claim, not a typo
    fix: `analytics.py` re-derives every triad from `sign`, and the
    disagreement should survive as its own edge. `UpdateEdgeBody` has no
    `sign` and no `edge_type` field, so neither can arrive through here."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)       # VOUCHED_FOR, sign +1
    before_sign, before_type = conn.execute(
        "SELECT sign, edge_type FROM core.edge WHERE id = %s", (tie,)).fetchone()

    r = _patch(client, token, case_id, "edges", tie,
               {"weight": 2, "sign": -1, "edge_type": "ACCUSED_SCAM"})
    # Whether the unknown fields are ignored (pydantic's default) or the
    # body is refused outright, the property under test is the same one.
    assert r.status_code in (200, 422), r.text
    after_sign, after_type = conn.execute(
        "SELECT sign, edge_type FROM core.edge WHERE id = %s", (tie,)).fetchone()
    assert after_sign == before_sign, "a vouch must not become an accusation here"
    assert after_type == before_type


def test_a_negative_or_oversized_weight_is_422(conn, client):
    """Direction lives in `sign`; a negative weight would silently invert
    the balance and centrality arithmetic. The bounds mirror
    numeric(14,4), so an out-of-range value is a sentence rather than a
    driver overflow."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)

    assert _patch(client, token, case_id, "edges", tie,
                  {"weight": -1}).status_code == 422
    assert _patch(client, token, case_id, "edges", tie,
                  {"weight": 1e12}).status_code == 422
    assert float(_edge_row(conn, tie)[0]) == 1.0


def test_an_unknown_confidence_is_refused_without_leaking_the_schema(
        conn, client):
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")
    b = _new_node(client, token, case_id, "bravo")
    tie = _new_edge(client, token, case_id, a, b)

    r = _patch(client, token, case_id, "edges", tie, {"confidence": "CERTAIN"})
    assert r.status_code == 400, r.text
    for leaked in ("Traceback", "PL/pgSQL", "CONTEXT:", "DETAIL:"):
        assert leaked not in r.text, leaked
    assert _edge_row(conn, tie)[1] == "LOW"
    assert _assertion_count(conn, "edge_id", tie) == 1
    assert _audit(conn, "EDGE_UPDATED", tie) is None


def test_an_exhibit_outside_this_case_cannot_be_cited(conn, client):
    """An exhibit may only support a claim in ITS OWN case. Otherwise a
    correction could cite an exhibit from a case the caller has no access
    to, and the assertion would then display a title and hash they were
    never cleared to see. 404 rather than 403, for the usual reason.

    **Stated exactly:** this cites an id that exists nowhere. `_check_evidence`
    is one query — `WHERE id = %s AND case_id = %s` — so an exhibit that
    exists in ANOTHER case takes the identical path to the identical 404;
    what this test does not do is construct one, because ingesting a real
    exhibit needs MinIO and this suite is DATABASE_URL-only.
    """
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")

    r = _patch(client, token, case_id, "nodes", a,
               {"label": "corrected",
                "assertion": {"evidence_id": str(uuid4())}})
    assert r.status_code == 404, r.text
    assert "exhibit" in r.text
    assert _node_row(conn, a)[0] == "alpha"
    assert _assertion_count(conn, "node_id", a) == 1


def test_classification_is_not_editable_through_a_correction(conn, client):
    """Re-labelling an element's TLP changes who can see it and whether it
    may leave the platform — an egress decision (invariant 8), not a typo
    fix. Folding it into the same call as "correct the spelling" would let
    a routine edit silently widen distribution."""
    _, token = _owner(conn, client)
    case_id = _create_case(client, token)
    a = _new_node(client, token, case_id, "alpha")     # AMBER

    r = _patch(client, token, case_id, "nodes", a,
               {"label": "alpha prime", "classification": "GREEN",
                "compartments": ["OPERATION-X"]})
    assert r.status_code in (200, 422), r.text
    row = conn.execute(
        "SELECT classification, compartments FROM core.node WHERE id = %s",
        (a,)).fetchone()
    assert row[0] == "AMBER", "the label must be unchanged"
    assert list(row[1] or []) == []
