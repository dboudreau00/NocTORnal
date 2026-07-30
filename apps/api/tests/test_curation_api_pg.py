"""The curation router over HTTP: tags and node sets, and what they refuse.

`TagService` and `NodeSetService` have been green since Phase 1 and had no
router, no endpoint and no caller outside their own tests -- the dead
subsystem the 2026-07-26 call-site audit found. `test_curation_pg.py`
covers the services; nothing there touches authorisation, because a service
has none. This file covers the half that only the router holds:

- a `tag_id`, `set_id`, `node_id` or `parent_id` from ANOTHER case is 404,
  never 403 and never 200 -- the route gate authorises against the
  `case_id` in the PATH, so an id from elsewhere would be operated on under
  an authorisation that never covered it;
- 404 and not 403, so none of these endpoints is an existence oracle: the
  answer for a foreign id and for a random UUID is asserted to be
  BYTE-IDENTICAL, not merely both-4xx;
- `curation.manage` is held by CASE_OWNER and ANALYST only (migration
  0053), so a CONTRIBUTOR or READ_ONLY assignee reads the overlay and
  cannot write it;
- the five-part gate is re-run against the NODE's own labels, because a RED
  node can live in an AMBER case and attaching an overlay to it is a write
  against the node;
- nothing here writes `core.assertion` or `core.edge` (invariants 1 and
  docs/01's reason for keeping working sets out of the graph);
- a member the caller cannot see is REPORTED as withheld, never silently
  dropped (invariant 12);
- every removal reaches `audit.event`, because `core.tag_assignment` and
  `core.node_set_member` record nothing about who removed a row.

**The email prefix is `curh-` and must stay unique.** Every `_pg` fixture
in this tree tears down by deleting on an email pattern, so two files
sharing a prefix delete each other's rows -- which surfaces as a foreign-key
error in whichever file tears down second, pointing at a table neither test
touched. `test_curation_pg.py` owns `cur-`, and `LIKE 'cur-%'` does not
match `curh-...` (the hyphen is literal), so the two coexist.

Global tags are the other shared-state trap: `core.tag.case_id IS NULL` is
outside any case-scoped sweep, so the ones created here carry a `curh-`
NAMESPACE and the teardown removes them by it.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; curation HTTP e2e is gated"
)

PASSWORD = "correct-horse-battery-staple"

# Set at import, exactly as the other HTTP e2e suites do: skipping instead
# would be worse than useless, because CI fails the run if any test skips.
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c

    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'curh-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    nsub = f"(SELECT id FROM core.node WHERE case_id IN {csub})"
    # Both halves of this suite's tag surface: the case-scoped ones, and the
    # GLOBAL taxonomy entries (case_id IS NULL) that no case-scoped sweep can
    # reach. The namespace is what makes the second half findable.
    tsub = (f"(SELECT id FROM core.tag WHERE case_id IN {csub} "
            f"    OR (case_id IS NULL AND namespace LIKE 'curh-%'))")

    # ONE transaction, deliberately. `assertion_protects_element` (0022) is a
    # DEFERRABLE INITIALLY DEFERRED constraint trigger: it fires at COMMIT and
    # refuses to let the last assertion of a STILL-EXISTING node go. Deleting
    # assertions and nodes in separate transactions would trip it; in one, the
    # node is already gone by the time the check runs.
    with c.transaction():
        c.execute(f"DELETE FROM core.tag_assignment "
                  f" WHERE node_id IN {nsub} OR tag_id IN {tsub}")
        c.execute(f"DELETE FROM core.node_set_member WHERE set_id IN "
                  f"(SELECT id FROM core.node_set WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.node_set WHERE case_id IN {csub}")
        # `core.tag.parent_id` is a self-FK (hierarchical taxonomies), so the
        # children have to stop pointing at the parents before either goes.
        c.execute(f"UPDATE core.tag SET parent_id = NULL WHERE id IN {tsub}")
        c.execute(f"DELETE FROM core.tag WHERE id IN {tsub}")
        # Same shape on core.node: a merged-away node points at its survivor.
        c.execute(f"UPDATE core.node SET merged_into_id = NULL "
                  f" WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user "
                  " WHERE email LIKE 'curh-%@noctornal.test'")
        # audit.event is NOT cleaned: it is append-only (invariant 6) and the
        # trigger would refuse. Nothing references it.
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    # A limiter this test owns: Redis is shared and blind to test boundaries,
    # so one test's budget would be another test's flake.
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- helpers ------------------------------------------------------------

def _make_user(conn, *, clearance="RED", global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"curh-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Curation", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
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


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-CURH-{uuid4().hex[:6]}", "title": "Operation Curation",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, user_id, role="ANALYST"):
    """Put a user on a case in a given role. The five-part gate reads the
    verb off the case ASSIGNMENT, not off a global role, so this is what
    decides whether `curation.manage` is held."""
    owner = conn.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone()[0]
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user_id, role, owner))


def _node(client, token, case_id, label, *, classification="AMBER") -> str:
    """A node through the real write path, so it carries its assertion
    (invariant 1) rather than being conjured straight into the table."""
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": label,
                          "classification": classification,
                          "assertion": {"basis": "DIRECT_OBSERVATION"}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _tag(client, token, case_id, *, namespace="ttp", name=None, **extra) -> str:
    body = {"namespace": namespace, "name": name or f"t-{uuid4().hex[:8]}"}
    body.update(extra)
    r = client.post(f"/api/v1/cases/{case_id}/curation/tags",
                    headers=_auth(token), json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _set(client, token, case_id, *, name=None, **extra) -> str:
    body = {"name": name or f"watchlist-{uuid4().hex[:6]}"}
    body.update(extra)
    r = client.post(f"/api/v1/cases/{case_id}/curation/sets",
                    headers=_auth(token), json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _global_tag(conn, *, name=None) -> tuple:
    """A GLOBAL taxonomy entry (case_id NULL) -- the MITRE ATT&CK shape that
    `external_id` exists for.

    Inserted directly because there is deliberately no endpoint that creates
    one: `CreateTagBody` has no `case_id` field, so a holder of
    `curation.manage` on one case can never author shared reference data.
    The `curh-` namespace is what lets the teardown find it again.
    """
    namespace = f"curh-{uuid4().hex[:8]}"
    name = name or "T1566"
    tag_id = conn.execute(
        """INSERT INTO core.tag (case_id, namespace, name, external_id)
           VALUES (NULL, %s, %s, %s) RETURNING id""",
        (namespace, name, name),
    ).fetchone()[0]
    return str(tag_id), namespace, name


@pytest.fixture
def owner(conn, client):
    """A logged-in CASE_OWNER (so: `curation.manage`) with a case."""
    uid, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    return uid, token, _create_case(client, token)


# ---------------------------------------------------------------------------
# Wiring. This subsystem's entire defect was being built, green and
# unreachable -- so "is it actually mounted" is a test, not an assumption.
# ---------------------------------------------------------------------------

def test_the_curation_router_is_mounted():
    """Asserted against the route table rather than by probing for a
    non-404, because "no such route" and "404 by design" are the two answers
    every other test in this file has to tell apart. If app.py forgets the
    include_router, this fails on its own and unambiguously.

    Reads the application directly rather than `client.app`, which is a
    TestClient implementation detail.

    THE ROUTE TABLE IS THE OPENAPI SCHEMA, NOT `app.routes`. This app wraps
    every `include_router` call in a `_IncludedRouter`, of which there are
    26 and NONE exposes a `.path`. Reading `app.routes` returns exactly
    three usable entries — `/`, `/healthz` and the `/ui` Mount — so a
    membership check against it fails for every API path in the tree,
    including ones that have shipped for months. The generated schema is
    the only view that enumerates them.
    """
    from noctornal_api.http.app import create_app
    paths = set(create_app().openapi()["paths"])
    for path in ("/api/v1/cases/{case_id}/curation/tags",
                 "/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                 "/api/v1/cases/{case_id}/curation/nodes/{node_id}/tags",
                 "/api/v1/cases/{case_id}/curation/sets",
                 "/api/v1/cases/{case_id}/curation/sets/{set_id}/members"):
        assert path in paths, path


def test_curation_routes_need_authentication(client):
    case_id = str(uuid4())
    base = f"/api/v1/cases/{case_id}/curation"
    for path in (f"{base}/tags", f"{base}/sets",
                 f"{base}/nodes/{uuid4()}/tags",
                 f"{base}/sets/{uuid4()}/members"):
        assert client.get(path).status_code == 401, path
    assert client.post(f"{base}/tags",
                       json={"namespace": "ttp", "name": "x"}).status_code == 401
    assert client.delete(
        f"{base}/tags/{uuid4()}/nodes/{uuid4()}").status_code == 401


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------

def test_a_tag_round_trips_and_carries_its_scope(client, owner, conn):
    _, token, case_id = owner
    node = _node(client, token, case_id, "bassterlord")

    created = client.post(f"/api/v1/cases/{case_id}/curation/tags",
                          headers=_auth(token),
                          json={"namespace": "ttp", "name": "phishing",
                                "colour": "#F76B1C", "external_id": "T1566"})
    assert created.status_code == 201, created.text
    tag_id = created.json()["id"]
    # `scope` rather than a raw case_id: a client must be able to tell a
    # case-local label from shared reference data outright.
    assert created.json()["scope"] == "case"

    listed = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                        headers=_auth(token))
    assert listed.status_code == 200, listed.text
    mine = [t for t in listed.json() if t["id"] == tag_id]
    assert len(mine) == 1
    assert mine[0]["visible_node_count"] == 0
    assert mine[0]["external_id"] == "T1566"

    assigned = client.post(
        f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
        headers=_auth(token), json={"node_id": node})
    # 201 only when something was actually created.
    assert assigned.status_code == 201, assigned.text
    assert assigned.json()["created"] is True

    on_node = client.get(
        f"/api/v1/cases/{case_id}/curation/nodes/{node}/tags",
        headers=_auth(token))
    assert on_node.status_code == 200, on_node.text
    assert [t["id"] for t in on_node.json()] == [tag_id]

    listed = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                        headers=_auth(token))
    assert [t for t in listed.json() if t["id"] == tag_id
            ][0]["visible_node_count"] == 1

    gone = client.delete(
        f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes/{node}",
        headers=_auth(token))
    assert gone.status_code == 204
    assert client.get(f"/api/v1/cases/{case_id}/curation/nodes/{node}/tags",
                      headers=_auth(token)).json() == []


def test_assigning_the_same_tag_twice_writes_one_row(client, owner, conn):
    """`core.tag_assignment` has no primary key and no unique index (0009),
    so INSERT twice inserts twice and the tag then renders twice with no
    `ON CONFLICT` target available to write instead. Re-tagging is one
    double-click away, so the duplicate is the expected case."""
    _, token, case_id = owner
    node = _node(client, token, case_id, "double click")
    tag_id = _tag(client, token, case_id)
    url = f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes"

    first = client.post(url, headers=_auth(token), json={"node_id": node})
    assert first.status_code == 201 and first.json()["created"] is True
    second = client.post(url, headers=_auth(token), json={"node_id": node})
    # 200, not 201: a blanket 201 on the no-op would tell a client it made a
    # change it did not make.
    assert second.status_code == 200 and second.json()["created"] is False

    assert conn.execute(
        "SELECT count(*) FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
        (tag_id, node)).fetchone()[0] == 1


def test_removing_an_assignment_that_is_not_there_is_still_204(client, owner):
    """A retried DELETE must not look like a failure."""
    _, token, case_id = owner
    node = _node(client, token, case_id, "never tagged")
    tag_id = _tag(client, token, case_id)
    url = f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes/{node}"
    assert client.delete(url, headers=_auth(token)).status_code == 204
    assert client.delete(url, headers=_auth(token)).status_code == 204


def test_a_duplicate_tag_is_409_and_whitespace_cannot_fork_the_vocabulary(
        client, owner, conn):
    """The uniqueness indexes are over the exact text, so " phishing" and
    "phishing" would become two tags that render identically -- a controlled
    vocabulary that quietly is not one.

    409 rather than the 400 the global `CurationError` handler gives: a
    duplicate is a state conflict, not a malformed request, and a client
    that wants "create or reuse" needs to tell them apart.
    """
    _, token, case_id = owner
    url = f"/api/v1/cases/{case_id}/curation/tags"

    first = client.post(url, headers=_auth(token),
                        json={"namespace": " ttp ", "name": " phishing "})
    assert first.status_code == 201, first.text
    assert first.json()["namespace"] == "ttp"
    assert first.json()["name"] == "phishing"
    assert conn.execute("SELECT namespace, name FROM core.tag WHERE id = %s",
                        (first.json()["id"],)).fetchone() == ("ttp", "phishing")

    again = client.post(url, headers=_auth(token),
                        json={"namespace": "ttp", "name": "phishing"})
    assert again.status_code == 409, again.text


def test_a_blank_name_is_refused(client, owner):
    _, token, case_id = owner
    url = f"/api/v1/cases/{case_id}/curation/tags"
    # Whitespace-only passes the Pydantic length bound and is caught after.
    r = client.post(url, headers=_auth(token),
                    json={"namespace": "ttp", "name": "   "})
    assert r.status_code == 400 and "blank" in r.text
    r = client.post(url, headers=_auth(token),
                    json={"namespace": "  ", "name": "phishing"})
    assert r.status_code == 400 and "blank" in r.text


def test_a_colour_must_be_a_hex_value(client, owner):
    """The colour is rendered by the analyst UI and ends up in a style
    attribute or a CSS custom property. Free text there is a stored
    injection into every analyst who opens the case."""
    _, token, case_id = owner
    url = f"/api/v1/cases/{case_id}/curation/tags"
    for bad in ("red;background:url(//evil.test/x)",
                "javascript:alert(1)", "#12345", "rgb(255,0,0)", ""):
        r = client.post(url, headers=_auth(token),
                        json={"namespace": "ttp", "name": f"c-{uuid4().hex[:6]}",
                              "colour": bad})
        assert r.status_code == 422, f"{bad!r} was accepted: {r.text}"
    for good in ("#F76B1C", "#f00"):
        r = client.post(url, headers=_auth(token),
                        json={"namespace": "ttp", "name": f"c-{uuid4().hex[:6]}",
                              "colour": good})
        assert r.status_code == 201, r.text


def test_the_body_cannot_choose_the_case(client, owner, conn):
    """`CreateTagBody` has no `case_id`, so a tag created through a
    case-scoped route is always a tag of THAT case. A body field would let a
    holder of `curation.manage` on one case write into another case (or into
    the shared global taxonomy) under an authorisation that only ever
    covered their own."""
    _, token, case_id = owner
    other = _create_case(client, token)
    r = client.post(f"/api/v1/cases/{case_id}/curation/tags",
                    headers=_auth(token),
                    json={"namespace": "ttp", "name": f"p-{uuid4().hex[:6]}",
                          "case_id": other})
    assert r.status_code == 201, r.text
    assert str(conn.execute("SELECT case_id FROM core.tag WHERE id = %s",
                            (r.json()["id"],)).fetchone()[0]) == case_id


# ---------------------------------------------------------------------------
# Invariant 1, and docs/01's reason for keeping working sets out of the graph
# ---------------------------------------------------------------------------

def test_curation_writes_no_assertion_and_no_edge(client, owner, conn):
    """Invariant 1 is not weakened by anything in this router, because
    nothing here writes a node attribute or an edge. A tag is not a claim
    ABOUT the entity, it is a note about the ANALYSIS -- `TAGGED "CONFIRMED
    LAUNDERER"` is not an assessment, and the assessment goes through
    /nodes/{id}/assertions with a source, an Admiralty grading and a time.

    And a node set is not forty edges: docs/01 keeps working sets out of the
    graph precisely so "these accounts are on my desk this week" does not
    distort every centrality number in the case.
    """
    _, token, case_id = owner
    node = _node(client, token, case_id, "accountant")
    # One assertion: the one the node's own create wrote.
    before = conn.execute(
        "SELECT count(*) FROM core.assertion WHERE case_id = %s",
        (case_id,)).fetchone()[0]
    assert before == 1

    tag_id = _tag(client, token, case_id, name="CONFIRMED LAUNDERER")
    assert client.post(f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                       headers=_auth(token),
                       json={"node_id": node}).status_code == 201
    set_id = _set(client, token, case_id)
    assert client.post(f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
                       headers=_auth(token),
                       json={"node_id": node, "note": "prime suspect"}
                       ).status_code == 201

    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE case_id = %s",
        (case_id,)).fetchone()[0] == before
    assert conn.execute(
        "SELECT count(*) FROM core.edge WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0


# ---------------------------------------------------------------------------
# Same-case verification. The repo has shipped this defect class before
# (evidence.py, then comms.py), so every caller-supplied id gets a test.
# ---------------------------------------------------------------------------

def test_a_tag_from_another_case_cannot_be_assigned(client, owner, conn):
    """The route gate authorised against the case in the PATH; the tag id
    came from the body's URL segment and could name anything."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_tag = _tag(client, token, theirs, name="their-vocabulary")
    node = _node(client, token, case_id, "mine")

    r = client.post(
        f"/api/v1/cases/{case_id}/curation/tags/{foreign_tag}/nodes",
        headers=_auth(token), json={"node_id": node})
    assert r.status_code == 404, r.text
    assert conn.execute(
        "SELECT count(*) FROM core.tag_assignment WHERE tag_id = %s",
        (foreign_tag,)).fetchone()[0] == 0


def test_a_node_from_another_case_cannot_be_tagged(client, owner, conn):
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_node = _node(client, token, theirs, "their actor")
    tag_id = _tag(client, token, case_id)

    r = client.post(f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                    headers=_auth(token), json={"node_id": foreign_node})
    assert r.status_code == 404, r.text
    assert conn.execute(
        "SELECT count(*) FROM core.tag_assignment WHERE node_id = %s",
        (foreign_node,)).fetchone()[0] == 0


def test_a_parent_tag_from_another_case_is_refused_and_nothing_is_created(
        client, owner, conn):
    """A parent from another case builds a hierarchy whose upper levels the
    caller cannot see, and leaks that case's vocabulary through any tree
    render. The child must not be created either -- a 404 that still wrote a
    row is not a refusal."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_parent = _tag(client, token, theirs, name="their-parent")

    name = f"child-{uuid4().hex[:8]}"
    r = client.post(f"/api/v1/cases/{case_id}/curation/tags",
                    headers=_auth(token),
                    json={"namespace": "ttp", "name": name,
                          "parent_id": foreign_parent})
    assert r.status_code == 404, r.text
    assert conn.execute(
        "SELECT count(*) FROM core.tag WHERE name = %s", (name,)
    ).fetchone()[0] == 0


def test_a_node_set_from_another_case_is_not_reachable(client, owner, conn):
    """`core.node_set.case_id` is NOT NULL, so unlike tags there is no
    global form: a set from another case is always 404, on all three of its
    endpoints."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_set = _set(client, token, theirs, name="their watchlist")
    node = _node(client, token, case_id, "mine")

    base = f"/api/v1/cases/{case_id}/curation/sets/{foreign_set}"
    assert client.post(f"{base}/members", headers=_auth(token),
                       json={"node_id": node}).status_code == 404
    assert client.get(f"{base}/members", headers=_auth(token)).status_code == 404
    assert client.delete(f"{base}/members/{node}",
                         headers=_auth(token)).status_code == 404
    assert conn.execute(
        "SELECT count(*) FROM core.node_set_member WHERE set_id = %s",
        (foreign_set,)).fetchone()[0] == 0


def test_a_node_from_another_case_cannot_join_a_set(client, owner, conn):
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_node = _node(client, token, theirs, "their actor")
    set_id = _set(client, token, case_id)

    r = client.post(f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
                    headers=_auth(token), json={"node_id": foreign_node})
    assert r.status_code == 404, r.text
    assert conn.execute(
        "SELECT count(*) FROM core.node_set_member WHERE node_id = %s",
        (foreign_node,)).fetchone()[0] == 0


def test_the_tags_of_a_node_in_another_case_are_not_readable(client, owner):
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_node = _node(client, token, theirs, "their actor")
    assert client.get(
        f"/api/v1/cases/{case_id}/curation/nodes/{foreign_node}/tags",
        headers=_auth(token)).status_code == 404
    # ...and it IS readable under its own case, so the 404 above is the
    # same-case check and not a broken endpoint.
    assert client.get(
        f"/api/v1/cases/{theirs}/curation/nodes/{foreign_node}/tags",
        headers=_auth(token)).status_code == 200


def test_a_foreign_path_cannot_remove_a_legitimate_assignment(
        client, owner, conn):
    """The removal paths take `require_live=False`, so they are the ones
    most likely to skip a check. A DELETE issued under case B against an
    assignment that belongs to case A must not land."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    node = _node(client, token, case_id, "mine")
    tag_id = _tag(client, token, case_id)
    set_id = _set(client, token, case_id)
    assert client.post(f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                       headers=_auth(token),
                       json={"node_id": node}).status_code == 201
    assert client.post(f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
                       headers=_auth(token),
                       json={"node_id": node}).status_code == 201

    assert client.delete(
        f"/api/v1/cases/{theirs}/curation/tags/{tag_id}/nodes/{node}",
        headers=_auth(token)).status_code == 404
    assert client.delete(
        f"/api/v1/cases/{theirs}/curation/sets/{set_id}/members/{node}",
        headers=_auth(token)).status_code == 404

    assert conn.execute(
        "SELECT count(*) FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
        (tag_id, node)).fetchone()[0] == 1
    assert conn.execute(
        "SELECT count(*) FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
        (set_id, node)).fetchone()[0] == 1


def test_a_foreign_id_is_indistinguishable_from_a_nonexistent_one(
        client, owner):
    """404 rather than 403 is only half the property. If the two answers
    differed in ANY respect -- status, title, detail -- these endpoints would
    still be an existence oracle for another case's vocabulary, working sets
    and entities. So they are asserted byte-identical."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    node = _node(client, token, case_id, "mine")

    foreign_tag = _tag(client, token, theirs)
    foreign_set = _set(client, token, theirs)
    foreign_node = _node(client, token, theirs, "theirs")

    probes = (
        ("post", f"/api/v1/cases/{case_id}/curation/tags/{{}}/nodes",
         {"node_id": node}, foreign_tag),
        ("post", f"/api/v1/cases/{case_id}/curation/sets/{{}}/members",
         {"node_id": node}, foreign_set),
        ("get", f"/api/v1/cases/{case_id}/curation/nodes/{{}}/tags",
         None, foreign_node),
        ("get", f"/api/v1/cases/{case_id}/curation/sets/{{}}/members",
         None, foreign_set),
    )
    for method, template, body, real_id in probes:
        call = getattr(client, method)
        kwargs = {"headers": _auth(token)}
        if body is not None:
            kwargs["json"] = body
        existing = call(template.format(real_id), **kwargs)
        absent = call(template.format(uuid4()), **kwargs)
        assert existing.status_code == 404, template
        assert absent.status_code == 404, template
        assert existing.json() == absent.json(), (
            f"{template} distinguishes an id that exists in another case "
            f"from one that does not exist at all")


def test_a_foreign_tag_never_renders_on_a_node_in_this_case(
        client, owner, conn):
    """Defence in depth against the data defect itself. A `tag_assignment`
    joining another case's tag to a node in this one should not exist -- but
    if one did, rendering its namespace and name would turn that defect into
    a cross-case disclosure. The read path filters on the TAG's case too."""
    _, token, case_id = owner
    uid = conn.execute('SELECT owner_user_id FROM core."case" WHERE id = %s',
                       (case_id,)).fetchone()[0]
    theirs = _create_case(client, token)
    foreign_tag = _tag(client, token, theirs, name="CROSS-CASE-LEAK-CANARY")
    node = _node(client, token, case_id, "mine")

    conn.execute(
        """INSERT INTO core.tag_assignment (tag_id, node_id, assigned_by)
           VALUES (%s, %s, %s)""", (foreign_tag, node, uid))

    r = client.get(f"/api/v1/cases/{case_id}/curation/nodes/{node}/tags",
                   headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.json() == []
    assert "CROSS-CASE-LEAK-CANARY" not in r.text


# ---------------------------------------------------------------------------
# The one deliberate exception: the shared global taxonomy
# ---------------------------------------------------------------------------

def test_a_global_tag_may_be_assigned_in_a_case(client, owner, conn):
    """`core.tag.case_id` is NULLABLE by design and the two partial unique
    indexes exist so a global entry and a case-local one can share a name. A
    global tag is the MITRE technique row `external_id` was added for --
    shared reference data, not the content of anybody's case. Refusing it
    would push analysts into re-creating T1566 once per case, which is how a
    controlled vocabulary dies."""
    _, token, case_id = owner
    tag_id, _, name = _global_tag(conn)
    node = _node(client, token, case_id, "phisher")

    r = client.post(f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                    headers=_auth(token), json={"node_id": node})
    assert r.status_code == 201, r.text

    on_node = client.get(f"/api/v1/cases/{case_id}/curation/nodes/{node}/tags",
                         headers=_auth(token))
    assert on_node.status_code == 200
    entry = [t for t in on_node.json() if t["id"] == tag_id]
    assert len(entry) == 1
    # Never confused with a case-local label.
    assert entry[0]["scope"] == "global"
    assert entry[0]["name"] == name


def test_the_global_taxonomy_can_be_excluded_from_the_picker(client, owner, conn):
    _, token, case_id = owner
    tag_id, _, _ = _global_tag(conn)
    local = _tag(client, token, case_id)

    with_global = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                             headers=_auth(token))
    assert tag_id in {t["id"] for t in with_global.json()}
    assert {t["scope"] for t in with_global.json()} >= {"case", "global"}

    without = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                         headers=_auth(token), params={"include_global": False})
    ids = {t["id"] for t in without.json()}
    assert tag_id not in ids
    assert local in ids


def test_a_global_tags_count_does_not_span_cases(client, owner, conn):
    """Without the `n.case_id` predicate in the count's EXISTS, a GLOBAL
    tag's `visible_node_count` would aggregate every case in the deployment
    and turn the tag list into a cross-case volume oracle: "T1566 is on 340
    nodes" out of cases the caller cannot open."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    tag_id, _, _ = _global_tag(conn)
    their_node = _node(client, token, theirs, "their phisher")

    assert client.post(f"/api/v1/cases/{theirs}/curation/tags/{tag_id}/nodes",
                       headers=_auth(token),
                       json={"node_id": their_node}).status_code == 201

    here = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                      headers=_auth(token)).json()
    assert [t for t in here if t["id"] == tag_id][0]["visible_node_count"] == 0
    there = client.get(f"/api/v1/cases/{theirs}/curation/tags",
                       headers=_auth(token)).json()
    assert [t for t in there if t["id"] == tag_id][0]["visible_node_count"] == 1


# ---------------------------------------------------------------------------
# The verb. 0053 granted `curation.manage` to CASE_OWNER and ANALYST only.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["READ_ONLY", "CONTRIBUTOR"])
def test_a_role_without_curation_manage_can_read_but_not_write(
        conn, client, owner, role):
    """0053 deliberately withheld the verb from CONTRIBUTOR and READ_ONLY: a
    tag renders next to the entity, in colour, and a misleading one
    ("CONFIRMED LAUNDERER") reads with the authority of the case file while
    resting on nobody's assertion. Both roles hold `case.read`, so the
    refusal must be the WRITE and only the write."""
    _, owner_token, case_id = owner
    node = _node(client, owner_token, case_id, "subject")
    tag_id = _tag(client, owner_token, case_id)
    set_id = _set(client, owner_token, case_id)

    reader_id, reader_email, reader_secret = _make_user(conn)
    _assign(conn, case_id, reader_id, role=role)
    reader = _login(client, reader_email, reader_secret)
    base = f"/api/v1/cases/{case_id}/curation"

    # Reads: allowed.
    assert client.get(f"{base}/tags", headers=_auth(reader)).status_code == 200
    assert client.get(f"{base}/sets", headers=_auth(reader)).status_code == 200
    assert client.get(f"{base}/nodes/{node}/tags",
                      headers=_auth(reader)).status_code == 200
    assert client.get(f"{base}/sets/{set_id}/members",
                      headers=_auth(reader)).status_code == 200

    # Writes: 403, and the route gate refuses before any id is even resolved.
    assert client.post(f"{base}/tags", headers=_auth(reader),
                       json={"namespace": "ttp", "name": "mine now"}
                       ).status_code == 403
    assert client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(reader),
                       json={"node_id": node}).status_code == 403
    assert client.delete(f"{base}/tags/{tag_id}/nodes/{node}",
                         headers=_auth(reader)).status_code == 403
    assert client.post(f"{base}/sets", headers=_auth(reader),
                       json={"name": "mine now"}).status_code == 403
    assert client.post(f"{base}/sets/{set_id}/members", headers=_auth(reader),
                       json={"node_id": node}).status_code == 403
    assert client.delete(f"{base}/sets/{set_id}/members/{node}",
                         headers=_auth(reader)).status_code == 403


def test_an_unassigned_caller_gets_404_not_403(conn, client, owner):
    """A caller with NO relationship to the case must not learn it exists --
    the same 404 a nonexistent case gives (deps.py, CHECK_ASSIGNMENT)."""
    _, _, case_id = owner
    # A global CASE_OWNER role and no assignment to THIS case: the gate
    # reads the verb off the assignment, so the role buys nothing here.
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    stranger = _login(client, email, secret)
    base = f"/api/v1/cases/{case_id}/curation"

    assert client.get(f"{base}/tags", headers=_auth(stranger)).status_code == 404
    assert client.get(f"{base}/sets", headers=_auth(stranger)).status_code == 404
    assert client.post(f"{base}/tags", headers=_auth(stranger),
                       json={"namespace": "ttp", "name": "theirs"}
                       ).status_code == 404


# ---------------------------------------------------------------------------
# Element labels, not just the case's. A RED node can live in an AMBER case
# (the TLP trigger enforces a FLOOR, not a ceiling), so passing the case
# gate is not permission to curate every node in the case.
# ---------------------------------------------------------------------------

def test_an_amber_analyst_cannot_tag_a_red_node(conn, client):
    """`require("curation.manage")` on the route authorised against the
    CASE. Attaching an overlay to a node is a write against the NODE, so the
    gate is re-run with the element's own labels -- the CR7 pattern
    `graph.py` uses for assertions.

    403 and not 404 here is deliberate and is the documented ordering: the
    same-case check has already passed (the node IS in this case, and the
    caller is assigned to it), so the only failing check is clearance.
    """
    _, owner_email, owner_secret = _make_user(conn, clearance="RED",
                                              global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)
    red_node = _node(client, owner_token, case_id, "red subject",
                     classification="RED")
    amber_node = _node(client, owner_token, case_id, "amber subject")
    tag_id = _tag(client, owner_token, case_id)
    assert conn.execute("SELECT classification FROM core.node WHERE id = %s",
                        (red_node,)).fetchone()[0] == "RED"

    analyst_id, analyst_email, analyst_secret = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, analyst_id, role="ANALYST")
    analyst = _login(client, analyst_email, analyst_secret)
    base = f"/api/v1/cases/{case_id}/curation"

    refused = client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(analyst),
                          json={"node_id": red_node})
    assert refused.status_code == 403, refused.text
    # The same analyst CAN curate a node at their own level, so the refusal
    # is the label check and not a broken route.
    assert client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(analyst),
                       json={"node_id": amber_node}).status_code == 201
    # ...and the RED-cleared owner can curate the RED node.
    assert client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(owner_token),
                       json={"node_id": red_node}).status_code == 201

    # On the READ path the answer is 404, not 403: the same answer a
    # nonexistent node gives, so a status code is not an existence oracle.
    assert client.get(f"{base}/nodes/{red_node}/tags",
                      headers=_auth(analyst)).status_code == 404
    assert client.get(f"{base}/nodes/{red_node}/tags",
                      headers=_auth(owner_token)).status_code == 200


def test_a_tag_count_does_not_disclose_red_nodes(conn, client):
    """`visible_node_count` is named for exactly what it is. Without the
    label predicates it would reveal how many RED nodes an AMBER analyst is
    not allowed to see."""
    _, owner_email, owner_secret = _make_user(conn, clearance="RED",
                                              global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)
    red_node = _node(client, owner_token, case_id, "red subject",
                     classification="RED")
    tag_id = _tag(client, owner_token, case_id)
    assert client.post(
        f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
        headers=_auth(owner_token), json={"node_id": red_node}).status_code == 201

    analyst_id, analyst_email, analyst_secret = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, analyst_id, role="ANALYST")
    analyst = _login(client, analyst_email, analyst_secret)

    seen = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                      headers=_auth(analyst)).json()
    assert [t for t in seen if t["id"] == tag_id][0]["visible_node_count"] == 0
    owner_view = client.get(f"/api/v1/cases/{case_id}/curation/tags",
                            headers=_auth(owner_token)).json()
    assert [t for t in owner_view if t["id"] == tag_id
            ][0]["visible_node_count"] == 1


def test_a_member_the_caller_cannot_see_is_withheld_not_dropped(conn, client):
    """Invariant 12: nothing is silently dropped. A member the caller cannot
    see is still a member, and a set that quietly renders 1 of 2 makes an
    analyst reason about a working set that is not the one on the screen.

    The count is deliberately undifferentiated -- it does not say whether a
    member is above your clearance, outside your compartments or
    soft-deleted, because that distinction is itself the disclosure.
    """
    _, owner_email, owner_secret = _make_user(conn, clearance="RED",
                                              global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)
    red_node = _node(client, owner_token, case_id, "RED-LABEL-CANARY",
                     classification="RED")
    amber_node = _node(client, owner_token, case_id, "amber subject")
    set_id = _set(client, owner_token, case_id)
    for node in (red_node, amber_node):
        assert client.post(
            f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
            headers=_auth(owner_token), json={"node_id": node}).status_code == 201

    analyst_id, analyst_email, analyst_secret = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, analyst_id, role="ANALYST")
    analyst = _login(client, analyst_email, analyst_secret)

    r = client.get(f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
                   headers=_auth(analyst))
    assert r.status_code == 200, r.text
    assert [m["node_id"] for m in r.json()["members"]] == [amber_node]
    assert r.json()["withheld"] == 1
    # Not even the id or the label of the withheld member leaves the process.
    assert red_node not in r.text
    assert "RED-LABEL-CANARY" not in r.text

    owner_view = client.get(
        f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
        headers=_auth(owner_token)).json()
    assert owner_view["withheld"] == 0
    assert len(owner_view["members"]) == 2

    # The set list's count is filtered the same way.
    listed = client.get(f"/api/v1/cases/{case_id}/curation/sets",
                        headers=_auth(analyst)).json()
    assert [s for s in listed if s["id"] == set_id
            ][0]["visible_member_count"] == 1


# ---------------------------------------------------------------------------
# Soft delete and merge. Neither destroys a row, and an overlay left on one
# must still be clearable or it accumulates entries nobody can remove.
# ---------------------------------------------------------------------------

def _soft_delete(conn, node_id, actor_id):
    """Soft-delete a node in SQL rather than through `DELETE
    /graph/nodes/{id}`.

    Deliberate: this file must assert the CURATION router's behaviour
    against a soft-deleted node without also depending on the shape of the
    graph router, which is being written concurrently. The state is what
    matters here, not the route that produced it.
    """
    conn.execute(
        "UPDATE core.node SET deleted_at = now(), deleted_by = %s WHERE id = %s",
        (actor_id, node_id))


def test_a_soft_delete_does_not_remove_the_row(conn, client, owner):
    """`deleted_at` is soft deletion; nothing is destroyed. The row and
    every assertion behind it survive, which is the precondition for
    everything below -- if the row went, curation would be answering about a
    node that no longer exists."""
    uid, token, case_id = owner
    node = _node(client, token, case_id, "retired")
    _soft_delete(conn, node, uid)

    row = conn.execute(
        "SELECT deleted_at, deleted_by FROM core.node WHERE id = %s",
        (node,)).fetchone()
    assert row is not None, "the row was destroyed; a soft delete must not"
    assert row[0] is not None
    assert str(row[1]) == str(uid)
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s",
        (node,)).fetchone()[0] == 1


def test_a_soft_deleted_node_cannot_be_curated_but_can_be_uncurated(
        conn, client, owner):
    """`require_live=True` on the write paths and False on the removal
    paths. A tag or membership left on a node that was later soft-deleted
    must still be removable, or the overlay accumulates entries no one can
    clear."""
    uid, token, case_id = owner
    node = _node(client, token, case_id, "later retired")
    tag_id = _tag(client, token, case_id)
    set_id = _set(client, token, case_id)
    base = f"/api/v1/cases/{case_id}/curation"
    assert client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(token),
                       json={"node_id": node}).status_code == 201
    assert client.post(f"{base}/sets/{set_id}/members", headers=_auth(token),
                       json={"node_id": node}).status_code == 201

    _soft_delete(conn, node, uid)

    # New overlay: refused, and it says why.
    refused = client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(token),
                          json={"node_id": node})
    assert refused.status_code == 409, refused.text
    assert "soft-deleted" in refused.text
    assert client.post(f"{base}/sets/{set_id}/members", headers=_auth(token),
                       json={"node_id": node}).status_code == 409

    # Existing overlay: still removable.
    assert client.delete(f"{base}/tags/{tag_id}/nodes/{node}",
                         headers=_auth(token)).status_code == 204
    assert client.delete(f"{base}/sets/{set_id}/members/{node}",
                         headers=_auth(token)).status_code == 204
    assert conn.execute(
        "SELECT count(*) FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
        (tag_id, node)).fetchone()[0] == 0
    assert conn.execute(
        "SELECT count(*) FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
        (set_id, node)).fetchone()[0] == 0
    # ...and the node row is still there. Removing an overlay destroys no
    # graph element.
    assert conn.execute("SELECT count(*) FROM core.node WHERE id = %s",
                        (node,)).fetchone()[0] == 1


def test_a_soft_deleted_member_is_withheld_rather_than_vanishing(
        conn, client, owner):
    """Invariant 12 again, on the other axis: a member whose node was
    retired after it joined is no longer renderable, and a set that silently
    shows 1 of 2 is lying about its own size."""
    uid, token, case_id = owner
    kept = _node(client, token, case_id, "still here")
    retired = _node(client, token, case_id, "retired later")
    set_id = _set(client, token, case_id)
    for node in (kept, retired):
        assert client.post(
            f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
            headers=_auth(token), json={"node_id": node}).status_code == 201
    _soft_delete(conn, retired, uid)

    r = client.get(f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members",
                   headers=_auth(token))
    assert r.status_code == 200
    assert [m["node_id"] for m in r.json()["members"]] == [kept]
    assert r.json()["withheld"] == 1


def test_a_merged_away_node_names_its_survivor(conn, client, owner):
    """Every read path filters `merged_into_id IS NULL`, so an overlay
    attached to the losing side of a merge is invisible everywhere.
    Accepting it would silently drop the analyst's work (invariant 12), so
    it is refused and the survivor is named so the analyst can retry.

    `merged_into_id` is set in SQL rather than through the merge router:
    this file is asserting the curation router's behaviour in that state,
    not the merge path that reaches it.
    """
    _, token, case_id = owner
    loser = _node(client, token, case_id, "duplicate persona")
    winner = _node(client, token, case_id, "surviving persona")
    tag_id = _tag(client, token, case_id)
    set_id = _set(client, token, case_id)
    conn.execute(
        """UPDATE core.node SET merged_into_id = %s, merged_at = now()
            WHERE id = %s""", (winner, loser))

    base = f"/api/v1/cases/{case_id}/curation"
    r = client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(token),
                    json={"node_id": loser})
    assert r.status_code == 409, r.text
    assert winner in r.text, "the survivor must be named so the analyst can retry"
    assert client.post(f"{base}/sets/{set_id}/members", headers=_auth(token),
                       json={"node_id": loser}).status_code == 409
    # The winner is curatable.
    assert client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(token),
                       json={"node_id": winner}).status_code == 201


# ---------------------------------------------------------------------------
# Node set notes
# ---------------------------------------------------------------------------

def test_an_omitted_note_does_not_erase_an_existing_one(client, owner, conn):
    """`add_member` upserts with `DO UPDATE SET note = EXCLUDED.note`, so a
    re-add with no note writes NULL over whatever was there. Re-adding is
    one drag or one double-click away, and the note is the analyst's own
    reasoning -- the single thing in a working set that cannot be
    reconstructed from the graph.

    So an ABSENT note means "leave it alone" and an EMPTY STRING means
    "clear it", which is the only way to say that deliberately.
    """
    _, token, case_id = owner
    node = _node(client, token, case_id, "prime suspect")
    set_id = _set(client, token, case_id)
    url = f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members"

    first = client.post(url, headers=_auth(token),
                        json={"node_id": node, "note": "awaiting warrant"})
    assert first.status_code == 201 and first.json()["created"] is True

    again = client.post(url, headers=_auth(token), json={"node_id": node})
    assert again.status_code == 200 and again.json()["created"] is False
    assert conn.execute(
        "SELECT note FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
        (set_id, node)).fetchone()[0] == "awaiting warrant"

    cleared = client.post(url, headers=_auth(token),
                          json={"node_id": node, "note": ""})
    assert cleared.status_code == 200
    assert conn.execute(
        "SELECT note FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
        (set_id, node)).fetchone()[0] == ""


def test_a_set_lists_pinned_first_and_reports_its_members(client, owner):
    _, token, case_id = owner
    # Pinned is created FIRST on purpose. The sort is `is_pinned DESC,
    # created_at DESC`, so if the pin were ignored the newer (plain) set
    # would come back first and this assertion would fail -- creating them
    # the other way round would pass either way and prove nothing.
    pinned = _set(client, token, case_id, name="pinned", is_pinned=True)
    plain = _set(client, token, case_id, name="plain")
    node = _node(client, token, case_id, "member")
    assert client.post(f"/api/v1/cases/{case_id}/curation/sets/{pinned}/members",
                       headers=_auth(token),
                       json={"node_id": node, "note": "prime suspect"}
                       ).status_code == 201

    listed = client.get(f"/api/v1/cases/{case_id}/curation/sets",
                        headers=_auth(token))
    assert listed.status_code == 200, listed.text
    ids = [s["id"] for s in listed.json()]
    assert ids.index(pinned) < ids.index(plain)

    members = client.get(
        f"/api/v1/cases/{case_id}/curation/sets/{pinned}/members",
        headers=_auth(token))
    assert members.status_code == 200
    assert members.json()["members"][0]["note"] == "prime suspect"
    assert members.json()["members"][0]["classification"] == "AMBER"
    assert members.json()["withheld"] == 0


def test_removing_a_member_that_is_not_there_is_still_204(client, owner):
    _, token, case_id = owner
    node = _node(client, token, case_id, "never a member")
    set_id = _set(client, token, case_id)
    url = f"/api/v1/cases/{case_id}/curation/sets/{set_id}/members/{node}"
    assert client.delete(url, headers=_auth(token)).status_code == 204
    assert client.delete(url, headers=_auth(token)).status_code == 204


# ---------------------------------------------------------------------------
# The audit log is the ONLY record of a removal
# ---------------------------------------------------------------------------

def _audit_count(conn, case_id, action) -> int:
    return conn.execute(
        "SELECT count(*) FROM audit.event WHERE case_id = %s AND action = %s",
        (case_id, action)).fetchone()[0]


def test_every_removal_is_recorded_and_a_no_op_is_not(client, owner, conn):
    """`core.node_set_member` has no `added_by` column and
    `core.tag_assignment` records `assigned_by` but nothing for removals, so
    for un-tagging and member removal `audit.event` is the ONLY record of
    who did it. Deletion here is real deletion -- correctly, since
    un-tagging retracts a sticky note and not a claim -- and the
    append-only log is what keeps "who un-tagged what" answerable.

    The second half matters as much: a retried DELETE is a 204 and must NOT
    add an event, or the log fills with rows describing nothing.
    """
    uid, token, case_id = owner
    node = _node(client, token, case_id, "audited")
    tag_id = _tag(client, token, case_id)
    set_id = _set(client, token, case_id)
    base = f"/api/v1/cases/{case_id}/curation"
    assert client.post(f"{base}/tags/{tag_id}/nodes", headers=_auth(token),
                       json={"node_id": node}).status_code == 201
    assert client.post(f"{base}/sets/{set_id}/members", headers=_auth(token),
                       json={"node_id": node}).status_code == 201

    assert _audit_count(conn, case_id, "TAG_CREATED") == 1
    assert _audit_count(conn, case_id, "TAG_ASSIGNED") == 1
    assert _audit_count(conn, case_id, "NODE_SET_CREATED") == 1
    assert _audit_count(conn, case_id, "NODE_SET_MEMBER_ADDED") == 1

    assert client.delete(f"{base}/tags/{tag_id}/nodes/{node}",
                         headers=_auth(token)).status_code == 204
    assert client.delete(f"{base}/sets/{set_id}/members/{node}",
                         headers=_auth(token)).status_code == 204
    assert _audit_count(conn, case_id, "TAG_UNASSIGNED") == 1
    assert _audit_count(conn, case_id, "NODE_SET_MEMBER_REMOVED") == 1

    # The actor is recorded, by durable id (invariant 9).
    actor = conn.execute(
        """SELECT actor_id, actor_kind FROM audit.event
            WHERE case_id = %s AND action = 'TAG_UNASSIGNED'""",
        (case_id,)).fetchone()
    assert str(actor[0]) == str(uid) and actor[1] == "USER"

    # Idempotent retries: 204, and no new events.
    assert client.delete(f"{base}/tags/{tag_id}/nodes/{node}",
                         headers=_auth(token)).status_code == 204
    assert client.delete(f"{base}/sets/{set_id}/members/{node}",
                         headers=_auth(token)).status_code == 204
    assert _audit_count(conn, case_id, "TAG_UNASSIGNED") == 1
    assert _audit_count(conn, case_id, "NODE_SET_MEMBER_REMOVED") == 1


def test_a_refused_cross_case_write_leaves_no_audit_row(client, owner, conn):
    """A refusal is not an act. The AUTHZ/NOT-FOUND path must not write a
    TAG_ASSIGNED event describing something that did not happen -- which is
    also how you would tell, from the log alone, that the check ran."""
    _, token, case_id = owner
    theirs = _create_case(client, token)
    foreign_node = _node(client, token, theirs, "theirs")
    tag_id = _tag(client, token, case_id)

    before = _audit_count(conn, case_id, "TAG_ASSIGNED")
    assert client.post(f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                       headers=_auth(token),
                       json={"node_id": foreign_node}).status_code == 404
    assert _audit_count(conn, case_id, "TAG_ASSIGNED") == before


def test_an_assignment_reports_its_actor_by_durable_id(client, owner, conn):
    """Invariant 9: durable identifiers, not displayed ones. The client
    resolves `assigned_by`, so a renamed or deactivated account cannot
    rewrite who tagged what."""
    uid, token, case_id = owner
    node = _node(client, token, case_id, "subject")
    tag_id = _tag(client, token, case_id)
    assert client.post(f"/api/v1/cases/{case_id}/curation/tags/{tag_id}/nodes",
                       headers=_auth(token),
                       json={"node_id": node}).status_code == 201

    r = client.get(f"/api/v1/cases/{case_id}/curation/nodes/{node}/tags",
                   headers=_auth(token))
    assert r.status_code == 200
    entry = r.json()[0]
    assert entry["assigned_by"] == str(uid)
    assert entry["assigned_at"]
    # The display name is not served here; a name in this field would be a
    # snapshot that silently goes stale.
    assert "Curation" not in r.text
