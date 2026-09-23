"""Accepting a proposal is held to the label ceiling, over HTTP.

Final review C12 (2026-09-23). `POST /cases/{id}/proposals/{pid}/accept`
ran `proposal.review` and nothing else, then handed the caller's
`classification` to the graph writer. Every other creation route calls
`check_writable_labels`; this one never did, and the database enforces
only the case FLOOR. So an AMBER reviewer on an AMBER case could send
`{"classification": "RED"}` and author a RED element that vanished from
their own graph at once, which they could then neither correct nor
retire. The same was true of a proposal whose payload already named a
classification above the reviewer's, with no body at all.

The ATTRIBUTE kind wrote an assertion onto an existing entity with no
look at that entity's labels, the gap CR7 closed on `graph.py`'s own
assertion route, and no check that the entity was in the proposal's case.

Every refusal test here fails on 1667cc1; the within-clearance test is
the guard that the fix did not close the door it watches. Email prefix
`pac-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; accept ceiling test is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "pac-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # One transaction: the deferred invariant-1 triggers fire at commit, so
    # assertions and their elements must go together.
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, clearance):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", "PAC", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def world(conn):
    """A RED owner's AMBER case, an AMBER-cleared REVIEWER on it, and one
    RED entity the reviewer cannot see."""
    from noctornal_api.cases import CaseService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = _user(conn, "RED")
    reviewer = _user(conn, "AMBER")
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-PAC-{uuid4().hex[:6]}", title="Accept ceiling",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification="AMBER")
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'REVIEWER', %s)""", (case_id, reviewer, owner))
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner)
    red_node = g.create_node(case_id=case_id, node_type="IDENTITY",
                             label="pac_red_persona", created_by=owner,
                             assertion=a, classification="RED")
    amber_node = g.create_node(case_id=case_id, node_type="IDENTITY",
                               label="pac_amber_persona", created_by=owner,
                               assertion=a, classification="AMBER")
    return {"case": case_id, "owner": owner, "reviewer": reviewer,
            "red_node": red_node, "amber_node": amber_node}


def _propose(conn, case_id, kind, payload):
    from noctornal_api.proposals import ProposalStore
    return ProposalStore(conn).propose(
        case_id=case_id, kind=kind, payload=payload, origin="pac_test_v1",
        rationale="raised by the accept-ceiling test", score=0.5)


def _state(conn, pid):
    return conn.execute("SELECT state, applied_node_id, applied_edge_id "
                        "FROM collect.proposal WHERE id = %s", (pid,)).fetchone()


def _accept(client, conn, w, pid, body=None):
    return client.post(
        f"/api/v1/cases/{w['case']}/proposals/{pid}/accept",
        headers=_auth(conn, w["reviewer"]), json=body or {})


def _nodes(conn, case_id):
    return conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                        (case_id,)).fetchone()[0]


def test_a_reviewer_cannot_accept_a_node_above_their_own_clearance(conn, client, world):
    """The finding's own reproduction: AMBER reviewer, `classification: RED`."""
    w = world
    pid = _propose(conn, w["case"], "NODE",
                   {"node_type": "IDENTITY", "label": "pac_suggested"})
    before = _nodes(conn, w["case"])
    r = _accept(client, conn, w, pid, {"classification": "RED"})
    assert r.status_code == 403, r.text
    assert "above your AMBER clearance" in r.json()["detail"]
    assert _nodes(conn, w["case"]) == before, "nothing may be written"
    assert _state(conn, pid) == ("PROPOSED", None, None), \
        "a refused accept leaves the proposal in the queue"


def test_a_payload_classification_above_the_reviewer_is_refused_too(conn, client, world):
    """No body at all: the label comes from the proposal, and it is the
    label that will be WRITTEN that is checked, not the one the caller sent."""
    w = world
    pid = _propose(conn, w["case"], "NODE",
                   {"node_type": "IDENTITY", "label": "pac_red_suggestion",
                    "classification": "RED"})
    before = _nodes(conn, w["case"])
    r = _accept(client, conn, w, pid)
    assert r.status_code == 403, r.text
    assert _nodes(conn, w["case"]) == before
    assert _state(conn, pid)[0] == "PROPOSED"


def test_an_edge_above_the_reviewer_is_refused(conn, client, world):
    w = world
    pid = _propose(conn, w["case"], "EDGE",
                   {"edge_type": "COMMUNICATES_WITH",
                    "src_node_id": str(w["amber_node"]),
                    "dst_node_id": str(w["amber_node"])})
    r = _accept(client, conn, w, pid, {"classification": "RED"})
    assert r.status_code == 403, r.text
    assert _state(conn, pid) == ("PROPOSED", None, None)


def test_accepting_within_clearance_still_works(conn, client, world):
    """The check must not close the door it guards: the default label and
    an explicit one at the reviewer's own level both go through, and the
    element is written at exactly the label that was checked."""
    w = world
    pid = _propose(conn, w["case"], "NODE",
                   {"node_type": "IDENTITY", "label": "pac_default"})
    r = _accept(client, conn, w, pid)
    assert r.status_code == 200, r.text
    node_id = r.json()["applied_node_id"]
    assert conn.execute("SELECT classification FROM core.node WHERE id = %s",
                        (node_id,)).fetchone()[0] == "AMBER"

    pid2 = _propose(conn, w["case"], "NODE",
                    {"node_type": "IDENTITY", "label": "pac_explicit"})
    r = _accept(client, conn, w, pid2, {"classification": "AMBER"})
    assert r.status_code == 200, r.text


def test_an_attribute_claim_about_an_entity_above_the_reviewer_is_refused(
        conn, client, world):
    """CR7's rule on the graph route, held on this one: asserting about an
    entity is a write against it, gated by ITS labels."""
    w = world
    pid = _propose(conn, w["case"], "ATTRIBUTE",
                   {"node_id": str(w["red_node"]), "claim_path": "attrs.role",
                    "claim_value": {"role": "initial access broker"}})
    r = _accept(client, conn, w, pid)
    assert r.status_code == 403, r.text
    assert _state(conn, pid)[0] == "PROPOSED"
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s "
        "AND claim_path IS NOT NULL", (w["red_node"],)).fetchone()[0] == 0

    ok = _propose(conn, w["case"], "ATTRIBUTE",
                  {"node_id": str(w["amber_node"]), "claim_path": "attrs.role",
                   "claim_value": {"role": "escrow agent"}})
    r = _accept(client, conn, w, ok)
    assert r.status_code == 200, r.text


def test_an_attribute_claim_about_another_cases_entity_is_refused(
        conn, client, world):
    """Nothing in the database ties an assertion's entity to its case, and
    the graph route refuses a foreign entity with a 404. This path wrote
    the assertion under this case against the other case's entity."""
    from noctornal_api.cases import CaseService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    w = world
    future = date(2028, 1, 1)
    other = CaseService(conn).create(
        code=f"OP-PAC-{uuid4().hex[:6]}", title="Another case",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=w["owner"],
        created_by=w["owner"], classification="AMBER")
    foreign = GraphWriteService(conn).create_node(
        case_id=other, node_type="IDENTITY", label="pac_foreign",
        created_by=w["owner"],
        assertion=AssertionInput(basis="DIRECT_OBSERVATION",
                                 created_by=w["owner"]))
    pid = _propose(conn, w["case"], "ATTRIBUTE",
                   {"node_id": str(foreign), "claim_path": "attrs.role",
                    "claim_value": {"role": "carder"}})
    r = _accept(client, conn, w, pid)
    assert r.status_code == 409, r.text
    assert "not in this case" in r.json()["detail"]
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE node_id = %s "
        "AND claim_path IS NOT NULL", (foreign,)).fetchone()[0] == 0


def test_the_service_and_the_route_share_one_label_rule():
    """Pure: the label checked is the label written. Two copies of this
    expression is how the route came to check nothing."""
    from noctornal_api.proposals import accepted_classification
    assert accepted_classification({}, None) == "AMBER"
    assert accepted_classification(None, None) == "AMBER"
    assert accepted_classification({"classification": "RED"}, None) == "RED"
    assert accepted_classification({"classification": "RED"}, "GREEN") == "GREEN"
