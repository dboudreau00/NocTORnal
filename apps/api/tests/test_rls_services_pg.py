"""The services that must see every row still do, as the request role (S1).

Each case here is run through the SERVICE on a connection SET ROLE to
the request role and bound as the reader, with
NOCTORNAL_TEST_ASSUME_ROLE set so that `db.system_connection` opens the
system role exactly as production does. Until 2026-09-25 each of these
read the caller's filtered view and got a wrong answer that looked right:
a retirement allowed over hidden ties, "nothing withheld", a legal hold
that held nothing.
"""
from __future__ import annotations

import pytest

import rls_support as s

pytestmark = s.GATED


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    s.cleanup(c)
    c.close()


@pytest.fixture
def scene(owner):
    boss = s.user(owner, "RED")
    analyst = s.user(owner, "AMBER")
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst, "CASE_OWNER")
    hub = s.node(owner, case_id, boss, "hub")
    spoke = s.node(owner, case_id, boss, "spoke")
    secret = s.node(owner, case_id, boss, "secret", "RED")
    s.edge(owner, case_id, boss, hub, spoke)
    s.edge(owner, case_id, boss, hub, secret, "RED")
    _, raw = s.session(owner, analyst)
    return {"boss": boss, "analyst": analyst, "case": case_id, "hub": hub,
            "spoke": spoke, "secret": secret, "raw": raw}


def test_retiring_a_node_with_a_hidden_tie_is_refused(owner, scene):
    """The node-retirement anti-join. On the request connection
    the RED tie is invisible, so a count there is zero; the guard counts on
    a system connection and refuses."""
    from noctornal_api.graph import GraphWriteError, GraphWriteService

    app = s.app_conn(scene["raw"])
    try:
        with pytest.raises(GraphWriteError, match="above your clearance"):
            GraphWriteService(app).soft_delete_node(
                scene["hub"], case_id=scene["case"], deleted_by=scene["analyst"],
                at=s.now(), clearance="AMBER", compartments=frozenset())
    finally:
        app.close()
    alive = owner.execute("SELECT deleted_at IS NULL FROM core.node WHERE id = %s",
                          (scene["hub"],)).fetchone()[0]
    assert alive


def test_the_withheld_counts_are_the_owners_counts(owner, scene):
    """Withheld-material counts (docs/14 U2)."""
    from noctornal_api.projections import GraphService, Projection

    projection = Projection(case_id=scene["case"], preset="all", include_inferred=False,
                            min_confidence="LOW", as_of=None)
    as_owner = GraphService(owner, clearance="AMBER",
                            compartments=frozenset()).withheld(projection)
    app = s.app_conn(scene["raw"])
    try:
        as_reader = GraphService(app, clearance="AMBER",
                                 compartments=frozenset()).withheld(projection)
    finally:
        app.close()
    assert as_owner.nodes == 1 and as_owner.edges == 1
    assert (as_reader.nodes, as_reader.edges) == (as_owner.nodes, as_owner.edges)
    assert as_reader.any_withheld is True


def test_a_legal_hold_reaches_an_exhibit_above_the_officer_and_refuses_a_ghost(owner, scene):
    """Legal hold on an exhibit. The route runs the hold on a
    system connection; the service refuses when nothing changed."""
    from uuid import uuid4

    from noctornal_api.db import SystemPurpose, system_connection
    from noctornal_api.retention import RetentionError, RetentionService

    exhibit = s.exhibit(owner, scene["case"], scene["boss"], "RED")
    app = s.app_conn(scene["raw"])
    try:
        with system_connection(SystemPurpose.RETENTION, reuse=app) as sconn:
            RetentionService(sconn).set_legal_hold(
                exhibit, actor_id=scene["analyst"], on=True, reason="court order 7")
            with pytest.raises(RetentionError, match="no such exhibit"):
                RetentionService(sconn).set_legal_hold(
                    uuid4(), actor_id=scene["analyst"], on=True, reason="court order 7")
        # On the request connection alone the same UPDATE touches nothing.
        cur = app.execute("UPDATE core.evidence SET legal_hold = true, "
                          "legal_hold_reason = 'x' WHERE id = %s", (exhibit,))
        assert cur.rowcount == 0
    finally:
        app.close()
    held = owner.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                         (exhibit,)).fetchone()[0]
    assert held is True
    owner.execute("UPDATE core.evidence SET legal_hold = false, legal_hold_reason = NULL "
                  "WHERE id = %s", (exhibit,))


def test_the_gate_still_answers_a_hidden_element_with_its_own_refusal(owner, scene):
    """The element facts reach the gate: an AMBER case owner asking for the
    RED node's labels learns them from the fact function, so
    authorize_object decides (403 and AUTHZ_DENIED), not a silent 404."""
    from noctornal_api.http.deps import element_labels

    app = s.app_conn(scene["raw"])
    try:
        assert app.execute("SELECT count(*) FROM core.node WHERE id = %s",
                           (scene["secret"],)).fetchone()[0] == 0
        facts = element_labels(app, "node", scene["secret"])
    finally:
        app.close()
    assert facts == (scene["case"], "RED", frozenset())
