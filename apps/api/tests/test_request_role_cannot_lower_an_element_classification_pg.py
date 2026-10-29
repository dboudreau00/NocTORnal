"""The request role cannot lower the classification of a node, a tie or an
exhibit, even to a label still on or above the case floor. A node and a tie
are held by a trigger; an exhibit by the column grants.

The case floor trigger refuses only a label below the case, and the row
policy lets a writer set any label within its own ceiling. So an assignee
cleared above an element could rewrite it down to the case floor and show it,
attributes and all, to every teammate cleared only that far. Raising a label
stays open, as do the label, attribute and merge writes the table UPDATE grant
exists for. The schema owner and the system role are exempt.

Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE (rls_support.GATED).
"""
from __future__ import annotations

import pytest

import rls_support as s

PREFIX = "tlpdown-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    conn = s.owner_conn()
    yield conn
    s.cleanup(conn, PREFIX)
    conn.close()


def _world(owner):
    """A RED-cleared case owner on an AMBER case, holding one RED node, tie
    and exhibit, and a request-role connection bound to that person."""
    uid = s.user(owner, clearance="RED", prefix=PREFIX)
    case_id = s.case(owner, uid, classification="AMBER")
    a = s.node(owner, case_id, uid, "filed above the floor", classification="RED")
    b = s.node(owner, case_id, uid, "the other end", classification="RED")
    rows = {
        "core.node": a,
        "core.edge": s.edge(owner, case_id, uid, a, b, classification="RED"),
        "core.evidence": s.exhibit(owner, case_id, uid, classification="RED"),
    }
    _session_id, raw = s.session(owner, uid)
    return rows, s.app_conn(raw)


def _label(conn, table: str, row_id) -> str | None:
    row = conn.execute(f"SELECT classification::text FROM {table} WHERE id = %s",
                       (row_id,)).fetchone()
    return row[0] if row else None


@s.GATED
@pytest.mark.parametrize(("table", "refusal"), [
    ("core.node", "may not be lowered"),
    ("core.edge", "may not be lowered"),
    # The request role may update only the storage version of an exhibit.
    ("core.evidence", "permission denied"),
])
def test_a_request_cannot_lower_an_element_to_the_case_floor(owner, table, refusal):
    import psycopg

    rows, app = _world(owner)
    try:
        assert _label(app, table, rows[table]) == "RED"
        with pytest.raises(psycopg.Error, match=refusal):
            app.execute(f"UPDATE {table} SET classification = 'AMBER' WHERE id = %s",
                        (rows[table],))
        app.rollback()
        assert _label(app, table, rows[table]) == "RED"
    finally:
        app.close()


@s.GATED
def test_a_request_can_still_raise_a_label_and_write_other_columns(owner):
    uid = s.user(owner, clearance="RED", prefix=PREFIX)
    case_id = s.case(owner, uid, classification="AMBER")
    node_id = s.node(owner, case_id, uid, "filed at the floor", classification="AMBER")
    _session_id, raw = s.session(owner, uid)
    app = s.app_conn(raw)
    try:
        app.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s", (node_id,))
        app.execute("UPDATE core.node SET label = 'renamed' WHERE id = %s", (node_id,))
        app.commit()
        assert _label(app, "core.node", node_id) == "RED"
    finally:
        app.close()


@s.GATED
def test_the_owner_can_still_lower_a_label(owner):
    uid = s.user(owner, clearance="RED", prefix=PREFIX)
    case_id = s.case(owner, uid, classification="AMBER")
    node_id = s.node(owner, case_id, uid, "owner remediates", classification="RED")
    owner.execute("UPDATE core.node SET classification = 'AMBER' WHERE id = %s", (node_id,))
    assert _label(owner, "core.node", node_id) == "AMBER"
