"""The request role cannot drop a compartment from case material, or lower the
labels of the tables that hold it.

The row policy asks only that the new compartments be within the writer's own,
so an assignee read into a compartment could write an empty list over it and
every teammate cleared to the level would read the row. A trigger on the node
and the tie holds the compartments, and the same two label columns are held on
the other tables of case material. Adding a compartment and raising a label stay
open, and the schema owner and the system role are exempt.

A table the request role can write a label on must carry the guard, or be named
below as one whose label another rule governs.

Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE (rls_support.GATED).
"""
from __future__ import annotations

import pytest

import rls_support as s

PREFIX = "cmpdrop-"
KEY = "CMPDROPX"
OTHER = "CMPDROPY"

#: Tables the request role can write a label on that the guard leaves to another rule: the case route
#: refuses a lower case label and fixes its compartments, the rest are configuration or notices the
#: system writes.
UNGUARDED = {
    "core.case",
    "collect.source",
    "collect.persona_act",
    "collect.egress_connection",
    "collect.collection_authority",
    "comms.pgp_key_lookup",
    "ingest.lookup",
    "ingest.lookup_result",
    "lab.yara_ruleset",
    "notify.jira_event",
    "notify.jira_link",
    "notify.notification",
}


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    conn = s.owner_conn()
    yield conn
    s.cleanup(conn, PREFIX)
    conn.execute("DELETE FROM iam.compartment WHERE key = ANY(%s)", ([KEY, OTHER],))
    conn.close()


def _register(conn) -> None:
    s.register(conn, KEY, OTHER)


def _world(owner):
    """A RED analyst read into one compartment, on an AMBER case with a node and a tie filed under it, and a
    request-role connection bound to that person."""
    _register(owner)
    uid = s.user(owner, clearance="RED", compartments=(KEY, OTHER), prefix=PREFIX)
    case_id = s.case(owner, uid, classification="AMBER")
    a = s.node(owner, case_id, uid, "read in", compartments=(KEY,))
    b = s.node(owner, case_id, uid, "the other end", compartments=(KEY,))
    tie = s.edge(owner, case_id, uid, a, b)
    owner.execute("UPDATE core.edge SET compartments = %s WHERE id = %s", ([KEY], tie))
    _session_id, raw = s.session(owner, uid)
    return {"core.node": a, "core.edge": tie}, s.app_conn(raw)


def _held(conn, table: str, row_id) -> list[str]:
    return list(conn.execute(f"SELECT compartments FROM {table} WHERE id = %s",
                             (row_id,)).fetchone()[0])


@s.GATED
@pytest.mark.parametrize("table", ["core.node", "core.edge"])
def test_a_request_cannot_drop_a_compartment(owner, table):
    import psycopg

    rows, app = _world(owner)
    try:
        assert _held(app, table, rows[table]) == [KEY]
        with pytest.raises(psycopg.Error, match="may not be dropped"):
            app.execute(f"UPDATE {table} SET compartments = '{{}}' WHERE id = %s", (rows[table],))
        app.rollback()
        with pytest.raises(psycopg.Error, match="may not be dropped"):
            app.execute(f"UPDATE {table} SET compartments = array_remove(compartments, %s) "
                        f"WHERE id = %s", (KEY, rows[table]))
        app.rollback()
        assert _held(app, table, rows[table]) == [KEY]
    finally:
        app.close()


@s.GATED
def test_a_request_can_still_add_a_compartment_it_holds(owner):
    _register(owner)
    rows, app = _world(owner)
    try:
        app.execute("UPDATE core.node SET compartments = %s WHERE id = %s",
                    ([KEY, OTHER], rows["core.node"]))
        app.commit()
        assert sorted(_held(app, "core.node", rows["core.node"])) == [KEY, OTHER]
    finally:
        app.close()


@s.GATED
def test_the_owner_can_still_drop_a_compartment(owner):
    rows, app = _world(owner)
    app.close()
    owner.execute("UPDATE core.node SET compartments = '{}' WHERE id = %s", (rows["core.node"],))
    assert _held(owner, "core.node", rows["core.node"]) == []


@s.GATED
def test_every_table_the_request_role_can_label_is_guarded_or_named(owner):
    """A table added later that the request role can write a label on fails here until it is guarded or
    named in UNGUARDED with the rule that governs it."""
    rows = owner.execute(
        """SELECT c.table_schema || '.' || c.table_name, c.column_name,
                  EXISTS (SELECT 1 FROM pg_trigger t
                           WHERE t.tgrelid = (quote_ident(c.table_schema) || '.' ||
                                              quote_ident(c.table_name))::regclass
                             AND NOT t.tgisinternal
                             AND (CASE c.column_name
                                    WHEN 'classification' THEN t.tgname ~ 'classification_kept$'
                                    ELSE t.tgname = 'compartments_kept' END))
             FROM information_schema.columns c
             JOIN pg_class k ON k.relname = c.table_name
             JOIN pg_namespace n ON n.oid = k.relnamespace AND n.nspname = c.table_schema
            WHERE c.column_name IN ('classification', 'compartments') AND k.relkind IN ('r', 'p')
              AND has_column_privilege(%s, quote_ident(c.table_schema) || '.' ||
                                       quote_ident(c.table_name), c.column_name, 'UPDATE')""",
        (s.APP_ROLE,)).fetchall()
    assert rows, "the request role was expected to hold some label writes"
    unguarded = sorted({f"{t}.{col}" for t, col, guarded in rows
                        if not guarded and t not in UNGUARDED})
    assert unguarded == []
