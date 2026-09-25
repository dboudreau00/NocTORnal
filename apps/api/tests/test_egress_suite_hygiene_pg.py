"""The egress suites leave a database's live egress configuration as they
found it (S2, 2026-09-25).

Several suites need no live route of a name, or their own passive default,
and retirement is terminal to the application, so they once retired a
developer's own profiles and routes (the demo configuration included) for
good. egress_support.preserved snapshots the live configuration and brings
it back exactly afterwards; a run killed half way is repaired by the next
one from the snapshot file.

Everything here runs inside one transaction that is rolled back, so this
suite changes nothing either. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import psycopg
import pytest

import egress_support as es

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egh-"


class _Rollback(Exception):
    pass


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


def _in_rollback(conn, body):
    try:
        with conn.transaction():
            body()
            raise _Rollback
    except _Rollback:
        pass


def _state(conn, pid, rid, did):
    profile = conn.execute(
        "SELECT is_active, is_passive_default, retired_at IS NULL, retire_reason "
        "FROM collect.egress_profile WHERE id = %s", (pid,)).fetchone()
    route = conn.execute(
        "SELECT is_active, retired_at IS NULL FROM collect.egress_integration_route "
        "WHERE id = %s", (rid,)).fetchone()
    dest = conn.execute("SELECT retired_at IS NULL FROM collect.egress_destination "
                        "WHERE id = %s", (did,)).fetchone()
    return profile, route, dest


def _operator_world(conn):
    """A live operator configuration: a passive default, an active profile
    that is not, and a live 'jira' route with one entry."""
    admin = es.user(conn, "SYS_ADMIN", prefix=PREFIX)
    conn.execute("UPDATE collect.egress_integration_route SET is_active = false, "
                 "retired_at = now(), retired_by = %s, retire_reason = 'hygiene start' "
                 "WHERE name = 'jira' AND retired_at IS NULL", (admin,))
    default = es.profile(conn, PREFIX, passive=True)
    other = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    conn.execute("UPDATE collect.egress_profile SET is_active = false WHERE id = %s", (other,))
    rid = conn.execute("INSERT INTO collect.egress_integration_route (name, description) "
                       "VALUES ('jira', 'the operator''s own tracker') RETURNING id"
                       ).fetchone()[0]
    did = conn.execute("INSERT INTO collect.egress_destination (route_id, entry, note) "
                       "VALUES (%s, 'jira.corp.example:443', 'the operator''s entry') "
                       "RETURNING id", (rid,)).fetchone()[0]
    return admin, default, other, rid, did


def _what_a_suite_does(conn, admin):
    """Retire everything live, then make its own default and its own jira."""
    conn.execute("UPDATE collect.egress_profile SET is_passive_default = false, "
                 "is_active = false, retired_at = now(), retired_by = %s, "
                 "retire_reason = 'a suite start' WHERE retired_at IS NULL", (admin,))
    conn.execute("UPDATE collect.egress_destination SET retired_at = now(), retired_by = %s "
                 "WHERE retired_at IS NULL", (admin,))
    conn.execute("UPDATE collect.egress_integration_route SET is_active = false, "
                 "retired_at = now(), retired_by = %s, retire_reason = 'a suite start' "
                 "WHERE retired_at IS NULL", (admin,))
    es.profile(conn, PREFIX + "suite-", passive=True)
    conn.execute("INSERT INTO collect.egress_integration_route (name, description) "
                 "VALUES ('jira', 'the suite''s own route')")


def test_preserved_brings_every_original_back_as_it_was(conn):
    def body():
        admin, default, other, rid, did = _operator_world(conn)
        before = _state(conn, default, rid, did), _state(conn, other, rid, did)
        with es.preserved(conn):
            _what_a_suite_does(conn, admin)
            assert _state(conn, default, rid, did)[0][2] is False
        assert (_state(conn, default, rid, did), _state(conn, other, rid, did)) == before
        assert before[0][0] == (True, True, True, None)
        assert before[1][0] == (False, False, True, None)
        live_jira = conn.execute(
            "SELECT id FROM collect.egress_integration_route "
            "WHERE name = 'jira' AND retired_at IS NULL").fetchall()
        assert live_jira == [(rid,)]
        assert conn.execute("SELECT id FROM collect.egress_profile "
                            "WHERE is_passive_default").fetchall() == [(default,)]
        # The terminal triggers are back on: an application update still
        # cannot bring a retired route back.
        suite_jira = conn.execute(
            "SELECT id FROM collect.egress_integration_route WHERE name = 'jira' "
            "AND description = 'the suite''s own route'").fetchone()[0]
        with pytest.raises(psycopg.errors.RaiseException):
            with conn.transaction():
                conn.execute("UPDATE collect.egress_integration_route SET retired_at = NULL, "
                             "retired_by = NULL, retire_reason = NULL WHERE id = %s",
                             (suite_jira,))

    _in_rollback(conn, body)


def test_a_run_killed_half_way_is_repaired_by_the_next(conn):
    def body():
        admin, default, other, rid, did = _operator_world(conn)
        before = _state(conn, default, rid, did)
        path = es._set_aside_file(conn)
        kept = path.read_text(encoding="utf-8") if path.exists() else None
        try:
            # A suite enters, retires, and dies: no restore ran, the file
            # stays.
            killed = es.preserved(conn)
            killed.__enter__()
            _what_a_suite_does(conn, admin)
            assert path.exists()
            with es.preserved(conn):
                assert _state(conn, default, rid, did) == before
            assert not path.exists()
        finally:
            if kept is not None:
                path.write_text(kept, encoding="utf-8")

    _in_rollback(conn, body)
