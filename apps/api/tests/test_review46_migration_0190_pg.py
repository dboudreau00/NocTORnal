"""Migration 0148 (egress-notify-address-list, review of 2026-10-03): the CHECK
on notify.preference.address, its round trip, and that the database and the
service read the same rule.

Every schema change runs inside a transaction that is rolled back (the
test_notify_ledger_migration_pg.py pattern), so the database the rest of the
suite uses never sees the intermediate state. Prefix `r46m-`. Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import psycopg
import pytest

from outbound_support import DATABASE_URL, make_user, teardown

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46m-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
CONSTRAINT = "preference_address_single"

CORPUS = [
    "me@corp.example", "a.analyst@Agency.Example", "o'brien+alerts@corp.example",
    "collector@attacker.example, me@corp.example", "collector@attacker.example; me@corp.example",
    "Collector <collector@attacker.example>", "me@corp.example\n", "me@corp.example\r\n",
    "me@corp.example\nBcc: x@attacker.example", "me @corp.example", "\"me\"@corp.example",
    "me@corp.example (comment)", "a@b@corp.example", "@corp.example", "me@", "me@corp",
    "me@-corp.example", "me@corp-.example", "me@corp..example", "me@corp.example.",
    ".me@corp.example", "me.@corp.example", "me..x@corp.example", "me@[127.0.0.1]",
    "mé@corp.example", "me@corp.éxample", "x" * 244 + "@corp.example",
    "x" * 250 + "@corp.example", "", " ", "me@corp.example ", " me@corp.example",
    "x%attacker.example@corp.example", "attacker.example!x@corp.example", "|x@corp.example",
    "a/b@corp.example", "a`b@corp.example", "a$b@corp.example", "a{b}@corp.example",
    "a=b@corp.example", "a*b@corp.example", "a#b@corp.example", "a&b@corp.example",
    "a^b@corp.example", "a~b@corp.example", "a?b@corp.example", "a_b-c+d'e@corp.example",
]


class _RollBack(Exception):
    pass


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _migration(conn):
    path = next(VERSIONS.glob("0148_*.py"))
    spec = importlib.util.spec_from_file_location("m0190", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def _constraint(conn):
    return conn.execute(
        """SELECT convalidated FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
             JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'notify' AND t.relname = 'preference' AND c.conname = %s""",
        (CONSTRAINT,)).fetchone()


def test_the_revision_chains_after_the_reserved_head_and_names_one_concern():
    module = _migration(None)
    assert module.revision == "0148" and module.down_revision == "0131"
    assert module.UPGRADE_SQL.count("ADD CONSTRAINT") == 1


def test_it_round_trips_and_leaves_a_not_valid_check(conn):
    m = _migration(conn)
    uid, _ = make_user(conn, PREFIX)
    with pytest.raises(_RollBack):
        with conn.transaction():
            m.downgrade()
            assert _constraint(conn) is None
            conn.execute("INSERT INTO notify.preference (user_id, channel, address) "
                         "VALUES (%s, 'SMTP', 'a@x.example, b@y.example')", (uid,))
            conn.execute("DELETE FROM notify.preference WHERE user_id = %s", (uid,))
            m.upgrade()
            assert _constraint(conn) == (False,), "NOT VALID: stored rows are left as they are"
            with pytest.raises(psycopg.errors.CheckViolation):
                with conn.transaction():
                    conn.execute("INSERT INTO notify.preference (user_id, channel, address) "
                                 "VALUES (%s, 'SMTP', 'a@x.example, b@y.example')", (uid,))
            raise _RollBack
    assert _constraint(conn) is not None, "the live database is back at head"


def test_a_row_stored_before_the_revision_cannot_be_rewritten_by_any_other_writer(conn):
    """NOT VALID still checks every new and updated row, which is why the
    service says what to do rather than rewriting such a row."""
    m = _migration(conn)
    uid, _ = make_user(conn, PREFIX)
    with pytest.raises(_RollBack):
        with conn.transaction():
            m.downgrade()
            conn.execute("INSERT INTO notify.preference (user_id, channel, address) "
                         "VALUES (%s, 'SMTP', 'a@x.example, b@y.example')", (uid,))
            m.upgrade()
            with pytest.raises(psycopg.errors.CheckViolation):
                with conn.transaction():
                    conn.execute("UPDATE notify.preference SET min_priority = 1 "
                                 "WHERE user_id = %s", (uid,))
            conn.execute("UPDATE notify.preference SET address = NULL WHERE user_id = %s",
                         (uid,))
            raise _RollBack


def test_the_database_and_the_service_accept_exactly_the_same_addresses(conn):
    """The pattern is spelled twice, once in Python and once in SQL, and a
    value one accepts and the other refuses is a hole or a lockout."""
    from noctornal_api.notifications import single_address_domain

    uid, _ = make_user(conn, PREFIX)
    disagreements = []
    for value in CORPUS:
        try:
            with conn.transaction(force_rollback=True):
                conn.execute("INSERT INTO notify.preference (user_id, channel, address) "
                             "VALUES (%s, 'SMTP', %s)", (uid, value))
            database = True
        except psycopg.errors.CheckViolation:
            database = False
        except psycopg.errors.DataError:
            database = False  # a character PostgreSQL will not store at all
        if database != (single_address_domain(value) is not None):
            disagreements.append((value[:40], database))
    assert disagreements == []


def test_a_null_address_is_the_default_and_is_allowed(conn):
    uid, _ = make_user(conn, PREFIX)
    with conn.transaction(force_rollback=True):
        conn.execute("INSERT INTO notify.preference (user_id, channel) VALUES (%s, 'SMTP')",
                     (uid,))
