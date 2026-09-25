"""The egress proxy's database role holds exactly EGRESS_GRANTS (S2, 2026-09-24).

Gated like test_app_role_privileges_pg.py: DATABASE_URL, and
NOCTORNAL_EGRESS_DB_ROLE naming the role, which exists only where initdb ran
db/init/20-egress-role.sh with NOCTORNAL_EGRESS_DB_PASSWORD set (CI creates
it before migrating). The attack cases connect AS the role, with
NOCTORNAL_EGRESS_DB_PASSWORD; the catalogue cases read over the owner's
connection.
"""
from __future__ import annotations

import os

import psycopg
import pytest

import egress_support as es
from noctornal_api import egress_ledger, egress_proxy

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ROLE = os.environ.get("NOCTORNAL_EGRESS_DB_ROLE", "").strip()
PASSWORD = os.environ.get("NOCTORNAL_EGRESS_DB_PASSWORD", "")
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and ROLE),
    reason="DATABASE_URL and NOCTORNAL_EGRESS_DB_ROLE required; the egress proxy's role "
           "exists only where initdb ran with NOCTORNAL_EGRESS_DB_PASSWORD set")


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.collection_standin(c):
        es.grant_egress_role(c)
        yield c
    c.close()


def _as_role():
    from noctornal_api.db import dsn
    info = psycopg.conninfo.conninfo_to_dict(dsn())
    info.update(user=ROLE, password=PASSWORD)
    return psycopg.connect(**info, autocommit=True, connect_timeout=5)


def test_the_role_is_the_one_this_build_grants(conn):
    assert ROLE == egress_ledger.EGRESS_ROLE


def test_the_role_holds_no_cluster_power_and_owns_nothing(conn):
    row = conn.execute(
        """SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,
                  rolinherit, rolcanlogin
             FROM pg_roles WHERE rolname = %s""", (ROLE,)).fetchone()
    assert row == (False, False, False, False, False, False, True)
    owned = conn.execute(
        "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
        "WHERE r.rolname = %s", (ROLE,)).fetchone()[0]
    assert owned == 0
    member = conn.execute(
        "SELECT pg_has_role(%s, current_user, 'MEMBER')", (ROLE,)).fetchone()[0]
    assert member is False


def test_every_declared_grant_is_held(conn):
    assert egress_ledger.missing_grants(conn, ROLE) == []


def test_nothing_beyond_the_declared_grants_is_held(conn):
    declared_tables = {(obj, privilege) for kind, obj, privilege, cols in egress_ledger.EGRESS_GRANTS
                       if kind == "table" and cols is None}
    declared_columns = {(obj, privilege, col)
                        for kind, obj, privilege, cols in egress_ledger.EGRESS_GRANTS
                        if kind == "table" and cols for col in cols}
    tables = {(f"{r[0]}.{r[1]}", r[2]) for r in conn.execute(
        """SELECT table_schema, table_name, privilege_type
             FROM information_schema.role_table_grants WHERE grantee = %s""",
        (ROLE,)).fetchall()}
    assert tables == declared_tables, tables ^ declared_tables
    columns = {(f"{r[0]}.{r[1]}", r[3], r[2]) for r in conn.execute(
        """SELECT table_schema, table_name, column_name, privilege_type
             FROM information_schema.column_privileges WHERE grantee = %s""",
        (ROLE,)).fetchall()}
    # A table-level grant shows up per column too: only the column-level ones count.
    columns = {c for c in columns if (c[0], c[1]) not in declared_tables}
    assert columns == declared_columns, columns ^ declared_columns


@pytest.mark.skipif(not PASSWORD, reason="NOCTORNAL_EGRESS_DB_PASSWORD is needed to sign in")
def test_as_the_role_it_appends_and_cannot_read_secrets_or_rewrite(conn):
    with _as_role() as role:
        seq = egress_ledger.write(role, egress_ledger.Row(
            event="REWRAP", route_id="proxy", reason="exits_rewrapped", item_count=0))
        assert seq > 0
        for statement in (
                "SELECT secret_ciphertext FROM collect.collection_account LIMIT 1",
                "SELECT * FROM audit.event LIMIT 1",
                "SELECT email FROM iam.app_user LIMIT 1",
                "SELECT * FROM collect.document LIMIT 1",
                "UPDATE collect.egress_connection SET reason = 'x' WHERE seq = 1",
                "DELETE FROM collect.egress_connection WHERE seq = 1",
                "UPDATE collect.egress_profile SET ceiling = 'RED'"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                role.execute(statement)
        # What the proxy starts on: the grants it checks all hold.
        assert egress_proxy.start_checks(role, production=True) == []
        assert egress_ledger.verify(conn)["first_break_seq"] is None


def test_a_role_missing_one_grant_is_refused_at_start(conn):
    conn.execute(f"REVOKE SELECT (base_url) ON collect.source FROM {ROLE}")
    try:
        missing = egress_ledger.missing_grants(conn, ROLE)
        assert missing == ["SELECT ON collect.source (base_url)"]
    finally:
        conn.execute(f"GRANT SELECT (base_url) ON collect.source TO {ROLE}")
