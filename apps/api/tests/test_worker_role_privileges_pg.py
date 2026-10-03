"""The system role bypasses row security and holds nothing else (S1).

2026-09-25. `noctornal_worker` is what `db.connect_system` connects as: the
work that must see every row. BYPASSRLS is the one power it has over
`noctornal_app`; privilege for privilege it holds what the request role
holds plus the IAM-plane writes 0109 took from the request role and the
whole-table UPDATE 0155 narrowed to columns for the request role on the
ingest records and credentials (F51, 2026-10-02), and in particular the
same closed ledgers and insert-only records. A later migration that
revokes something from one runtime role and forgets the other fails here.

Catalog reads over the owner's connection, gated like
test_app_role_privileges_pg.py; CI creates both roles before migrating.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

import rls_support as s

pytestmark = s.GATED

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def _migration(prefix: str):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn():
    c = s.owner_conn()
    yield c
    c.close()


def test_the_gate_names_the_role_the_migration_grants():
    assert os.environ.get("NOCTORNAL_WORKER_DB_ROLE", "noctornal_worker") == \
        _migration("0108").WORKER_ROLE


def test_it_bypasses_row_security_and_holds_no_other_power(conn):
    row = conn.execute(
        """SELECT rolcanlogin, rolbypassrls, rolsuper, rolcreaterole, rolcreatedb,
                  rolreplication, rolinherit
             FROM pg_roles WHERE rolname = %s""", (s.WORKER_ROLE,)).fetchone()
    assert row is not None, (
        f"{s.WORKER_ROLE} does not exist: CI creates it in the runtime role step "
        f"(NOCTORNAL_WORKER_DB_PASSWORD), a development database with "
        f"scripts/runtime_roles.py ensure")
    login, bypass, *powers = row
    assert login and bypass
    assert not any(powers), powers


def test_it_owns_nothing_and_is_a_member_of_nothing_that_does(conn):
    owned = conn.execute(
        """SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
            WHERE r.rolname = %s""", (s.WORKER_ROLE,)).fetchone()[0]
    assert owned == 0
    owner = conn.execute("SELECT pg_get_userbyid(relowner) FROM pg_class "
                         "WHERE oid = 'core.node'::regclass").fetchone()[0]
    for role in (owner, s.APP_ROLE):
        for how in ("USAGE", "MEMBER"):
            assert not conn.execute("SELECT pg_has_role(%s, %s, %s)",
                                    (s.WORKER_ROLE, role, how)).fetchone()[0], (role, how)


def test_privilege_for_privilege_it_is_the_request_role_plus_the_iam_plane(conn):
    lockdown = _migration("0109")
    narrowed = _migration("0155")
    tables = [r[0] for r in conn.execute(
        """SELECT n.nspname || '.' || quote_ident(c.relname)
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND n.nspname = ANY(%s)""",
        (list(_migration("0108").SCHEMAS),)).fetchall()]
    assert len(tables) >= 100
    differ = {}
    for table in tables:
        read_only = (table.split(".", 1)[0] in lockdown.RUNTIME_READ_ONLY_SCHEMAS
                     or table in lockdown.RUNTIME_READ_ONLY_TABLES)
        for priv in PRIVILEGES:
            worker = conn.execute("SELECT has_table_privilege(%s, %s, %s)",
                                  (s.WORKER_ROLE, table, priv)).fetchone()[0]
            app = conn.execute("SELECT has_table_privilege(%s, %s, %s)",
                               (s.APP_ROLE, table, priv)).fetchone()[0]
            if read_only and priv in ("INSERT", "UPDATE", "DELETE"):
                # The system role writes the IAM plane unless an older
                # migration closed the table to both runtime roles.
                continue
            if priv == "UPDATE" and table in narrowed.SYSTEM_KEEPS_UPDATE:
                # 0155 (F51, 2026-10-02): the purge, a compartment rename,
                # scoring and the re-wrap write columns no request does.
                continue
            if worker != app:
                differ[(table, priv)] = {"worker": worker, "app": app}
    assert not differ, differ


def _column_updates(conn, role: str, table: str) -> set[str]:
    return {r[0] for r in conn.execute(
        """SELECT attname FROM pg_attribute
            WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped
              AND has_column_privilege(%s, attrelid, attnum, 'UPDATE')""",
        (table, role)).fetchall()}


def test_on_the_ingest_records_it_keeps_only_what_a_system_path_writes(conn):
    """0155 (F51, 2026-10-02). On the reveal authorisations no system
    connection writes anything but the count, so the system role is the
    request role exactly: query_count and nothing else. On the records and
    the credentials it keeps table UPDATE, which the purge, a compartment
    rename, scoring and the KEK re-wrap need, and so every column the
    request role holds."""
    narrowed = _migration("0155")
    for table, columns in narrowed.RUNTIME_COLUMN_UPDATES.items():
        app = _column_updates(conn, s.APP_ROLE, table)
        worker = _column_updates(conn, s.WORKER_ROLE, table)
        assert app == set(columns), (table, app)
        whole = conn.execute("SELECT has_table_privilege(%s, %s, 'UPDATE')",
                             (s.WORKER_ROLE, table)).fetchone()[0]
        if table in narrowed.SYSTEM_KEEPS_UPDATE:
            assert whole and app < worker, (table, worker)
        else:
            assert not whole and worker == app, (table, worker)


def test_ensure_replays_the_column_grants_after_the_blanket_ones(conn):
    """`scripts/runtime_roles.py ensure` replays 0108's blanket grant, which
    hands both roles table UPDATE on every table; without 0155's replay
    after it, a role created after 0155 ran would get the authorisation's
    window and a record's case back (F51, 2026-10-02). Run inside a
    transaction that is rolled back, on this test database only."""
    import psycopg

    scripts = VERSIONS.parents[2] / "scripts"
    spec = importlib.util.spec_from_file_location("runtime_roles_t", scripts / "runtime_roles.py")
    roles = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(roles)
    narrowed = _migration("0155")
    seen = {}
    try:
        with conn.transaction():
            roles.grant(conn)
            for table in narrowed.RUNTIME_COLUMN_UPDATES:
                seen[table] = {
                    role: (conn.execute("SELECT has_table_privilege(%s, %s, 'UPDATE')",
                                        (role, table)).fetchone()[0],
                           _column_updates(conn, role, table))
                    for role in (s.APP_ROLE, s.WORKER_ROLE)}
            raise psycopg.Rollback()
    except psycopg.Rollback:
        pass
    for table, columns in narrowed.RUNTIME_COLUMN_UPDATES.items():
        assert seen[table][s.APP_ROLE] == (False, set(columns)), (table, seen[table])
        if table not in narrowed.SYSTEM_KEEPS_UPDATE:
            assert seen[table][s.WORKER_ROLE] == (False, set(columns)), (table, seen[table])


def test_the_iam_plane_is_writable_to_it_and_read_only_to_the_request_role(conn):
    for table in ("iam.session", "iam.app_user", "iam.case_assignment",
                  "iam.break_glass", "iam.user_role", "lab.download_ticket"):
        assert conn.execute("SELECT has_table_privilege(%s, %s, 'INSERT')",
                            (s.WORKER_ROLE, table)).fetchone()[0], table
        assert not conn.execute("SELECT has_table_privilege(%s, %s, 'INSERT')",
                                (s.APP_ROLE, table)).fetchone()[0], table
    for ledger in ("audit.event", "core.evidence_custody", "core.purge_tombstone",
                   "lab.sample_access"):
        for priv in ("UPDATE", "DELETE", "TRUNCATE"):
            assert not conn.execute("SELECT has_table_privilege(%s, %s, %s)",
                                    (s.WORKER_ROLE, ledger, priv)).fetchone()[0], (ledger, priv)
