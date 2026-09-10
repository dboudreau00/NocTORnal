"""The runtime role holds what the product needs and does not own the tables.

Every REVOKE this schema carries -- 0013 on `audit.event`, 0052 on
`core.purge_tombstone` and `lab.sample_access`, 0058 on
`core.evidence_custody` -- takes privileges away from PUBLIC. An owner's
rights are implicit and are not in the ACL, so none of those statements
constrained the connection the API actually holds, which in the shipped
compose belongs to the role that owns the schema. `ALTER TABLE audit.event
DISABLE TRIGGER ALL` needs table ownership and nothing else.

`db/init/10-app-role.sh` creates `noctornal_app` and migration 0060 grants it.
This file reads the catalog and asserts what that pair left behind.

## What it proves, and what it cannot

Every assertion here is a CATALOG READ, made over the owner's connection about
a different role. It proves the privileges; it does not attempt the attack,
because attempting it would need this file to connect AS `noctornal_app`, and
the password for that role is deliberately not available to the test suite: it
lives in `infra/production/secrets.env`, which is gitignored, is never part of
a checkout, and is read by nothing here.

The inference is exact rather than approximate: `ALTER TABLE`, `DROP TABLE` and
`TRUNCATE` are owner-only operations with no grantable privilege behind them
except TRUNCATE, which nothing grants. So "is not the owner, is not a
superuser, and is not a member of the owner" IS "cannot drop the append-only
triggers". The three facts are asserted separately below for that reason.

## Why this file is doubly gated

`DATABASE_URL`, as every `*_pg` file is. And `NOCTORNAL_APP_DB_ROLE`, because
the role exists only where initdb ran with `NOCTORNAL_APP_DB_PASSWORD` set --
which is a production-shaped stack, and is NOT the dev compose, any developer
database, or CI. Everywhere else 0060 is a deliberate no-op and there is
nothing here to assert.

The gate is read from the ENVIRONMENT rather than from the database, and read
at import time into a module constant, because a `pytest.mark.skipif`
expression is evaluated during collection: a gate that queried `pg_roles` would
have to open a connection to decide whether to skip, and would fail collection
outright on a machine with no database rather than skipping. The module must
import with nothing running.

**CI's "No tests were skipped" step fails on any skip.** So a CI run that does
not create the role will go red here. That is a deployment decision rather than
a test one -- either CI creates `noctornal_app` before `alembic upgrade head`
(the role must exist BEFORE 0060 runs, or 0060 no-ops and grants nothing) and
exports `NOCTORNAL_APP_DB_ROLE=noctornal_app`, or the gate step learns about
this file. `db/README.md` records the ordering.

No fixture here writes anything, so this file has no email prefix and no
cleanup: it cannot collide with a suite running beside it.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
#: The role name, not a boolean: an operator who runs a differently-named role
#: is told that this file does not cover it (see the first test) instead of
#: silently asserting nothing.
APP_DB_ROLE = os.environ.get("NOCTORNAL_APP_DB_ROLE", "").strip()
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and APP_DB_ROLE),
    reason="DATABASE_URL and NOCTORNAL_APP_DB_ROLE required; the least-privilege "
           "role exists only where initdb ran with NOCTORNAL_APP_DB_PASSWORD set")

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "db" / "migrations" / "versions" / "0060_app_role_grants.py"

#: The primary-key column whose DEFAULT draws from a sequence, per ledger.
#: `core.purge_tombstone` is deliberately `None`: its id is a uuid from
#: `gen_random_uuid()`, so it has no sequence, and asserting that keeps this
#: map honest if a later migration changes the column.
LEDGER_SEQUENCE_COLUMN = {
    "audit.event": "seq",
    "core.evidence_custody": "id",
    "lab.sample_access": "id",
    "core.purge_tombstone": None,
}

#: A FLOOR, not a count. The tree holds 79 tables at 0060 and gains more with
#: nearly every revision, so an exact figure would be a number somebody has to
#: edit -- and a number edited on every commit is a number nobody reads. What
#: this guards against is the scan silently matching nothing (a typo in the
#: schema list, a filter that excludes everything) and the loop below then
#: passing vacuously, which is the failure mode a privilege test has.
MINIMUM_TABLES = 60


@pytest.fixture
def conn():
    """The OWNER's connection. `DATABASE_URL` is the owner here by
    construction: the runtime role's DSN is a production secret and the test
    suite could not use it anyway -- ten `*_pg` files run `ALTER TABLE ...
    DISABLE TRIGGER`, which is precisely what this role exists to be unable to
    do. Read-only, so there is nothing to clean up."""
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


def _migration():
    """0060 itself. Its constants are one half of every claim below; the
    catalog is the other."""
    spec = importlib.util.spec_from_file_location("m0060", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scalar(conn, sql, params=None):
    # `None` rather than `()`: psycopg only runs its client-side binder when
    # params is not None, and the binder treats `%` as a placeholder marker.
    # A parameterless query carrying a LIKE pattern would have to double every
    # per cent sign, which is a trap worth not setting.
    return conn.execute(sql, params).fetchone()[0]


def _table_privileges(conn, table: str) -> dict[str, bool]:
    """Every privilege that can exist on a table, for the runtime role.
    Collected as a dict so a failure prints the whole picture rather than the
    one flag that tripped -- an ACL is only readable all at once."""
    return {p: _scalar(conn, "SELECT has_table_privilege(%s, %s, %s)",
                       (APP_DB_ROLE, table, p))
            for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE",
                      "REFERENCES", "TRIGGER")}


def test_the_gate_names_the_role_the_migration_grants():
    """`NOCTORNAL_APP_DB_ROLE` is a gate, not a parameter. If it names some
    other role, every assertion in this file would be made about a role 0060
    never touched and would mean nothing, so the mismatch is the failure."""
    m = _migration()
    assert APP_DB_ROLE == m.APP_ROLE, (
        f"NOCTORNAL_APP_DB_ROLE is {APP_DB_ROLE!r} but migration 0060 grants "
        f"{m.APP_ROLE!r}. This file only covers the role the migration names.")


def test_the_runtime_role_exists_and_holds_no_cluster_power(conn):
    """Four attributes, each of which would undo the control on its own.

    `rolsuper` bypasses privilege checks entirely. `rolcreaterole` is the
    quiet one: on PostgreSQL before 16 a CREATEROLE role could `ALTER ROLE
    <owner> PASSWORD ...` on any non-superuser role and then simply log in as
    the owner, so it is ownership one statement away. `rolbypassrls` matters
    for the row-level policies this schema does not have yet -- a control
    that is inert today and silently defeated on the day it is added is worse
    than no control. `rolreplication` can stream the whole cluster, including
    every ledger, out of the box.
    """
    row = conn.execute(
        """SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb,
                  rolbypassrls, rolreplication
             FROM pg_roles WHERE rolname = %s""", (APP_DB_ROLE,)).fetchone()
    assert row is not None, (
        f"role {APP_DB_ROLE} does not exist, but NOCTORNAL_APP_DB_ROLE says "
        f"this database has one. Initdb ran without NOCTORNAL_APP_DB_PASSWORD, "
        f"and initdb scripts do not re-run: the volume has to be rebuilt.")
    canlogin, *powers = row
    names = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolbypassrls",
             "rolreplication")
    assert canlogin, "the API connects as this role; it has to be able to log in"
    # strict=True: the names and the SELECT list are two hand-written lists in
    # one order, and a failure message that silently dropped the last flag
    # would misreport which power the role holds.
    assert not any(powers), dict(zip(names, powers, strict=True))

    # Granted by the init script, not by 0060, and asserted here because it is
    # the one privilege whose absence looks like an outage rather than a
    # permission error: libpq reports it at connect time, before any query.
    #
    # It does NOT prove the init script's GRANT ran. CONNECT belongs to PUBLIC
    # on a stock cluster, so this passes either way; what it catches is the
    # deployment that hardened the database with `REVOKE CONNECT ON DATABASE
    # ... FROM PUBLIC` and did not put the role's own grant back.
    assert _scalar(conn, "SELECT has_database_privilege(%s, current_database(), "
                         "'CONNECT')", (APP_DB_ROLE,))


def test_it_owns_nothing_and_is_not_a_member_of_the_owner(conn):
    """The whole control, stated as the catalog holds it.

    Ownership is not a privilege and cannot be revoked, only transferred, so
    the only way the API cannot `ALTER TABLE ... DISABLE TRIGGER` is that it
    connects as a role that owns nothing. Membership is the back door: a role
    that is a member of the owner can reach every one of the owner's rights,
    by inheritance if it has INHERIT and by `SET ROLE` regardless -- which is
    why both senses are checked.
    """
    m = _migration()
    rows = conn.execute(
        """SELECT n.nspname || '.' || c.relname, pg_get_userbyid(c.relowner)
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p', 'S') AND n.nspname = ANY(%s)
            ORDER BY 1""", (list(m.SCHEMAS),)).fetchall()
    assert len(rows) >= MINIMUM_TABLES, (
        f"only {len(rows)} relations found across {list(m.SCHEMAS)}; the scan "
        f"has stopped matching the schema and everything below it is vacuous")
    assert not [t for t, owner in rows if owner == APP_DB_ROLE], (
        "the runtime role OWNS these, and an owner may disable any trigger on "
        "them: " + ", ".join(t for t, owner in rows if owner == APP_DB_ROLE))

    owner = _scalar(conn, "SELECT pg_get_userbyid(relowner) FROM pg_class "
                          "WHERE oid = 'core.node'::regclass")
    assert owner != APP_DB_ROLE
    for how in ("USAGE", "MEMBER"):
        assert not _scalar(conn, "SELECT pg_has_role(%s, %s, %s)",
                           (APP_DB_ROLE, owner, how)), (
            f"{APP_DB_ROLE} can reach {owner} via {how}, so every grant below "
            f"is decoration: it can SET ROLE to the owner and drop the triggers")


def test_the_catalog_and_the_migration_agree_on_which_tables_are_ledgers(conn):
    """0060's `LEDGERS` is a hand-written tuple, and the reason UPDATE and
    DELETE come back off those four tables is that each carries an append-only
    trigger pair. The catalog holds the real list: a `BEFORE TRUNCATE`
    statement trigger exists on exactly the four tables the chain made
    append-only -- `audit.event` (0013) and `core.evidence_custody` (0023),
    which arrived with both triggers, and `lab.sample_access` (0031) and
    `core.purge_tombstone` (0032), which arrived with only the row-level one
    and gained the statement-level one in 0052.

    A fifth ledger added by a later migration lands here first. It will have
    inherited UPDATE and DELETE from 0060's default privileges the moment it
    was created -- silently, because that is what a default privilege does --
    and its own migration must revoke them.
    """
    m = _migration()
    found = {r[0] for r in conn.execute(
        """SELECT n.nspname || '.' || c.relname
             FROM pg_trigger t
             JOIN pg_class c ON c.oid = t.tgrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE NOT t.tgisinternal
              AND pg_get_triggerdef(t.oid) LIKE '%BEFORE TRUNCATE%'""")}
    assert found == set(m.LEDGERS), {
        "append-only in the database but not revoked by 0060":
            sorted(found - set(m.LEDGERS)),
        "revoked by 0060 but no longer append-only":
            sorted(set(m.LEDGERS) - found)}
    assert set(LEDGER_SEQUENCE_COLUMN) == set(m.LEDGERS)


def test_the_ledgers_are_readable_appendable_and_nothing_else(conn):
    """SELECT and INSERT, and none of the other five.

    TRUNCATE is the interesting absence. Nothing revokes it, because a GRANT
    of DML never confers it: it is an owner-only operation unless explicitly
    granted, and it is the one that would empty a ledger without firing a
    row-level trigger (0052 exists because of exactly that gap). TRIGGER is
    checked for the same reason in reverse -- it would let this role install
    its own trigger on the ledger, though not drop the existing one.
    """
    m = _migration()
    for table in m.LEDGERS:
        got = _table_privileges(conn, table)
        assert got["SELECT"] and got["INSERT"], (table, got)
        assert not got["UPDATE"] and not got["DELETE"], (
            f"{table} is append-only and the runtime role can mutate it: {got}")
        assert not got["TRUNCATE"], (table, got)
        assert not got["TRIGGER"], (table, got)


def test_the_ledger_sequences_are_usable_or_every_audited_action_fails(conn):
    """The grant that reads as boilerplate and is not.

    This database has exactly three sequences and all three sit behind
    append-only ledgers. A column DEFAULT `nextval(...)` is evaluated as the
    INSERTING role, so without USAGE the very first audited action fails --
    and it fails saying `permission denied for sequence event_seq_seq`, which
    names the sequence and not the table, sending whoever reads the log to the
    wrong place.
    """
    seen = 0
    for table, column in LEDGER_SEQUENCE_COLUMN.items():
        seq = _scalar(conn, "SELECT pg_get_serial_sequence(%s, %s)",
                      (table, column or "id"))
        if column is None:
            assert seq is None, (
                f"{table}.id now draws from {seq}; it used to be a uuid "
                f"default, and this file's map has to say so")
            continue
        assert seq is not None, f"{table}.{column} no longer has a sequence"
        assert _scalar(conn, "SELECT has_sequence_privilege(%s, %s, 'USAGE')",
                       (APP_DB_ROLE, seq)), (
            f"INSERT into {table} will fail: no USAGE on {seq}")
        # SELECT is the spare half, and asserted because 0060 grants it, not
        # because an INSERT needs it: USAGE alone already covers `nextval`
        # AND `currval`. SELECT is what lets a session read `last_value` off
        # the sequence itself, which nothing in the product does today. A
        # database holding one and not the other diverged from 0060 by hand.
        assert _scalar(conn, "SELECT has_sequence_privilege(%s, %s, 'SELECT')",
                       (APP_DB_ROLE, seq))
        seen += 1
    assert seen == 3, f"expected three ledger sequences, checked {seen}"


def test_an_ordinary_table_carries_the_full_four(conn):
    """The other half of the same contract: the role is least-privilege, not
    read-only. `core.node` is the graph's central table -- `graph.py` inserts
    into it and `graph.py` and `merges.py` update it -- so a control that made
    it unwritable would have replaced a security problem with an outage.

    DELETE is asserted for the shape of the grant, not for a path the product
    walks: nothing in `apps/api/src` deletes a `core.node` row, because history
    here is superseded rather than overwritten (docs/01). The blanket grant
    confers it, and this table is the control that the blanket grant landed --
    an ordinary table keeping all four while the four ledgers keep two."""
    got = _table_privileges(conn, "core.node")
    assert got["SELECT"] and got["INSERT"] and got["UPDATE"] and got["DELETE"], got
    assert not got["TRUNCATE"], got


def test_every_table_in_every_product_schema_is_reachable(conn):
    """The blanket grants, checked one table at a time.

    `GRANT ... ON ALL TABLES IN SCHEMA` applies to the tables that existed
    when it ran and to nothing else; the ALTER DEFAULT PRIVILEGES clauses are
    what cover later ones, and they bind to a specific creating role. A table
    created by a migration run as some other identity is therefore reachable
    by its owner and by nothing the product runs, and the symptom is a single
    endpoint returning 500 with `permission denied for table <something>` long
    after the migration that introduced it went green.
    """
    m = _migration()
    tables = [r[0] for r in conn.execute(
        """SELECT n.nspname || '.' || c.relname
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND n.nspname = ANY(%s)
            ORDER BY 1""", (list(m.SCHEMAS),)).fetchall()]
    assert len(tables) >= MINIMUM_TABLES, (
        f"only {len(tables)} tables found; the scan is not seeing the schema")

    ledgers = set(m.LEDGERS)
    unreachable = {}
    for table in tables:
        got = _table_privileges(conn, table)
        wanted = ("SELECT", "INSERT") if table in ledgers else (
            "SELECT", "INSERT", "UPDATE", "DELETE")
        missing = [p for p in wanted if not got[p]]
        if missing:
            unreachable[table] = missing
    assert not unreachable, unreachable


def test_the_version_table_is_readable_and_not_writable(conn):
    """`readiness.py`'s `migrations_at_head` check reads `alembic_version` on
    the API's own connection. Alembic creates that table, so it belongs to the
    owner and carries no grant of its own -- without 0060's explicit SELECT
    the readiness endpoint reports `permission denied for table
    alembic_version` as a failed check, which reads as "this deployment is
    behind" and is nothing of the sort.

    SELECT only. A runtime process that could stamp a revision could tell the
    check what it wanted to hear.
    """
    m = _migration()
    got = _table_privileges(conn, m.VERSION_TABLE)
    assert got["SELECT"], got
    assert not (got["INSERT"] or got["UPDATE"] or got["DELETE"]), got
    assert _scalar(conn, "SELECT has_schema_privilege(%s, 'public', 'USAGE')",
                   (APP_DB_ROLE,)), (
        "pgcrypto's digest() lives in public and audit_verify.py calls it by "
        "name; without USAGE on the schema the chain cannot be verified")


def test_every_schema_the_migrations_create_is_granted(conn):
    """0060's `SCHEMAS` against the database. A migration that adds an
    eleventh schema and forgets this list produces a runtime role that cannot
    see it at all -- `permission denied for schema <new>` on every query --
    and nothing else in the tree compares the two.
    """
    m = _migration()
    # Single per cent signs, and no parameters: see `_scalar`. The backslash
    # escapes the LIKE wildcard `_` so `pg_toast_temp_3` is excluded and a
    # schema honestly named `pgvector` would not be.
    live = {r[0] for r in conn.execute(
        r"""SELECT nspname FROM pg_namespace
             WHERE nspname NOT LIKE 'pg\_%'
               AND nspname NOT IN ('public', 'information_schema')""")}
    assert live == set(m.SCHEMAS), {
        "in the database, not granted by 0060": sorted(live - set(m.SCHEMAS)),
        "granted by 0060, not in the database": sorted(set(m.SCHEMAS) - live)}
    for schema in m.SCHEMAS:
        assert _scalar(conn, "SELECT has_schema_privilege(%s, %s, 'USAGE')",
                       (APP_DB_ROLE, schema)), schema
        assert not _scalar(conn, "SELECT has_schema_privilege(%s, %s, 'CREATE')",
                           (APP_DB_ROLE, schema)), (
            f"{schema}: the runtime role can create objects in it, so it can "
            f"own them, and an owner may disable their triggers")
