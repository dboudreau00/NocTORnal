"""The catalog and the row-level security registry agree (S1, 2026-09-25).

`noctornal_api/rls_registry.py` classifies every table in the product
schemas as under policy, exempt with a reason, or deferred with the reader
work still owed. These tests hold the database to it, so that:

- a table a later migration adds that carries case_id, classification,
  compartments, read_compartments, visibility_clearance or
  visibility_compartments, or a foreign key to a policied table, and is in
  none of the three maps, FAILS BY NAME (a table added later, such as the
  forum and Telegram side tables, is what this must catch);
- the tables with row security enabled are exactly the POLICY set, none
  forced, each with a policy that governs SELECT;
- a policy never decides with a caller-settable value or an anti-join;
- every SECURITY DEFINER function pins its search path, and every trigger
  function that reads a policied table sees the truth (definer) or is
  allow-listed with a reason.

Catalog reads over the owner's connection: they run in the main suite and
on every developer database, with or without the runtime roles.
"""
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set")

SCHEMAS = ("analytics", "audit", "collect", "comms", "core", "deception",
           "iam", "ingest", "lab", "notify")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


def _tables(conn) -> dict[str, tuple[bool, bool]]:
    rows = conn.execute(
        """SELECT n.nspname || '.' || c.relname, c.relrowsecurity,
                  c.relforcerowsecurity
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND n.nspname = ANY(%s)""",
        (list(SCHEMAS),)).fetchall()
    return {r[0]: (r[1], r[2]) for r in rows}


def test_every_table_is_classified_once_and_every_entry_exists(conn):
    from noctornal_api import rls_registry as reg

    overlap = (set(reg.POLICY) & set(reg.EXEMPT)) | (set(reg.POLICY) & set(reg.DEFERRED)) \
        | (set(reg.EXEMPT) & set(reg.DEFERRED))
    assert not overlap, f"classified twice: {sorted(overlap)}"
    live = set(_tables(conn))
    stale = sorted(set(reg.classified()) - live)
    assert not stale, f"the registry names tables that do not exist: {stale}"
    assert "iam.dual_control_request" not in reg.classified()


def test_a_case_or_label_carrying_table_is_never_unclassified(conn):
    """The registry test every later table relies on, the forum and
    Telegram side tables included: a new table with a label column or a
    foreign key to a policied table must be put under policy, exempted or
    deferred, by name."""
    from noctornal_api import rls_registry as reg

    labelled = {r[0] for r in conn.execute(
        """SELECT DISTINCT n.nspname || '.' || c.relname
             FROM pg_attribute a
             JOIN pg_class c ON c.oid = a.attrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND n.nspname = ANY(%s)
              AND a.attnum > 0 AND NOT a.attisdropped
              AND a.attname = ANY(%s)""",
        (list(SCHEMAS), list(reg.LABEL_COLUMNS))).fetchall()}
    policied = sorted(reg.POLICY)
    children = {r[0] for r in conn.execute(
        """SELECT DISTINCT n.nspname || '.' || c.relname
             FROM pg_constraint k
             JOIN pg_class c ON c.oid = k.conrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_class p ON p.oid = k.confrelid
             JOIN pg_namespace pn ON pn.oid = p.relnamespace
            WHERE k.contype = 'f' AND n.nspname = ANY(%s)
              AND pn.nspname || '.' || p.relname = ANY(%s)""",
        (list(SCHEMAS), policied)).fetchall()}
    unclassified = sorted((labelled | children) - set(reg.classified()))
    assert not unclassified, (
        "these tables carry a case or a label, or reference a policied table, "
        "and noctornal_api/rls_registry.py does not say what row-level "
        "security does with them. Put each under policy (a template in the "
        f"registry's docstring), or in DEFERRED or EXEMPT with a reason: {unclassified}")


def test_row_security_is_enabled_on_exactly_the_policy_set_and_forced_nowhere(conn):
    from noctornal_api import rls_registry as reg

    tables = _tables(conn)
    enabled = {t for t, (on, _force) in tables.items() if on}
    assert enabled == set(reg.POLICY), {
        "enabled but not in POLICY": sorted(enabled - set(reg.POLICY)),
        "in POLICY but not enabled": sorted(set(reg.POLICY) - enabled)}
    forced = sorted(t for t, (_on, force) in tables.items() if force)
    assert not forced, (
        f"FORCE ROW LEVEL SECURITY binds the owner too, which is Alembic, the "
        f"fixtures and pg_dump: {forced}")
    assert len(reg.POLICY) >= reg.POLICY_FLOOR


def test_every_policied_table_can_be_read_and_the_ledger_child_cannot_change(conn):
    from noctornal_api import rls_registry as reg

    rows = conn.execute(
        """SELECT schemaname || '.' || tablename, cmd FROM pg_policies
            WHERE schemaname || '.' || tablename = ANY(%s)""",
        (sorted(reg.POLICY),)).fetchall()
    commands: dict[str, set[str]] = {}
    for table, cmd in rows:
        commands.setdefault(table, set()).add(cmd)
    for table, template in reg.POLICY.items():
        got = commands.get(table, set())
        assert got & {"ALL", "SELECT"}, (table, got)
        if template == "LEDGER_CHILD":
            assert got == {"SELECT", "INSERT"}, (table, got)


def test_no_policy_decides_with_a_caller_settable_value_or_an_anti_join(conn):
    """A policy that read current_setting() would trust a value the request
    role sets itself; current_user and session_user name the ROLE, not the
    person; NOT EXISTS over a filtered table is true because of what the
    caller cannot see. The actor comes only from iam.rls_actor()."""
    rows = conn.execute(
        """SELECT schemaname || '.' || tablename, policyname,
                  coalesce(qual, '') || ' ' || coalesce(with_check, '')
             FROM pg_policies WHERE schemaname = ANY(%s)""",
        (list(SCHEMAS),)).fetchall()
    assert rows, "no policies at all: 0114 has not run"
    for table, name, text in rows:
        lowered = text.lower()
        for word in ("current_setting", "current_user", "session_user", "not exists",
                     "not in (", "set_config"):
            assert word not in lowered, (table, name, word)


def test_every_definer_function_pins_its_search_path(conn):
    """A SECURITY DEFINER function runs as the owner. With the caller's
    search path, a temporary object could shadow a name it uses. 0085's
    recording trigger predates this rule and names every object fully; it
    is the one allowed to pin pg_catalog alone."""
    rows = conn.execute(
        """SELECT p.oid::regprocedure::text, coalesce(p.proconfig, '{}')
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = ANY(%s) AND p.prosecdef""",
        (list(SCHEMAS),)).fetchall()
    assert len(rows) >= 20, rows
    for fn, config in rows:
        paths = [c for c in config if c.startswith("search_path=")]
        assert paths, f"{fn} is SECURITY DEFINER with no pinned search_path"
        names = [x.strip() for x in paths[0].split("=", 1)[1].split(",")]
        assert names[0] == "pg_catalog", (fn, names)
        if fn != "collect.record_egress_binding()":
            assert names[-1] == "pg_temp", (fn, names)


def test_the_ceiling_lookup_inlines_and_the_helpers_are_parallel_safe(conn):
    row = conn.execute(
        """SELECT l.lanname, p.prosecdef, p.proconfig, p.provolatile
             FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
            WHERE p.oid = 'iam.rls_ceiling_for(jsonb, uuid)'::regprocedure""").fetchone()
    assert row == ("sql", False, None, "s"), row
    unsafe = conn.execute(
        """SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'iam'
              AND p.proname IN ('rls_actor', 'rls_clearance', 'rls_compartments',
                                'rls_ceilings', 'rls_cases', 'rls_ceiling_for')
              AND p.proparallel <> 's'""").fetchall()
    assert not unsafe, f"a policy helper that is not PARALLEL SAFE makes every query serial: {unsafe}"


def test_every_trigger_function_reading_a_policied_table_sees_the_truth(conn):
    """0113's rule, as a catalog test rather than a fixed list: a trigger
    function whose body names a policied table runs as the definer, or it
    reads only the writer's view and an invariant fails open."""
    from noctornal_api import rls_registry as reg

    names = []
    for table in reg.POLICY:
        schema, rel = table.split(".")
        names.append(f'{schema}."{rel}"' if rel == "case" else f"{schema}.{rel}")
    rows = conn.execute(
        """SELECT n.nspname || '.' || p.proname, p.prosecdef, p.prosrc
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = ANY(%s) AND p.prorettype = 'trigger'::regtype""",
        (list(SCHEMAS),)).fetchall()
    import re
    offenders = []
    for fn, definer, src in rows:
        reads = [t for t in names
                 if re.search(re.escape(t) + r"(?![a-z_])", src)]
        if reads and not definer and fn not in reg.INVOKER_TRIGGER_FUNCTIONS:
            offenders.append((fn, reads))
    assert not offenders, (
        "trigger functions that read a policied table as the writer (make "
        "them SECURITY DEFINER with a pinned search_path, as 0113 does, or "
        f"allow-list them in rls_registry with a reason): {offenders}")


def test_the_egress_role_reads_only_exempt_tables(conn):
    """noctornal_egress is subject to row security and has no binding; a
    policy on a table it reads would blind the proxy."""
    from noctornal_api import rls_registry as reg

    from noctornal_api.egress_ledger import EGRESS_GRANTS

    exists = conn.execute(
        "SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_egress'").fetchone()
    # The tables the proxy's grant list names are all EXEMPT. Collected
    # documents and proposals are policied since 0118 (S1, 2026-09-25) and
    # the proxy reads neither, so the rule is the grant list, not the schema.
    granted = sorted({obj for kind, obj, _priv, _cols in EGRESS_GRANTS
                      if kind == "table"})
    tables = [t for t in granted if t not in reg.EXEMPT]
    assert not tables, tables
    if exists:
        readable = [t for t in reg.POLICY if conn.execute(
            "SELECT has_any_column_privilege('noctornal_egress', %s, 'SELECT')",
            (t.replace("core.case", 'core."case"'),)).fetchone()[0]]
        assert not readable, readable
