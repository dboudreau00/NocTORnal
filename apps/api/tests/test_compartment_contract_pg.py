"""The compartment registry contract (docs/00 decision 71, 2026-09-24).

0059 bound eighteen compartment columns to `iam.compartment` and rendered
`iam.compartment_in_use` as a fixed union over them, which no later
migration could extend: three later features would each have restated
it, and whichever ran last would have dropped the others' columns from
the guard.
Migration 0069 makes the triggers the registry: `iam.compartment_bindings()`
reads every binding from the catalog, and `iam.compartment_in_use` asks
each of them, refusing while any cannot be read. docs/05, "Binding a
compartment column", is the contract every later compartments column
follows; this file enforces it:

- the migrations (0059's tuple plus every later `ADDED_BOUND_COLUMNS`,
  less any `REMOVED_BOUND_COLUMNS`, in chain order), the release's
  `compartment_lifecycle.BOUND_COLUMNS` and the live bindings are one set;
- every text column named like a compartment is bound, and every column a
  binding names is in that set;
- no later migration uses another name for its declaration, or restates
  the three registry functions;
- a column bound after 0059 guards its keys with no function restated, and
  a binding that cannot be read fails CLOSED, per trigger, with the reason;
- the downgrade body is 0059's, and the readiness row reads the bindings.

`added_bound_columns()` and `bound_columns_at_head()` are for the other
compartment tests and for later ones: import them rather than restating
a list. Env-gated on DATABASE_URL. Registry keys `CC-T1-`. Everything that
creates a scratch table or binding runs in a transaction that is rolled
back.
"""
from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; contract tests are gated")

ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "db" / "migrations"

#: The released migration that bound the first eighteen, and 0069, which
#: made the triggers the registry, found by their file slugs, which a
#: renumbering leaves alone.
M0059_SLUG = "_compartments_registered.py"
M0069_SLUG = "_compartment_in_use_reads_bindings.py"

#: Columns named like a compartment that are deliberately NOT bound, each
#: with its reason. APPEND-ONLY, each under a comment naming its migration.
#: Empty: every such column stores compartment keys, including a derived
#: copy (docs/05, rule 1). A stale entry fails.
UNBOUND_BY_DESIGN: dict[str, str] = {}

REGISTRY_FUNCTIONS = ("compartment_in_use", "compartment_bindings",
                      "refuse_compartment_removal")

#: A statement that creates, replaces, alters or drops a registry function,
#: quoted or not.
_RESTATES = re.compile(
    r"(CREATE|DROP|ALTER)\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:IF\s+EXISTS\s+)?"
    r"\"?iam\"?\s*\.\s*\"?(" + "|".join(REGISTRY_FUNCTIONS) + r")\"?",
    re.IGNORECASE)
#: The one ALTER a later migration may make: row-level security's SECURITY
#: DEFINER, or a change of owner (docs/00 decision 76).
_ALLOWED_ALTER = re.compile(
    r"ALTER\s+FUNCTION\s+\"?iam\"?\s*\.\s*\"?\w+\"?\s*\([^)]*\)\s+"
    r"(SECURITY\s+DEFINER|OWNER\s+TO\s+\"?\w+\"?)\s*;?\s*$",
    re.IGNORECASE)


# ---------------------------------------------------------------------------
# The migrations, in chain order
# ---------------------------------------------------------------------------

def _load(path: Path):
    spec = importlib.util.spec_from_file_location(
        f"cc_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _chain() -> list[Path]:
    """Every migration file, base to head, by Alembic's own graph rather
    than by file name, so the order is the chain's whatever the numbers."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    return [Path(s.path) for s in
            reversed(list(ScriptDirectory.from_config(cfg).walk_revisions()))]


def _after(slug: str) -> list[Path]:
    chain = _chain()
    at = next(i for i, p in enumerate(chain) if p.name.endswith(slug))
    return chain[at + 1:]


def _m0059():
    return _load(next(p for p in _chain() if p.name.endswith(M0059_SLUG)))


def _m0069():
    return _load(next(p for p in _chain() if p.name.endswith(M0069_SLUG)))


def added_bound_columns() -> list[tuple[str, str, str, str]]:
    """Every `ADDED_BOUND_COLUMNS` after 0059, in chain order."""
    out: list[tuple[str, str, str, str]] = []
    for path in _after(M0059_SLUG):
        out.extend(tuple(t) for t in
                   getattr(_load(path), "ADDED_BOUND_COLUMNS", ()))
    return out


def bound_columns_at_head() -> list[tuple[str, str, str, str]]:
    """0059's eighteen, then each later migration's additions and removals
    in chain order (docs/05, rules 2 and 2b)."""
    cols = [tuple(t) for t in _m0059().BOUND_COLUMNS]
    for path in _after(M0059_SLUG):
        module = _load(path)
        cols.extend(tuple(t) for t in getattr(module, "ADDED_BOUND_COLUMNS", ()))
        for gone in getattr(module, "REMOVED_BOUND_COLUMNS", ()):
            cols.remove(tuple(gone))
    return cols


def restatements(text: str) -> list[str]:
    """The statements in `text` that restate a registry function, other
    than the one ALTER row-level security may make."""
    found = []
    for m in _RESTATES.finditer(text):
        end = text.find(";", m.start())
        stmt = text[m.start(): len(text) if end < 0 else end + 1]
        if m.group(1).upper() == "ALTER" and _ALLOWED_ALTER.match(
                " ".join(stmt.split())):
            continue
        found.append(" ".join(stmt.split())[:120])
    return found


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.execute("DELETE FROM iam.compartment WHERE key LIKE 'CC-T1-%'")
    c.close()


def _tx() -> psycopg.Connection:
    """A non-autocommit connection whose work is always rolled back."""
    from noctornal_api.db import dsn
    return psycopg.connect(dsn())


def _key() -> str:
    return f"CC-T1-{uuid4().hex[:6].upper()}"


def _bindings(conn) -> list[tuple]:
    return conn.execute(
        """SELECT schema_name, table_name, column_name, kind, enabled,
                  problem FROM iam.compartment_bindings()""").fetchall()


def _binding_sql(table: str, column: str, kind: str, name: str) -> str:
    """The contract's trigger, as a migration renders it (docs/05 rule 1)."""
    when = (f"cardinality(NEW.{column}) > 0" if kind == "array"
            else f"NEW.{column} IS NOT NULL")
    return (f"CREATE TRIGGER {name} BEFORE INSERT OR UPDATE OF {column} "
            f"ON collect.{table} FOR EACH ROW WHEN ({when}) EXECUTE FUNCTION "
            f"iam.refuse_unregistered_compartment('{column}', '{kind}')")


def _refused(tx, sql: str, params=()) -> str:
    tx.execute("SAVEPOINT refused")
    try:
        tx.execute(sql, params)
    except psycopg.errors.RaiseException as exc:
        tx.execute("ROLLBACK TO SAVEPOINT refused")
        return str(exc).splitlines()[0]
    tx.execute("RELEASE SAVEPOINT refused")
    pytest.fail(f"accepted, but the registry must refuse it: {sql}")


# ---------------------------------------------------------------------------
# The migrations follow the contract
# ---------------------------------------------------------------------------

def test_no_migration_after_0059_uses_another_name():
    """One declaration name, ADDED_BOUND_COLUMNS. 0059's own BOUND_COLUMNS
    after it, or the samples-static draft's BOUND_COLUMNS_ADDED, would be
    read by nobody, and the column would be bound in the database and
    unknown to every test that holds the lists together."""
    wrong = [p.name for p in _after(M0059_SLUG)
             if any(hasattr(_load(p), n)
                    for n in ("BOUND_COLUMNS", "BOUND_COLUMNS_ADDED"))]
    assert wrong == [], wrong


def test_no_later_migration_restates_the_registry_functions():
    """Decision 71: one owner. Whichever static body ran last would drop
    every other migration's column from the guard."""
    offenders = {p.name: restatements(p.read_text(encoding="utf-8"))
                 for p in _after(M0069_SLUG)}
    assert {k: v for k, v in offenders.items() if v} == {}
    # The scanner itself, on the spellings it has to catch and the two it
    # has to let through.
    caught = restatements(
        "DROP FUNCTION IF EXISTS iam.compartment_in_use(text);\n"
        'CREATE OR REPLACE FUNCTION "iam"."compartment_bindings"() AS 1;\n'
        "create function iam.refuse_compartment_removal() returns trigger;\n"
        "ALTER FUNCTION iam.compartment_in_use(text) RENAME TO x;\n"
        "ALTER FUNCTION iam.compartment_in_use(text) SECURITY DEFINER;\n"
        "ALTER FUNCTION iam.compartment_bindings() OWNER TO noctornal;\n")
    assert len(caught) == 4, caught


def test_the_catalog_the_release_and_the_migrations_agree(conn):
    from noctornal_api.compartment_lifecycle import BOUND_COLUMNS, NOUNS
    rows = _bindings(conn)
    assert [r for r in rows if r[5] is not None] == [], (
        "a binding that cannot be read")
    assert [r for r in rows if not r[4]] == [], "a disabled binding"
    live = {(s, t, c, k) for s, t, c, k, _e, _p in rows}
    head = bound_columns_at_head()
    assert len(head) == len(set(head)), "a column declared twice"
    assert live == set(head) == set(BOUND_COLUMNS), {
        "live but not declared": sorted(live - set(head)),
        "declared but not live": sorted(set(head) - live),
        "not in compartment_lifecycle": sorted(set(head) - set(BOUND_COLUMNS)),
        "only in compartment_lifecycle": sorted(set(BOUND_COLUMNS) - set(head))}
    assert len(BOUND_COLUMNS) == len(set(BOUND_COLUMNS))
    assert set(NOUNS) == {(s, t) for s, t, _c, _k in BOUND_COLUMNS}
    assert ("collect", "document", "compartments", "array") in added_bound_columns()


def test_every_column_named_like_a_compartment_is_bound(conn):
    """By name, not by the three names 0059 knew, so a differently named
    copy (a `read_compartments`, say) is caught. Base tables only: a view
    stores no key."""
    named = {f"{s}.{t}.{c}" for s, t, c in conn.execute(
        """SELECT c.table_schema, c.table_name, c.column_name
             FROM information_schema.columns c
             JOIN information_schema.tables t
               ON t.table_schema = c.table_schema
              AND t.table_name = c.table_name
            WHERE t.table_type = 'BASE TABLE'
              AND c.column_name LIKE '%%compartment%%'
              AND (c.data_type = 'text' OR c.udt_name = '_text')
              AND c.table_schema NOT IN ('pg_catalog', 'information_schema')"""
    ).fetchall()}
    bound = {f"{s}.{t}.{c}" for s, t, c, _k in bound_columns_at_head()}
    assert named - set(UNBOUND_BY_DESIGN) == bound, {
        "named like a compartment and unbound": sorted(
            named - bound - set(UNBOUND_BY_DESIGN)),
        "bound and not named like one": sorted(bound - named)}
    stale = set(UNBOUND_BY_DESIGN) - named
    assert not stale, f"UNBOUND_BY_DESIGN names columns that are gone: {stale}"
    # And every column ANY trigger calling the guard names is a bound
    # column, whatever the trigger is called: a misnamed binding cannot
    # hide from the lists.
    guarded = set()
    for schema, table, args in conn.execute(
            """SELECT n.nspname, c.relname, tg.tgargs
                 FROM pg_trigger tg
                 JOIN pg_class c ON c.oid = tg.tgrelid
                 JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE NOT tg.tgisinternal
                  AND tg.tgfoid =
                      'iam.refuse_unregistered_compartment()'::regprocedure"""
    ).fetchall():
        column = bytes(args).split(b"\x00")[0].decode()
        guarded.add(f"{schema}.{table}.{column}")
    assert guarded == bound


# ---------------------------------------------------------------------------
# The functions, on columns bound after 0059
# ---------------------------------------------------------------------------

def test_a_column_bound_after_0059_guards_its_keys():
    """A scratch table with an array binding and a second, scalar binding
    under `compartments_registered_<column>`: both are read from the
    catalog, both guard the registry, and no function was restated."""
    key = _key()
    tx = _tx()
    try:
        tx.execute("CREATE TABLE collect.cc_scratch (id int, "
                   "compartments text[] NOT NULL DEFAULT '{}', forced text)")
        tx.execute(_binding_sql("cc_scratch", "compartments", "array",
                                "compartments_registered"))
        tx.execute(_binding_sql("cc_scratch", "forced", "scalar",
                                "compartments_registered_forced"))
        mine = [r for r in _bindings(tx) if r[1] == "cc_scratch"]
        # The positive control: a binding written exactly by the contract
        # reads as well formed.
        assert sorted(mine) == [
            ("collect", "cc_scratch", "compartments", "array", True, None),
            ("collect", "cc_scratch", "forced", "scalar", True, None)]
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (key,))
        # The binding guards writes too, on the second column as well.
        typo = _key()
        refused = _refused(
            tx, "INSERT INTO collect.cc_scratch (id, forced) VALUES (1, %s)",
            (typo,))
        assert typo in refused and "collect.cc_scratch.forced" in refused
        tx.execute("INSERT INTO collect.cc_scratch (id, compartments, forced) "
                   "VALUES (1, %s, %s)", ([key], key))
        assert tx.execute("SELECT iam.compartment_in_use(%s)",
                          (key,)).fetchone()[0] == [
            "collect.cc_scratch.compartments", "collect.cc_scratch.forced"]
        first = _refused(tx, "DELETE FROM iam.compartment WHERE key = %s",
                         (key,))
        assert "collect.cc_scratch.compartments" in first
        assert "collect.cc_scratch.forced" in first
        tx.execute("UPDATE collect.cc_scratch SET compartments = '{}', "
                   "forced = NULL")
        tx.execute("DELETE FROM iam.compartment WHERE key = %s", (key,))
    finally:
        tx.rollback()
        tx.close()


#: (what is wrong, how to build it, the problem sentence it must report).
_BROKEN = [
    ("a column the table does not have",
     "CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF "
     "compartments ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('nope', 'array')",
     "it names a column the table does not have"),
    ("a kind that is neither",
     "CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF "
     "compartments ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('compartments', 'set')",
     "its kind is neither array nor scalar"),
    ("the wrong type for its kind",
     "CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF "
     "compartments ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('compartments', 'scalar')",
     "the column is not of the type its kind says"),
    ("insert only",
     "CREATE TRIGGER compartments_registered BEFORE INSERT ON "
     "collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('compartments', 'array')",
     "it is not BEFORE INSERT OR UPDATE FOR EACH ROW"),
    ("two columns",
     "CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF "
     "compartments, other ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('compartments', 'array')",
     "it does not fire on UPDATE OF exactly that column"),
    ("one argument",
     "CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF "
     "compartments ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('compartments')",
     "it passes 1 argument, and a binding passes two"),
    ("another function under the name",
     "CREATE TRIGGER compartments_registered BEFORE INSERT OR UPDATE OF "
     "compartments ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_compartment_removal()",
     "it does not call iam.refuse_unregistered_compartment"),
    ("the guard under another name",
     "CREATE TRIGGER keys_checked BEFORE INSERT OR UPDATE OF compartments "
     "ON collect.cc_broken FOR EACH ROW EXECUTE FUNCTION "
     "iam.refuse_unregistered_compartment('compartments', 'array')",
     "its name does not follow the binding rule"),
]


@pytest.mark.parametrize("what,create,problem", _BROKEN,
                         ids=[b[0] for b in _BROKEN])
def test_a_binding_that_cannot_be_read_fails_closed(what, create, problem):
    """Each malformed binding is reported with its problem, and while it
    exists no registered key can be dropped, even one nothing carries:
    whether rows there carry it is unknown."""
    key = _key()
    tx = _tx()
    try:
        tx.execute("CREATE TABLE collect.cc_broken (id int, "
                   "compartments text[] NOT NULL DEFAULT '{}', other int)")
        tx.execute(create)
        mine = [r for r in _bindings(tx) if r[1] == "cc_broken"]
        assert len(mine) == 1 and mine[0][5] is not None, mine
        assert mine[0][5].startswith(problem), mine
        tx.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                   (key,))
        refused = _refused(tx, "DELETE FROM iam.compartment WHERE key = %s",
                           (key,))
        assert refused.startswith(
            f"compartment {key} was not dropped or renamed: the binding on "
            f"collect.cc_broken cannot be read ({problem}"), refused
        assert "\n" not in refused
    finally:
        tx.rollback()
        tx.close()


def test_the_in_use_function_names_exactly_the_columns_that_carry_a_key():
    """0059's six seeded columns and a captured document, one key in each:
    exactly those seven, sorted as 0059 sorted them; NULL for a key nobody
    carries."""
    from test_compartment_binding_pg import _seed_rows
    key, idle = _key(), _key()
    tx = _tx()
    try:
        for k in (key, idle):
            tx.execute("INSERT INTO iam.compartment (key, label) "
                       "VALUES (%s, 'x')", (k,))
        rows = _seed_rows(tx)
        for _label, (table, column, row_id) in rows.items():
            value = key if column == "forced_compartment" else [key]
            tx.execute(f"UPDATE {table} SET {column} = %s WHERE id = %s",
                       (value, row_id))
        source = tx.execute(
            """INSERT INTO collect.source (kind, name, default_reliability)
               VALUES ('MANUAL', %s, 'F') RETURNING id""",
            (f"cc-{uuid4().hex[:6]}",)).fetchone()[0]
        tx.execute(
            """INSERT INTO collect.document (source_id, body_text,
                                             content_sha256, compartments)
               VALUES (%s, 'cc', %s, %s)""", (source, os.urandom(32), [key]))
        assert tx.execute("SELECT iam.compartment_in_use(%s)",
                          (key,)).fetchone()[0] == sorted(
            [*rows, "collect.document.compartments"])
        assert tx.execute("SELECT iam.compartment_in_use(%s)",
                          (idle,)).fetchone()[0] is None
    finally:
        tx.rollback()
        tx.close()


def test_the_functions_keep_their_shape(conn):
    rows = {r[0]: r[1:] for r in conn.execute(
        """SELECT p.proname, p.provolatile, p.proconfig, p.proargnames,
                  p.prorettype::regtype::text,
                  obj_description(p.oid, 'pg_proc'), p.prosecdef
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'iam'
              AND p.proname IN ('compartment_in_use',
                                'compartment_bindings')""").fetchall()}
    for name in ("compartment_in_use", "compartment_bindings"):
        volatile, config, _args, _ret, _comment, definer = rows[name]
        assert volatile == "s", f"{name} is not STABLE"
        assert config == ["search_path=pg_catalog, pg_temp"], config
        assert definer is False, "SECURITY DEFINER is row-level security's call (decision 76)"
    _v, _c, args, ret, comment, _d = rows["compartment_in_use"]
    assert args == ["key"] and ret == "text[]"
    assert "compartment_bindings" in comment


def test_the_downgrade_body_is_0059s():
    m59, m69 = _m0059(), _m0069()
    assert m69.BOUND_0059 == m59.BOUND_COLUMNS
    assert m69.in_use_0059_body() == m59._in_use_sql()
    key, held = _key(), _key()
    tx = _tx()
    try:
        tx.execute(m69.IN_USE_0059_SQL)
        assert tx.execute(
            """SELECT l.lanname FROM pg_proc p
                 JOIN pg_language l ON l.oid = p.prolang
                WHERE p.proname = 'compartment_in_use'""").fetchone()[0] == "sql"
        for k in (key, held):
            tx.execute("INSERT INTO iam.compartment (key, label) "
                       "VALUES (%s, 'x')", (k,))
        tx.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash,
                                         compartments)
               VALUES (%s, 'CC', 'x', %s)""",
            (f"cc-{uuid4().hex[:8]}@noctornal.test", [held]))
        assert tx.execute("SELECT iam.compartment_in_use(%s)",
                          (key,)).fetchone()[0] is None
        assert tx.execute("SELECT iam.compartment_in_use(%s)",
                          (held,)).fetchone()[0] == ["iam.app_user.compartments"]
    finally:
        tx.rollback()
        tx.close()
    # The pure half: a later binding is named, the eighteen are not, and a
    # binding that cannot be read is named by its table and problem.
    assert m69.extra_bindings(
        [(s, t, c, None) for s, t, c, _k in m69.BOUND_0059]) == []
    assert m69.extra_bindings([
        ("collect", "cc_scratch", "compartments", None),
        ("collect", "cc_broken", None, "its kind is neither array nor scalar"),
    ]) == ["collect.cc_broken (a binding that cannot be read: its kind is "
           "neither array nor scalar)", "collect.cc_scratch.compartments"]


@pytest.mark.parametrize("extra,want,unwanted", [
    ([("collect", "cc_scratch", "compartments", None)],
     "A column bound after 0059 still carries the binding: "
     "collect.cc_scratch.compartments. Restoring 0059's fixed list would "
     "stop the registry seeing it, so a key it carries could be dropped "
     "while rows are filed under that key. Downgrade the migration that "
     "bound it first.", ("Columns", " them", " they ", "migrations")),
    ([("collect", "cc_a", "compartments", None),
      ("collect", "cc_b", "compartments", None)],
     "Columns bound after 0059 still carry the binding: "
     "collect.cc_a.compartments, collect.cc_b.compartments. Restoring 0059's "
     "fixed list would stop the registry seeing them, so a key they carry "
     "could be dropped while rows are filed under that key. Downgrade the "
     "migrations that bound them first.", ("carries", " it ", "migration ")),
])
def test_the_downgrade_refusal_agrees_with_its_count(monkeypatch, extra, want,
                                                     unwanted):
    """The refusal once said 'Columns ... carry ... them' when it named
    one binding. The count rule holds for operator text, so the downgrade
    itself is run with its catalog read faked and its sentence compared
    whole."""
    m69 = _m0069()
    rows = [(s, t, c, None) for s, t, c, _k in m69.BOUND_0059] + extra
    monkeypatch.setattr(m69, "query", lambda _sql: rows)
    monkeypatch.setattr(m69, "run", lambda _sql: pytest.fail("ran SQL"))
    with pytest.raises(RuntimeError) as refused:
        m69.downgrade()
    assert str(refused.value) == want
    for word in unwanted:
        assert word not in str(refused.value), word


def test_the_register_row_reads_the_bindings(conn):
    from noctornal_api.readiness import _compartment_bindings_intact
    ok = _compartment_bindings_intact(conn)
    assert ok.ok, ok.evidence
    assert ok.evidence.endswith(
        "compartment columns are bound to the registry, as this release "
        "expects.")
    tx = _tx()
    try:
        tx.execute("CREATE TABLE collect.cc_scratch (id int, "
                   "compartments text[] NOT NULL DEFAULT '{}')")
        tx.execute(_binding_sql("cc_scratch", "compartments", "array",
                                "compartments_registered"))
        unknown = _compartment_bindings_intact(tx)
        assert not unknown.ok
        assert ("1 column is bound in the database and unknown to this "
                "release (collect.cc_scratch.compartments)") in unknown.evidence
        assert unknown.action.startswith("run alembic upgrade head")
        tx.rollback()
        tx.execute("ALTER TABLE deception.call_record "
                   "DISABLE TRIGGER compartments_registered")
        off = _compartment_bindings_intact(tx)
        assert not off.ok
        assert ("The binding on deception.call_record.compartments is "
                "disabled") in off.evidence
        for bad in ("OP-", "(s)", chr(0x2014)):
            assert bad not in off.evidence + unknown.evidence
    finally:
        tx.rollback()
        tx.close()
