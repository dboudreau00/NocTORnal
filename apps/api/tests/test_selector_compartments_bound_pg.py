"""Migration 0170: `core.selector.compartments` is bound to the compartment
catalogue (the first full run of the merged beta, 2026-10-03).

0134 gave `core.selector` a compartments column and left it unbound, which
the two catalogue tests (test_compartment_binding_pg, test_compartment_contract_pg)
caught. What is held here is what binding it must change, beyond those two:

- the database refuses a row filed under a key nobody registered, on insert
  and on update, in the first line `http/errors.safe_detail` forwards;
- the binding composes with 0134's owner-labels trigger: an owned row still
  takes its owner's keys, and a key the writer names is still judged first;
- `iam.compartment_in_use` sees the column, so a key a selector carries
  cannot be retired;
- a rename moves selector rows, owned and not, with the entity they follow;
- the revision has a real downgrade, upgrade, downgrade, upgrade restores
  the same catalogue, and the upgrade repairs and then refuses on the two
  ways an existing row can already be wrong.

Env-gated on the row security role, as every test that seeds a case is.
Registry keys `SCB-T1-`. The alembic round trip is last because it moves
the schema.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "db" / "migrations"
MIGRATION = MIGRATIONS / "versions" / "0170_selector_compartments_bound.py"
KEY_LIKE = "SCB-T1-%"
COLUMN = "core.selector.compartments"


def _m0170():
    spec = importlib.util.spec_from_file_location("m0170", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Undo(Exception):
    """Rolls a whole up, down, up back so the suite's database is never left
    half way."""


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.execute("DELETE FROM iam.compartment WHERE key LIKE %s", (KEY_LIKE,))
    c.close()


def _key() -> str:
    return f"SCB-T1-{uuid4().hex[:6].upper()}"


def _selector(owner, case_id, value, *, node_id=None, compartments=()):
    """A row as a writer that names its own compartments would write it.

    fixture-guard: deliberate unregistered write. This file shows what the
    binding does with a key nobody registered, so the helper writes
    whichever keys the test names; the tests that need a registered key
    register it themselves first.
    """
    return owner.execute(
        "INSERT INTO core.selector (case_id, selector_type, raw_value, "
        "norm_value, node_id, compartments) "
        "VALUES (%s, 'EMAIL', %s, %s, %s, %s) RETURNING id",
        (case_id, value, value.lower(), node_id, list(compartments))
    ).fetchone()[0]


def _held(owner, selector_id) -> list[str]:
    return owner.execute("SELECT compartments FROM core.selector WHERE id = %s",
                         (selector_id,)).fetchone()[0]


def _binding_definition(conn) -> str | None:
    row = conn.execute(
        "SELECT pg_get_triggerdef(oid) FROM pg_trigger "
        "WHERE tgrelid = 'core.selector'::regclass "
        "AND tgname = 'compartments_registered' AND NOT tgisinternal"
    ).fetchone()
    return row[0] if row else None


def _bound_here(conn) -> bool:
    return any((r[0], r[1], r[2]) == ("core", "selector", "compartments")
               for r in conn.execute(
                   "SELECT schema_name, table_name, column_name "
                   "FROM iam.compartment_bindings()").fetchall())


# ---------------------------------------------------------------------------
# The binding does its job on this column
# ---------------------------------------------------------------------------

def test_a_selector_row_cannot_be_filed_under_an_unregistered_key(owner):
    w = g.World(owner)
    typo, good = _key(), _key()
    s.register(owner, good)

    with pytest.raises(psycopg.errors.RaiseException) as refused, \
            owner.transaction():
        _selector(owner, w.case_id, "a@example.org", compartments=[typo])
    first = str(refused.value).splitlines()[0]
    assert typo in first and COLUMN in first, first

    # The positive control: a registered key goes in, and an update to a
    # key nobody registered is refused as an insert is.
    row = _selector(owner, w.case_id, "b@example.org", compartments=[good])
    assert _held(owner, row) == [good]
    with pytest.raises(psycopg.errors.RaiseException, match=typo), \
            owner.transaction():
        owner.execute("UPDATE core.selector SET compartments = %s WHERE id = %s",
                      ([typo], row))
    assert _held(owner, row) == [good], "a refused write changes nothing"


def test_the_binding_and_the_owner_trigger_agree(owner):
    """The binding sorts before 0134's `selector_labels_follow_owner`, so it
    judges what the writer supplied and the owner trigger then replaces it
    with a copy of `core.node.compartments`, a bound column (docs/05, rule
    6). An owned row therefore ends under its owner's keys whatever
    registered key was named, and an unregistered one is refused anyway."""
    w = g.World(owner)
    kept, other, typo = _key(), _key(), _key()
    node = s.node(owner, w.case_id, w.boss, "scb holder", "AMBER", (kept,))
    s.register(owner, other)

    row = _selector(owner, w.case_id, "c@example.org", node_id=node,
                    compartments=[other])
    assert _held(owner, row) == [kept]
    with pytest.raises(psycopg.errors.RaiseException, match=typo), \
            owner.transaction():
        _selector(owner, w.case_id, "d@example.org", node_id=node,
                  compartments=[typo])


def test_a_key_a_selector_carries_cannot_be_retired(owner):
    """The registry's own guard asks every binding, so a row this column
    holds is now among the reasons a key stays."""
    w = g.World(owner)
    key = _key()
    s.register(owner, key)
    # Unattributed, so no entity carries the key and the selector is the
    # only carrier: what the registry says is about this column alone.
    _selector(owner, w.case_id, "e@example.org", compartments=[key])

    assert owner.execute("SELECT iam.compartment_in_use(%s)",
                         (key,)).fetchone()[0] == [COLUMN]
    with pytest.raises(psycopg.errors.RaiseException) as refused, \
            owner.transaction():
        owner.execute("DELETE FROM iam.compartment WHERE key = %s", (key,))
    assert COLUMN in str(refused.value).splitlines()[0]


def test_a_rename_moves_the_selector_rows_with_the_entity(owner):
    """Before 0170 the lifecycle did not know the column: the entity moved
    to the new key and its selector rows stayed under the old one, a name
    registered to nobody."""
    from noctornal_api.compartment_lifecycle import CompartmentLifecycle
    w = g.World(owner)
    old, new = _key(), _key()
    node = s.node(owner, w.case_id, w.boss, "scb renamed", "AMBER", (old,))
    owned = _selector(owner, w.case_id, "f@example.org", node_id=node)
    unattributed = _selector(owner, w.case_id, "g@example.org",
                             compartments=[old])
    assert _held(owner, owned) == [old]

    out = CompartmentLifecycle(owner).rename(
        old, new, label=None, actor_id=w.boss)

    assert out["rows"][COLUMN] == 2, out["rows"]
    assert "2 selectors" in out["summary"], out["summary"]
    assert _held(owner, owned) == [new]
    assert _held(owner, unattributed) == [new]
    assert owner.execute("SELECT compartments FROM core.node WHERE id = %s",
                         (node,)).fetchone()[0] == [new]
    # Nothing carries the old name any more (the function answers NULL for
    # a key with no carrier), and the registry's final drop of it, which
    # refuses while any bound column still carries it, went through.
    assert not owner.execute("SELECT iam.compartment_in_use(%s)",
                             (old,)).fetchone()[0]


# ---------------------------------------------------------------------------
# The revision
# ---------------------------------------------------------------------------

def test_the_revision_chains_from_0169_and_declares_what_it_binds():
    m = _m0170()
    assert (m.revision, m.down_revision) == ("0170", "0169")
    assert m.ADDED_BOUND_COLUMNS == (("core", "selector", "compartments",
                                      "array"),)
    assert m.UPGRADE_SQL.strip() and m.DOWNGRADE_SQL.strip()
    # The binding is the one 0069 describes: written exactly so, or the
    # contract test would not count it.
    assert m.trigger_sql(*m.ADDED_BOUND_COLUMNS[0]).startswith(
        "CREATE TRIGGER compartments_registered\n"
        '  BEFORE INSERT OR UPDATE OF compartments ON core."selector"')


def test_the_release_names_the_column_and_what_its_rows_are_called():
    from noctornal_api.compartment_lifecycle import BOUND_COLUMNS, NOUNS
    assert ("core", "selector", "compartments", "array") in BOUND_COLUMNS
    assert NOUNS[("core", "selector")] == ("selector", "selectors")


def test_up_down_up_restores_the_same_binding_and_the_upgrade_checks_first(
        owner):
    """The frozen SQL of the revision, in one transaction that is rolled
    back (test_g44_migrations_pg's way). Down: the binding is gone and the
    hole is open again. Back up, the two ways an existing row can be wrong
    are met as the migration meets them: an owned row that drifted from its
    owner is repaired, and a row under a key nobody registered stops the
    upgrade with a message that says how many and what to do."""
    m = _m0170()
    w = g.World(owner)
    kept, stale, orphan = _key(), _key(), _key()
    node = s.node(owner, w.case_id, w.boss, "scb round trip", "AMBER", (kept,))
    before = _binding_definition(owner)
    assert before and _bound_here(owner)

    with pytest.raises(_Undo):
        with owner.transaction():
            owner.execute(m.DOWNGRADE_SQL)
            assert _binding_definition(owner) is None
            assert not _bound_here(owner)
            # The hole, open again.
            hole = _selector(owner, w.case_id, "h@example.org",
                             compartments=[orphan])
            assert _held(owner, hole) == [orphan]

            # Drift 1: an owned row left under a key its owner no longer
            # holds, which only a write that skipped 0134's trigger can do
            # (the lifecycle's rename could not reach this column then).
            owner.execute("ALTER TABLE core.selector "
                          "DISABLE TRIGGER selector_labels_follow_owner")
            drifted = _selector(owner, w.case_id, "i@example.org",
                                node_id=node, compartments=[stale])
            # Drift 2: the same, where the owner's labels are already held
            # by another row of the case for that value, so the repair
            # would collide with the unique key and must leave it alone.
            held = _selector(owner, w.case_id, "j@example.org",
                             node_id=node, compartments=[kept])
            collides = _selector(owner, w.case_id, "j@example.org",
                                 node_id=node, compartments=[stale])
            owner.execute("ALTER TABLE core.selector "
                          "ENABLE TRIGGER selector_labels_follow_owner")
            assert _held(owner, drifted) == [stale]

            repaired = owner.execute(m.REPAIR_SQL).rowcount
            assert repaired == 1, "only the row that could be repaired"
            assert _held(owner, drifted) == [kept]
            assert _held(owner, held) == [kept]
            assert _held(owner, collides) == [stale], "left for a person"

            # What is left is exactly what the check reports, with counts.
            found = owner.execute(m.UNREGISTERED_SQL).fetchall()
            assert sorted(found) == sorted([(orphan, 1), (stale, 1)])
            said = m.refusal_message(sorted(found))
            assert "2 selector rows carry" in said
            assert orphan in said and stale in said
            assert "Register the key" in said
            for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
                assert bad not in said
            assert "1 selector row carries" in m.refusal_message([(orphan, 1)])

            # Registered, nothing is left to refuse on, and the frozen
            # upgrade restores exactly what was there.
            s.register(owner, orphan, stale)
            assert owner.execute(m.UNREGISTERED_SQL).fetchall() == []
            owner.execute(m.UPGRADE_SQL)
            assert _binding_definition(owner) == before
            assert _bound_here(owner)
            with pytest.raises(psycopg.errors.RaiseException), \
                    owner.transaction():
                _selector(owner, w.case_id, "k@example.org",
                          compartments=[_key()])
            raise _Undo
    assert _binding_definition(owner) == before, (
        "the round trip left something behind")


def _alembic():
    from alembic.config import Config
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(MIGRATIONS))
    return cfg


def test_alembic_downgrades_the_binding_and_upgrades_it_again(owner):
    """The real command, both ways, on the test database. Guarded as
    test_compartment_binding_pg's round trip is: only when the database is
    at the chain head, and the schema is put back to head whatever
    happened between."""
    from alembic import command
    from alembic.script import ScriptDirectory
    cfg = _alembic()
    head = ScriptDirectory.from_config(cfg).get_current_head()
    version = owner.execute("SELECT version_num FROM alembic_version"
                            ).fetchone()[0]
    assert version == head, (
        f"the database is at {version} and the chain head is {head}; run "
        "`alembic upgrade head` before this suite")
    before = _binding_definition(owner)
    assert before
    try:
        command.downgrade(cfg, "0169")
        assert _binding_definition(owner) is None
        assert owner.execute("SELECT count(*) FROM information_schema.columns "
                             "WHERE table_schema = 'core' "
                             "AND table_name = 'selector' "
                             "AND column_name = 'compartments'"
                             ).fetchone()[0] == 1, (
            "the column is 0134's, so this downgrade leaves it")
        command.upgrade(cfg, "head")
        assert _binding_definition(owner) == before
    finally:
        if owner.execute("SELECT version_num FROM alembic_version"
                         ).fetchone()[0] != head:
            command.upgrade(cfg, "head")
