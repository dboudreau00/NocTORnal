"""Revisions 0139 to 0142 (unit g44, 2026-10-03): each has a real downgrade, and
upgrade, downgrade, upgrade restores the same catalogue.

The frozen SQL of each revision is run inside ONE transaction that is rolled
back, so the suite's own database is never left half way and a round trip
does not depend on the data other suites left behind. Where a downgrade
stops by design (0141 restores a UNIQUE key over exhibits that the revision
exists to allow two of, and a database holding two exhibits of one file in
one case cannot take it back), that refusal is asserted and the round trip
carries on without it.

A real `alembic downgrade` to below 0139 then `upgrade head` is the job of
`test_exhibit_production_pg.py`'s round trips and of CI's head, base, head
step; this file covers what is specific to these four.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import psycopg
import pytest

import g44_support as g

pytestmark = g.GATED

conn = g.conn

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
NAMES = ("0139_evidence_storage_version", "0140_evidence_anchors_fixed",
         "0141_evidence_identity_per_labels", "0142_evidence_hold_and_purge_exclusive")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"g44_{name}", VERSIONS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = [_load(n) for n in NAMES]


class _Undo(Exception):
    """Rolls the whole round trip back."""


def _catalogue(conn) -> dict:
    """What these four revisions touch, read from the catalogs."""
    return {
        "columns": conn.execute(
            """SELECT column_name FROM information_schema.columns
                WHERE table_schema = 'core' AND table_name = 'evidence'
                ORDER BY 1""").fetchall(),
        "triggers": conn.execute(
            """SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger
                WHERE tgrelid = 'core.evidence'::regclass AND NOT tgisinternal
                ORDER BY 1""").fetchall(),
        "indexes": conn.execute(
            """SELECT indexname, indexdef FROM pg_indexes
                WHERE schemaname = 'core' AND tablename = 'evidence'
                ORDER BY 1""").fetchall(),
        "constraints": conn.execute(
            """SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
                WHERE conrelid = 'core.evidence'::regclass ORDER BY 1""").fetchall(),
        "functions": conn.execute(
            """SELECT proname, prosecdef, proconfig FROM pg_proc
                WHERE proname IN ('guard_evidence_anchors', 'guard_evidence_hold_purge')
                ORDER BY 1""").fetchall(),
    }


def test_the_four_revisions_chain_from_0138_and_name_their_sql():
    # The test was written when the first of these hung off 0131. The merge
    # put other units' 0132 to 0138 in front of the four, and the migrations
    # were renumbered with it; the four still run in this order and hang off
    # the revision before them.
    assert [m.revision for m in MODULES] == ["0139", "0140", "0141", "0142"]
    assert [m.down_revision for m in MODULES] == ["0138", "0139", "0140", "0141"]
    for m in MODULES:
        assert m.UPGRADE_SQL.strip() and m.DOWNGRADE_SQL.strip()
        assert callable(m.upgrade) and callable(m.downgrade)


def test_downgrade_then_upgrade_restores_the_same_catalogue(conn):
    before = _catalogue(conn)
    assert {"storage_version_id"} <= {c[0] for c in before["columns"]}
    names = {t[0] for t in before["triggers"]}
    assert {"evidence_anchors_fixed", "evidence_hold_purge_exclusive"} <= names
    duplicates = conn.execute(
        """SELECT count(*) FROM (SELECT 1 FROM core.evidence
                                  GROUP BY case_id, sha256 HAVING count(*) > 1) d"""
    ).fetchone()[0]
    with pytest.raises(_Undo):
        with conn.transaction():
            conn.execute(MODULES[3].DOWNGRADE_SQL)
            skipped = False
            if duplicates:
                # The designed refusal: nothing is merged or deleted to make
                # a rollback succeed.
                with pytest.raises(psycopg.errors.UniqueViolation):
                    with conn.transaction():
                        conn.execute(MODULES[2].DOWNGRADE_SQL)
                skipped = True
            else:
                conn.execute(MODULES[2].DOWNGRADE_SQL)
            conn.execute(MODULES[1].DOWNGRADE_SQL)
            conn.execute(MODULES[0].DOWNGRADE_SQL)
            down = _catalogue(conn)
            assert "storage_version_id" not in {c[0] for c in down["columns"]}
            assert not {"evidence_anchors_fixed", "evidence_hold_purge_exclusive"} & {
                t[0] for t in down["triggers"]}
            assert down["functions"] == []
            if not skipped:
                assert any(c[0] == "evidence_case_id_sha256_key"
                           for c in down["constraints"])
            conn.execute(MODULES[0].UPGRADE_SQL)
            conn.execute(MODULES[1].UPGRADE_SQL)
            if not skipped:
                conn.execute(MODULES[2].UPGRADE_SQL)
            conn.execute(MODULES[3].UPGRADE_SQL)
            assert _catalogue(conn) == before
            raise _Undo
    assert _catalogue(conn) == before, "the round trip left something behind"


def test_0141_refuses_to_restore_the_old_key_over_two_exhibits_of_one_file(conn):
    """The designed refusal, shown on a database that has one: it is the
    reason this revision's downgrade is not written to merge anything."""
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    first, data = g.lodge(conn, store, case_id, boss, classification="RED")
    g.lodge(conn, store, case_id, boss, data=data, classification="AMBER",
            reader_ceiling=("AMBER", frozenset()))
    with pytest.raises(_Undo):
        with conn.transaction():
            with pytest.raises(psycopg.errors.UniqueViolation):
                with conn.transaction():
                    conn.execute(MODULES[2].DOWNGRADE_SQL)
            raise _Undo
    assert first.evidence_id
