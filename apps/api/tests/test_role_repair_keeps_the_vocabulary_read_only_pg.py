"""After the role repair the request role still cannot write the reference vocabulary.

`scripts/runtime_roles.py ensure` replays the blanket grant of INSERT, UPDATE and DELETE on every
table, then the revisions that take writes back. The ontology tables, the comms platform catalogue
and the ingest category vocabulary carry no case and no row policy, so a write to them reaches every
case. Run on this test database inside a transaction that is rolled back.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    c.close()


def test_the_repair_leaves_the_vocabulary_read_only(owner):
    roles = _load("runtime_roles_vocabulary_pg", ROOT / "scripts" / "runtime_roles.py")
    vocabulary = _load("m_vocabulary_pg", next(VERSIONS.glob("*_vocabulary_read_only.py"))
                       ).RUNTIME_READ_ONLY_TABLES
    held = []
    try:
        with owner.transaction():
            roles.grant(owner)
            held = [(table, privilege)
                    for table in vocabulary
                    for privilege in ("INSERT", "UPDATE", "DELETE")
                    if owner.execute("SELECT has_table_privilege(%s, %s, %s)",
                                     (s.APP_ROLE, table, privilege)).fetchone()[0]]
            readable = all(
                owner.execute("SELECT has_table_privilege(%s, %s, 'SELECT')",
                              (s.APP_ROLE, table)).fetchone()[0]
                for table in vocabulary)
            raise psycopg.Rollback()
    except psycopg.Rollback:
        pass
    assert held == []
    assert readable
