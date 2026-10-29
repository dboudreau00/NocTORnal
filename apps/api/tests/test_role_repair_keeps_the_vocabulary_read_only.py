"""The role repair leaves the reference vocabulary read-only to the request role.

`scripts/runtime_roles.py ensure` replays the blanket grant of INSERT, UPDATE and DELETE on every
table. On a database that already took those writes off the ontology and the comms and ingest
vocabularies, the replay has to take them off again afterwards, or the request role can rewrite
which identifiers raise merge leads and which identifier a platform is indexed on, for every case.

Static: drives `grant` against a connection that records each statement and reports the database at
head. No Postgres.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vocabulary() -> tuple[str, ...]:
    return _load("m_vocabulary", next(VERSIONS.glob("*_vocabulary_read_only.py"))
                 ).RUNTIME_READ_ONLY_TABLES


def _head() -> str:
    return max(path.name[:4] for path in VERSIONS.glob("[0-9][0-9][0-9][0-9]_*.py"))


class _Result:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _Recorder:
    """Keeps every statement and answers the revision query with the head."""

    def __init__(self, version: str):
        self.version = version
        self.statements: list[str] = []

    def execute(self, sql, params=None):
        text = sql if isinstance(sql, str) else str(sql)
        self.statements.append(text)
        if "alembic_version" in text:
            return _Result((self.version,))
        return _Result(None)


def test_the_repair_revokes_vocabulary_writes_after_the_blanket_grant():
    """Every vocabulary table loses INSERT, UPDATE and DELETE for the request role in a statement
    that runs after the blanket grant to that role."""
    roles = _load("runtime_roles_vocabulary", ROOT / "scripts" / "runtime_roles.py")
    conn = _Recorder(_head())
    roles.grant(conn)
    granted_at = next(
        i for i, statement in enumerate(conn.statements)
        if "noctornal_app" in statement and "GRANT SELECT, INSERT, UPDATE, DELETE" in statement)
    vocabulary = _vocabulary()
    assert vocabulary
    still_writable = [
        table for table in vocabulary
        if not any(f"REVOKE INSERT, UPDATE, DELETE ON {table} " in statement
                   and "noctornal_app" in statement
                   for statement in conn.statements[granted_at + 1:])]
    assert not still_writable, still_writable
