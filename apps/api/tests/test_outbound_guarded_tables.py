"""The outbound integrations' guarded ledgers lose what their migrations say
they lose (F7, F15.2 to F15.4, 2026-09-25).

test_app_role_privileges_pg.py reads the catalog for every GUARDED_TABLES
entry, but only where the least-privilege role exists (a production-shaped
stack, and CI once it creates the role). Everywhere else it skips, so a
migration that declared a table guarded and forgot its REVOKE would pass
here unseen. This reads the migrations themselves: every table that 0097,
0098, 0099 or 0101 declares in GUARDED_TABLES has DELETE revoked from the
runtime role in the same migration, and UPDATE too where the declaration
keeps no UPDATE. The triggers that refuse DELETE and TRUNCATE are tested
against the database in each item's own file.

Pure: no database.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
MIGRATIONS = ("0097_notify_jira.py", "0098_outbound_providers.py",
              "0099_lookup_ledger.py", "0101_lookup_batches.py")
_REVOKE = re.compile(r"REVOKE ([A-Z, ]+) ON ([a-z_.,\s]+?) FROM")


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name[:-3], VERSIONS / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _revoked(source: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for privileges, tables in _REVOKE.findall(source):
        for table in (t.strip() for t in tables.split(",")):
            out.setdefault(table, set()).update(p.strip() for p in privileges.split(","))
    return out


@pytest.mark.parametrize("name", MIGRATIONS)
def test_every_guarded_table_loses_what_its_declaration_does_not_keep(name):
    module = _load(name)
    guarded = getattr(module, "GUARDED_TABLES", {})
    assert guarded, f"{name} declares no GUARDED_TABLES"
    revoked = _revoked((VERSIONS / name).read_text(encoding="utf-8"))
    for table, kept in guarded.items():
        assert "DELETE" not in kept, (name, table)
        assert "DELETE" in revoked.get(table, set()), (name, table, revoked)
        if "UPDATE" not in kept:
            assert "UPDATE" in revoked.get(table, set()), (name, table)
