"""Migrations 0102 (screening) and 0103 (sandbox detonation), F13 and
F14, 2026-09-24.

Each downgrade refuses on the one fact it states (a MATCH result; a SUBMIT
detonation), naming the count; a database without either is not refused;
the runtime role's grants are declared in GUARDED_TABLES and the REVOKE
takes exactly each declaration's complement; every guarded table carries
its TRUNCATE trigger; 0103 keeps the five legacy statuses legal for
record-only rows. The real upgrade, downgrade and upgrade was run on a
clone of a development database, and CI's head-base-head round trip
covers the empty case.

Email prefix `scrm-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
ALL = ("SELECT", "INSERT", "UPDATE", "DELETE")


def _module(stem: str):
    path = next(VERSIONS.glob(f"*_{stem}.py"))
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


@pytest.mark.parametrize("stem,count", [("sample_screening", 3),
                                        ("sandbox_detonation", 1)])
def test_the_downgrade_refuses_naming_the_count(stem, count, monkeypatch):
    module = _module(stem)
    monkeypatch.setattr(module, "query", lambda _sql: [(count,)])
    monkeypatch.setattr(module, "run", lambda _sql: pytest.fail("changed something"))
    with pytest.raises(RuntimeError, match=f"refusing to downgrade .*{count}"):
        module.downgrade()


@pytest.mark.parametrize("stem", ["sample_screening", "sandbox_detonation"])
def test_the_refusal_counts_the_right_rows(stem, conn):
    """The count query is the refusal's predicate: nothing the demo estate
    or a scrubbed suite leaves is counted, so the 0058 round trip that
    downgrades the suite database through both is never refused."""
    module = _module(stem)
    assert conn.execute(module.COUNT_SQL).fetchone()[0] == 0


@pytest.mark.parametrize("stem", ["sample_screening", "sandbox_detonation"])
def test_the_revoke_takes_exactly_the_complement_of_each_declaration(stem):
    module = _module(stem)
    revoked: dict[str, set[str]] = {}
    # The SQL literal is split over lines inside format(); join the pieces.
    text = re.sub(r"'\s*\n\s*'", "", module.REVOKE_SQL)
    for verbs, tables in re.findall(r"REVOKE ([A-Z, ]+) ON ([a-z_., ]+?) FROM",
                                    text):
        for table in re.split(r"[,\s]+", tables.strip()):
            if table:
                revoked.setdefault(table, set()).update(
                    v.strip() for v in verbs.split(","))
    for table, kept in module.GUARDED_TABLES.items():
        assert revoked.get(table, set()) == set(ALL) - set(kept), table


@pytest.mark.parametrize("table", ["lab.screening_list", "lab.screening_hash",
                                   "lab.screening_result", "lab.screening_review",
                                   "lab.detonation"])
def test_every_guarded_table_has_its_truncate_trigger(table, conn):
    found = conn.execute(
        """SELECT count(*) FROM pg_trigger WHERE tgrelid = %s::regclass
             AND NOT tgisinternal
             AND pg_get_triggerdef(oid) LIKE '%%BEFORE TRUNCATE%%'""",
        (table,)).fetchone()[0]
    assert found == 1


def test_record_only_rows_keep_every_legacy_status(conn):
    definition = conn.execute(
        """SELECT pg_get_constraintdef(oid) FROM pg_constraint
            WHERE conname = 'detonation_status_by_mode'""").fetchone()[0]
    for status in ("PENDING", "AUTHORISED", "SUBMITTED", "REPORTED", "REFUSED"):
        assert status in definition


def test_the_two_permissions_are_the_security_officers(conn):
    rows = conn.execute(
        """SELECT p.key, p.requires_step_up, array_agg(rp.role_key)
             FROM iam.permission p
             JOIN iam.role_permission rp ON rp.permission_key = p.key
            WHERE p.key IN ('sample.screening.manage', 'sample.screening.review')
            GROUP BY p.key, p.requires_step_up ORDER BY p.key""").fetchall()
    assert rows == [("sample.screening.manage", True, ["SECURITY_OFFICER"]),
                    ("sample.screening.review", True, ["SECURITY_OFFICER"])]
