"""The Telegram platform names the ontology's durable selector type (roadmap
F5.4 (b), 2026-09-24; migration 0107). DATABASE_URL-gated.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; these tests need the database")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


@pytest.fixture
def conn():
    from noctornal_api.db import connect

    c = connect()
    yield c
    c.close()


def test_the_telegram_platform_names_the_ontology_durable_type(conn):
    from noctornal_api.comms import PLATFORM_SELECTOR_TYPE

    row = conn.execute(
        """SELECT p.durable_selector_type,
                  EXISTS (SELECT 1 FROM core.selector_type t
                           WHERE t.key = p.durable_selector_type)
             FROM comms.platform p WHERE p.key = 'TELEGRAM'""").fetchone()
    assert row == ("TELEGRAM_ID", True)
    assert PLATFORM_SELECTOR_TYPE["TELEGRAM"] == row[0]


def test_the_migration_round_trips_the_one_row(conn):
    """0107's own statements, applied inside a transaction that is rolled
    back: down restores the seed's value on the TELEGRAM row only, and up
    corrects it again."""
    path = next(VERSIONS.glob("*_comms_platform_telegram_type.py"))
    spec = importlib.util.spec_from_file_location("m0107", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    statements = []
    module.run = statements.append
    module.downgrade()
    module.upgrade()
    down, up = statements
    before = dict(conn.execute("SELECT key, durable_selector_type FROM comms.platform"
                               ).fetchall())
    with pytest.raises(RuntimeError), conn.transaction():
        conn.execute(down)
        after_down = dict(conn.execute(
            "SELECT key, durable_selector_type FROM comms.platform").fetchall())
        assert after_down["TELEGRAM"] == "TELEGRAM_UID"
        assert {k: v for k, v in after_down.items() if k != "TELEGRAM"} == \
            {k: v for k, v in before.items() if k != "TELEGRAM"}
        conn.execute(up)
        assert conn.execute("SELECT durable_selector_type FROM comms.platform "
                            "WHERE key = 'TELEGRAM'").fetchone()[0] == "TELEGRAM_ID"
        raise RuntimeError("roll back")
