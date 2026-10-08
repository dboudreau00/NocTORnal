"""docs/17, "Tests and code structure", test isolation (Beta 1.1).

Some tests skipped or failed depending on rows other suites leave, and CI's
no-skip gate turns the skips into failures. Five suites now run in ONE
transaction that is rolled back (`rolled_back.py`), hide what the database
already holds that their checks count, and so need no skip; a sixth stopped
guessing how long a lock wait takes and asks `pg_stat_activity`.

The suites themselves are the fix, and each was run over a database with the
leftovers it used to skip for. What these hold is that the fix stays:

- the helper rolls back, and says so when a test commits;
- the named suites carry no skip of their own and run in the helper;
- the lock-wait suite polls instead of sleeping a second.

Env-gated on DATABASE_URL, except the scans.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from uuid import uuid4

import pytest

TESTS = Path(__file__).resolve().parent

NAMED = {
    "test_telegram_readiness_pg.py": "rolled_back",
    "test_screening_readiness_pg.py": "rolled_back",
    "test_review46_screening_window_pg.py": "rolled_back",
    "test_ledger_anchor_g49_pg.py": "empty_ledgers",
    "test_ledger_anchor_script_g49_pg.py": "empty_ledgers",
}

needs_db = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                              reason="needs a migrated database")


@pytest.mark.parametrize("name, helper", sorted(NAMED.items()))
def test_a_named_suite_has_no_skip_of_its_own_and_uses_the_rolled_back_helper(name, helper):
    text = (TESTS / name).read_text(encoding="utf-8")
    assert not re.search(r"pytest\.skip\(", text), \
        f"{name} skips for the state of the database; hide that state in its transaction"
    assert helper in text, f"{name} does not use {helper}"


def test_the_lock_wait_suite_polls_and_does_not_sleep_a_second():
    text = (TESTS / "test_collected_document_retention_pg.py").read_text(encoding="utf-8")
    assert not re.search(r"time\.sleep\(\s*1(\.0)?\s*\)", text)
    assert "pg_stat_activity" in text


@needs_db
def test_a_rolled_back_test_leaves_nothing_in_the_database():
    import psycopg

    from noctornal_api.db import dsn
    from rolled_back import rolled_back

    key = f"ROLLEDBACK_{uuid4().hex[:8].upper()}"
    with rolled_back() as conn:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')", (key,))
        with conn.transaction():
            conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'y')",
                         (key + "_B",))
        assert conn.execute("SELECT count(*) FROM iam.compartment WHERE key LIKE %s",
                            (key + "%",)).fetchone()[0] == 2
    with psycopg.connect(dsn()) as other:
        assert other.execute("SELECT count(*) FROM iam.compartment WHERE key LIKE %s",
                             (key + "%",)).fetchone()[0] == 0


@needs_db
def test_a_test_that_commits_is_told_so():
    import psycopg

    from noctornal_api.db import dsn
    from rolled_back import rolled_back

    key = f"COMMITTED_{uuid4().hex[:8].upper()}"
    try:
        with pytest.raises(AssertionError, match="committed its transaction"):
            with rolled_back() as conn:
                conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x')",
                             (key,))
                conn.commit()
    finally:
        with psycopg.connect(dsn(), autocommit=True) as other:
            other.execute("DELETE FROM iam.compartment WHERE key = %s", (key,))
