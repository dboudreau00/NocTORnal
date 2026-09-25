"""The dead dual-control configuration of 0012 is gone (F9c,
2026-09-24; migration retire_dead_dual_control).

`iam.permission.requires_dual_control` was seeded and never read, and said
case.delete took two people when it took one; `iam.dual_control_request`
was replaced by `core.approval_request` before anything wrote to it. The
catalogue in `approvals.OPERATIONS` and `iam.dual_control_operation` are
the one reader now. The migration's own directions run inside rolled-back
transactions, and it is located by the stem of its file name, never by
number. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the schema is gated")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


class _RollBack(Exception):
    pass


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


def _migration(conn):
    path = next(VERSIONS.glob("*_retire_dead_dual_control.py"))
    spec = importlib.util.spec_from_file_location("m_retire", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def _column(conn) -> int:
    return conn.execute(
        "SELECT count(*) FROM information_schema.columns WHERE table_schema = "
        "'iam' AND table_name = 'permission' AND column_name = "
        "'requires_dual_control'").fetchone()[0]


def _table(conn):
    return conn.execute("SELECT to_regclass('iam.dual_control_request')"
                        ).fetchone()[0]


def test_the_dead_dual_control_configuration_is_gone(conn):
    assert _column(conn) == 0
    assert _table(conn) is None


def test_the_retirement_round_trips(conn):
    m = _migration(conn)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        assert _column(conn) == 1
        marked = {r[0] for r in conn.execute(
            "SELECT key FROM iam.permission WHERE requires_dual_control")}
        assert marked == set(m.MARKED)
        assert _table(conn) is not None
        check = conn.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'dual_control_distinct'").fetchone()
        assert check is not None
        assert "approved_by <> requested_by" in check[0]
        m.upgrade()
        assert _column(conn) == 0 and _table(conn) is None
        raise _RollBack


def test_the_retirement_refuses_rows_it_does_not_understand(conn):
    m = _migration(conn)
    admin = conn.execute("SELECT id FROM iam.app_user ORDER BY created_at "
                         "LIMIT 1").fetchone()
    if admin is None:
        pytest.skip("no account to name as the requester of a stray row")
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        conn.execute("""INSERT INTO iam.dual_control_request
                            (action, payload, requested_by)
                        VALUES ('case.delete', '{}', %s),
                               ('role.manage', '{}', %s)""", (admin[0], admin[0]))
        with pytest.raises(psycopg.errors.RaiseException,
                           match=f"refusing to upgrade {m.revision}: "
                                 "iam.dual_control_request holds 2 rows"), \
                conn.transaction():
            m.upgrade()
        raise _RollBack
