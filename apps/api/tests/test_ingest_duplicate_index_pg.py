"""An index on ingest.record(duplicate_of) (L4, 2026-09-24, migration 0072).

The ingest queue counts each page's folded copies in one pass, and a
record's detail lists its copies; with no index on `duplicate_of` both
scanned the table. 0072 adds a partial btree (`WHERE duplicate_of IS NOT
NULL`), turns a failed concurrent build of that name into a rebuild rather
than accepting an INVALID index, and refuses a different index under the
name. Each test fails on ab27a4a, where no such index existed.

The EXPLAIN tests run the route's own text (`_queue_sql` with
`_queue_params`, and `_COPIES_SQL`), with sequential scans off in a
rolled-back transaction: a small test table would otherwise be scanned
whatever indexes exist, and the test would lie either way.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; index tests are gated")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
INDEX = "record_duplicate_of_idx"


def _migration():
    path = next(p for p in VERSIONS.glob("*.py")
                if p.name.endswith("_record_duplicate_of_index.py"))
    spec = importlib.util.spec_from_file_location("l4_index", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dsn() -> str:
    from noctornal_api.db import dsn
    return dsn()


def _seed(c) -> dict:
    """A primary and two copies of it, with the key and batch they need."""
    uid = c.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash)
           VALUES (%s, 'L4', 'x') RETURNING id""",
        (f"ldx-{uuid4().hex[:8]}@noctornal.test",)).fetchone()[0]
    key = c.execute(
        """INSERT INTO ingest.api_key (key_id, secret_hmac, pepper_id, name,
                                       expires_at, owner_user_id)
           VALUES (%s, %s, 'env:v1', 'ldx', now() + interval '1 day', %s)
           RETURNING id""", (uuid4().hex[:8], os.urandom(32), uid)).fetchone()[0]
    batch = c.execute(
        """INSERT INTO ingest.batch (api_key_id, raw_key, raw_bytes, raw_sha256)
           VALUES (%s, %s, 1, %s) RETURNING id""",
        (key, f"ldx/{uuid4().hex}", os.urandom(32))).fetchone()[0]

    def record(duplicate_of=None):
        return c.execute(
            """INSERT INTO ingest.record (batch_id, payload, content_sha256,
                                          duplicate_of)
               VALUES (%s, '{}'::jsonb, %s, %s) RETURNING id""",
            (batch, os.urandom(32), duplicate_of)).fetchone()[0]

    primary = record()
    return {"user": uid, "key": key, "batch": batch, "primary": primary,
            "copies": [record(primary), record(primary)]}


def _unseed(c, seeded: dict) -> None:
    c.execute("DELETE FROM ingest.record WHERE batch_id = %s", (seeded["batch"],))
    c.execute("DELETE FROM ingest.batch WHERE id = %s", (seeded["batch"],))
    c.execute("DELETE FROM ingest.api_key WHERE id = %s", (seeded["key"],))
    c.execute("DELETE FROM iam.app_user WHERE id = %s", (seeded["user"],))


def test_the_duplicate_index_exists_is_valid_and_partial():
    with psycopg.connect(_dsn()) as c:
        row = c.execute(
            """SELECT pg_get_indexdef(i.indexrelid), i.indisvalid
                 FROM pg_index i
                WHERE i.indexrelid = to_regclass('ingest.' || %s)""",
            (INDEX,)).fetchone()
    assert row is not None, "no index on ingest.record(duplicate_of)"
    definition, valid = row
    assert definition == _migration().EXPECTED_DEF
    assert "(duplicate_of)" in definition
    assert "WHERE (duplicate_of IS NOT NULL)" in definition
    assert valid is True


def test_the_queue_and_the_record_copies_use_it():
    from noctornal_api.http.routers.ingest import (
        _COPIES_SQL,
        _queue_params,
        _queue_sql,
    )
    from noctornal_api.security.access import Tlp
    tx = psycopg.connect(_dsn())
    try:
        seeded = _seed(tx)
        # A realistic table, analysed: on a near-empty one every path costs
        # the same and the planner's choice says nothing about the index.
        # Rolled back with the rest (L4, 2026-09-24).
        tx.execute(
            """INSERT INTO ingest.record (batch_id, payload, content_sha256)
               SELECT %s, '{}'::jsonb, gen_random_bytes(32)
                 FROM generate_series(1, 2000)""", (seeded["batch"],))
        tx.execute("ANALYZE ingest.record")
        tx.execute("SET LOCAL enable_seqscan = off")
        plan = tx.execute(
            "EXPLAIN (FORMAT JSON) " + _queue_sql(" AND r.id = %(rid)s"),
            _queue_params([], False, Tlp.RED, frozenset(),
                          rid=seeded["primary"])).fetchone()[0]
        assert INDEX in json.dumps(plan), plan
        plan = tx.execute(
            "EXPLAIN (FORMAT JSON) " + _COPIES_SQL,
            # Case-less copies included, as the seeded batch's are: a query
            # that can select nothing lets the planner take any index.
            (seeded["primary"], "RED", [], [], True)).fetchone()[0]
        assert INDEX in json.dumps(plan), plan
    finally:
        tx.rollback()
        tx.close()


def test_a_different_index_under_the_name_is_refused():
    upgrade = _migration().UPGRADE_SQL
    tx = psycopg.connect(_dsn())
    try:
        tx.execute(f"DROP INDEX ingest.{INDEX}")
        tx.execute(f"CREATE INDEX {INDEX} ON ingest.record (duplicate_of)")
        with pytest.raises(psycopg.errors.RaiseException) as refused:
            tx.execute(upgrade)
        said = str(refused.value).splitlines()[0]
        assert said.startswith(f"ingest.{INDEX} exists with a different "
                               f"definition (CREATE INDEX {INDEX} ON "
                               f"ingest.record USING btree (duplicate_of))")
        assert said.endswith("drop it or rename it, then run the upgrade again.")
    finally:
        tx.rollback()
        tx.close()


def test_an_invalid_index_under_the_name_is_rebuilt():
    """A failed CREATE UNIQUE INDEX CONCURRENTLY leaves an INVALID index
    of that name (no superuser needed), which IF NOT EXISTS would accept.
    The upgrade builds it again. The finally puts the schema back to head
    and removes the seed whatever happened."""
    upgrade = _migration().UPGRADE_SQL
    c = psycopg.connect(_dsn(), autocommit=True)
    seeded = _seed(c)
    try:
        c.execute(f"DROP INDEX ingest.{INDEX}")
        with pytest.raises(psycopg.errors.UniqueViolation):
            c.execute(f"CREATE UNIQUE INDEX CONCURRENTLY {INDEX} ON "
                      f"ingest.record (duplicate_of) "
                      f"WHERE duplicate_of IS NOT NULL")
        assert c.execute(
            "SELECT indisvalid FROM pg_index WHERE indexrelid = "
            "to_regclass('ingest.' || %s)", (INDEX,)).fetchone() == (False,)
        c.execute(upgrade)
        definition, valid = c.execute(
            "SELECT pg_get_indexdef(indexrelid), indisvalid FROM pg_index "
            "WHERE indexrelid = to_regclass('ingest.' || %s)",
            (INDEX,)).fetchone()
        assert valid is True
        assert definition == _migration().EXPECTED_DEF
    finally:
        c.execute(upgrade)
        _unseed(c, seeded)
        c.close()
