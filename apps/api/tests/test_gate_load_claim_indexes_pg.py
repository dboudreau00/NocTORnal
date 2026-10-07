"""Every claim about an element or an exhibit is found by an index, live or
not (G62 load gate, 2026-10-07, migration assertion_element_indexes).

`core.assertion`'s indexes on `node_id` and `edge_id` are partial, live
claims only, and `evidence_id` had none; `core.evidence_link` had none on
`evidence_id` either. A lookup that does not repeat the live predicate
cannot use a partial index, so these scanned the whole table, every case's
claims, on every call. Measured on a 1,254,000-claim database: the deferred
invariant-1 check behind every entity or tie create (`core.require_node_
assertion`) was a parallel sequential scan of 29,000 buffers, 188 ms per
element, and the evidence register computed each exhibit's backs with one
such scan per exhibit.

The EXPLAIN tests run the statements the product runs: the trigger
functions' own lookup, the claim history's (`read._assertions` with
`include_retracted`, captured from the function itself), a retraction's
restore (`GraphWriteService._supported_value`, captured), and the register's
backs (`evidence._backs_counts`). Sequential scans are off in a rolled-back
transaction, so the planner takes an index whenever one can answer, on a
small database as on a large one. Each EXPLAIN test fails before the
migration, where the plan is a sequential scan.

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


def _migration():
    path = next(p for p in VERSIONS.glob("*.py")
                if p.name.endswith("_assertion_element_indexes.py"))
    spec = importlib.util.spec_from_file_location("g62_indexes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _dsn() -> str:
    from noctornal_api.db import dsn
    return dsn()


@pytest.fixture()
def tx():
    c = psycopg.connect(_dsn())
    try:
        c.execute("SET LOCAL enable_seqscan = off")
        yield c
    finally:
        c.rollback()
        c.close()


def _plan(tx, sql: str, params) -> str:
    return json.dumps(tx.execute("EXPLAIN (FORMAT JSON) " + sql, params).fetchone()[0])


class _Capture:
    """Stands in for a connection: keeps the first statement a function
    issues and answers it with nothing, so the function returns early."""

    def __init__(self):
        self.sql = None
        self.params = None

    def execute(self, sql, params=None):
        if self.sql is None:
            self.sql, self.params = sql, params
        return self

    def fetchall(self):
        return []

    def fetchone(self):
        return (None, False, None)


def test_the_claim_lookup_indexes_exist_are_valid_and_are_what_was_built():
    m = _migration()
    expected = {name: m.expected_def(name, table, column)
                for name, (table, column) in m.INDEXES.items()}
    with psycopg.connect(_dsn()) as c:
        for name, definition in expected.items():
            schema_table = definition.split(" ON ")[1].split(" USING")[0]
            schema = schema_table.split(".")[0]
            row = c.execute(
                """SELECT pg_get_indexdef(i.indexrelid), i.indisvalid
                     FROM pg_index i
                    WHERE i.indexrelid = to_regclass(%s)""",
                (f"{schema}.{name}",)).fetchone()
            assert row is not None, f"no index {name}"
            assert row == (definition, True)


def test_the_invariant_one_triggers_find_a_claim_by_index(tx):
    """The deferred `require_node_assertion` / `require_edge_assertion`
    check, as the function bodies write it, for an element just created."""
    for column, index in (("node_id", "assertion_node_any_idx"),
                          ("edge_id", "assertion_edge_any_idx")):
        body = tx.execute(
            "SELECT prosrc FROM pg_proc WHERE oid = %s::regprocedure",
            (f"core.require_{column[:4]}_assertion()",)).fetchone()[0]
        assert f"FROM core.assertion WHERE {column} = NEW.id" in body, body
        plan = _plan(tx, f"SELECT EXISTS (SELECT 1 FROM core.assertion "
                         f"WHERE {column} = %s)", (uuid4(),))
        assert index in plan, plan
        assert "Seq Scan" not in plan, plan


def test_an_elements_claim_history_uses_the_index(tx):
    from noctornal_api.http.routers.read import _assertions
    for column, index in (("node_id", "assertion_node_any_idx"),
                          ("edge_id", "assertion_edge_any_idx")):
        cap = _Capture()
        _assertions(cap, column, uuid4(), True, "RED", [],
                    doc_clearance="RED", doc_compartments=[])
        assert "retracted_at IS NULL" not in cap.sql.split("WHERE a.")[-1]
        plan = _plan(tx, cap.sql, cap.params)
        assert index in plan, plan


def test_a_retractions_restore_reads_the_claims_by_index(tx):
    from noctornal_api.graph import GraphWriteService
    for column, index in (("node_id", "assertion_node_any_idx"),
                          ("edge_id", "assertion_edge_any_idx")):
        cap = _Capture()
        GraphWriteService(cap)._supported_value(column, uuid4(), "label")
        plan = _plan(tx, cap.sql, cap.params)
        assert index in plan, plan


def test_the_canvas_evidence_mark_reads_claims_by_index(tx):
    """`has_evidence` on every entity and tie the graph view draws
    (`projections.evidenced_sql`). It asks for unretracted claims citing an
    exhibit and says nothing of supersession, so the live index cannot
    answer it; before the migration it scanned the table once per drawn
    entity (1,864 loops of 82 ms on a 2,000-entity view)."""
    from noctornal_api.projections import evidenced_sql
    for column, alias, table, index in (
            ("node_id", "n", "core.node", "assertion_node_any_idx"),
            ("edge_id", "e", "core.edge", "assertion_edge_any_idx")):
        plan = _plan(tx, f"SELECT {evidenced_sql(column, alias)} "
                         f"FROM {table} {alias} WHERE {alias}.id = %s",
                     ("RED", [], uuid4()))
        assert index in plan, plan
        assert "Seq Scan" not in plan, plan


def test_the_registers_backs_read_claims_and_links_by_index(tx):
    """One exhibit's backs, as every register row computes them."""
    from noctornal_api.http.routers.evidence import _backs_counts
    plan = _plan(tx, f"SELECT {_backs_counts('%(ev)s')}",
                 {"ev": uuid4(), "case": uuid4(), "clr": "RED", "comp": []})
    assert "assertion_evidence_idx" in plan, plan
    assert "evidence_link_evidence_idx" in plan, plan
    assert "Seq Scan" not in plan, plan


def test_a_different_index_under_a_name_is_refused():
    m = _migration()
    upgrade = m.UPGRADE_SQL
    c = psycopg.connect(_dsn())
    try:
        c.execute("DROP INDEX core.assertion_evidence_idx")
        c.execute("CREATE INDEX assertion_evidence_idx ON core.assertion (evidence_id)")
        with pytest.raises(psycopg.errors.RaiseException) as refused:
            c.execute(upgrade)
        said = str(refused.value).splitlines()[0]
        assert said.startswith(
            "core.assertion_evidence_idx exists with a different definition "
            "(CREATE INDEX assertion_evidence_idx ON core.assertion USING "
            "btree (evidence_id))")
    finally:
        c.rollback()
        c.close()
