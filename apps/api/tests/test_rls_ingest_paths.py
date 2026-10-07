"""The ingest readers, converted for row-level security (F51, 2026-10-02).

Static: no database. Each conversion is pinned by the code that carries it,
so a later edit cannot quietly undo one:

- the work that must see every record runs as `SystemPurpose.INGEST`: a
  batch's parse, a dead letter's replay, every scoring pass and the
  fingerprint correlation; the queue's copy total is a WITHHELD count and
  the retention counts are RETENTION's;
- the routes read a record's labels and a batch's cases as facts
  (`iam.ingest_record_facts`, `iam.ingest_batch_reach`), never through a
  join to a row the reader may not see (decision 146's anti-join trap);
- the selector-hit notice is raised from the scoring pass alone, so it
  runs on the INGEST connection, which is what lets an operator off the
  case tell its owner (its behaviour is in test_rls_ingest_pg.py);
- the unauthenticated submit opens no system connection;
- a category correction and a reveal refuse a write that changed no row,
  and the correction decides the expiry in its statement;
- the four tables are under policy in the registry and no longer deferred.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


def _function(rel: str, name: str) -> str:
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    found = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert found, f"{rel} has no function {name}: this test is stale"
    return ast.unparse(found[0])


#: (module, function) -> the system purpose its work runs under.
_MUST_BE_SYSTEM = {
    ("ingest.py", "parse_batch"): "INGEST",
    ("ingest.py", "replay"): "INGEST",
    ("ingest.py", "score_record"): "INGEST",
    ("ingest.py", "score_records"): "INGEST",
    ("ingest.py", "search_by_fingerprint"): "INGEST",
    ("ingest.py", "_watches_for"): "INGEST",
    ("http/routers/ingest.py", "_copy_totals"): "WITHHELD",
    ("http/routers/governance.py", "rules"): "RETENTION",
    ("http/routers/governance.py", "confirm_rule"): "RETENTION",
}


def test_the_work_that_must_see_every_record_runs_on_a_system_connection():
    missing = [f"{rel}::{fn} ({purpose})"
               for (rel, fn), purpose in _MUST_BE_SYSTEM.items()
               if f"SystemPurpose.{purpose}" not in _function(rel, fn)]
    assert not missing, missing


def _readers_of(rel: str, fn: str, table: str) -> set[str]:
    """The connection names whose `.execute(...)` in `fn` names `table`."""
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    node = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == fn)
    out = set()
    for call in ast.walk(node):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "execute" and call.args
                and isinstance(call.args[0], ast.Constant)
                and table in str(call.args[0].value)):
            out.add(ast.unparse(call.func.value))
    return out


def test_the_retention_counts_read_on_the_system_connection():
    for fn in ("_categories_in_use", "confirm_rule"):
        assert _readers_of("http/routers/governance.py", fn,
                           "ingest.record") == {"sconn"}, fn


def test_the_gate_reads_a_record_and_a_batch_as_facts():
    own = _function("http/routers/ingest.py", "_own_record")
    assert "iam.ingest_record_facts(" in own
    assert not re.search(r"FROM ingest\.record", own)
    for fn in ("dead_letters", "_dead_letter_reach"):
        code = _function("http/routers/ingest.py", fn)
        assert "iam.ingest_batch_reach(" in code, fn
        assert not re.search(r"(FROM|JOIN) ingest\.record\b", code), (
            f"{fn} reads the batch's cases through the record policy")


def test_the_selector_hit_notice_is_raised_from_the_scoring_pass_alone():
    """2026-10-02: the notice reads the record and its
    case on whatever connection it is handed, and only the INGEST one
    `score_records` opens sees them for a scorer off the case. So it is
    called from `_score_records` and from nowhere else."""
    tree = ast.parse((SRC / "ingest.py").read_text(encoding="utf-8"))
    callers = {fn.name for fn in ast.walk(tree)
               if isinstance(fn, ast.FunctionDef)
               for call in ast.walk(fn)
               if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
               and call.func.attr == "_notify_selector_hits"}
    assert callers == {"_score_records"}, callers
    assert "self._on(sconn)._score_records(" in _function("ingest.py", "score_records")


def test_the_unauthenticated_submit_opens_no_system_connection():
    code = _function("http/routers/ingest.py", "submit")
    for word in ("SystemPurpose", "system_connection", "system_conn"):
        assert word not in code


def test_a_write_that_changed_no_row_is_refused():
    correct = _function("ingest.py", "correct_category")
    assert "rowcount != 1" in correct
    reveal = _function("ingest.py", "reveal_credential")
    assert reveal.count("rowcount != 1") == 2
    assert "self._c.transaction()" in reveal


def test_a_correction_decides_the_expiry_in_its_statement_and_the_console_says_so():
    """2026-10-03: the correction writes the greater of
    the stored expiry and its rule's, in the statement, and leaves a NULL one
    NULL (greatest() skips NULL and would date the record); the console must
    not print 'The expiry stays not recorded' for a record with none."""
    correct = _function("ingest.py", "correct_category")
    assert "greatest(retain_until, %s)" in correct
    assert "WHEN retain_until IS NULL THEN NULL" in correct
    assert "RETURNING retain_until" in correct
    console = (SRC / "http" / "static" / "app.js").read_text(encoding="utf-8")
    assert "out.retain_until === null" in console


def test_the_ingest_tables_are_under_policy_and_no_longer_deferred():
    from noctornal_api import rls_registry as reg

    assert {t: reg.POLICY.get(t) for t in (
        "ingest.record", "ingest.victim_credential", "ingest.dead_letter",
        "ingest.pii_authorisation")} == {
        "ingest.record": "CUSTOM_RECORD", "ingest.victim_credential": "CHILD",
        "ingest.dead_letter": "CUSTOM_DEAD_LETTER",
        "ingest.pii_authorisation": "CUSTOM_PII_AUTHORISATION"}
    assert not [t for t in reg.DEFERRED if t.startswith("ingest.")]
    assert reg.POLICY_FLOOR == len(reg.POLICY)
    for template in ("CUSTOM_RECORD", "CUSTOM_DEAD_LETTER", "CUSTOM_PII_AUTHORISATION"):
        assert template in (reg.__doc__ or ""), template
