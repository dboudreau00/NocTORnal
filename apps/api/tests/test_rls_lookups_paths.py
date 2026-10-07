"""The lookup ledger's readers, converted for row-level security (F51,
2026-10-02).

Static: no database. Each conversion is pinned by the code that carries
it, so a later edit cannot quietly undo one:

- the two label joins over the answer read `iam.lookup_result_facts`, never
  a join to a row the reader may not see (decision 146's anti-join trap);
- every reader that must see every row names `SystemPurpose.LOOKUPS`: the
  interactive send and the sign-off from the gates on, the provider test,
  the quota counts, the cache, the value check, a batch's cancel, and a
  provider's withdrawal and usage;
- the four tables are under policy in the registry, with their templates.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


def _tree(rel: str) -> ast.Module:
    return ast.parse((SRC / rel).read_text(encoding="utf-8"))


def _constant(tree: ast.Module, name: str, *, in_class: str | None = None) -> str:
    body = tree.body
    if in_class:
        body = next(n for n in tree.body
                    if isinstance(n, ast.ClassDef) and n.name == in_class).body
    for node in body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"no constant {name}: this test is stale")


def _function(rel: str, name: str) -> str:
    found = [n for n in ast.walk(_tree(rel))
             if isinstance(n, ast.FunctionDef) and n.name == name]
    assert found, f"{rel} has no function {name}: this test is stale"
    return ast.unparse(found[0])


def test_the_answers_label_is_read_as_a_fact_by_triage_and_the_ledger():
    source = _constant(_tree("proposals.py"), "_SOURCE_FROM")
    assert "iam.lookup_result_facts(p.lookup_result_id) lr" in source
    assert not re.search(r"JOIN\s+ingest\.lookup_result\b", source)
    read = _constant(_tree("lookups.py"), "_READ", in_class="LookupService")
    assert "iam.lookup_result_facts(l.result_id) rf" in read
    assert re.search(r"greatest\(rf\.classification,", read)
    assert not re.search(r"greatest\(r\.classification,", read), (
        "the answer's label from the join reads LOW for a reader below it")


#: (module, function): each runs its work as the LOOKUPS purpose.
_LOOKUPS = (
    ("lookups.py", "window_counts"),
    ("lookups.py", "_derived"),
    ("lookups.py", "_cached"),
    ("lookups.py", "_sample_hashes"),
    ("lookups.py", "request"),
    ("lookups.py", "sign_off"),
    ("lookups.py", "test_provider"),
    ("lookups.py", "providers_for"),
    ("lookups.py", "plan"),
    ("lookups.py", "commit_batch"),
    ("lookups.py", "cancel_batch"),
    ("providers.py", "_simple"),
    ("providers.py", "retire"),
    ("providers.py", "update"),
    ("providers.py", "decide_exposure_change"),
    ("providers.py", "usage"),
)


def test_every_reader_that_must_see_every_lookup_runs_as_lookups():
    missing = [f"{rel}::{fn}" for rel, fn in _LOOKUPS
               if "SystemPurpose.LOOKUPS" not in _function(rel, fn)]
    assert not missing, missing


def test_a_reservation_refuses_a_connection_row_security_filters():
    code = _function("lookups.py", "_reserve")
    assert "is_exempt(self._c)" in code and "SystemContextUnavailable" in code


def test_the_lookup_tables_are_under_policy_and_no_longer_deferred():
    from noctornal_api import rls_registry as reg

    assert {t: reg.POLICY.get(t) for t in (
        "ingest.lookup", "ingest.lookup_result", "ingest.lookup_attempt",
        "ingest.lookup_batch")} == {
        "ingest.lookup": "CASE_LABELLED", "ingest.lookup_result": "CASE_LABELLED",
        "ingest.lookup_attempt": "LEDGER_CHILD", "ingest.lookup_batch": "CASE"}
    assert not [t for t in reg.DEFERRED if t.startswith("ingest.lookup")]
    assert reg.POLICY_FLOOR == len(reg.POLICY)
