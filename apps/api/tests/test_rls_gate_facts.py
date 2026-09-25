"""The gate reads facts; content reads go through row security (S1).

Static: no database. The gate (`deps.authorize_object`, `evaluate()`)
must decide and audit exactly as it did before a case or element row could
be hidden from the caller: an assigned analyst asking for a RED node gets
the gate's 403 and its AUTHZ_DENIED row, not row-level security's silent
404. So everything that FEEDS the gate reads labels and lock facts through
the definer fact functions (`iam.case_facts`, `iam.case_code`,
`iam.element_facts` via `deps.element_labels`), and never `core."case"`
or the element tables directly. The reads most easily missed (break-glass
invoke and the officer's queue, the exhibit production ticket,
notify_events) are each pinned here by name.
"""
from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "apps" / "api" / "src" / "noctornal_api"

#: (module, function) -> a fact function its source must use.
_FACT_READERS = {
    ("http/deps.py", "effective_labels"): "iam.case_facts",
    ("http/deps.py", "refuse_if_case_read_only"): "iam.case_facts",
    ("http/deps.py", "counted_at_case_gate"): "iam.case_facts",
    ("http/deps.py", "element_labels"): "iam.element_facts",
    ("http/routers/live.py", "_may_read"): "iam.case_facts",
    ("http/routers/governance.py", "_assigned_case_code"): "iam.case_code",
    ("http/routers/governance.py", "unreviewed"): "iam.case_code",
    ("http/routers/governance.py", "_own_evidence"): "element_labels",
    ("notify_events.py", "_case"): "iam.case_facts",
    ("projections.py", "_disclosure_mode"): "iam.case_facts",
    ("http/routers/ach.py", "_withheld"): "iam.case_facts",
    ("evidence.py", "redeem_production_ticket"): "iam.element_facts",
    ("evidence.py", "_production_refusal"): "iam.element_facts",
    ("http/routers/graph.py", "_element_labels"): "element_labels",
    ("http/routers/graph.py", "_gate_for_change"): "element_labels",
    ("http/routers/graph.py", "retract_assertion"): "element_labels",
    ("http/routers/curation.py", "_node_for_write"): "element_labels",
    ("http/routers/evidence.py", "_authorize_exhibit"): "element_labels",
    ("http/routers/proposals.py", "_check_accept_labels"): "element_labels",
    ("http/routers/evidence.py", "_authorize_export"): "element_labels",
    # S1, 2026-09-25: comms under policy (0122). The conversation's case
    # is found as a fact before the gate's work proceeds.
    ("http/routers/comms.py", "_own_conversation"): "element_labels",
}


def _function(rel: str, name: str) -> ast.FunctionDef:
    tree = ast.parse((SRC / rel).read_text(encoding="utf-8"))
    found = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    assert found, f"{rel} has no function {name}: the table below is stale"
    return found[0]


def _code(fn: ast.FunctionDef) -> str:
    """The function's source without its docstring and comments."""
    body = list(fn.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(
            getattr(body[0], "value", None), ast.Constant):
        body = body[1:]
    return "\n".join(ast.unparse(stmt) for stmt in body)


def test_every_gate_input_reads_a_fact_function():
    missing = [f"{rel}::{fn} ({fact})"
               for (rel, fn), fact in _FACT_READERS.items()
               if fact not in _code(_function(rel, fn))]
    assert not missing, missing


def test_no_gate_input_reads_the_case_row_itself():
    offenders = [f"{rel}::{fn}"
                 for (rel, fn) in _FACT_READERS
                 if 'FROM core."case"' in _code(_function(rel, fn))
                 or "JOIN core.\"case\"" in _code(_function(rel, fn))]
    assert not offenders, offenders


def test_an_element_pre_read_happens_before_its_content_read():
    """In each router gate, the labels come from the fact function and the
    gate runs before the element row itself is read."""
    for rel, fn in (("http/routers/graph.py", "_gate_for_change"),
                    ("http/routers/curation.py", "_node_for_write")):
        code = _code(_function(rel, fn))
        assert code.index("element_labels(") < code.index("authorize_object(") \
            < code.index("FROM core."), f"{rel}::{fn}"


def test_two_person_and_notification_reads_fail_closed():
    """No case read fails open. A missing case row requires the
    second signature, and a notification about a missing case is refused
    rather than labelled AMBER."""
    dual = _code(_function("approvals.py", "case_requires_dual_control"))
    assert "if row is None:\n    return True" in dual
    note = _code(_function("notify_events.py", "_case"))
    assert "raise ValueError" in note and "'AMBER'" not in note
