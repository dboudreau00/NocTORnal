"""The approvals catalogue says only what the code does (F9, F9b, F9c,
2026-09-24). No database.

Administration, Two-person controls draws `approvals.OPERATIONS`: each
operation's scope, who asks, who signs second, and whether anything
actually enforces it. A screen that says "two people" over an operation
nothing spends is a false assurance, and one that says "not enforced yet"
over one that is enforced hides a control. So every claim the catalogue
makes is held to the source here, by reading it (ast), not by trusting a
docstring:

- each operation states its scope and exactly one of "the function that
  spends it" and "why nothing does";
- that function exists and calls `consume` with the operation's key as a
  literal; no other function spends an operation said to be unenforced;
- a separate signer is a pair declared in `iam.separated_duty` by some
  migration, so the second person is a different role by construction;
- the migrations after the policy tables arrived write them only through
  the ledger, or with the guard disabled by name, and none after the
  retirement names the dead column.

Migrations are found by the stem of their file name and ordered by their
own `down_revision` chain, never by number, so a renumbered migration is
still found.
"""
from __future__ import annotations

import ast
import importlib.util
import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
VERSIONS = ROOT / "db" / "migrations" / "versions"


def _module(path: Path):
    spec = importlib.util.spec_from_file_location(f"m_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@lru_cache(maxsize=1)
def _chain() -> list[Path]:
    """Every migration file in upgrade order, by revision and down_revision."""
    rev = re.compile(r'^revision\s*=\s*["\']([^"\']+)["\']', re.M)
    down = re.compile(r'^down_revision\s*=\s*(?:["\']([^"\']+)["\']|None)', re.M)
    by_down: dict[str | None, Path] = {}
    for path in VERSIONS.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        r, d = rev.search(text), down.search(text)
        if r is None or d is None:
            continue
        by_down[d.group(1)] = path
    order, parent = [], None
    while parent in by_down:
        path = by_down[parent]
        order.append(path)
        parent = rev.search(path.read_text(encoding="utf-8")).group(1)
    return order


def _after(stem_suffix: str) -> list[Path]:
    chain = _chain()
    index = next(i for i, p in enumerate(chain) if p.stem.endswith(stem_suffix))
    return chain[index + 1:]


def _ops():
    from noctornal_api.approvals import OPERATIONS
    return OPERATIONS


def _function(enforced_at: str) -> ast.AST | None:
    """The function `relative/path.py::Qualname` names, or None."""
    rel, qualname = enforced_at.split("::")
    path = SRC / rel
    if not path.is_file():
        return None
    node: ast.AST = ast.parse(path.read_text(encoding="utf-8"))
    for part in qualname.split("."):
        node = next((n for n in ast.iter_child_nodes(node)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                                       ast.ClassDef)) and n.name == part), None)
        if node is None:
            return None
    return node


def _consumed_keys(tree: ast.AST) -> set[str]:
    """The literal `operation=` of every `.consume(...)` call under `tree`."""
    keys = set()
    for call in ast.walk(tree):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "consume"):
            for kw in call.keywords:
                if (kw.arg == "operation" and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)):
                    keys.add(kw.value.value)
    return keys


def test_every_operation_states_its_scope_and_enforcement():
    from noctornal_api.approvals import MODES
    for key, op in _ops().items():
        assert op.key == key
        assert op.scope in {"case", "global"}, key
        assert op.modes and list(op.modes) == [m for m in MODES if m in op.modes], (
            f"{key}: modes must be an ordered subset of {MODES}")
        assert (op.enforced_at is None) != (not op.not_enforced_because), (
            f"{key}: exactly one of enforced_at and not_enforced_because")


def test_the_deployment_wide_operations_are_global():
    ops = _ops()
    for key in ("role.manage", "collection_account.reveal", "dual_control.policy"):
        assert ops[key].scope == "global", key
    for key in ("node.merge", "case.delete", "evidence.purge", "case.policy.relax"):
        assert ops[key].scope == "case", key


def test_an_entry_without_scope_or_enforcement_does_not_construct():
    from datetime import timedelta

    import pytest

    from noctornal_api.approvals import Operation
    with pytest.raises(TypeError):
        Operation(key="x", permission="x", ttl=timedelta(hours=1),
                  description="x")


def _declared_pairs() -> set[frozenset[str]]:
    pairs: set[frozenset[str]] = set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "SEPARATED_DUTIES" not in text and "NEW_PAIR" not in text:
            continue
        module = _module(path)
        for name in ("SEPARATED_DUTIES",):
            for entry in getattr(module, name, ()) or ():
                pairs.add(frozenset(entry[:2]))
        new = getattr(module, "NEW_PAIR", None)
        if new:
            pairs.add(frozenset(new[:2]))
    return pairs


def test_a_separate_signer_is_a_declared_separated_pair():
    pairs = _declared_pairs()
    assert frozenset({"victim_pii.authorise", "victim_pii.reveal"}) in pairs
    for key, op in _ops().items():
        if op.approver_permission is None:
            continue
        assert frozenset({op.permission, op.approver_permission}) in pairs, (
            f"{key}: its signer's permission is not held apart from the "
            f"requester's by any migration's SEPARATED_DUTIES or NEW_PAIR")


def test_the_screen_never_claims_what_the_code_does_not_do():
    spent_anywhere: dict[str, list[str]] = {}
    for path in SRC.rglob("*.py"):
        for key in _consumed_keys(ast.parse(path.read_text(encoding="utf-8"))):
            spent_anywhere.setdefault(key, []).append(str(path.relative_to(SRC)))
    for key, op in _ops().items():
        if op.enforced_at is None:
            assert key not in spent_anywhere, (
                f"{key} is shown as not enforced, but "
                f"{spent_anywhere.get(key)} spend it")
            continue
        fn = _function(op.enforced_at)
        assert fn is not None, f"{key}: {op.enforced_at} does not exist"
        assert key in _consumed_keys(fn), (
            f"{key}: {op.enforced_at} never calls consume with "
            f"operation={key!r}")


def test_every_other_control_names_a_function_that_exists():
    from noctornal_api.dual_control import OTHER_TWO_PERSON_CONTROLS
    keys = [c.key for c in OTHER_TWO_PERSON_CONTROLS]
    assert len(keys) == len(set(keys))
    for control in OTHER_TWO_PERSON_CONTROLS:
        assert control.act and control.first and control.second, control.key
        assert _function(control.enforced_at) is not None, (
            f"{control.key}: {control.enforced_at} does not exist")


def test_every_per_case_mode_has_a_column_and_a_default():
    from noctornal_api.approvals import _PER_CASE_READ, PER_CASE_COLUMN
    policy = _module(next(VERSIONS.glob("*_dual_control_policy.py")))
    for key, op in _ops().items():
        if "PER_CASE" not in op.modes:
            assert key not in policy.DEFAULT_MODES or op.configurable, key
            continue
        assert key in PER_CASE_COLUMN and key in _PER_CASE_READ, key
        assert PER_CASE_COLUMN[key] in _PER_CASE_READ[key], key
        assert policy.DEFAULT_MODES.get(key) in op.modes, (
            f"{key}: no seeded mode, or one outside its catalogue modes")
    for key in policy.DEFAULT_MODES:
        assert _ops()[key].configurable, (
            f"{key} is seeded a row but has one mode: the row is never read")


def test_the_blocking_events_are_the_ones_iam_admin_writes():
    path = next(VERSIONS.glob("*_dual_control_policy.py"))
    policy = _module(path)
    text = path.read_text(encoding="utf-8")
    written = {n.value for n in ast.walk(ast.parse(
        (SRC / "iam_admin.py").read_text(encoding="utf-8")))
        if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for action in policy.COUNTERSIGN_BLOCKING_EVENTS:
        assert action in written, f"iam_admin.py never audits {action}"
        assert text.count(action) >= 2, (
            f"{action} is declared but the function text does not use it")
    # The console's sentences cover every one, so nobody reads a fallback.
    from noctornal_api import approvals, dual_control
    for action in policy.COUNTERSIGN_BLOCKING_EVENTS:
        assert action in approvals._PROPOSER_WORDS, action
        assert action in dual_control._PROVENANCE, action
        assert action in approvals._OWN_WORDS or action == "ROLE_GRANTED", action


_WRITES = {
    "separated_duty": (re.compile(
        r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(iam\.)?separated_duty\b",
        re.I), "separated_duty_written_by_ledger"),
    "dual_control_operation": (re.compile(
        r"\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(iam\.)?dual_control_operation\b",
        re.I), "dual_control_operation_written_by_ledger"),
}


def _disables(text: str, guard: str) -> bool:
    """The trigger disabled by name, spelled out or through a module constant
    holding exactly that name (0080: DISABLE TRIGGER {LEDGER_TRIGGER})."""
    if re.search(rf"DISABLE\s+TRIGGER\s+{guard}\b", text):
        return True
    return any(re.search(rf"""^{name}\s*=\s*["']{guard}["']\s*$""", text, re.M)
               for name in re.findall(r"DISABLE\s+TRIGGER\s+\{(\w+)\}", text))


def test_only_the_ledger_writes_the_policy_tables():
    for path in _after("_dual_control_policy"):
        text = path.read_text(encoding="utf-8")
        for table, (writes, guard) in _WRITES.items():
            if writes.search(text):
                assert _disables(text, guard), (
                    f"{path.name} writes iam.{table} without disabling "
                    f"{guard} by name for its own run")


def test_no_migration_after_the_retirement_names_the_dead_column():
    later = _after("_retire_dead_dual_control")
    for path in later:
        assert "requires_dual_control" not in path.read_text(encoding="utf-8"), (
            f"{path.name} names iam.permission.requires_dual_control, which "
            f"the retirement dropped: it will fail at upgrade")


def test_the_chain_reaches_this_cluster_in_order():
    stems = [p.stem for p in _chain()]
    order = [next(i for i, s in enumerate(stems) if s.endswith(suffix))
             for suffix in ("_approval_request_frozen", "_dual_control_policy",
                            "_case_merge_relax_two_people",
                            "_retire_dead_dual_control")]
    assert order == sorted(order), stems[-6:]


def test_the_shortest_signature_is_still_the_credential_reveal():
    shortest = min(_ops().values(), key=lambda o: o.ttl)
    assert shortest.key == "collection_account.reveal"


def test_the_global_gate_is_what_something_spends():
    from noctornal_api.approvals import GLOBAL_GATE_PERMISSIONS
    assert GLOBAL_GATE_PERMISSIONS == ("dual_control.countersign",
                                       "dual_control.manage")


def test_the_relax_payload_is_the_switch_as_it_stands():
    from noctornal_api.approvals import relax_payload
    assert relax_payload(4) == {"setting": "dual_control_merge", "from": True,
                                "to": False, "epoch": 4}
