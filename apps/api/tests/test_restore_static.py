"""The restore's invariants, held by reading the tree (decision 240).

- Every read of a stored object version goes through the function that resolves it
  (`core.evidence_current_version`, `lab.sample_current_preserved_version`). A SELECT of the recorded
  column in another statement would read a version a restore has moved on from, so the exhibit would raise
  an integrity alarm in the store it was restored into. The writers (an UPDATE, an INSERT) and the
  restore tool, which needs the lodged version to say what it replaced, are the only other mentions.
- Nothing in the restore tool lifts a hold, deletes an object or asks the store to shorten a lock.
- The policy the README gives the restore account grants exactly what the tool calls and nothing that deletes,
  lifts a hold or bypasses a retention, so an operator who copies it gets an account that cannot do harm.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
COLUMNS = ("storage_version_id", "preserved_version_id")
#: The one module whose SELECT names the recorded column: it reports what the restore replaced.
MAY_SELECT = {"apps/api/src/noctornal_api/restore.py"}


def _sql_strings(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"\bselect\b", node.value, re.I):
                yield node.lineno, node.value


def _python_sources():
    for base in (SRC, ROOT / "scripts"):
        yield from sorted(base.rglob("*.py"))


def test_every_read_of_a_stored_version_goes_through_the_current_version_function():
    offenders = []
    for path in _python_sources():
        rel = path.relative_to(ROOT).as_posix()
        if rel in MAY_SELECT:
            continue
        for line, text in _sql_strings(path):
            for column in COLUMNS:
                for hit in re.finditer(rf"[\w.]*\b{column}\b", text):
                    # A column named only to say it is written is not a read of it.
                    if re.match(rf"(?:\w+\.)?{column}\s*=\s*%s", text[hit.start():]):
                        continue
                    offenders.append(f"{rel}:{line} selects {hit.group(0)}")
    assert offenders == [], offenders


def test_the_two_reads_of_an_exhibit_and_the_two_of_a_sample_use_the_functions():
    evidence = (SRC / "evidence.py").read_text(encoding="utf-8")
    samples = (SRC / "samples.py").read_text(encoding="utf-8")
    assert evidence.count("core.evidence_current_version(") == 2
    assert samples.count("lab.sample_current_preserved_version(") == 2


#: The seam's methods that delete, lift, place or reconfigure. The restore tool names none of them, so no
#: later edit can add one without this test saying so; `put` and `set_compliance_retention` (which can only
#: lengthen a COMPLIANCE lock the store will not shorten) are the writes it makes.
NEVER_CALLED = {"delete_version", "delete_key", "remove_bucket", "set_legal_hold", "make_bucket",
                "set_default_retention"}


def test_the_restore_tool_names_no_method_that_deletes_places_or_lifts_anything():
    for path in (SRC / "restore.py", ROOT / "scripts" / "restore_object_versions.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        named = ({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
                 | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)})
        assert named & NEVER_CALLED == set(), (path.name, sorted(named & NEVER_CALLED))


# ---------------------------------------------------------------------------
# The restore account's policy, in the README an operator copies it from
# ---------------------------------------------------------------------------

README = (ROOT / "infra" / "production" / "README.md").read_text(encoding="utf-8")

#: What each store call the tool makes needs, as the adapter issues it. A call the tool starts making that is
#: not here fails `test_the_restore_account_policy_covers_every_call_the_tool_makes_and_nothing_more`, so the
#: policy is decided with the call.
STORE_NEEDS = {
    "get": {"s3:GetObject", "s3:GetObjectVersion"},
    "put": {"s3:PutObject", "s3:PutObjectRetention"},
    "list_versions": {"s3:ListBucket", "s3:ListBucketVersions"},
    "get_retention": {"s3:GetObjectRetention"},
    "set_compliance_retention": {"s3:PutObjectRetention"},
    "legal_hold_is_on": {"s3:GetObjectLegalHold"},
}
PRESERVATION_NEEDS = {
    "preserve": {"s3:PutObject", "s3:PutObjectLegalHold", "s3:GetObject", "s3:GetObjectVersion",
                 "s3:GetObjectLegalHold"},
    "get": {"s3:GetObject", "s3:GetObjectVersion"},
    "is_held": {"s3:GetObjectLegalHold"},
}


def _restore_policy() -> dict:
    section = README.split("**The restore account.**", 1)[1].split("**Look first.**", 1)[0]
    [block] = re.findall(r"```json\n(.*?)\n```", section, flags=re.S)
    return json.loads(block)


def _granted(policy: dict) -> set[str]:
    found: set[str] = set()
    for statement in policy["Statement"]:
        actions = statement["Action"]
        found.update([actions] if isinstance(actions, str) else actions)
    return found


def _calls_made() -> dict[str, set[str]]:
    """The methods `restore.py` calls on a store (`store`) and on the preservation storage
    (`self.preserved`), read from the tree."""
    tree = ast.parse((SRC / "restore.py").read_text(encoding="utf-8"))
    made: dict[str, set[str]] = {"store": set(), "self.preserved": set()}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        receiver = node.func.value
        if isinstance(receiver, ast.Name) and receiver.id == "store":
            made["store"].add(node.func.attr)
        elif (isinstance(receiver, ast.Attribute) and receiver.attr == "preserved"
              and isinstance(receiver.value, ast.Name) and receiver.value.id == "self"):
            made["self.preserved"].add(node.func.attr)
    return made


def test_the_restore_account_policy_in_the_readme_has_no_delete_and_no_way_to_lift_a_retention_or_a_hold():
    policy = _restore_policy()
    assert policy["Version"] == "2012-10-17"
    for statement in policy["Statement"]:
        assert statement["Effect"] == "Allow"
        for action in ([statement["Action"]] if isinstance(statement["Action"], str)
                       else statement["Action"]):
            assert "*" not in action and "Delete" not in action, action
            assert "BypassGovernanceRetention" not in action, action
    # A hold is set ON only, and only on the preservation bucket's objects.
    [hold] = [st for st in policy["Statement"] if "s3:PutObjectLegalHold" in st["Action"]]
    assert hold["Condition"] == {"StringEquals": {"s3:object-lock-legal-hold": ["ON"]}}
    assert hold["Resource"] == ["arn:aws:s3:::PRESERVE_BUCKET/*"]
    # A retention is written only on the evidence bucket's objects (a COMPLIANCE lock the store will not
    # shorten), never on the preservation bucket's.
    for statement in policy["Statement"]:
        if "s3:PutObjectRetention" in statement["Action"]:
            assert statement["Resource"] == ["arn:aws:s3:::EVIDENCE_BUCKET/*"]


def test_the_restore_account_policy_covers_every_call_the_tool_makes_and_nothing_more():
    made = _calls_made()
    assert made["store"] <= set(STORE_NEEDS), sorted(made["store"] - set(STORE_NEEDS))
    assert made["self.preserved"] <= set(PRESERVATION_NEEDS), sorted(
        made["self.preserved"] - set(PRESERVATION_NEEDS))
    assert made["store"] and made["self.preserved"], "the calls were not found in the tree"
    needed = {a for m in made["store"] for a in STORE_NEEDS[m]}
    needed |= {a for m in made["self.preserved"] for a in PRESERVATION_NEEDS[m]}
    granted = _granted(_restore_policy())
    assert needed <= granted, sorted(needed - granted)
    assert granted <= needed | {"s3:GetBucketLocation"}, sorted(granted - needed)


def test_the_runbook_says_the_limit_counts_what_a_run_restores():
    flat = " ".join(README.split())
    assert "`--limit N` counts the objects the run restores" in flat
    assert "one refused and one that failed do not use it up" in flat
