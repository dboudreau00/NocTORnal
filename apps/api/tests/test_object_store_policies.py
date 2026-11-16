"""The three least-privilege policies in docs/22 section 4 are held to the code and to the production compose.

They are prose JSON an operator copies into a store, so nothing else would notice when the code starts calling
an S3 action the policy leaves out, or when `infra/production/compose.yml` changes the policy it mints.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import re
from pathlib import Path

from noctornal_api.objectstore.store import ObjectStore

ROOT = Path(__file__).resolve().parents[3]
PAGE = (ROOT / "docs" / "22-object-store-requirements.md").read_text(encoding="utf-8")
COMPOSE = (ROOT / "infra" / "production" / "compose.yml").read_text(encoding="utf-8")

#: The S3 actions each `ObjectStore` method needs, as the adapter issues them. A method added to the seam
#: without a line here fails `test_every_seam_method_is_mapped`, so the policy is decided with the method.
NEEDS: dict[str, tuple[str, ...]] = {
    "put": ("s3:PutObject", "s3:PutObjectRetention"),
    "get": ("s3:GetObject", "s3:GetObjectVersion"),
    "head": ("s3:GetObject", "s3:GetObjectVersion"),
    "list_versions": ("s3:ListBucketVersions",),
    "get_retention": ("s3:GetObjectRetention",),
    "set_compliance_retention": ("s3:PutObjectRetention",),
    "legal_hold_is_on": ("s3:GetObjectLegalHold",),
    "delete_version": ("s3:DeleteObjectVersion",),
    "delete_key": ("s3:DeleteObject",),
    "bucket_exists": ("s3:ListBucket",),
    "bucket_capabilities": ("s3:ListBucket", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
                            "s3:GetBucketLocation"),
}
#: Not the API's: the preservation account sets a hold; an administrator makes, empties and configures buckets
#: (`object_store_provision.py --apply`, with its own credential).
OTHER_ACCOUNTS = {"set_legal_hold": "preservation", "make_bucket": "admin", "remove_bucket": "admin",
                  "set_default_retention": "admin"}


def _policies() -> list[dict]:
    section = PAGE.split("## 4. The three accounts' policies", 1)[1].split("\n## ", 1)[0]
    blocks = re.findall(r"```json\n(.*?)\n```", section, flags=re.S)
    return [json.loads(b) for b in blocks]


def _actions(policy: dict) -> set[str]:
    found: set[str] = set()
    for statement in policy["Statement"]:
        actions = statement["Action"]
        found.update([actions] if isinstance(actions, str) else actions)
    return found


def _compose_policy(marker: str) -> dict:
    [line] = [ln for ln in COMPOSE.splitlines() if marker in ln and "printf '{\"Version\"" in ln]
    raw = re.search(r"printf '(\{.*\})' ", line).group(1)
    return json.loads(raw.replace("%s", "BUCKET"))


def _check_script():
    spec = importlib.util.spec_from_file_location("object_store_check", ROOT / "scripts" / "object_store_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_page_carries_three_valid_policies():
    policies = _policies()
    assert len(policies) == 3
    for policy in policies:
        assert policy["Version"] == "2012-10-17"
        for statement in policy["Statement"]:
            assert statement["Effect"] == "Allow"


def test_no_policy_has_a_wildcard_action_or_the_governance_bypass():
    for policy in _policies():
        for action in _actions(policy):
            assert "*" not in action, action
            assert "BypassGovernanceRetention" not in action
    assert "Never grant `s3:BypassGovernanceRetention`" in PAGE


def test_every_seam_method_is_mapped():
    methods = {name for name, _ in inspect.getmembers(ObjectStore, inspect.isfunction)
               if not name.startswith("_")}
    assert methods == set(NEEDS) | set(OTHER_ACCOUNTS)


def test_the_api_policy_covers_every_call_the_evidence_path_makes():
    api, _samples, _preserve = _policies()
    granted = _actions(api)
    for method, needed in NEEDS.items():
        missing = set(needed) - granted
        assert not missing, f"ObjectStore.{method} needs {sorted(missing)}, which the API policy does not grant"


def test_the_api_policy_grants_nothing_the_code_never_calls():
    api, _samples, _preserve = _policies()
    needed = {a for actions in NEEDS.values() for a in actions} | {"s3:GetObjectLegalHold"}
    assert _actions(api) <= needed, sorted(_actions(api) - needed)


def test_the_samples_and_preservation_policies_are_the_ones_compose_mints():
    _api, samples, preserve = _policies()
    assert samples == _compose_policy("sample-policy.json")
    assert preserve == _compose_policy("preserve-policy.json")


def test_the_preservation_policy_sets_a_hold_only_on_and_deletes_nothing():
    _api, _samples, preserve = _policies()
    actions = _actions(preserve)
    assert not {a for a in actions if "Delete" in a or "Retention" in a}
    [hold] = [s for s in preserve["Statement"] if "s3:PutObjectLegalHold" in s["Action"]]
    assert hold["Condition"] == {"StringEquals": {"s3:object-lock-legal-hold": ["ON"]}}


def test_the_preflight_prints_the_same_actions_as_the_page():
    api, samples, preserve = _policies()
    printed = _check_script().IAM_ACTIONS
    by_account = {"api": api, "samples": samples, "preservation": preserve}
    for account, policy in by_account.items():
        [key] = [k for k in printed if k.startswith(account)]
        names = {re.sub(r" \(.*\)$", "", a) for a in printed[key]}
        assert names == _actions(policy), account
