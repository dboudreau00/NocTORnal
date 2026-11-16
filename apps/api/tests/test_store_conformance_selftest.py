"""The conformance suite's own proof: it passes a store that behaves and catches each store broken on purpose.

The live suite (`apps/api/store_conformance`) runs only against a real endpoint, outside the CI test path. Its
checks are plain functions, so this file runs the very same functions against `objectstore_helpers.FakeS3`, an
in-process store with AWS's semantics, and then against fakes broken the ways real stores have been seen to
break, asserting that the check named for each failure is the one that catches it. Without this, a suite that
passed everything would look exactly like a store that conformed.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest
from objectstore_helpers import FakeS3, Unreachable

API = Path(__file__).resolve().parents[1]
if str(API) not in sys.path:
    sys.path.insert(0, str(API))

from store_conformance import checks  # noqa: E402


def _ctx(store: FakeS3) -> checks.Ctx:
    ctx = checks.Ctx(store=store, locked="locked", plain="plain", lock_seconds=60,
                     unreachable=Unreachable,
                     read_only=lambda: store.account(delete_denied=True))
    store.make_bucket(ctx.locked, object_lock=True)
    store.make_bucket(ctx.plain, object_lock=False)
    return ctx


def _failures(**flags) -> set[str]:
    """The checks a store with `flags` fails, each run on a store of its own."""
    failed = set()
    for check in (*checks.REQUIRED, *checks.OPTIONAL):
        try:
            check(_ctx(FakeS3(**flags)))
        except Exception:  # noqa: BLE001 - any failure of a check is the check failing, as in a live run
            failed.add(check.__name__)
    return failed


def test_a_conforming_fake_passes_every_required_check():
    assert _failures() == set()


def test_the_minio_profile_on_an_aws_style_store_is_caught():
    """AWS's AccessDenied read by MinIO's words is not a lock: the run says this store needs the s3 profile,
    and the register's proofs fail with it."""
    failed = _failures(profile="minio")
    assert "the_profiles_rule_reads_this_stores_lock_refusal_as_a_lock" in failed
    assert "the_write_once_probe_passes_and_its_tidy_works" in failed


@pytest.mark.parametrize("flag, caught_by", [
    ("deletes_locked", "a_version_delete_of_a_locked_version_is_refused_and_the_version_survives"),
    ("marker_on_version_delete",
     "a_version_delete_of_a_locked_version_is_refused_and_the_version_survives"),
    ("records_governance", "the_retention_reads_back_as_compliance_at_the_requested_instant"),
    ("ignores_legal_hold", "a_held_version_cannot_be_deleted_and_survives"),
    ("lets_retention_shorten", "a_compliance_retention_cannot_be_shortened"),
    ("no_marker_for_absent_key", "a_keyless_delete_of_an_absent_key_leaves_a_removable_marker"),
    ("no_version_id", "a_put_returns_a_version_id_and_a_get_by_that_version_returns_the_bytes"),
])
def test_each_broken_fake_is_caught_by_the_check_named_for_it(flag, caught_by):
    failed = _failures(**{flag: True})
    assert caught_by in failed, (flag, sorted(failed))


def test_a_store_that_deletes_locked_versions_fails_the_register_too():
    failed = _failures(deletes_locked=True)
    assert "the_write_once_probe_passes_and_its_tidy_works" in failed
    assert "delete_all_versions_on_a_locked_key_reports_locked_and_the_bytes_survive" in failed


def test_every_check_is_run_by_the_live_suite():
    """The live file runs REQUIRED and OPTIONAL whole, so a check added to `checks.py` and left out of both
    lists would be a property nobody tests."""
    tree = ast.parse((API / "store_conformance" / "checks.py").read_text(encoding="utf-8"))
    public = {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")}
    listed = {c.__name__ for c in (*checks.REQUIRED, *checks.OPTIONAL)}
    assert public == listed, public ^ listed


def test_known_gaps_are_strict_xfail(tmp_path, monkeypatch):
    from store_conformance import conftest

    (tmp_path / "somestore.txt").write_text(
        "# a comment\na_hold_only_object_has_no_retention  # upstream issue 1, https://example.invalid/1\n",
        encoding="utf-8")
    monkeypatch.setattr(conftest, "GAPS", tmp_path)
    monkeypatch.setenv("OBJECT_STORE_CONFORMANCE_STORE", "somestore")
    assert conftest.known_gaps("somestore") == {
        "a_hold_only_object_has_no_retention": "upstream issue 1, https://example.invalid/1"}

    class Item:
        def __init__(self, check):
            self.name = f"test_required[{check}]"
            self.callspec = type("C", (), {"id": check})()
            self.marks = []

        def add_marker(self, mark):
            self.marks.append(mark)

    items = [Item("a_hold_only_object_has_no_retention"), Item("the_hold_probe_passes")]
    conftest.pytest_collection_modifyitems(None, items)
    [mark] = items[0].marks
    assert mark.name == "xfail" and mark.kwargs["strict"] is True
    assert items[1].marks == []


def test_the_conformance_suite_lives_outside_the_ci_test_path():
    """The CI gate fails a run on any skip, and a suite with no store to run against would skip or fail: it is
    kept out of `testpaths` and out of the CI Tests step."""
    root = API.parents[1]
    pyproject = (API / "pyproject.toml").read_text(encoding="utf-8")
    assert 'testpaths = ["tests"]' in pyproject
    ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    test_steps = [ln for ln in ci.splitlines() if "pytest apps/api/tests" in ln]
    assert test_steps and not [ln for ln in test_steps if "store_conformance" in ln]
    assert (API / "store_conformance" / "test_store_conformance.py").is_file()
    assert not (API / "tests" / "store_conformance").exists()
