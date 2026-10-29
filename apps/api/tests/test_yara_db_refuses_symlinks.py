"""scripts/yara_db.py refuses symbolic links in a pulled rule repository
(infra-13, 2026-10-03).

A source's repository is somebody else's tree, fetched at HEAD. A
`rules/innocent.yar` that is a symlink to a path on the operator's machine
was kept by the prune (it has the right extension), listed by `os.walk` as a
file, opened by `_source_bundle` and stored in a rule set version by `import`,
where lab members and the activating Security Officer read it as rule text.

Creating a symlink needs a privilege on Windows (and git there checks them out
as text), so these skip where one cannot be made; CI runs on Linux. The
reproduction before the fix is `scratchpad/review/yara_symlink_probe2.py`.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "yara_db.py"
CANARY = b"G48-CANARY-local-file-outside-the-vendor-tree: operator secret"
RULE = b'rule real_rule { strings: $a = "needle" condition: $a }\n'


@pytest.fixture
def yara_db(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("g48_yara_db", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "VENDOR", str(tmp_path / "vendor"))
    monkeypatch.setattr(module, "load_sources", lambda: [
        {"name": "evil-source", "repo": "https://example.invalid/x.git",
         "rules_subdir": "rules", "license": "MIT", "review": False}])
    return module


def _symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")


@pytest.fixture
def pulled(tmp_path):
    """vendor/evil-source/rules with one real rule and one outside file."""
    rules = tmp_path / "vendor" / "evil-source" / "rules"
    rules.mkdir(parents=True)
    (rules / "real.yar").write_bytes(RULE)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "operator-secret.txt").write_bytes(CANARY)
    return rules, outside


def test_the_prune_removes_a_link_that_is_named_like_a_rule(yara_db, pulled, tmp_path):
    rules, outside = pulled
    link = rules / "innocent.yar"
    _symlink(outside / "operator-secret.txt", link)
    removed = yara_db._prune_to_rules(str(tmp_path / "vendor" / "evil-source"))
    assert removed == 1
    assert not os.path.lexists(link), "the link is still there"
    assert (rules / "real.yar").read_bytes() == RULE, "a real rule file was kept"
    assert (outside / "operator-secret.txt").read_bytes() == CANARY, "the target was never touched"


def test_the_prune_removes_a_linked_directory_and_leaves_its_target(yara_db, pulled, tmp_path):
    rules, outside = pulled
    _symlink(outside, rules / "sub")
    yara_db._prune_to_rules(str(tmp_path / "vendor" / "evil-source"))
    assert not os.path.lexists(rules / "sub")
    assert (outside / "operator-secret.txt").exists()


def test_the_listing_skips_a_link_even_if_one_is_there(yara_db, pulled):
    """The prune runs at fetch; the listing is what `build` and `import` use,
    and a link can be there without a fetch (a vendor tree restored from
    somewhere, a repository that changed since)."""
    rules, outside = pulled
    _symlink(outside / "operator-secret.txt", rules / "innocent.yar")
    listed = [Path(path).name for _name, path in yara_db._iter_files()]
    assert listed == ["real.yar"], listed


def test_the_listing_does_not_follow_a_rules_directory_that_is_a_link(yara_db, tmp_path):
    base = tmp_path / "vendor" / "evil-source"
    base.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "stolen.yar").write_bytes(CANARY)
    _symlink(outside, base / "rules")
    assert list(yara_db._iter_files()) == []


def test_a_normal_pulled_repository_lists_and_survives_the_prune(yara_db, pulled, tmp_path):
    """The other direction: nothing a source legitimately ships is lost."""
    rules, _outside = pulled
    nested = rules / "malware" / "family"
    nested.mkdir(parents=True)
    (nested / "deep.yara").write_bytes(RULE)
    (rules / "README.md").write_text("not a rule", encoding="utf-8")
    removed = yara_db._prune_to_rules(str(tmp_path / "vendor" / "evil-source"))
    assert removed == 1  # the README, which was never a rule
    assert sorted(Path(p).name for _n, p in yara_db._iter_files()) == ["deep.yara", "real.yar"]


def test_the_helper_accepts_a_regular_file_and_refuses_everything_else(yara_db, pulled, tmp_path):
    rules, outside = pulled
    base = str(tmp_path / "vendor" / "evil-source")
    assert yara_db._is_plain_file_inside(base, str(rules / "real.yar"))
    assert not yara_db._is_plain_file_inside(base, str(rules / "missing.yar"))
    assert not yara_db._is_plain_file_inside(base, str(outside / "operator-secret.txt"))
    assert not yara_db._is_plain_file_inside(base, str(rules))


def test_a_link_swapped_in_after_the_listing_is_not_opened(yara_db, pulled, tmp_path, monkeypatch):
    """`_source_bundle` opens with O_NOFOLLOW where the platform has it, so a
    link that appears between the listing and the read is refused, not read."""
    if not hasattr(os, "O_NOFOLLOW"):
        pytest.skip("no O_NOFOLLOW on this platform")
    rules, outside = pulled
    link = rules / "swapped.yar"
    _symlink(outside / "operator-secret.txt", link)
    monkeypatch.setattr(yara_db, "_iter_files", lambda: iter([("evil-source", str(link))]))
    with pytest.raises(OSError):
        yara_db._source_bundle("evil-source")
