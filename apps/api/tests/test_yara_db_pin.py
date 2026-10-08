"""scripts/yara_db.py pulls a source at the commit sources.json pins and goes no
further without `--update` (docs/17, "the YARA fetch does not pin the head").

Nothing here reaches the network: the "remote" is a repository made in a
temporary directory with `git`, which is what the tool runs. Needs `git` on the
path (the suite's checkout needed it). No yara-x, no database.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "yara_db.py"
RULE_A = 'rule first { strings: $a = "one" condition: $a }\n'
RULE_B = 'rule second { strings: $a = "two" condition: $a }\n'


def _git(cwd, *args) -> str:
    out = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, capture_output=True, text=True, check=True)
    return out.stdout.strip()


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A remote with two commits, the tool pointed at a vendor tree of its
    own, and the manifest it reads."""
    remote = tmp_path / "remote"
    remote.mkdir()
    _git(remote, "init", "-q")
    (remote / "a.yar").write_text(RULE_A, encoding="utf-8")
    (remote / "sample.exe").write_bytes(b"MZ not a rule")
    _git(remote, "add", ".")
    _git(remote, "commit", "-q", "-m", "first")
    first = _git(remote, "rev-parse", "HEAD")
    (remote / "b.yar").write_text(RULE_B, encoding="utf-8")
    _git(remote, "add", ".")
    _git(remote, "commit", "-q", "-m", "second")
    second = _git(remote, "rev-parse", "HEAD")

    spec = importlib.util.spec_from_file_location("yara_db_pin_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "VENDOR", str(tmp_path / "vendor"))
    monkeypatch.setattr(module, "DIST", str(tmp_path / "dist"))
    monkeypatch.setattr(module, "LOCK", str(tmp_path / "fetch.lock.json"))
    sources = tmp_path / "sources.json"
    monkeypatch.setattr(module, "SOURCES", str(sources))

    def manifest(**entry):
        sources.write_text(json.dumps({"schema": 1, "sources": [
            {"name": "remote-rules", "repo": str(remote), "license": "MIT",
             "review": False, **entry}]}), encoding="utf-8")

    class World:
        pass

    w = World()
    w.module, w.remote, w.first, w.second = module, remote, first, second
    w.manifest = manifest
    w.vendor = tmp_path / "vendor" / "remote-rules"
    w.lock = tmp_path / "fetch.lock.json"
    return w


def _fetch(w, *, update=False, only=None):
    return w.module.cmd_fetch(argparse.Namespace(
        only=only, jobs=1, update=update))


def _head(w) -> str:
    return _git(w.vendor, "rev-parse", "HEAD")


def _rules(w) -> set[str]:
    return {p.name for p in w.vendor.glob("*.yar")}


def _record(w) -> dict:
    return json.loads(w.lock.read_text(encoding="utf-8"))["sources"][0]


def test_a_pinned_source_is_pulled_at_its_commit_and_not_past_it(world, capsys):
    world.manifest(commit=world.first)
    assert _fetch(world) == 0
    assert _head(world) == world.first, "the upstream's newer commit is not taken"
    assert _rules(world) == {"a.yar"}
    record = _record(world)
    assert record["ok"] and record["commit"] == world.first
    assert record["pinned"] == world.first and "moved_past_pin" not in record
    assert "at its pin" in capsys.readouterr().out
    # Fetching again changes nothing, and the upstream moving on does not either.
    (world.remote / "c.yar").write_text(RULE_A.replace("first", "third"), encoding="utf-8")
    _git(world.remote, "add", ".")
    _git(world.remote, "commit", "-q", "-m", "third")
    assert _fetch(world) == 0 and _head(world) == world.first
    assert _rules(world) == {"a.yar"}


def test_what_is_not_a_rule_is_still_pruned_from_a_pinned_checkout(world):
    world.manifest(commit=world.first)
    assert _fetch(world) == 0
    assert not (world.vendor / "sample.exe").exists()
    assert _record(world)["pruned_non_rule_files"] >= 1


def test_a_checkout_that_is_at_another_commit_is_moved_back_to_the_pin(world):
    world.manifest(commit=world.second)
    assert _fetch(world) == 0 and _head(world) == world.second
    world.manifest(commit=world.first)
    assert _fetch(world) == 0
    assert _head(world) == world.first and _rules(world) == {"a.yar"}


def test_update_follows_the_default_branch_past_the_pin_and_prints_what_to_pin(
        world, capsys):
    world.manifest(commit=world.first)
    assert _fetch(world) == 0
    capsys.readouterr()
    assert _fetch(world, update=True) == 0
    out = capsys.readouterr().out
    assert _head(world) == world.second and _rules(world) == {"a.yar", "b.yar"}
    record = _record(world)
    assert record["commit"] == world.second and record["moved_past_pin"] == world.first
    assert f'"commit": "{world.second}"' in out
    # The pin in the manifest is the operator's to move: nothing wrote it.
    assert json.loads(Path(world.module.SOURCES).read_text())["sources"][0]["commit"] \
        == world.first
    # And the next plain fetch goes back to it.
    assert _fetch(world) == 0 and _head(world) == world.first


def test_a_source_with_no_pin_is_refused_without_update_and_pulled_with_it(
        world, capsys):
    world.manifest()
    assert _fetch(world) == 1
    out = capsys.readouterr().out
    assert "no commit is pinned" in out and "fetch --update" in out
    assert not world.vendor.exists(), "nothing was pulled"
    record = _record(world)
    assert record["ok"] is False and record["pinned"] is None
    assert _fetch(world, update=True) == 0
    assert _head(world) == world.second
    assert f'"commit": "{world.second}"' in capsys.readouterr().out


@pytest.mark.parametrize("bad", ["main", "v1.2.0", "abc123", "A" * 40, "g" * 40,
                                 "0" * 39, 5, ["x"]])
def test_a_pin_that_is_not_a_full_commit_id_is_refused_by_name(world, capsys, bad):
    world.manifest(commit=bad)
    assert _fetch(world) == 2
    assert "remote-rules: commit must be a full" in capsys.readouterr().err
    assert not world.vendor.exists()


def test_a_pin_the_source_does_not_hold_fails_that_source_and_says_so(world, capsys):
    world.manifest(commit="0" * 40)
    assert _fetch(world) == 1
    record = _record(world)
    assert record["ok"] is False and "pinned commit" in record["error"]
    out = capsys.readouterr().out
    assert "FAIL" in out and "remote-rules" in out


def test_stats_flags_a_source_that_is_unpinned_or_not_at_its_pin(world, capsys):
    world.manifest(commit=world.first)
    assert _fetch(world) == 0
    capsys.readouterr()
    world.module.cmd_stats(argparse.Namespace())
    shown = capsys.readouterr().out
    assert "[UNPINNED]" not in shown and "[NOT AT ITS PIN]" not in shown
    world.manifest()
    world.module.cmd_stats(argparse.Namespace())
    assert "[UNPINNED]" in capsys.readouterr().out
    world.manifest(commit=world.second)
    world.module.cmd_stats(argparse.Namespace())
    assert "[NOT AT ITS PIN]" in capsys.readouterr().out


def test_the_shipped_manifest_is_valid_and_pins_are_optional():
    spec = importlib.util.spec_from_file_location("yara_db_manifest_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sources = module.load_sources()
    assert sources and all(s["repo"].startswith("https://") for s in sources)
    assert all(s.get("commit") is None or module.COMMIT_RE.match(s["commit"])
               for s in sources)
