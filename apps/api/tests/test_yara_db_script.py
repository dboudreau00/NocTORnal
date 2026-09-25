"""scripts/yara_db.py against the product (F12 N, 2026-09-24).

`build` compiles with the product's own two-pass compile, so "compiles"
means there what it means in the Lab: a file with any error contributes
no rule. `import` stores pulled sources as rule set versions recorded as
imported on this host (SYSTEM, the host user), and never activates one: a
lab member must adopt it before an officer can activate it.

Email prefix `ytd-`. The import test is env-gated on DATABASE_URL; both
skip without yara-x.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from lab_static_fixtures import teardown

pytest.importorskip("yara_x")

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "yara_db.py"
PREFIX = "ytd-"


@pytest.fixture
def script(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("yara_db_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "VENDOR", str(tmp_path / "vendor"))
    monkeypatch.setattr(module, "DIST", str(tmp_path / "dist"))
    monkeypatch.setattr(module, "LOCK", str(tmp_path / "fetch.lock.json"))
    return module


def _pull(tmp_path, name: str) -> None:
    rules = tmp_path / "vendor" / name / "rules"
    rules.mkdir(parents=True)
    (rules / "good.yar").write_text(
        'rule good { strings: $a = "needle" condition: $a }\n', encoding="utf-8")
    (rules / "broken.yar").write_text(
        "rule before { condition: true } rule broken { condition: nosuch }\n",
        encoding="utf-8")


def test_build_uses_the_product_engine_and_two_pass_compile(script, tmp_path, monkeypatch, capsys):
    name = f"ytd-{uuid4().hex[:6]}"
    _pull(tmp_path, name)
    monkeypatch.setattr(script, "load_sources", lambda: [
        {"name": name, "repo": "https://example.invalid/x.git",
         "rules_subdir": "rules", "license": "MIT", "review": False}])
    assert script.cmd_build(argparse.Namespace()) == 0
    index = json.loads((tmp_path / "dist" / "index.json").read_text())
    by = {Path(f["file"]).name: f for f in index["files"]}
    assert by["good.yar"]["compiles"] is True
    assert by["broken.yar"]["compiles"] is False
    assert by["broken.yar"]["error"].startswith("E009")
    assert "nosuch" not in json.dumps(index["manifest"])
    assert index["manifest"]["yara_x"] is True
    dead = json.loads((tmp_path / "dist" / "dead_letter.json").read_text())
    assert [Path(d["file"]).name for d in dead] == ["broken.yar"]


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                    reason="DATABASE_URL not set")
def test_import_never_activates_records_system_and_needs_adoption(script, tmp_path, monkeypatch, capsys):
    from noctornal_api.db import connect
    name = f"ytd-{uuid4().hex[:6]}"
    _pull(tmp_path, name)
    monkeypatch.setattr(script, "load_sources", lambda: [
        {"name": name, "repo": "https://example.invalid/x.git",
         "homepage": "https://example.invalid/x", "rules_subdir": "rules",
         "license": "DRL-1.1", "review": True}])
    (tmp_path / "fetch.lock.json").write_text(json.dumps({"sources": [
        {"name": name, "ok": True, "commit": "abc123def456",
         "fetched_at": "2026-09-24T00:00:00+00:00"}]}), encoding="utf-8")
    conn = connect()
    try:
        rc = script.cmd_import(argparse.Namespace(
            only=[name], classification="AMBER", compartments=""))
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "Nothing was activated" in out and "adopt" in out
        row = conn.execute(
            """SELECT r.created_by, r.created_via, v.uploaded_by, v.adopted_by,
                      v.licence, v.licence_review_required, v.provenance,
                      v.files
                 FROM lab.yara_ruleset r
                 JOIN lab.yara_ruleset_version v ON v.ruleset_id = r.id
                WHERE r.key = %s""", (name,)).fetchone()
        created_by, via, uploaded_by, adopted_by, licence, review, prov, files = row
        assert created_by is None and via == "yara_db.py"
        assert uploaded_by is None and adopted_by is None
        assert licence == "DRL-1.1" and review is True
        assert prov["via"] == "yara_db.py" and prov["source_commit"] == "abc123def456"
        # Paths as they sit in the source repository, for provenance.
        assert {f["path"] for f in files} == {"rules/good.yar", "rules/broken.yar"}
        assert conn.execute(
            """SELECT count(*) FROM lab.yara_activation a
                 JOIN lab.yara_ruleset r ON r.id = a.ruleset_id
                WHERE r.key = %s""", (name,)).fetchone()[0] == 0
        kinds = {r[0] for r in conn.execute(
            """SELECT e.actor_kind FROM audit.event e
                 JOIN lab.yara_ruleset r ON r.id = e.object_id
                WHERE r.key = %s""", (name,)).fetchall()}
        assert kinds == {"SYSTEM"}
        # Both the set's creation and its version name the host user who
        # ran the import (the verifier of 2026-09-24 found the creation's
        # audit without it).
        details = {r[0]: r[1] for r in conn.execute(
            """SELECT e.action, e.detail FROM audit.event e
                 JOIN lab.yara_ruleset r ON r.id = e.object_id
                WHERE r.key = %s""", (name,)).fetchall()}
        import getpass
        assert details["YARA_RULESET_CREATED"]["host_user"] == getpass.getuser()
        assert details["YARA_RULESET_VERSION_ADDED"]["host_user"] == getpass.getuser()
    finally:
        teardown(conn, name + "-")
        conn.close()
