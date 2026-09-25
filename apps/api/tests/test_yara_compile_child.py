"""The YARA compile and scan children (F12 D and F, 2026-09-24).

yara-x keeps the valid rules of a source whose add_source raised (probed
2026-09-24), so a file with any error must contribute NO rule: pass one
compiles each file alone, pass two builds only the files pass one
accepted. Includes are refused. The report names where an error is and
never quotes the rule text. The scan returns offsets and counts, never
matched bytes, and a rule's console output never reaches the channel the
parent reads.

Pure: no database. Skips where yara-x is not installed (CI installs the
extra; test_yara_scan_pg.py fails if it stops).
"""
from __future__ import annotations

import json

import pytest

from noctornal_api import lab_static, lab_triage, yara_rules

pytest.importorskip("yara_x")


@pytest.fixture
def settings():
    return lab_triage.settings_or_default()


def _compile(files, settings, cap=yara_rules.MAX_COMPILED_BYTES):
    canon = yara_rules.canonical_json(files)
    return lab_triage.run_child(
        {"mode": "yara_compile", "sample_len": len(canon),
         "limits": {"memory_bytes": settings.memory_bytes, "cpu_s": 60}},
        (canon,), wall_s=70, stdout_cap=cap)


def _scan(blob, data, settings):
    res = lab_triage.run_child(
        {"mode": "yara_scan", "sample_len": len(data), "rules_len": len(blob),
         "timeout_s": 10, "limits": {"memory_bytes": settings.memory_bytes,
                                     "cpu_s": 15}},
        (data, blob), wall_s=25)
    assert res.ok, res.failure
    return json.loads(res.output)


def test_a_failed_file_contributes_no_rule(settings):
    res = _compile([
        ("broken.yar", "rule before { condition: true } "
                       "rule broken { condition: nosuch } "
                       "rule after { condition: true }"),
        ("good.yar", 'rule good { strings: $a = "needle" condition: $a }'),
    ], settings)
    report, blob = lab_static.unframe_compile(res.output)
    assert report["status"] == "PARTIAL" and report["rule_count"] == 1
    status = {f["path"]: f["status"] for f in report["files"]}
    assert status == {"broken.yar": "failed", "good.yar": "compiled"}
    out = _scan(blob, b"an unrelated buffer with no needle-less text", settings)
    names = {r["identifier"] for r in out["rules"]}
    assert "before" not in names and "after" not in names


def test_includes_are_refused_and_the_file_failed(settings):
    res = _compile([("inc.yar", 'include "other.yar"\nrule z { condition: true }')],
                   settings)
    report, blob = lab_static.unframe_compile(res.output)
    assert report["status"] == "FAILED" and blob == b""
    assert report["files"][0]["errors"][0]["code"] == "E044"


def test_a_cross_file_reference_fails_its_file(settings):
    res = _compile([
        ("base.yar", 'rule base { strings: $a = "x1" condition: $a }'),
        ("uses.yar", "rule uses { condition: base }"),
    ], settings)
    report, _blob = lab_static.unframe_compile(res.output)
    status = {f["path"]: f["status"] for f in report["files"]}
    assert status == {"base.yar": "compiled", "uses.yar": "failed"}


def test_the_report_never_quotes_rule_text(settings):
    res = _compile([("q.yar", 'rule q { strings: $s = "SECRET-PATTERN-7Q" '
                              "condition: $s and nosuch }")], settings)
    report, _blob = lab_static.unframe_compile(res.output)
    assert "SECRET-PATTERN-7Q" not in json.dumps(report)
    clean = lab_triage._clean_report(report)
    assert set(clean["files"][0]["errors"][0]) == {"code", "title", "line",
                                                   "column"}


def test_compile_output_is_framed_and_capped(settings):
    res = _compile([("g.yar", 'rule g { strings: $a = "zz" condition: $a }')],
                   settings, cap=1024)
    assert not res.ok and res.failure == "output_too_large"
    with pytest.raises(ValueError):
        lab_static.unframe_compile(b"\x00" * 4)
    with pytest.raises(ValueError):
        lab_static.unframe_compile(b"\x7f" * 16)


def test_console_log_never_reaches_the_output_channel(settings):
    res = _compile([("c.yar", 'import "console"\nrule c { condition: '
                              'console.log("LOG-MARKER-9") }')], settings)
    _report, blob = lab_static.unframe_compile(res.output)
    raw = lab_triage.run_child(
        {"mode": "yara_scan", "sample_len": 4, "rules_len": len(blob),
         "timeout_s": 10, "limits": {"memory_bytes": settings.memory_bytes,
                                     "cpu_s": 15}},
        (b"abcd", blob), wall_s=25)
    assert raw.ok and b"LOG-MARKER-9" not in raw.output


def test_no_matched_bytes_are_returned(settings):
    res = _compile([("m.yar", 'rule m : tag1 { meta: family = "Emotet" '
                              'strings: $a = "MATCHED-BYTES-42" condition: $a }')],
                   settings)
    _report, blob = lab_static.unframe_compile(res.output)
    out = _scan(blob, b"xx MATCHED-BYTES-42 yy MATCHED-BYTES-42", settings)
    assert out["matched"] == 1
    rule = out["rules"][0]
    assert rule["metadata"] == {"family": "Emotet"} and rule["tags"] == ["tag1"]
    assert rule["patterns"] == [{"identifier": "$a", "hits": 2,
                                 "offsets": [3, 23]}]
    assert "MATCHED-BYTES" not in json.dumps({k: v for k, v in out.items()
                                              if k != "rules"}) + json.dumps(
        rule["patterns"])


def test_an_undecodable_build_is_said_so_not_crashed(settings):
    out = _scan(b"not a build" * 10, b"abc", settings)
    assert out["error"] == "rules_rejected"
