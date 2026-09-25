"""The console's side of the Lab seams (F11-core J, 2026-09-24): custody
rows the product wrote say so and name nobody, a SCANNED read has words
of its own, machine findings name what produced them and no person, and
every gap status reads in words, with "does not apply" never counted as a
check not done.

Pure: reads the shipped console, and runs the gap summary under Node.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function, from its keyword to its own closing brace
    (braces counted outside string literals, so a one-line function stops
    where it ends)."""
    js = _js()
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    i = js.index("{", m.start())
    depth = 0
    quote = None
    while True:
        ch = js[i]
        if quote:
            if ch == "\\":
                i += 1
            elif ch == quote:
                quote = None
        elif js.startswith("//", i):
            i = js.index("\n", i)
            continue
        elif js.startswith("/*", i):
            i = js.index("*/", i) + 2
            continue
        elif ch in "'\"`":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return js[m.start():i + 1]
        i += 1


def _object(name: str) -> str:
    js = _js()
    start = js.index(f"const {name} = {{")
    return js[start:js.index("};", start)]


def test_system_custody_rows_read_as_automated():
    panel = _fn("custodyPanel")
    assert "c.actor_kind === 'SYSTEM'" in panel
    assert "'NocTORnal (automated)'" in panel
    assert "'person is-automated'" in panel
    # The person's row is drawn exactly as before.
    assert "smpPerson(c.actor_name, c.actor_email)" in panel
    assert "automated analysis" in panel, "the help does not mention machine reads"


def test_scanned_has_words_of_its_own():
    line = _fn("custodyLine")
    assert "case 'SCANNED':" in line
    assert "SHA-256 verified" in line and "was written to disk or served" in line


def test_machine_rows_name_no_person():
    row = _fn("analysisRow")
    assert "a.origin === 'machine'" in row
    assert "fact('produced by', a.produced_by" in row
    # An analyst's row still names the analyst.
    assert "personFact('recorded by', a.analyst_name, a.analyst_email)" in row


def test_every_gap_status_has_words():
    from noctornal_api.samples import GAP_STATUSES
    words = _object("GAP_STATUS_WORDS")
    for status in GAP_STATUSES:
        assert f"{status}:" in words, f"{status} has no words"
    assert "'waiting for static triage'" in words
    assert "'not available in this deployment'" in words


@pytest.mark.skipif(not NODE, reason="Node is not installed here")
def test_not_applicable_is_not_counted_as_not_done():
    code = "\n".join([
        "function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }",
        "const PROHIBITED_GAP = 'prohibited_content_screening';",
        _fn("gapStep"), _fn("gapStatus"), _fn("gapsNotDone"), _fn("gapSummary"),
        "const gaps = " + json.dumps([
            {"step": "imphash", "status": "not_applicable", "reason": "x"},
            {"step": "rich_header_hash", "status": "not_applicable", "reason": "x"},
            {"step": "yara", "status": "pending", "reason": "x"},
            {"step": "prohibited_content_screening", "status": "unavailable",
             "reason": "x"}]) + ";",
        "console.log(JSON.stringify([gapSummary(gaps), gapSummary(gaps.slice(0, 2)),"
        " gapSummary(gaps.slice(2, 3))]));",
    ])
    out = subprocess.run([NODE], input=code, capture_output=True,
                         encoding="utf-8", timeout=30, check=True).stdout
    with_screening, only_moot, one = json.loads(out)
    assert with_screening == ("Not screened for prohibited content · 1 other "
                              "check not done")
    assert only_moot == "0 triage checks not done"
    assert one == "1 triage check not done"
    card = _fn("openSample")
    assert "'Checks not done'" in card and "'Does not apply'" in card


def test_new_copy_has_no_dash_double_hyphen_or_s_in_brackets():
    for name in ("custodyLine", "custodyPanel", "analysisRow", "gapSummary"):
        body = _fn(name)
        for literal in re.findall(r"'((?:[^'\\]|\\.)*)'", body):
            assert "\u2014" not in literal and "\u2013" not in literal, literal
            assert not re.search(r"\s--(\s|$)", literal), literal
            assert "(s)" not in literal, literal
    assert "(s)" not in _object("GAP_STATUS_WORDS")
