"""The report preview shows a bidi override as an escape, not as an effect.

The labels in the preview (assumptions, entities, relationship ends,
exhibit titles, hypotheses, the line saying what the numbers were computed over, the
hypothesis warnings) and the full markdown about to be saved come
from forum text. `textContent` stops markup but leaves a right-to-left
override in force, so "harmless" + RLO + "fdp.exe" reads as
"harmlessexe.pdf" and a relationship can appear to run the other way. The
preview is where the analyst checks a document before it leaves, so each of
these goes through `visibleText` first.

Runs the real preview under Node with the DOM faked (skipped where Node is
not installed).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)

RLO = "\u202e"


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _deceptive() -> str:
    js = _js()
    start = js.index("const _DECEPTIVE = new RegExp(")
    return js[start:js.index("'g');", start) + 5]


HARNESS = """
const REPORT_SIGN = { '1': 'positive', '-1': 'negative', '0': 'neutral' };
function el(tag, cls, text) {
  return { tag, cls, text: text === undefined || text === null ? '' : String(text),
    childNodes: [], appendChild(c) { this.childNodes.push(c); return c; } };
}
const BOX = el('div');
function $(_id) { return BOX; }
function clear(node) { node.childNodes = []; }
function fmtDate(v) { return v || 'none'; }
function typeName(k) { return k; }
function texts(node, out) {
  out.push(node.text);
  for (const c of node.childNodes) texts(c, out);
  return out;
}
"""


def _render(body: dict) -> list[str]:
    if not NODE:
        pytest.skip("Node is not installed here")
    script = HARNESS + "\n".join([
        _deceptive(), _fn("visibleText"), _fn("shortId"), _fn("countOf"),
        _fn("fact"), _fn("reportList"), _fn("reportRow"), _fn("renderReportBody"),
        f"renderReportBody({json.dumps(body)});",
        "console.log(JSON.stringify(texts(BOX, [])));"])
    run = subprocess.run([NODE, "-"], input=script, capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


BODY = {
    "summary": {"entities": 2, "relationships": 1, "exhibits": 1,
                "computed_over": "case" + RLO + "fdp.exe"},
    "case": {"legal_basis": "warrant"},
    "assumptions": [{"statement": "a" + RLO + "b", "status": "open",
                     "made_by_name": "Rae", "reviewed_at": None}],
    "actors": [
        {"id": "n-1", "label": "harmless" + RLO + "fdp.exe", "type": "IDENTITY",
         "classification": "AMBER", "has_evidence": True},
        {"id": "n-2", "label": "Sam" + RLO + "lA", "type": "IDENTITY",
         "classification": "AMBER", "has_evidence": True},
    ],
    "relationships": [{"src": "n-1", "dst": "n-2", "type": "KNOWS", "sign": "1",
                       "confidence": 0.5, "has_evidence": True}],
    "evidence": [{"id": "e-1", "title": "photo" + RLO + "gpj.exe", "sha256": "ab" * 32}],
    "hypotheses": {"hypotheses": [{"id": 1, "statement": "x" + RLO + "y",
                                   "inconsistency": 0, "support": 1}],
                   "statuses": {}, "warnings": ["one" + RLO + "fdp.exe"]},
    "document": "# Report\n\nharmless" + RLO + "fdp.exe\n",
}


def test_no_bidi_override_reaches_the_preview():
    painted = _render(BODY)
    leaks = [t for t in painted if RLO in t]
    assert not leaks, f"painted with the override in force: {leaks!r}"
    assert any("harmless\u2039U+202E\u203afdp.exe" in t for t in painted)


def test_the_full_text_keeps_its_line_breaks():
    painted = _render(BODY)
    assert any(t.startswith("# Report\n\n") for t in painted)
