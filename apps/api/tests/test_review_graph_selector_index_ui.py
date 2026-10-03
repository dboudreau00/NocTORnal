"""The console says when a selector it just wrote is already held
(graph-selector-index-drift, review 2026-10-03).

The server now returns `selector_owner_id` from a correction of a selector
entity (`PATCH /graph/nodes/{id}`) and from the accept of a proposal that
names a selector type, as `POST /nodes` already did. The create form says
"already recorded against X ... a merge lead"; a correction and an accept
said nothing, so the lead the server found was never seen. These tests hold
the two new lines and the words they use. Server half:
`test_review_graph_selector_index_pg.py`.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static"
APP_JS = STATIC / "app.js"

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

EM, EN = chr(0x2014), chr(0x2013)


def _function(name: str) -> str:
    js = APP_JS.read_text(encoding="utf-8")
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text("\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_an_accept_and_a_correction_say_the_lead_the_server_returned():
    outcome = _function("showTriageOutcome")
    assert "if (out.selector_owner_id) {" in outcome
    assert "labelOf(out.selector_owner_id)" in outcome
    # said before the Undo, so it is on the line whatever the role
    assert outcome.index("selectorLeadWords(") < outcome.index("triageCanUndo(p)")
    submit = _function("submitCorrection")
    assert "out && out.selector_owner_id" in submit
    assert "selectorLeadWords('selector value', labelOf(out.selector_owner_id))" in submit


@needs_node
def test_the_lead_names_the_holder_and_says_what_to_do(tmp_path):
    got = _run([_function("selectorLeadWords")], """
console.log(JSON.stringify([
  selectorLeadWords('EMAIL', 'vendor one'),
  selectorLeadWords('selector value', 'entity 1234abcd'),
]));
""", tmp_path)
    first, second = got
    assert first.startswith("This EMAIL is already recorded against vendor one, ")
    assert "it stays there and this entity does not hold it" in first
    assert "compare them under Entity resolution." in first
    assert "entity 1234abcd" in second
    for text in got:
        assert EM not in text and EN not in text and " -- " not in text
