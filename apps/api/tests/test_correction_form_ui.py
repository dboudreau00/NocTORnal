"""Correct... is a graded form: the console half of gap-api-grade-required.

Decided 2026-09-23: the API requires every claim's grading (basis,
reliability, credibility, confidence) and answers a missing field with a
422 naming it. A correction is a claim ("this is now called X", invariant
1), and the console's Correct... was two window prompts that sent the
reason alone, leaving the server to grade it DIRECT_OBSERVATION F6 LOW.
Under the new rule that request is refused, and grading it in the console
instead would only move the old gap into the browser. So the inspector
has a Correct form, graded the way the create forms and Add a claim are:
nothing chosen for the analyst, refused until all four are picked.

Pure, as `test_tie_claim_ui.py` is: the static checks run everywhere, and
the ones marked `needs_node` EXECUTE the shipped functions under Node.
`test_api_grade_required_pg.py` holds the server half.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

API = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
STATIC = API / "http" / "static"
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

EM, EN = chr(0x2014), chr(0x2013)


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _function(name: str) -> str:
    """A top-level function's source, closed on the first `}` at column 0."""
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _fix_markup() -> str:
    html = _html()
    start = html.index('<div id="insp-fix"')
    return html[start:html.index("</form>", start)]


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text("\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------

def test_the_inspector_has_a_graded_correct_form():
    markup = _fix_markup()
    assert '<form id="fix-form"' in markup and "novalidate" in markup
    for field in ("basis", "conf", "rel", "cred"):
        m = re.search(r'<select id="fix-' + field + r'"[^>]*>', markup)
        assert m and "required" in m.group(0), (
            f"#fix-{field} must be a required select, as the create forms' are")
    for element_id in ("fix-heading", "fix-help", "fix-label-field", "fix-label",
                       "fix-conf-label", "fix-rationale", "fix-rat-req",
                       "fix-evidence", "fix-observed", "fix-ref", "fix-error",
                       "fix-submit", "fix-cancel"):
        assert f'id="{element_id}"' in markup, element_id
    assert re.search(r'<p id="fix-error"[^>]*role="alert"', markup)
    assert "Observed at (UTC)" in markup, "every console time is UTC and says so"
    assert "style=" not in markup
    assert EM not in markup and EN not in markup
    # Under the element's actions, where Correct... is pressed.
    html = _html()
    assert html.index('id="insp-actions"') < html.index('id="insp-fix"') < (
        html.index('id="insp-metrics-sec"'))


def test_correct_opens_the_form_and_asks_nothing_in_a_prompt():
    wiring = _function("wireElementActions")
    assert "edit.addEventListener('click', openCorrection);" in wiring
    assert "wireCorrection();" in wiring
    js = _js()
    for gone in ("window.prompt('Corrected label'",
                 "window.prompt('Why? This is recorded",
                 "body.assertion = { rationale: why"):
        assert gone not in js, gone


def test_a_correction_is_graded_and_checked_before_anything_is_sent():
    body = _function("submitCorrection")
    sent = body.index("await api(")
    for check in ("gradingProblem('fix')", "assertionFrom('fix')",
                  "rationaleProblem(assertion)", "A label cannot be blank."):
        assert check in body and body.index(check) < sent, check
    assert "body.assertion = assertion;" in body
    assert "method: 'PATCH', json: body" in body
    # A tie's re-grade is the correction's own grade, sent as both.
    assert "body = { confidence: assertion.confidence };" in body
    # Nothing is chosen for the analyst.
    reset = _function("resetCorrection")
    assert "resetGrading('fix');" in reset
    for default in ("'DIRECT_OBSERVATION'", "'C'", "'3'", "'F'", "'6'",
                    "'LOW'", "'MODERATE'"):
        assert default not in reset


def test_every_claim_the_console_records_is_graded_first():
    """The four writes that record a claim, each refusing an ungraded one
    before its request: nothing is left for the server to grade."""
    for name, prefix in (("createNode", "node"), ("createEdge", "edge"),
                         ("addTieClaim", "claim"), ("submitCorrection", "fix")):
        body = _function(name)
        assert f"gradingProblem('{prefix}')" in body, name
        assert body.index(f"gradingProblem('{prefix}')") < body.index("await api("), name
    # And no other PATCH reaches the graph's correction routes.
    js = _js()
    graph_patches = [m.start() for m in re.finditer(r"method: 'PATCH'", js)
                     if "cpath('/graph/'" in js[max(0, m.start() - 200):m.start()]]
    submit_at = js.index("async function submitCorrection(")
    assert len(graph_patches) == 1, "a second correction request appeared"
    assert submit_at < graph_patches[0] < submit_at + len(
        _function("submitCorrection"))


def test_a_correction_belongs_to_one_element():
    body = _function("submitCorrection")
    guard = "sel.kind !== correction.kind || sel.id !== correction.id"
    assert guard in body and body.index(guard) < body.index("await api(")
    assert "caseChanged(token)" in body
    assert "syncCorrection(sel);" in _function("renderInspector")
    js = _js()
    hook = js[js.index("onCaseSwitch(() => {\n  correction.kind = null;"):]
    hook = hook[:hook.index("});")]
    assert "resetCorrection()" in hook and "showCorrection(false)" in hook


def test_the_form_offers_the_cases_exhibits_and_is_wired():
    assert "'fix'" in _function("refreshEvidencePickers")
    wiring = _function("wireCorrection")
    for wired in ("$('fix-cancel')",
                  "$('fix-form').addEventListener('submit', submitCorrection)",
                  "syncRationaleHint('fix')",
                  "setAttribute('aria-controls', 'insp-fix')"):
        assert wired in wiring, wired
    assert "setAttribute('aria-expanded'" in _function("showCorrection")


def test_a_refused_lowering_carries_what_was_entered():
    carry = _function("carryCorrectionIntoTieClaim")
    assert "openTieClaim(conf)" in carry
    assert "resetGrading('claim', gradingOf('fix'))" in carry
    assert "'rationale', 'evidence', 'observed', 'ref'" in carry
    assert "resetCorrection()" in carry and "showCorrection(false)" in carry


def test_what_the_form_block_says_carries_no_dash():
    js = _js()
    region = js[js.index("/* ── inspector: correct the selected element"):
                js.index("/* Attach an exhibit already in this case")]
    assert EM not in region and EN not in region
    assert " -- " not in region


def test_the_card_no_longer_explains_a_correction_by_an_api_default():
    """Verifier round on gap-api-grade-required, 2026-09-23. The card
    headlines a correction as "Correction" rather than its basis, and the
    comment gave the reason as "the basis it carries is the server's
    ungraded default". Corrections now carry the basis the analyst chose,
    so that reason was false for every new one. The display stays (the
    recorded basis is in the meta line); the reason is restated, and the
    ux05 note above it says the prompt-only dialogue is gone."""
    flat = " ".join(_js().split())
    assert "the basis it carries is the server's ungraded default" not in flat
    assert "dialogue sends only a rationale, and the server fills in" not in flat
    render = _function("renderAssertions")
    assert "a.is_correction ? 'Correction'" in render
    assert "gap-api-grade-required" in render
    assert "'recorded basis ' + basisName(a.basis)" in render


# ---------------------------------------------------------------------------
# Executed under Node
# ---------------------------------------------------------------------------

CONF_RANK = "const CONF_RANK = { LOW: 0, MODERATE: 1, HIGH: 2 };"


@needs_node
def test_the_words_say_what_is_corrected_and_that_nothing_is_graded(tmp_path):
    got = _run([CONF_RANK, _function("correctionWords")], """
console.log(JSON.stringify([
  correctionWords('node', null),
  correctionWords('edge', 'MODERATE'),
  correctionWords('edge', null),
]));
""", tmp_path)
    node, tie, unknown = got
    assert node["heading"] == "Correct this entity"
    assert node["conf"] == "Confidence (ICD 203)"
    assert "audit record" in node["help"]
    assert tie["heading"] == "Re-grade this tie"
    assert tie["conf"] == "Tie confidence (ICD 203)"
    assert tie["help"].startswith("The tie is MODERATE now. ")
    assert "retract the claims graded above it" in tie["help"]
    assert not unknown["help"].startswith("The tie is")
    for words in got:
        assert words["help"].endswith("Nothing is graded for you.")
        for text in words.values():
            assert EM not in text and EN not in text and " -- " not in text


@needs_node
def test_the_form_empties_when_the_selection_moves(tmp_path):
    stubs = """
let resets = 0, open = null;
function resetCorrection() { resets += 1; }
function showCorrection(on) { open = on; }
const correction = { kind: null, id: null };
"""
    got = _run([stubs, _function("syncCorrection")], """
const out = [];
const step = (sel) => { syncCorrection(sel);
  out.push([correction.kind, correction.id, resets, open]); };
step({kind: 'node', id: 'n1'});
open = true;                           // the analyst opened it and typed
step({kind: 'node', id: 'n1'});        // a reload re-renders the same entity
step({kind: 'edge', id: 'n1'});        // same id, another kind of element
step({kind: 'edge', id: 'e2'});        // another tie
step(null);                            // nothing selected
console.log(JSON.stringify(out));
""", tmp_path)
    first, same, other_kind, other, none = got
    assert first == ["node", "n1", 1, False]
    assert same == ["node", "n1", 1, True], "a re-render keeps the draft"
    assert other_kind == ["edge", "n1", 2, False]
    assert other == ["edge", "e2", 3, False]
    assert none == [None, None, 4, False]
