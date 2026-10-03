"""The console half of two review findings (2026-10-03):

- graph-valid-to-cannot-be-set-after-creation: the Retire dialog told the
  analyst to "set valid_to" and nothing in the console could. The Correct
  form now has a date, "Stopped being true on", sent as `valid_to` with the
  correction, and the dialog points at it.
- graph-retracted-correction-stays-in-force: retracting a correction now
  gives its value back, so the prompt says so.

Pure, as `test_correction_form_ui.py` is: the static checks run everywhere
and the ones marked `needs_node` EXECUTE the shipped functions under Node.
The server half is `test_review_graph_valid_to_pg.py`.
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
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text("\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# --- the form ----------------------------------------------------------------

def test_the_correct_form_has_a_date_that_says_it_is_utc():
    html = _html()
    start = html.index('<div id="insp-fix"')
    markup = html[start:html.index("</form>", start)]
    assert re.search(r'<input id="fix-valid-to" type="date">', markup)
    assert 'for="fix-valid-to">Stopped being true on (UTC date)</label>' in markup
    assert "style=" not in markup
    assert EM not in markup and EN not in markup
    # in the form of an entity AND of a tie: it is outside the label field
    # that only an entity shows
    label_field = markup[markup.index('id="fix-label-field"'):]
    label_field = label_field[:label_field.index("</div>")]
    assert "fix-valid-to" not in label_field


def test_the_date_is_sent_with_the_correction_after_the_checks_and_cleared_with_the_form():
    body = _function("submitCorrection")
    sent = body.index("await api(")
    assert "correctionEndDate($('fix-valid-to').value" in body
    assert body.index("correctionEndDate(") < sent
    assert "if (end !== undefined) body.valid_to = end;" in body
    assert body.index("body.valid_to = end") < sent
    assert "'fix-valid-to'" in _function("resetCorrection")
    # an end date alone is a correction: the label is not restated
    assert "end !== undefined && held && label === held.label" in body


def test_the_dialog_that_told_the_analyst_to_set_valid_to_says_where():
    wiring = _function("wireElementActions")
    flat = " ".join(wiring.split())
    assert "set valid_to" not in flat
    assert ('To say instead "this stopped being true in March", cancel and use '
            'Correct... with a date in Stopped being true on.') in " ".join(
                re.sub(r"'\s*\+\s*'", "", flat).split())


def test_the_words_of_the_form_name_the_date_and_stay_dash_free():
    js = _js()
    region = js[js.index("function correctionWords("):js.index("function openCorrection(")]
    assert "Stopped being true on" in region
    assert EM not in region and EN not in region and " -- " not in region
    end = _function("correctionEndDate")
    assert EM not in end and EN not in end


# --- executed under Node ------------------------------------------------------

@needs_node
def test_the_end_date_the_form_sends(tmp_path):
    """undefined: nothing to send. null: the end date is cleared. A string:
    the end of that UTC day, as the create forms write `valid_to`."""
    got = _run([_function("correctionEndDate")], """
const show = (v) => (v === undefined ? 'nothing' : v);
const day = '2026-03-01';
console.log(JSON.stringify({
  untouched_none: show(correctionEndDate('', null)),
  untouched_undefined: show(correctionEndDate('', undefined)),
  untouched_held: show(correctionEndDate(day, '2026-03-01T23:59:59Z')),
  set_new: show(correctionEndDate(day, null)),
  moved: show(correctionEndDate('2026-05-02', '2026-03-01T23:59:59Z')),
  cleared: show(correctionEndDate('', '2026-03-01T23:59:59Z')),
  garbage: show(correctionEndDate('not a date', null)),
  leap: show(correctionEndDate('2028-02-29', null)),
}));
""", tmp_path)
    assert got == {
        "untouched_none": "nothing",
        "untouched_undefined": "nothing",
        "untouched_held": "nothing",
        "set_new": "2026-03-01T23:59:59.000Z",
        "moved": "2026-05-02T23:59:59.000Z",
        "cleared": None,
        "garbage": "nothing",
        "leap": "2028-02-29T23:59:59.000Z",
    }


@needs_node
def test_the_retract_prompt_says_a_correction_gives_its_value_back(tmp_path):
    got = _run([_function("retractionWords")], """
console.log(JSON.stringify([
  retractionWords([{is_correction: false}], 'node', 0, true),
  retractionWords([{is_correction: false}], 'node', 0, false),
  retractionWords([{is_correction: false}], 'edge', 0),
  retractionWords([], 'node', 2, true),
]));
""", tmp_path)
    correction, plain, unspecified, last = got
    assert "this claim is a correction" in correction["prompt"].lower()
    assert "went back" not in correction["prompt"]
    assert "gone back to the value the remaining claims support" in correction["done"]
    for words in (plain, unspecified):
        assert "correction" not in words["prompt"].lower().replace(
            "corrections", "")
        assert "gone back" not in words["done"]
    # the last claim dissolves the element: no value to give back
    assert "gone back" not in last["done"]
    for words in got:
        for text in (words["prompt"], words["done"]):
            assert EM not in text and EN not in text and " -- " not in text


@needs_node
def test_the_help_of_each_form_mentions_the_date(tmp_path):
    got = _run(["const CONF_RANK = { LOW: 0, MODERATE: 1, HIGH: 2 };",
                _function("correctionWords")], """
console.log(JSON.stringify([correctionWords('node', null),
                            correctionWords('edge', 'MODERATE')]));
""", tmp_path)
    node, tie = got
    assert "Stopped being true on" in node["help"] and "as-of view" in node["help"]
    assert "Stopped being true on" in tie["help"] and "confidence as it is" in tie["help"]
    assert "retracting the correction puts it back" in node["help"]


def _deceptive() -> str:
    js = _js()
    start = js.index("const _DECEPTIVE = new RegExp(")
    return js[start:js.index("]', 'g');", start) + len("]', 'g');")]


@needs_node
def test_an_end_date_correction_reads_as_a_date_in_the_assertion_list(tmp_path):
    """The verifier's cosmetic: a date-only correction read `valid_to ->
    nothing` when the date was cleared and printed a raw ISO timestamp when
    it was set."""
    got = _run([_deceptive(), _function("visibleText"),
                _function("claimValueText"), _function("claimLine")], """
const line = (path, value) => claimLine(
  {is_correction: true, claim_path: path, claim_value: value}, 'node');
console.log(JSON.stringify({
  set: line('valid_to', {valid_to: '2026-03-01T23:59:59+00:00'}),
  set_z: line('valid_to', {valid_to: '2026-03-01T23:59:59.000Z'}),
  cleared: line('valid_to', {valid_to: null}),
  other_time: line('valid_to', {valid_to: '2026-03-01T10:15:00+00:00'}),
  with_label: line(null, {label: 'viper', valid_to: '2026-03-01T23:59:59Z'}),
  label_only: line('label', {label: 'viper'}),
}));
""", tmp_path)
    assert got == {
        "set": "Correction: valid until 2026-03-01",
        "set_z": "Correction: valid until 2026-03-01",
        "cleared": "Correction: no end date",
        "other_time": "Correction: valid until 2026-03-01T10:15:00+00:00",
        "with_label": 'Correction: label → "viper", valid until 2026-03-01',
        "label_only": 'Correction: label → "viper"',
    }
    for text in got.values():
        assert EM not in text and EN not in text and " -- " not in text
