"""The tie inspector: adding a claim, and what Correct... says about lowering.

Final review of 2026-09-23, group g09 (tie confidence):

- C14: since migration 0064 a tie's confidence is the highest grade among
  its live claims, so a correction cannot lower a tie past a claim that
  still stands. The server refuses it (409) and names the remedy, "add the
  lower claim, then retract the higher one", and the console had no way to
  add a claim to a tie at all. Correct... collected a reason first and
  then showed the 409. The only route left, retract then correct, left the
  tie resting on an ungraded correction with no exhibit.
- U11 (console half): the inspector header called a tie's confidence "its
  strongest live claim" when no live claim graded it, and the Retract
  prompt counted superseded rows as live support, which the projection
  (and now the rule everywhere) does not.

`test_tie_confidence_pg.py` holds the server half of both. Pure, as
`test_inspector_evidence_ui.py` is: the static checks run everywhere, and
the ones marked `needs_node` EXECUTE the shipped functions under Node.
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


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _html() -> str:
    return INDEX.read_text(encoding="utf-8")


def _function(name: str) -> str:
    """A top-level function's source, closed on the first `}` at column 0."""
    js = _js()
    start = js.index(f"function {name}(")
    return js[start:js.index("\n}", start) + 2]


def _claim_markup() -> str:
    html = _html()
    start = html.index('<div id="insp-claim"')
    return html[start:html.index("</form>", start)]


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text("\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


CONF_RANK = "const CONF_RANK = { LOW: 0, MODERATE: 1, HIGH: 2 };"


# ---------------------------------------------------------------------------
# C14: the form exists, is graded like the create forms, and posts a claim
# ---------------------------------------------------------------------------

def test_the_tie_inspector_has_an_add_a_claim_form():
    markup = _claim_markup()
    assert 'id="claim-open"' in markup and 'aria-controls="claim-form"' in markup
    assert '<form id="claim-form"' in markup and "novalidate" in markup
    for field in ("basis", "conf", "rel", "cred"):
        m = re.search(r'<select id="claim-' + field + r'"[^>]*>', markup)
        assert m and "required" in m.group(0), (
            f"#claim-{field} must be a required select, as the create forms' are")
    for element_id in ("claim-rationale", "claim-rat-req", "claim-evidence",
                       "claim-observed", "claim-ref", "claim-error",
                       "claim-submit", "claim-cancel"):
        assert f'id="{element_id}"' in _html(), element_id
    assert re.search(r'<p id="claim-error"[^>]*role="alert"', _html())
    assert "style=" not in markup


def test_a_claim_is_graded_and_checked_before_anything_is_sent():
    body = _function("addTieClaim")
    sent = body.index("await api(")
    for check in ("gradingProblem('claim')", "assertionFrom('claim')",
                  "rationaleProblem(assertion)"):
        assert check in body and body.index(check) < sent, check
    assert "cpath('/edges/' + edgeId + '/assertions')" in body
    assert "json: assertion" in body
    # Nothing is chosen for the analyst beyond what Correct... was asked.
    reset = _function("resetTieClaim")
    assert "resetGrading('claim', conf ? { conf: conf } : null)" in reset
    for default in ("'DIRECT_OBSERVATION'", "'C'", "'3'", "'F'", "'6'"):
        assert default not in reset


def test_a_claim_belongs_to_one_tie():
    """Typed for one tie, never recorded against another: the submit
    refuses a selection that has moved, the form empties when the
    selection changes, and on a case switch or sign-out."""
    body = _function("addTieClaim")
    assert "sel.id !== edgeId" in body
    assert body.index("sel.id !== edgeId") < body.index("await api(")
    assert "caseChanged(token)" in body
    assert "syncTieClaim(sel)" in _function("renderInspector")
    js = _js()
    hook = js[js.index("onCaseSwitch(() => {\n  tieClaim.edgeId = null;"):]
    hook = hook[:hook.index("});")]
    assert "resetTieClaim()" in hook and "showTieClaimForm(false)" in hook


def test_the_claim_form_offers_the_cases_exhibits():
    # 'fix': the Correct form offers them too (gap-api-grade-required).
    assert "['node', 'edge', 'claim', 'fix']" in _function("refreshEvidencePickers")
    assert "if (!btn) return;" in _function("renderSameGrading"), (
        "resetGrading('claim') must not trip on the absent same-grading offer")
    wiring = _function("wireTieClaim")
    for wired in ("$('claim-open')", "$('claim-cancel')",
                  "$('claim-form').addEventListener('submit', addTieClaim)",
                  "syncRationaleHint('claim')"):
        assert wired in wiring, wired
    assert "wireTieClaim();" in _function("wireElementActions")


@needs_node
def test_the_form_empties_when_the_selection_moves(tmp_path):
    stubs = """
const shown = {};
function $(id) { return { id: id }; }
function show(node, on) { shown[node.id] = on; }
let resets = 0;
function resetTieClaim() { resets += 1; }
function showTieClaimForm(open) { shown.form = open; }
const tieClaim = { edgeId: null };
"""
    got = _run([stubs, _function("syncTieClaim")], """
const out = [];
const step = (sel) => { syncTieClaim(sel);
  out.push([tieClaim.edgeId, resets, shown['insp-claim'], shown.form]); };
step({kind: 'edge', id: 'e1'});
shown.form = true;                     // the analyst opened it and typed
step({kind: 'edge', id: 'e1'});        // a reload re-renders the same tie
step({kind: 'edge', id: 'e2'});        // another tie
step({kind: 'node', id: 'n1'});        // an entity
console.log(JSON.stringify(out));
""", tmp_path)
    first, same, other, entity = got
    assert first == ["e1", 1, True, False]
    assert same == ["e1", 1, True, True], "a re-render keeps the draft"
    assert other == ["e2", 2, True, False], "another tie starts empty"
    assert entity == [None, 3, False, False], "no claim form on an entity"


# ---------------------------------------------------------------------------
# C14: Correct... stops before sending when it would lower the tie
# ---------------------------------------------------------------------------

def test_correct_checks_for_lowering_before_anything_is_sent():
    """Correct... is a graded form since gap-api-grade-required
    (2026-09-23), not two prompts, so the reason is written alongside the
    grade. What C14 asked still holds: a lowering re-grade is stopped
    before anything is sent, the claim form it opens is the remedy, and
    what the analyst wrote goes with it instead of being thrown away
    (test_correction_form_ui.py has the rest of the form)."""
    submit = _function("submitCorrection")
    check = submit.index("tieLoweringWords(")
    assert check < submit.index("await api("), (
        "a correction the server would refuse must not be sent")
    branch = submit[check:submit.index("body = { confidence: assertion.confidence };")]
    assert "carryCorrectionIntoTieClaim(assertion.confidence)" in branch
    assert "return;" in branch
    assert "openTieClaim(conf)" in _function("carryCorrectionIntoTieClaim")
    assert "relTieCache.get(sel.id)" in submit, (
        "a tie opened from the Relationships list is read the way the "
        "inspector reads it")


@needs_node
def test_the_lowering_refusal_names_the_way_to_lower_it(tmp_path):
    got = _run([CONF_RANK, _function("tieLoweringWords")], """
console.log(JSON.stringify([
  tieLoweringWords('HIGH', 'MODERATE'),
  tieLoweringWords('MODERATE', 'LOW'),
  tieLoweringWords('LOW', 'HIGH'),
  tieLoweringWords('MODERATE', 'MODERATE'),
  tieLoweringWords(null, 'LOW'),
]));
""", tmp_path)
    high_to_moderate, moderate_to_low, raise_, same, unknown = got
    assert high_to_moderate.startswith("This tie is HIGH")
    assert "cannot lower it past a claim that still stands" in high_to_moderate
    assert "nothing was sent" in high_to_moderate
    assert "add a MODERATE claim" in high_to_moderate
    assert "Add a claim form" in high_to_moderate
    assert "retract each claim graded above MODERATE" in high_to_moderate
    assert "add a LOW claim" in moderate_to_low
    assert raise_ is None and same is None and unknown is None
    for words in got:
        assert words is None or ("\u2014" not in words and "\u2013" not in words)


@needs_node
def test_the_recorded_banner_says_what_the_tie_is_now(tmp_path):
    got = _run([CONF_RANK, _function("tieClaimDoneWords")], """
console.log(JSON.stringify([
  tieClaimDoneWords('MODERATE', 'HIGH', true),
  tieClaimDoneWords('HIGH', 'HIGH', false),
  tieClaimDoneWords('HIGH', null, false),
]));
""", tmp_path)
    below, raised, unknown = got
    assert below.startswith("The tie stays HIGH while a claim graded above "
                            "MODERATE stands")
    assert "retract each such claim" in below and "It carries its exhibit." in below
    assert raised == "The tie is HIGH now, the highest grade among its live claims."
    assert unknown.startswith("The tie is HIGH now")


# ---------------------------------------------------------------------------
# U11, console half: the header and the Retract count say what is true
# ---------------------------------------------------------------------------

def test_the_header_does_not_call_an_ungraded_tie_its_strongest_claim():
    inspector = _function("renderInspector")
    assert "the highest grade among its live claims, LOW when none grades it" in (
        inspector)
    code = re.sub(r"/\*.*?\*/", "", inspector, flags=re.S)
    assert "its strongest live claim" not in code


def test_live_support_means_one_thing_in_the_projection_and_the_prompt():
    """The Retract prompt counts what the projection counts, and every
    live-provenance leg of the projection now leaves superseded rows out,
    as `core.tie_confidence` and the assertion list always did."""
    src = (API / "projections.py").read_text(encoding="utf-8")
    legs = re.findall(
        r"EXISTS \(SELECT 1 FROM core\.assertion a\s+WHERE a\.(?:node|edge)_id"
        r" = [ne]\.id\s+AND a\.retracted_at IS NULL\s*(AND a\.superseded_at IS"
        r" NULL)?\)", src)
    assert len(legs) == 4, "two legs in project(), two in withheld()"
    assert all(legs), "a live-provenance leg still counts superseded rows"
    assert "!x.retracted_at && !x.superseded_at && x.id !== a.id" in (
        _function("renderAssertions"))


def test_what_this_group_wrote_carries_no_em_or_en_dash():
    js = _js()
    region = js[js.index("/* ── inspector: add a claim"):
                js.index("/* Attach an exhibit already in this case")]
    assert "\u2014" not in region and "\u2013" not in region
    # The Correct... prompt carried one, and this group rewrote it. Built
    # with chr() so this file holds no dash of its own.
    em, en = chr(0x2014), chr(0x2013)
    assert "'Confidence " + em + " LOW" not in js
    # The prompt is gone (gap-api-grade-required, 2026-09-23): the
    # re-grade is a required select in the Correct form, no free text.
    assert re.search(r'<select id="fix-conf" class="select" required>', _html())
    markup = _claim_markup()
    assert em not in markup and en not in markup
