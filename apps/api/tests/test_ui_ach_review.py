"""The ACH pane after the 2026-09-23 usability review (ux11-ach).

Pure, beside `test_ui_invariants.py`: these read the shipped static assets
and the router source, with no database. The checks marked `needs_node`
EXECUTE the shipped functions under Node with a small DOM stub, because
"Cancel does nothing" and "a second save keeps the note" are claims about
behaviour, and the defects they close were each a line that read fine and
did the wrong thing:

- the stance chooser cleared its note box on every open and sent the
  emptiness (stance-note-erased-on-rescore);
- window.prompt's Cancel returned null and the assumption was withdrawn,
  for good (withdraw-cancel-still-withdraws);
- Confirm on a refuted assumption sent no note and got a rule refusal
  with "needs case.update" glued to it (refuted-assumption-cannot-be-
  confirmed);
- the router could reject a hypothesis and the console never asked it to
  (no-hypothesis-lifecycle-in-console).
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
SRC = STATIC.parents[1]

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    m = re.search(r"(?ms)^const " + re.escape(name) + r" = .*?;$", _js())
    assert m, f"const {name} is gone"
    return m.group(0)


_DOM = """
let focused = null;
function walk(n, out) {
  for (const c of n.children || []) { out.push(c); walk(c, out); }
  return out;
}
function el(tag, cls, text) {
  return {
    tagName: String(tag).toUpperCase(), className: cls || '',
    textContent: text === undefined || text === null ? '' : String(text),
    title: '', value: '', checked: false, hidden: false, disabled: false,
    type: '', name: '', children: [], attrs: {}, dataset: {}, listeners: {},
    setAttribute(k, v) { this.attrs[k] = v; },
    appendChild(c) { this.children.push(c); return c; },
    removeChild(c) { this.children = this.children.filter((x) => x !== c); },
    get lastChild() { return this.children[this.children.length - 1] || null; },
    addEventListener(k, f) { (this.listeners[k] = this.listeners[k] || []).push(f); },
    focus() { focused = this; },
    closest() { return null; },
    querySelector(sel) {
      const nodes = walk(this, []);
      if (sel === 'input:checked') {
        return nodes.find((x) => x.tagName === 'INPUT' && x.checked) || null;
      }
      if (sel === 'input') return nodes.find((x) => x.tagName === 'INPUT') || null;
      return null;
    },
    querySelectorAll() { return walk(this, []); },
  };
}
const document = {
  createTextNode(t) { return { tagName: '#text', textContent: String(t), children: [] }; },
  contains() { return true; },
  querySelector() { return null; },
};
const boxes = {};
function $(id) {
  if (!boxes[id]) {
    const set = /-options$/.test(id);
    boxes[id] = el(set ? 'fieldset' : 'div');
    if (set) boxes[id].appendChild(el('legend'));
  }
  return boxes[id];
}
function show(n, on) { n.hidden = !on; }
function clear(n) { n.children = []; }
function setMsg(node, text) { node.textContent = text || ''; node.hidden = !text; }
function fmtTime(x) { return x + ' UTC'; }
function countOf(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
function renderStanceBasis() {}
function cpath(s) { return '/cases/C' + s; }
function caseToken() { return 0; }
function caseChanged() { return false; }
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
class ApiError extends Error {
  constructor(status, title, detail) {
    super(title); this.status = status; this.title = title; this.detail = detail || '';
  }
}
const calls = [];
const failed = [];
let reply = () => ({});
async function api(path, o) {
  calls.push({ path: path, method: (o || {}).method || 'GET', json: (o || {}).json });
  return reply(path, o);
}
function fail(err) { failed.push(String(err)); }
let reloads = 0;
async function loadAch() { reloads += 1; }
async function loadAssumptions() { reloads += 1; }
let _stanceCtx = null;
let _decideCtx = null;
const state = { assertionMeta: new Map(), ach: {
  stance_scale: {'-2': 'strongly inconsistent', '-1': 'inconsistent', '0': 'neutral',
                 '1': 'consistent', '2': 'strongly consistent'},
  cells: [{assertion_id: 'a1', hypothesis_id: 'h1', stance: -1,
           note: 'posting pattern breaks at the split', note_by_name: 'Ada',
           note_at: '2026-09-23T10:00:00+00:00',
           earlier_notes: [{note: 'first reading', by: 'Bo', at: '2026-09-22T09:00:00+00:00'}]}],
}};
const text = (n) => (n.textContent || '') + (n.children || []).map(text).join('');
const pick = (fs, value) => {
  for (const r of walk(fs, [])) if (r.tagName === 'INPUT') r.checked = r.value === value;
};
const submit = async (f) => f({ preventDefault() {} });
"""

_SHIPPED = ("achCell", "achKey", "stanceText", "openStanceChooser",
            "renderStanceNoteTrail", "closeStanceChooser", "refocusAchCell",
            "saveStance", "clearStance", "showAchRefusal", "refusalText",
            "closeClause", "openAchDecision", "achDecisionChoice",
            "syncAchDecision", "closeAchDecision", "submitAchDecision",
            "openHypothesisStatus", "openHypothesisReword", "reviewAssumption",
            "assumptionVerbs")


def _run(body: str, tmp_path: Path):
    sources = [_const("STANCE_CLASS"), _const("ACH_STANCES"),
               _const("ACH_STATUS"), *(_fn(n) for n in _SHIPPED)]
    script = tmp_path / "run.js"
    script.write_text(_DOM + "\n".join(sources) + "\n(async () => {\n" + body
                      + "\n})().catch((e) => { console.error(e); process.exit(1); });",
                      encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# --- stance-note-erased-on-rescore -------------------------------------------

@needs_node
def test_the_chooser_opens_with_the_note_and_a_resave_does_not_send_it(tmp_path):
    got = _run("""
const h = {id: 'h1', number: 3, statement: 'the same operator'};
openStanceChooser({assertion_id: 'a1', label: 'vellum_ram'}, h, -1, el('button'));
const opened = {note: $('ach-stance-note').value, trail: text($('ach-stance-trail')),
                clearShown: !$('ach-stance-clear').hidden,
                hypothesis: $('ach-stance-hypothesis').textContent};
pick($('ach-stance-options'), '-2');
await submit(saveStance);
const kept = calls.pop();
openStanceChooser({assertion_id: 'a1', label: 'vellum_ram'}, h, -2, el('button'));
$('ach-stance-note').value = 'a better reason';
await submit(saveStance);
const edited = calls.pop();
openStanceChooser({assertion_id: 'a1', label: 'vellum_ram'}, h, -2, el('button'));
$('ach-stance-note').value = '   ';
await submit(saveStance);
const emptied = calls.pop();
openStanceChooser({assertion_id: 'a9', label: 'fresh'}, h, undefined, el('button'));
const fresh = {note: $('ach-stance-note').value, clearShown: !$('ach-stance-clear').hidden};
console.log(JSON.stringify({opened, kept, edited, emptied, fresh, reloads}));
""", tmp_path)
    assert got["opened"]["note"] == "posting pattern breaks at the split"
    assert "Written by Ada, 2026-09-23T10:00:00+00:00 UTC" in got["opened"]["trail"]
    assert "Saving keeps it unless you change it" in got["opened"]["trail"]
    assert "1 earlier note" in got["opened"]["trail"]
    assert "first reading (Bo" in got["opened"]["trail"]
    assert got["opened"]["clearShown"], "a scored cell can be cleared"
    assert got["opened"]["hypothesis"] == "H3: the same operator"
    assert got["kept"]["method"] == "PUT"
    assert got["kept"]["json"] == {"assertion_id": "a1", "stance": -2}, (
        "an unedited note must not be sent: the router keeps it only when "
        "the field is left out")
    assert got["edited"]["json"]["note"] == "a better reason"
    assert got["emptied"]["json"]["note"] is None, "emptying the box clears it"
    assert got["fresh"] == {"note": "", "clearShown": False}
    assert got["reloads"] == 3


@needs_node
def test_clear_puts_the_cell_back_to_not_assessed(tmp_path):
    got = _run("""
openStanceChooser({assertion_id: 'a1', label: 'vellum_ram'},
                  {id: 'h1', number: 1, statement: 's'}, -1, el('button'));
await clearStance();
console.log(JSON.stringify({call: calls.pop(), open: !$('ach-stance-scrim').hidden}));
""", tmp_path)
    assert got["call"]["method"] == "DELETE"
    assert got["call"]["path"] == "/cases/C/ach/hypotheses/h1/stance/a1"
    assert got["open"] is False


def test_the_router_keeps_a_note_the_body_leaves_out():
    router = (SRC / "http" / "routers" / "ach.py").read_text(encoding="utf-8")
    assert '"note" in body.model_fields_set' in router
    assert re.search(r'@router\.delete\("/hypotheses/\{hypothesis_id\}/stance/'
                     r'\{assertion_id\}"', router)
    assert '"note_was"' in router, "a replaced note is not kept anywhere"


# --- withdraw-cancel-still-withdraws and refuted-assumption-cannot-be-confirmed

@needs_node
def test_cancel_on_withdraw_withdraws_nothing(tmp_path):
    got = _run("""
const a = {id: 'x1', statement: 'the handle is one person', status: 'OPEN'};
reviewAssumption(a, 'WITHDRAWN', el('button'), el('p'));
const sheet = {open: !$('ach-decide-scrim').hidden, what: $('ach-decide-what').textContent,
               go: $('ach-decide-go').textContent, cls: $('ach-decide-go').className};
closeAchDecision();
console.log(JSON.stringify({sheet, calls: calls.length,
                            open: !$('ach-decide-scrim').hidden}));
""", tmp_path)
    assert got["sheet"]["open"]
    assert "permanent" in got["sheet"]["what"] and "report" in got["sheet"]["what"]
    assert got["sheet"]["go"] == "Withdraw it" and "danger" in got["sheet"]["cls"]
    assert got["calls"] == 0, "Cancel sent the withdrawal"
    assert got["open"] is False


@needs_node
def test_confirming_a_refuted_assumption_asks_for_the_note_it_needs(tmp_path):
    got = _run("""
const a = {id: 'x1', statement: 'the handle is one person', status: 'REFUTED'};
const rowMsg = el('p');
reviewAssumption(a, 'CONFIRMED', el('button'), rowMsg);
await submit(submitAchDecision);
const refused = {calls: calls.length, msg: $('ach-decide-msg').textContent};
$('ach-decide-note').value = 'the second account was a relay';
await submit(submitAchDecision);
const sent = calls.pop();
// A plain confirm of an OPEN one is one click, and a rule refusal from the
// service is said on the row without a permission glued to it.
reply = () => { throw new ApiError(400, 'Invalid request',
  'a refuted assumption cannot be re-opened without a review note'); };
const open = {id: 'x2', statement: 's', status: 'OPEN'};
reviewAssumption(open, 'CONFIRMED', el('button'), rowMsg);
await new Promise((r) => setTimeout(r, 0));
console.log(JSON.stringify({refused, sent, rowMsg: rowMsg.textContent,
  verbs: {OPEN: assumptionVerbs('OPEN').map((v) => v[0]),
          CONFIRMED: assumptionVerbs('CONFIRMED').map((v) => v[0]),
          REFUTED: assumptionVerbs('REFUTED').map((v) => v[0])}}));
""", tmp_path)
    assert got["refused"]["calls"] == 0
    assert "Why does the refutation no longer stand?" in got["refused"]["msg"]
    assert got["sent"]["method"] == "PATCH"
    assert got["sent"]["json"] == {"status": "CONFIRMED",
                                   "note": "the second account was a relay"}
    assert got["rowMsg"].startswith("A refuted assumption cannot be re-opened")
    assert "case.update" not in got["rowMsg"], (
        "a rule refusal read as a missing permission")
    assert got["verbs"]["OPEN"] == ["Confirm", "Refute…", "Withdraw…"]
    assert got["verbs"]["CONFIRMED"] == ["Refute…", "Reopen…", "Withdraw…"]
    assert got["verbs"]["REFUTED"] == ["Confirm…", "Reopen…", "Withdraw…"]


def test_the_register_no_longer_asks_through_window_prompt():
    for name in ("reviewAssumption", "assumptionRow", "assumptionVerbs"):
        assert "window.prompt" not in _code(_fn(name)), name
    assert "'OPEN'" in _code(_fn("assumptionVerbs")), "no Reopen verb"


# --- no-hypothesis-lifecycle-in-console ---------------------------------------

@needs_node
def test_a_hypothesis_is_rejected_with_its_reason(tmp_path):
    got = _run("""
const h = {id: 'h2', number: 2, statement: 'separate operators', status: 'PROPOSED'};
openHypothesisStatus(h, el('button'));
const offered = walk($('ach-decide-options'), []).filter((n) => n.tagName === 'INPUT')
  .map((n) => n.value);
pick($('ach-decide-options'), 'REJECTED');
syncAchDecision();
const label = $('ach-decide-note-label').textContent;
await submit(submitAchDecision);
const unsent = calls.length;
$('ach-decide-note').value = 'the handle predates the split';
await submit(submitAchDecision);
const sent = calls.pop();
const back = {id: 'h2', number: 2, statement: 's', status: 'REJECTED'};
openHypothesisStatus(back, el('button'));
pick($('ach-decide-options'), 'PROPOSED');
syncAchDecision();
const reopen = $('ach-decide-note-label').textContent;
openHypothesisReword({id: 'h4', number: 4, statement: 'old words'}, el('button'));
const prefilled = $('ach-decide-note').value;
$('ach-decide-note').value = 'new words';
await submit(submitAchDecision);
console.log(JSON.stringify({offered, label, unsent, sent, reopen, prefilled,
                            reword: calls.pop()}));
""", tmp_path)
    assert got["offered"] == ["ACCEPTED", "DISPUTED", "REJECTED", "SUPERSEDED"]
    assert "What rules it out? Required" in got["label"]
    assert got["unsent"] == 0, "a rejection went out without its reason"
    assert got["sent"]["path"] == "/cases/C/ach/hypotheses/h2/status"
    assert got["sent"]["json"] == {"status": "REJECTED",
                                   "note": "the handle predates the split"}
    assert "Why does the rejection no longer stand? Required" in got["reopen"]
    assert got["prefilled"] == "old words"
    assert got["reword"]["method"] == "PATCH"
    assert got["reword"]["json"] == {"statement": "new words"}


@needs_node
def test_the_status_note_says_where_it_goes(tmp_path):
    """The Reject label promised "printed in the report" while the report
    printed only the status (verifier of ux11-ach:no-hypothesis-lifecycle-
    in-console, 2026-09-23). reports.py now prints the reason recorded with
    each current status, and leaves a SUPERSEDED hypothesis out entirely,
    so the label says exactly that (test_ach_lifecycle_pg::test_the_report_
    prints_why_a_hypothesis_was_ruled_out holds the server's half)."""
    got = _run("""
const labels = {};
for (const v of ['ACCEPTED', 'DISPUTED', 'REJECTED', 'SUPERSEDED']) {
  openHypothesisStatus({id: 'h2', number: 2, statement: 's', status: 'PROPOSED'},
                       el('button'));
  pick($('ach-decide-options'), v);
  syncAchDecision();
  labels[v] = $('ach-decide-note-label').textContent;
}
openHypothesisStatus({id: 'h2', number: 2, statement: 's', status: 'REJECTED'},
                     el('button'));
pick($('ach-decide-options'), 'SUPERSEDED');
syncAchDecision();
labels.back = $('ach-decide-note-label').textContent;
console.log(JSON.stringify(labels));
""", tmp_path)
    for v in ("ACCEPTED", "DISPUTED", "REJECTED"):
        assert got[v].endswith("printed in the report."), (v, got[v])
    assert got["REJECTED"].startswith("What rules it out? Required")
    assert "report" not in got["SUPERSEDED"], got["SUPERSEDED"]
    assert got["back"].startswith("Why does the rejection no longer stand? Required")
    assert "report" not in got["back"], "a superseded one leaves the report"
    reports = (SRC / "reports.py").read_text(encoding="utf-8")
    assert "status::text <> 'SUPERSEDED'" in reports


def test_the_console_offers_the_lifecycle_the_router_defines():
    router = (SRC / "http" / "routers" / "ach.py").read_text(encoding="utf-8")
    assert '@router.post("/hypotheses/{hypothesis_id}/status"' in router
    assert '@router.patch("/hypotheses/{hypothesis_id}"' in router
    from noctornal_api.http.routers.ach import _STATUSES
    offered = set(re.findall(r"\['([A-Z]+)', '", _const("ACH_STATUS")))
    assert offered == set(_STATUSES)
    card = _code(_fn("achCard"))
    assert "openHypothesisStatus(h" in card and "openHypothesisReword(h" in card
    assert "fact('confidence'" in card, "the confidence sent is never shown"
    html = _html()
    for id_ in ("ach-decide-scrim", "ach-decide-form", "ach-decide-options",
                "ach-decide-note", "ach-decide-go", "ach-decide-cancel",
                "ach-stance-clear", "ach-stance-trail"):
        assert f'id="{id_}"' in html, id_
    wiring = _code(_js())
    for hook in ("$('ach-decide-form').addEventListener('submit', submitAchDecision)",
                 "$('ach-decide-cancel').addEventListener('click', closeAchDecision)",
                 "$('ach-stance-clear').addEventListener('click', clearStance)"):
        assert hook in wiring, hook


# --- evidence-row-is-a-name-not-a-claim and grading-weight-unexplained ---------

def test_a_row_names_its_subject_claim_grade_and_weight():
    cell = _code(_fn("achEvidenceCell"))
    assert "achOpenElement(e)" in cell, "the row does not open its element"
    assert "'weight ' + achNum(e.weight)" in cell
    assert "achClaim(e)" in cell
    subject = _code(_fn("achSubject"))
    assert "e.src_label" in subject and "e.dst_label" in subject
    assert "visibleText(" in subject, "a handle an attacker chose is drawn raw"
    # Two decimals, so 0.49 is not "0.5" and 0.04 is not "0.0".
    assert "toFixed(2)" in _code(_fn("achNum"))
    assert "toFixed(1)" not in _code(_fn("achCard"))


def test_every_new_string_is_free_of_dashes_and_bracketed_plurals():
    names = ("achCard", "achSubject", "achClaim", "achEvidenceCell",
             "achUnknownWhy", "renderStanceNoteTrail", "reviewAssumption",
             "openHypothesisStatus", "openHypothesisReword", "renderAchMatrix",
             "renderAchRanking", "showAchRefusal", "loadAch")
    for name in names:
        strings = re.findall(r"'(?:[^'\\\n]|\\.)*'", _code(_fn(name)))
        for s in strings:
            assert not re.search("[\u2013\u2014]| -- ", s), (name, s)
            assert not re.search(r"\w\((?:s|es)\)", s), (name, s)
    assert not re.search("[\u2013\u2014]", _const("ACH_STATUS"))
