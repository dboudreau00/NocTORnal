"""Triage, the inbox and dual control in the console, held to what the
2026-09-22 review found in them (the ux08-triage findings).

Pure: the shipped static assets, with the real functions run under Node
against stubs (skipped where Node is absent), beside test_ui_invariants.
The server halves are in test_triage_inbox_pg.py.
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


def _css() -> str:
    return re.sub(r"/\*.*?\*/", "",
                  (STATIC / "app.css").read_text(encoding="utf-8"), flags=re.S)


def _visible(html: str) -> str:
    return " ".join(re.sub(r"<!--.*?-->", "", html, flags=re.S).split())


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(name: str) -> str:
    js = _js()
    m = re.search(rf"(?m)^const {re.escape(name)} = ", js)
    assert m, f"const {name} is gone"
    line = js[m.start():js.index("\n", m.start())]
    if line.rstrip().endswith(";") and line.count("{") == line.count("}"):
        return line + "\n"
    close = js.index("\n}", m.start()) + 1
    return js[m.start():js.index("\n", close) + 1]


_STUBS = r"""
function el(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', children: [], attrs: {}, listeners: {}, hidden: false,
           disabled: false, dataset: {},
           classList: { _s: new Set(), add(c) { this._s.add(c); },
                        contains(c) { return this._s.has(c); },
                        toggle(c, on) { if (on) this._s.add(c); else this._s.delete(c); } },
           setAttribute(k, v) { this.attrs[k] = v; },
           removeAttribute(k) { delete this.attrs[k]; },
           addEventListener(t, fn) { this.listeners[t] = fn; },
           appendChild(c) { this.children.push(c); return c; },
           isConnected: true,
           contains(x) { return x === this || this.children.some(
             (c) => c && typeof c.contains === 'function' && c.contains(x)); },
           focus() { document.activeElement = this; } };
}
const document = { createTextNode(t) { return { tag: '#text', textContent: t }; },
                   activeElement: null };
function fmtTime(x) { return 'T(' + x + ')'; }
function shortId(id) { return id ? String(id).slice(0, 8) : 'unknown'; }
function visibleText(s) { return s === null || s === undefined ? '' : String(s); }
function typeName(k) { return k === 'IDENTITY' ? 'Identity' : k; }
function countOf(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }
function agree(n, one, many) { return Number(n) === 1 ? one : many; }
function asSentence(t) { t = String(t || '').trim(); if (!t) return '';
  t = t.charAt(0).toUpperCase() + t.slice(1); return /[.!?]$/.test(t) ? t : t + '.'; }
const TLP = ['CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'];
const MERGE_OPERATION = 'node.merge';
const RELAX_OPERATION = 'case.policy.relax';   // F9b
"""


def _run(sources: list[str], body: str, tmp_path: Path):
    script = tmp_path / "run.js"
    script.write_text(_STUBS + "\n".join(sources) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True,
                         text=True, encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# ---------------------------------------------------------------------------
# triage-keys-fire-on-browser-chords
# ---------------------------------------------------------------------------

@needs_node
def test_the_triage_keys_act_on_the_page_or_a_card_and_nowhere_else(tmp_path):
    """A plain A pressed while the Dual control Load button had the focus
    accepted the highlighted proposal: the only guard was INPUT, TEXTAREA
    and SELECT. Since ux18-a11y:triage-letter-keys-global the letters act
    only inside the list as well, so this holds them to a card or the list
    itself, never a button in it, a field, a chord or an open sheet."""
    got = _run([_fn("triageKeyTarget"), _fn("onTriageKey")], """
const calls = [];
const state = { tab: 'triage', triage: [{id: 1}, {id: 2}], triageIndex: 0 };
function acceptProposal(p) { calls.push('accept'); }
function rejectProposal(p) { calls.push('reject'); }
function deferProposal(p) { calls.push('defer'); }
function renderTriage() {}
let sheetOpen = false;
function anyDialogOpen() { return sheetOpen; }
function triageLettersOn() { return true; }
function triageAcceptQuestion() { return 'Accept?'; }
const window = { confirm: () => true };
document.body = { tagName: 'BODY' };
document.documentElement = { tagName: 'HTML' };
const card = { tagName: 'DIV', classList: { contains: (c) => c === 'triage-card' } };
const listEl = { tagName: 'DIV', id: 'triage-list', classList: { contains: () => false },
                 children: [], focus() {} };
const inList = new Set([card, listEl]);
const button = { tagName: 'BUTTON', id: 'apr-refresh', classList: { contains: () => false } };
inList.add(button);                    // a button inside a card
listEl.contains = (t) => inList.has(t);
const select = { tagName: 'SELECT', id: 'triage-state', classList: { contains: () => false } };
function $(id) { return id === 'triage-list' ? listEl : { children: [] }; }
const press = (target, key, mods) => {
  let prevented = false;
  onTriageKey(Object.assign({ key: key, target: target,
    preventDefault() { prevented = true; } }, mods || {}));
  return prevented;
};
const out = {};
press(button, 'a'); press(select, 'r'); press(document.body, 'a');
press(card, 'a', { ctrlKey: true }); press(card, 'd', { metaKey: true });
out.ignored = calls.splice(0);
sheetOpen = true; press(card, 'a'); sheetOpen = false;
out.underSheet = calls.splice(0);
press(card, 'a'); press(listEl, 'r'); press(card, 'd');
out.taken = calls.splice(0);
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["ignored"] == [], f"a key meant for something else was a verdict: {got}"
    assert got["underSheet"] == [], "a key reached the queue under the keyboard sheet"
    assert got["taken"] == ["accept", "reject", "defer"]


def test_the_keyboard_sheet_says_what_a_does_and_lists_d():
    """The sheet promised "a confirmation step" that Accept never had, and
    listed J K, A and R without D."""
    text = _visible(_html())
    flat = " ".join(text.split())
    assert "Nothing here writes to the graph without a confirmation step" not in text
    # A asks first since ux18-a11y:triage-letter-keys-global, and the Undo
    # this pass added still follows it; both are said where the keys are.
    assert "A asks for a confirmation" in flat and "Undo retires it" in flat
    sheet = text[text.index('<h3 class="h-xs">Triage</h3>'):]
    sheet = sheet[:sheet.index("</dl>")]
    for key in ("J", "K", "A", "R", "D"):
        assert f'<span class="kbd">{key}</span>' in sheet, key
    assert "offers an Undo" in " ".join(sheet.split())
    assert "A asks before it accepts, and the line above the queue then says" in flat, (
        "the pane's own hint does not say it")
    docs = (SRC.parents[3] / "docs" / "06-interface.md").read_text(encoding="utf-8")
    assert "`D` discard" not in docs and "`D`\n  defer" in docs


@needs_node
def test_an_accept_says_what_it_wrote_and_offers_an_undo(tmp_path):
    """The card left the queue with no word: an analyst whose Ctrl+A had
    been taken as A never learned a proposal had left review."""
    got = _run([_fn("triageRefName"), _fn("triageTitle"), _fn("triageChosenLevel"),
                _fn("showTriageOutcome"), _fn("triageCanUndo"), _fn("caseCan"),
                _const("TRIAGE_UNDO_PERMISSION"), _const("TRIAGE_UNDO_WORDS")], """
function clear(n) { n.children = []; }
function show(n, on) { n.hidden = !on; }
const line = el('p', 'msg'); line.hidden = true;
function $(id) { return line; }
const state = { triageAcceptAt: {} };
function undoAccept() {}
showTriageOutcome({ id: 'p1', kind: 'NODE', classification: 'RED',
                    payload: { label: 'spectre.lynx@protonmail.com' } }, 'accept', {});
const accepted = { hidden: line.hidden, text: line.children.map((c) => c.textContent) };
showTriageOutcome({ id: 'p2', kind: 'NODE', payload: { label: 'x' } }, 'defer', {});
console.log(JSON.stringify({ accepted, deferred: line.children.map((c) => c.textContent) }));
""", tmp_path)
    assert got["accepted"]["hidden"] is False
    assert got["accepted"]["text"] == [
        "Accepted: spectre.lynx@protonmail.com, written at TLP:RED. ", "Undo"]
    assert got["deferred"] == ["Deferred: x."]


def test_undo_retires_what_the_accept_wrote():
    undo = _fn("undoAccept")
    assert "'/graph/nodes/' + out.applied_node_id" in undo
    assert "'/graph/edges/' + out.applied_edge_id" in undo
    assert "'/assertions/' + out.applied_assertion_id + '/retract'" in undo
    assert "showTriageOutcome(p, path, out || {})" in _fn("disposition")
    model = (SRC / "http" / "routers" / "proposals.py").read_text(encoding="utf-8")
    assert "applied_assertion_id: str | None" in model


# ---------------------------------------------------------------------------
# attribute-proposal-no-label-no-value
# ---------------------------------------------------------------------------

@needs_node
def test_a_card_names_what_accepting_would_write(tmp_path):
    got = _run([_fn("triageRefName"), _fn("triageTitle"), _fn("triageClaimValue")], """
const n1 = '899b2ae7-1a22-4ddc-9270-7727b02181ef';
const n2 = 'cfd825cb-a90d-43d4-ba8b-13e2e067b049';
const attr = { kind: 'ATTRIBUTE',
  payload: { node_id: n1, claim_path: 'comms.tox', claim_value: 'ABCD' },
  refs: { [n1]: { label: 'Meridian crew', node_type: 'IDENTITY' } } };
const hidden = { kind: 'ATTRIBUTE',
  payload: { node_id: n2, claim_path: 'comms.tox', claim_value: { v: 1 } }, refs: {} };
const edge = { kind: 'EDGE',
  payload: { src_node_id: n1, dst_node_id: n2, edge_type: 'COMMUNICATES_WITH' },
  refs: { [n1]: { label: 'Meridian crew', node_type: 'IDENTITY' } } };
const node = { kind: 'NODE', payload: { label: 'spectre_lynx' } };
console.log(JSON.stringify([triageTitle(attr), triageClaimValue(attr),
  triageTitle(hidden), triageClaimValue(hidden), triageTitle(edge),
  triageTitle(node), triageTitle({ kind: 'NODE', payload: {} })]));
""", tmp_path)
    assert got[0] == "Meridian crew (Identity) gains comms.tox"
    assert got[1] == "ABCD"
    assert got[2] == "entity cfd825cb, not visible to you gains comms.tox"
    assert got[3] == '{"v":1}'
    assert got[4] == ("Meridian crew (Identity) → COMMUNICATES_WITH → "
                      "entity cfd825cb, not visible to you")
    assert got[5] == "spectre_lynx"
    assert "(no label)" not in _js().replace('read "(no label)"', "")
    assert got[6] == "unnamed suggestion"


def test_an_attribute_card_shows_its_value_with_a_copy_button():
    render = _fn("renderTriage")
    assert "triageClaimValue(p)" in render
    assert "copyable(el('code', 'mono', visibleText(value)), value" in render


# ---------------------------------------------------------------------------
# accept-downgrades-classification, gap-capture-classification
# ---------------------------------------------------------------------------

@needs_node
def test_a_card_offers_no_label_below_its_capture(tmp_path):
    got = _run([_fn("triageAcceptLevels")], """
console.log(JSON.stringify([triageAcceptLevels({ classification: 'AMBER' }),
                            triageAcceptLevels({ classification: 'RED' })]));
""", tmp_path)
    assert got == [["AMBER", "AMBER_STRICT", "RED"], ["RED"]]
    render = _fn("renderTriage")
    assert "'TLP:' + p.classification" in render, "the card carries no TLP chip"
    assert "classification: triageChosenLevel(p)" in _fn("acceptProposal")


# ---------------------------------------------------------------------------
# queue-vocabulary-and-empty-text
# ---------------------------------------------------------------------------

@needs_node
def test_a_parked_item_is_deferred_and_each_queue_has_its_own_empty_text(tmp_path):
    got = _run([_const("TRIAGE_STATE_WORD"), _const("TRIAGE_EMPTY"),
                _fn("triageCountsLine"), _fn("triageOutcome")], """
console.log(JSON.stringify([
  triageCountsLine({ PROPOSED: 3, DISPUTED: 1, ACCEPTED: 2 }),
  triageOutcome({ state: 'DISPUTED', review_note: 'need the full thread' }),
  triageOutcome({ state: 'REJECTED', review_note: null }),
  TRIAGE_EMPTY]));
""", tmp_path)
    line, parked, rejected, empty = got
    assert line == "3 awaiting review · 1 deferred · 2 accepted"
    assert "disputed" not in line.lower()
    assert parked == "Deferred: need the full thread"
    assert rejected == "Rejected"
    assert empty["ACCEPTED"] == "No accepted proposals yet."
    assert empty["DISPUTED"] == "Nothing deferred."
    assert "TRIAGE_EMPTY[queue]" in _fn("renderTriage")


# ---------------------------------------------------------------------------
# graph-says-unreviewed-triage-says-nothing
# ---------------------------------------------------------------------------

def test_the_ring_comes_from_the_queue_and_never_from_edge_review():
    """The Triage half of the ring is the queue's own count. A tie's review
    is the other half since gap-tie-review (2026-09-23) made the column
    real and clearable: it is counted into its own map, never into the
    Triage count, and each half has a row naming where it is cleared."""
    index = re.sub(r"/\*.*?\*/", "", _fn("indexProjection"), flags=re.S)
    assert "nodeProposed" not in index, (
        "the Triage count is derived from edge.review again")
    assert "state.nodeUnreviewed = unreviewed;" in index
    assert "state.nodeProposed = new Map(Object.entries(data.pending_by_node"\
        in _fn("loadTriage")
    metrics = _fn("renderNodeMetrics")
    assert "'Proposals waiting in Triage'" in metrics
    assert "'Ties awaiting review'" in metrics
    assert "unreviewed proposal" not in _visible(_html())
    assert ">proposal in Triage or tie to review<" in _visible(_html())


# ---------------------------------------------------------------------------
# source-document-not-reachable
# ---------------------------------------------------------------------------

@needs_node
def test_the_source_view_marks_the_match_without_markup(tmp_path):
    got = _run([_fn("triageSourceText")], """
const pre = triageSourceText({ text: 'mail me at a@b.io today', offset: 10,
  length: 100, match: { start: 11, end: 17 }, purged: false });
console.log(JSON.stringify(pre.children.map((c) => [c.tag, c.textContent])));
""", tmp_path)
    assert got == [["#text", "…mail me at "], ["mark", "a@b.io"], ["#text", " today…"]]
    line = _fn("triageSourceLine")
    assert "p.document_title" in line and "'Open source'" in line
    assert "cpath('/proposals/' + p.id + '/source')" in _fn("toggleTriageSource")


# The real renderTriage and the source view, over a stubbed page: the
# helpers that only paint text are no-ops here.
_TRIAGE_PAGE = r"""
const nodes = { 'triage-list': el('div'), 'triage-empty': el('p'),
                'triage-counts': el('p'), 'triage-state': { value: 'PROPOSED' } };
function $(id) { return nodes[id]; }
function clear(x) { x.children = []; }
function show(x, on) { x.hidden = !on; }
function showEmptyState(id, on) { show($(id), on); }   // ux17-failure
function setMsg() {}
function renderTriageBadge() {}
function triageCountsLine() { return ''; }
const TRIAGE_EMPTY = { PROPOSED: 'Nothing awaiting review.' };
function triageTitle(p) { return p.id; }
function triageClaimValue() { return ''; }
function copyable(x) { return x; }
function num(v) { return String(v); }
function triageActions() { return el('div', 'triage-actions'); }
function triageOutcome() { return ''; }
let rebuilds = 0;
const SRC = { title: 'escrow thread', classification: 'AMBER', captured_at: 'c',
  text: 'mail me at a@b.io today', offset: 0, length: 23,
  match: { start: 11, end: 17 }, purged: false };
const state = { triage: [{ id: 'p1', kind: 'NODE', state: 'PROPOSED',
                           document_id: 'd1', payload: {} },
                         { id: 'p2', kind: 'NODE', state: 'PROPOSED',
                           document_id: 'd1', payload: {} }],
                triageCounts: {}, triageIndex: 0,
                triageSources: { p1: SRC, gone: SRC } };
let selection = { isCollapsed: true };
const window = { getSelection() { return selection; } };
function viewOf(card) {
  const line = card.children.find((c) => c.className === 'triage-source-line');
  return { btn: line.children[1], view: line.children[2] };
}
"""


@needs_node
def test_a_click_or_a_selection_inside_an_opened_capture_keeps_it_open(tmp_path):
    """The verifier of the first fix: the source view sits inside the card,
    whose click handler rebuilt the whole list, so a click or a drag-select
    in the opened capture closed it and dropped the selection."""
    got = _run([_fn("renderTriage"), _fn("pickTriageCard"),
                _fn("triageSourceLine"), _fn("fillTriageSource"),
                _fn("triageSourceHeading"), _fn("triageSourceText")],
               _TRIAGE_PAGE + """
renderTriage();
const box = nodes['triage-list'];
const first = box.children[0];
const out = { pruned: Object.keys(state.triageSources).sort() };
const v = viewOf(first);
out.openAfterRebuild = [v.view.hidden, v.btn.textContent,
  v.view.children[1].children.map((c) => c.tag)];
out.closedOther = viewOf(box.children[1]).view.hidden;

// A drag-select that ends inside the capture: the card's click fires with a
// selection standing. Nothing may be rebuilt, and nothing may take focus.
selection = { isCollapsed: false };
document.activeElement = null;
first.listeners.click();
out.sameCard = nodes['triage-list'].children[0] === first;
out.stillOpen = !viewOf(first).view.hidden;
out.focusDuringSelection = document.activeElement;

// A plain click on the other card moves the highlight, still without a
// rebuild, and the capture on the first card stays open.
selection = { isCollapsed: true };
box.children[1].listeners.click();
out.index = state.triageIndex;
out.on = box.children.map((c) => c.classList.contains('on'));
out.sameAfterMove = nodes['triage-list'].children[0] === first;
out.stillOpenAfterMove = !viewOf(first).view.hidden;
out.focused = document.activeElement === box.children[1];
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["pruned"] == ["p1"], "a capture whose card left the list was kept"
    assert got["openAfterRebuild"] == [False, "Hide source", ["#text", "mark", "#text"]], (
        "a rebuild (J, K, a live reload) closed the capture the analyst opened")
    assert got["closedOther"] is True
    assert got["sameCard"] and got["stillOpen"], (
        "a click inside the opened capture rebuilt the list and closed it")
    assert got["focusDuringSelection"] is None, "focus was moved mid-selection"
    assert got["index"] == 1 and got["on"] == [False, True]
    assert got["sameAfterMove"] and got["stillOpenAfterMove"]
    assert got["focused"], "the clicked card did not take the keys"
    body = _fn("renderTriage").split("{", 1)[1]
    assert "renderTriage()" not in body and "pickTriageCard(i)" in body, (
        "the card's click handler rebuilds the list again")


@needs_node
def test_hiding_a_capture_forgets_it_and_a_late_answer_reopens_it(tmp_path):
    got = _run([_fn("renderTriage"), _fn("pickTriageCard"),
                _fn("triageSourceLine"), _fn("fillTriageSource"),
                _fn("toggleTriageSource"), _fn("triageSourceHeading"),
                _fn("triageSourceText")],
               _TRIAGE_PAGE + """
function caseToken() { return 1; }
function caseChanged() { return false; }
function cpath(p) { return p; }
function refusalText(e, t) { return t; }
let answer = null;
async function api() { return answer; }
(async () => {
  const out = {};
  renderTriage();
  let v = viewOf(nodes['triage-list'].children[0]);
  await toggleTriageSource(state.triage[0], v.btn, v.view);
  out.forgotten = !('p1' in state.triageSources);
  out.hidden = v.view.hidden;

  // Open p2, but the list is rebuilt while the read is in flight.
  v = viewOf(nodes['triage-list'].children[1]);
  v.view.isConnected = false;
  answer = SRC;
  await toggleTriageSource(state.triage[1], v.btn, v.view);
  const now = viewOf(nodes['triage-list'].children[1]);
  out.late = [('p2' in state.triageSources), now.view.hidden, now.btn.textContent];
  console.log(JSON.stringify(out));
})();
""", tmp_path)
    assert got["forgotten"] and got["hidden"], "Hide source kept it in the store"
    assert got["late"] == [True, False, "Hide source"], (
        "an answer that landed after a rebuild opened a detached view")


# ---------------------------------------------------------------------------
# open-approvals-wrong-case, notifications-no-path-to-object
# ---------------------------------------------------------------------------

@needs_node
def test_every_notification_kind_has_a_route_and_names_another_case(tmp_path):
    got = _run([_fn("notificationRoute"), _fn("notificationRouteLabel")], """
const mk = (object_type, extra) => Object.assign(
  { case_id: 'B', case_code: 'OP-CORVID-26', object_type, object_id: 'x1',
    kind: 'K' }, extra || {});
const rows = [mk('approval_request'), mk('triage'), mk('evidence'),
  mk('node_merge'), mk('case_review'), mk('break_glass'),
  mk('break_glass', { case_id: null }), mk(null, { kind: 'PROPOSAL_QUEUED' }),
  mk('notification', { case_id: null })];
console.log(JSON.stringify(rows.map((n) => {
  const r = notificationRoute(n);
  return r ? [r.label, r.tab || null, notificationRouteLabel(n, r, 'A')] : null;
})));
""", tmp_path)
    assert got[0] == ["Open the request", "triage", "Open the request in OP-CORVID-26"]
    assert got[1][:2] == ["Open Triage", "triage"]
    assert got[2][:2] == ["Open the exhibit", "evidence"]
    assert got[3][:2] == ["Open the merge", "graph"]
    # The rail's caption, Records, not the old Lifecycle (u23, 2026-09-24).
    assert got[4][:2] == ["Open Records", "governance"]
    assert got[5][:2] == ["Open Break-glass", "governance"]
    assert got[6] == ["Open Oversight", None, "Open Oversight"]
    assert got[7][:2] == ["Open Triage", "triage"]
    assert got[8] is None


@needs_node
def test_open_goes_to_the_case_the_request_belongs_to(tmp_path):
    """In OP-NIGHTJAR-26, Open approvals on an OP-CORVID-26 request stayed
    in NIGHTJAR and said there were no pending requests."""
    got = _run([_fn("notificationRoute"), _fn("openNotificationTarget")], """
const log = [];
const state = { caseId: 'nightjar', caseRec: {} };
async function openCase(id) { log.push('open:' + id); state.caseId = id; state.caseRec = {}; }
function selectTab(t) { log.push('tab:' + t + ':' + state.caseId + ':' + state.approvalTarget); }
const selectGovSub = null;
function showAdmin() { log.push('admin'); }
function focusExhibit() {} async function focusMerge() {}
(async () => {
  await openNotificationTarget({ case_id: 'corvid', object_type: 'approval_request',
                                 object_id: 'req-7' });
  const across = log.splice(0);
  await openNotificationTarget({ case_id: 'corvid', object_type: 'triage' });
  console.log(JSON.stringify({ across, same: log }));
})();
""", tmp_path)
    assert got["across"] == ["open:corvid", "tab:triage:corvid:req-7"]
    assert len(got["same"]) == 1 and got["same"][0].startswith("tab:triage:corvid"), (
        "a notification about the open case reopened it")


@needs_node
def test_oversight_from_the_case_less_inbox_leaves_the_inbox(tmp_path):
    """The verifier of the first fix: a security officer's BREAK_GLASS
    alert belongs to no case, so its Open goes to Oversight; showAdmin
    never put the case-less Inbox away, and both views stood on screen."""
    got = _run([_fn("notificationRoute"), _fn("openNotificationTarget")], """
const log = [];
const state = { caseId: null, caseRec: null };
let adminView = false;
async function showAdmin() { log.push('admin'); adminView = !state.caseId; }
function leaveInbox() { log.push('leave-inbox:' + adminView); }
async function openCase() {} function selectTab(t) { log.push('tab:' + t); }
const selectGovSub = null;
function focusExhibit() {} async function focusMerge() {}
(async () => {
  const alert = { case_id: null, object_type: 'break_glass', object_id: 'g1' };
  await openNotificationTarget(alert);
  const listed = log.splice(0);
  // Inside a case, showAdmin opens the rail tab and there is no case-less
  // Inbox to leave.
  state.caseId = 'nightjar'; adminView = false;
  await openNotificationTarget(alert);
  console.log(JSON.stringify({ listed, inCase: log }));
})();
""", tmp_path)
    assert got["listed"] == ["admin", "leave-inbox:true"], (
        "Oversight opened over the case-less Inbox without putting it away")
    assert got["inCase"] == ["admin"]


def test_the_request_a_notification_named_is_brought_into_view():
    load = _fn("loadApprovals")
    assert "focusApprovalTarget()" in load
    focus = _fn("focusApprovalTarget")
    assert "$('apr-' + id)" in focus and "is-highlighted" in focus
    assert "card.id = 'apr-' + a.id" in _fn("approvalRow")


def test_the_integrity_alarm_opens_the_exhibit_and_its_custody():
    focus = _fn("focusExhibit")
    assert "$('ev-' + id)" in focus and "custody.click()" in focus


# ---------------------------------------------------------------------------
# approval-row-uuids-no-requester
# ---------------------------------------------------------------------------

@needs_node
def test_an_approval_card_names_both_entities_and_the_direction(tmp_path):
    got = _run([_fn("approvalEntity"), _fn("approvalTitle"),
                _fn("approvalConsequence")], """
const a = { operation: 'node.merge',
  payload: { source_node_id: '899b2ae7-1', target_node_id: 'cfd825cb-a' },
  subjects: { source: { label: 'Meridian crew', node_type: 'IDENTITY' },
              target: null } };
console.log(JSON.stringify([approvalTitle(a), approvalConsequence(a),
  approvalTitle({ operation: 'case.delete', operation_description: 'Delete a case',
                  payload: {} })]));
""", tmp_path)
    assert got[0] == ('Merge "Meridian crew" (Identity) INTO entity cfd825cb, '
                      'which you cannot see')
    assert got[1].startswith('"Meridian crew" leaves the live graph')
    assert got[2] == "Delete a case", "the operation's key was shown, not its name"


@needs_node
def test_each_party_sees_only_the_buttons_the_server_allows(tmp_path):
    got = _run([_fn("approvalActions")], """
const state = { userId: 'me' };
const log = [];
window = { confirm: () => { log.push('confirm'); return false; }, prompt: () => null };
async function api(path) { log.push('api:' + path); return {}; }
function cpath(p) { return p; }
function loadApprovals() {} function refreshWaiting() {} function banner() {}
function inlineProblem() {} function fail() {}
class ApiError {}
const mine = approvalActions({ id: 'r1', requested_by: 'me', justification: 'j' },
                             'Merge', 'you', true);
const theirs = approvalActions({ id: 'r2', requested_by: 'them', justification: 'j' },
                               'Merge', 'Ada', false);
const buttons = (box) => box.children.filter((c) => c.tag === 'button')
  .map((c) => c.textContent);
const withdraw = mine.children.find((c) => c.textContent === 'Withdraw');
withdraw.listeners.click();
setTimeout(() => console.log(JSON.stringify({
  mine: buttons(mine), theirs: buttons(theirs), log })), 0);
""".replace("window = {", "var window = {"), tmp_path)
    assert got["mine"] == ["Withdraw"]
    assert got["theirs"] == ["Approve", "Reject"]
    assert got["log"] == ["confirm"], "Withdraw fired without a confirmation"
    assert "&& mine)" in _fn("approvalRow"), "Execute merge is offered to non-requesters"


# ---------------------------------------------------------------------------
# approval-reach-warning-dropped
# ---------------------------------------------------------------------------

@needs_node
def test_a_request_nobody_was_told_about_says_so(tmp_path):
    got = _run([_fn("approvalRaisedTitle"), _fn("approvalRaisedText")], """
const warned = { warnings: ['the request is recorded but no approver was notified: '
  + 'nobody else on this case holds the permission'], approvers_notified: 0 };
const told = { warnings: [], approvers_notified: 2 };
console.log(JSON.stringify([approvalRaisedTitle(warned), approvalRaisedText(warned),
  approvalRaisedTitle(told), approvalRaisedText(told)]));
""", tmp_path)
    assert got[0] == "Approval requested, but nobody was told"
    assert got[1].startswith("The request is recorded but no approver was notified")
    assert got[2] == "Approval requested"
    assert "2 approvers were notified." in got[3]
    merge = _fn("runMerge")
    assert "const raised = await api(cpath('/approvals')" in merge
    assert "approvalRaisedText(raised)" in merge
    row = _fn("approvalRow")
    assert "a.approvers_notified === 0" in row and "'no approver notified'" in row
    assert "out.warnings" in _fn("approvalActions"), "the decision's warning is dropped"


# ---------------------------------------------------------------------------
# urgent-read-vs-ack-invisible, inbox-actions-fail-silently
# ---------------------------------------------------------------------------

@needs_node
def test_the_badge_stays_up_and_urgent_while_an_alarm_is_unacknowledged(tmp_path):
    got = _run([_fn("inboxBadgeState"), _fn("escalationLine")], """
console.log(JSON.stringify([inboxBadgeState(0, 1), inboxBadgeState(3, 0),
  inboxBadgeState(0, 0),
  escalationLine({ escalates_at: '2026-09-23T14:05:00Z' }, Date.parse('2026-09-23T13:30:00Z')),
  escalationLine({ escalates_at: '2026-09-23T14:05:00Z' }, Date.parse('2026-09-23T15:00:00Z')),
  escalationLine({ escalates_at: null })]));
""", tmp_path)
    glanced, unread, none, future, past, never = got
    assert glanced["show"] and glanced["urgent"] and glanced["text"] == "1", (
        "reading an urgent alarm took the badge to zero")
    assert "escalates to someone else unless acknowledged" in glanced["title"]
    assert unread == {"show": True, "text": "3", "urgent": False,
                      "title": "3 unread notifications"}
    assert none["show"] is False
    assert future.startswith("Escalates at T(2026-09-23T14:05:00Z) unless acknowledged")
    assert past.startswith("Past its escalation time")
    assert never == ""
    assert ".rail-badge.urgent" in _css() and ".hdr-badge.urgent" in _css()
    assert "needs_action=true" in _fn("loadInbox")
    assert 'id="inbox-needs-action"' in _html() and "inbox-unread-only" not in _html()


@needs_node
def test_a_failed_inbox_action_says_so_and_can_be_retried(tmp_path):
    got = _run([_fn("inboxAction")], """
const msg = el('p', 'msg'); msg.hidden = true;
function $() { return msg; }
function setMsg(n, t) { n.textContent = t || ''; n.hidden = !t; }
function refusalText(err, ctx) { return 'Refused. ' + ctx; }
async function loadInbox() {}
let fails = true;
async function api() { if (fails) throw new Error('offline'); return { marked: 2 }; }
const btn = el('button', 'btn', 'Acknowledge');
(async () => {
  await inboxAction(btn, '/notifications/n1/acknowledge', 'Acknowledged: x.');
  const failed = { text: msg.textContent, cls: msg.className, disabled: btn.disabled };
  fails = false;
  await inboxAction(btn, '/notifications/n1/acknowledge', 'Acknowledged: x.');
  console.log(JSON.stringify({ failed, ok: [msg.textContent, msg.className] }));
})();
""", tmp_path)
    assert got["failed"] == {"text": "Refused. Nothing was changed.",
                             "cls": "msg bad", "disabled": False}
    assert got["ok"] == ["Acknowledged: x.", "msg ok"]
    render = _fn("renderInbox")
    assert "inboxAction(read," in render and "inboxAction(ack," in render
    assert "await api('/notifications/' + n.id" not in render


def test_mark_all_read_asks_first_and_names_the_urgent_ones():
    """The confirmation is ux17-failure's counted one (inboxReadAllText,
    test_ui_failure_states), which names the urgent ones and says reading
    does not acknowledge; the outcome is said as this pass said it."""
    init = _fn("initInbox")
    assert "window.confirm(inboxReadAllText())" in init
    assert "api('/notifications/read-all', { method: 'POST' })" in init
    assert "' read.' + (p1 ? ' Urgent items still need '" in init
    said = _fn("inboxReadAllText")
    assert "'is urgent', 'are urgent'" in said
    flat = re.sub(r"'\s*\+\s*'", "", said)          # join the concatenated lines
    assert "Reading does not acknowledge" in flat


# ---------------------------------------------------------------------------
# prefs-unlabelled-and-opaque, quiet-hours-utc-not-local
# ---------------------------------------------------------------------------

@needs_node
def test_the_priority_says_what_it_delivers_and_what_it_drops(tmp_path):
    got = _run([_fn("prefKindsText")], """
const kinds = {
  APPROVAL_REQUESTED: { priority: 2, description: 'Someone is asking for your second signature' },
  EVIDENCE_INTEGRITY_ALARM: { priority: 1, description: 'An exhibit failed its integrity check' },
  PROPOSAL_QUEUED: { priority: 3, description: 'New proposals are waiting in triage' },
};
console.log(JSON.stringify([prefKindsText(kinds, 1), prefKindsText(kinds, 3)]));
""", tmp_path)
    urgent, everything = got
    assert urgent.startswith("Delivers: An exhibit failed its integrity check.")
    assert "Leaves out: Someone is asking for your second signature" in urgent
    assert "Requests for your second signature will not arrive" in urgent
    assert everything.endswith("Leaves out nothing.")


@needs_node
def test_quiet_hours_show_and_save_their_zone(tmp_path):
    got = _run([_fn("prefZoneOptions"), _fn("prefZoneNote")], """
console.log(JSON.stringify([prefZoneOptions('UTC', 'America/New_York'),
  prefZoneNote('UTC', 'America/New_York'), prefZoneNote('UTC', 'UTC')]));
""", tmp_path)
    options, differs, same = got
    assert options == [["UTC", "UTC"],
                       ["America/New_York", "America/New_York (this browser)"]]
    assert differs.startswith("Quiet hours are read in UTC.")
    assert "This browser is on America/New_York" in differs
    assert same == "Quiet hours are read in UTC."
    prefs = _fn("loadInboxPreferences")
    assert "timezone: zone.value" in prefs, "the chosen zone is not saved"
    assert "your local time" not in prefs
    for label in ("'Deliver on this channel'", "'Minimum priority'",
                  "'Hourly digest'", "'Quiet from'", "'Zone'"):
        assert label in prefs, label


# ---------------------------------------------------------------------------
# no-work-waiting-at-sign-in
# ---------------------------------------------------------------------------

@needs_node
def test_the_case_list_says_what_is_waiting(tmp_path):
    got = _run([_fn("caseWaitingText")], """
console.log(JSON.stringify([caseWaitingText({ triage: 3, signatures: 1 }),
  caseWaitingText({ triage: 1, signatures: 0 }), caseWaitingText(null)]));
""", tmp_path)
    assert got == ["3 proposals to triage, 1 request to sign",
                   "1 proposal to triage", "nothing"]
    assert "Waiting for you" in _visible(_html())
    assert "'case-waiting absent', 'not counted'" in _fn("renderCases")
    assert "if (!state.waiting) return;" in _fn("paintCaseWaiting")
    assert "api('/notifications/waiting')" in _fn("refreshWaiting")


def test_the_inbox_is_in_the_header_and_opens_without_a_case():
    html = _html()
    header = html[html.index('<header class="appbar">'):html.index("</header>")]
    assert 'id="btn-inbox"' in header and 'id="hdr-inbox-badge"' in header
    assert 'id="view-inbox"' in html
    opener = _fn("openInbox")
    assert "if (state.caseId) { selectTab('inbox'); return; }" in opener
    assert "$('view-inbox').appendChild(pane)" in opener
    assert "leaveInbox()" in _js()
    badge = _fn("renderInboxBadge")
    assert "'hdr-inbox-badge'" in badge


def test_the_triage_badge_counts_signatures_too():
    badge = _fn("renderTriageBadge")
    assert "mine.signatures" in badge and "proposed + sign" in badge


# ---------------------------------------------------------------------------
# stale-badges-and-list
# ---------------------------------------------------------------------------

@needs_node
def test_a_proposal_event_reloads_the_queue(tmp_path):
    got = _run([_fn("onLiveChange")], """
const log = [];
function liveAway() { return false; }
const _liveHeld = {};
function liveStatus() {}
const _badgeSoon = () => log.push('badge');
const _triageSoon = () => log.push('triage');
const _refetchSoon = () => log.push('graph');
for (const kind of ['proposal', 'notification', 'node']) onLiveChange({ kind });
console.log(JSON.stringify(log));
""", tmp_path)
    assert got == ["triage", "badge", "graph"]
    badge = _const("_badgeSoon")
    assert "if (inboxOnScreen()) loadInbox();" in badge, (
        "the open inbox list still ignores a notification that arrived")
    blocks = _js()[_js().index("function initCommsBlocks()"):]
    blocks = blocks[:blocks.index("\n}\n")]
    assert "e.proposal_id)) loadTriage();" in blocks
    events = (SRC / "proposals.py").read_text(encoding="utf-8")
    assert "announce(self._c, case_id)" in events


def test_nothing_new_puts_a_dash_or_a_lazy_plural_in_front_of_a_reader():
    names = ("triageTitle", "triageRefName", "triageOutcome", "showTriageOutcome",
             "undoAccept", "triageActions", "triageSourceLine", "triageSourceHeading",
             "approvalTitle", "approvalConsequence", "approvalRow", "approvalActions",
             "approvalRaisedText", "notificationRoute", "escalationLine",
             "inboxBadgeState", "prefKindsText", "prefZoneNote", "caseWaitingText",
             "initInbox", "renderInbox", "loadInboxPreferences", "focusApprovalTarget",
             "focusExhibit", "focusMerge", "triageBadgeTitle")
    for name in names:
        for s in re.findall(r"'(?:[^'\\\n]|\\.)*'", _fn(name)):
            assert not re.search("[\u2013\u2014]| -- ", s), (name, s)
            assert "(s)" not in s, (name, s)
